---
title: "When the stack trace lies"
publishDate: 2026-07-16 01:30:47 +0530
tags: [ programming ]
description: "A bug that hid behind a perfectly normal-looking failure for months"
---

I've written a few RCA-themed posts here in the past. They're pretty fun to write about & a chance to look back and tell
the whole story. This is one of them. What makes this one interesting is how long it took me to even realize there *was*
an issue in the first place. The bug masked itself behind a perfectly normal failure mode, silently influencing a lot of
the architectural decisions I made along the way. And it got progressively worse over time.

### The background story

Early this year, I started working on something new, that's quite different from the things I have been doing for
our consumer apps. This project involves heavy use of multimodal LLMs, particular Gemini 3.1,
which unfortunately is still the best model for analysing large videos. Until this point, I had fairly limited
experience of working with these LLM APIs. All I had done was to use them for a few parts of a larger system, things
like generating a few embeddings, summarising a few things etc. Nothing that centered on it. Nothing that would push
them to max of their context windows & thinking levels.

### The abysmal success rate

Anyway, withing a few weeks, I had a POC, and in a month I had deployed it to production (although pretty primitive &
shabby). The initial version of the pipeline had a less than 70% success rate. While over time, I fixed most of the
issues,
what remained were issues with the Gemini client (<insert-sdk-here>) calls failing for various reasons. I didn't really
have ideas of how to fix it, so I asked around, asked people in my team who had much more experience with LLMs. And I
got quite useful tips like "add timeout to gemini client", "use vertex-ai=True", set a proper thinking config, validate
the outputs etc. And what if it still fails? Just add retries! And this was a good advice. You can't expect an API
running trillion parameter models behind the scene to always work perfectly, surely they are bound to fail sometimes,
right! So I did, just like other repos in the org. All my gemini calls were now wrapped in a tenacity retry decorator.
And it worked, the success rate improved drastically.

### Progressive decline

Over the course of a month or two, the quality of results improved, and with that the requirements expanded
as well. This forced me to introduce a few steps in the pipeline that would call Gemini to understand & respond using a
video often reaching upto two hours!, using hacks like speeding up the video, reducing resolution etc. Most of these
calls were timing out, throwing `ReadTimeout`. But it worked or at-least it worked once given the absurd no of retires I
had to put in place. With these retries, the account would hit the rate-limits more often. So naturally, the next thing
I did was to add exponential backoff, increase the timeouts etc. Also switched to "generateContentStream" with
includeThoughts set to true. This worked
for a while, but now, a job that can complete under an hour took hours, sometimes a day to process. Clearly it was my
fault for borderline abusing the Gemini API. A while after that, I am not sure what happened, but Gemini completely
started failing, no amount of retries would help it.

### Attempts at a fix

So I decided to do the long pending thing, fix my own code. Instead of throwing the whole video, I will break it down to
parts, process them, & reconcile/merge the data later. The reconciliation was a much harder task, with its output being
not as good as just throwing the whole video in, but it was what needed to be done. It took me time but the outcome was
good. This worked pretty well (at least in all the test runs done on my PC). But once it hit production, I will start
seeing the same issue again. While the probability of these `ReadTimeout` reduced, more chunks meant more single point
of failures. Ultimately this didn't help much with the issue. While it was an architecturally sound decision to make,
one that would help us scale beyond just two hours of input,it just didn't help. At this point, I could sense something
was wrong. I had always felt that the pipeline worked better on my local setup somehow. All the testing I was doing on
my local worked perfectly fine, and it took considerably less time (aka retries) on my local setup as well. Now that
feeling was too strong. Clearly, there was a mismatch in my local vs production. I searched on internet, found a single
possibly related ticket, tried the solutions in them in vain. After brainstorming, I came
up with few ideas (btw claude didn't really any of them) of my own. Setting max_keepalive_connections to 0 to force a
new
connection everytime, initialising a client per call etc. My idea was, if this is an issue with client or the
connection pool its holding, maybe I can isolate / contain it to per call. Like claude expected, this didn't work at
all.

### The gottcha

Defeated, I went back to claude, one of the things it was persistently telling me was to try was to set some socket
options in the underlying code. I haven't given it a proper read. Because, blaming it on the client was already a
ridiculous thing, going down to the tcp level options to fix it feel absurd to say the least. Surely it can't be the
client? Millions of people must be using it, if there was an issue, someone would have found it by now. Anyway,
after eliminating all other options, I gave what claude was saying a proper read. The more I read it, the more it was
making sense. It said, that since I was deploying the job in a k8s cluster on a cloud, my egress is most likely via a
NAT gateway & the NAT gateways typically
have an idle-timeout that would close connections that have been idle for a while. Indeed, I was behind a NAT gateway. I
knew it, but I never thought of them having an idle-timeout. On second though, it made sense, why wouldn't they? But
apparently, most often, they do so silently, i.e. without sending any `RST`/`FIN` to either the client or the server!
This
means the client won't know the connection is broken at all! And the way around this idle timeout is to set TCP
keepalive socket options. Again something I have read about but never though of. This seemed to explain all my issues &
experience so far perfectly well. This would also explain why moving to streaming response with include thoughts set to
true helped a bit. Anyway, The NAT gateway's idle-timeout was indeed the default 4 mins. But it still seemed too good to
be true. If so, how was it working till now! How did no one else know or tell me this? It means all the tweaks I was
doing with timeouts, setting it beyond 15-20mins were completely useless, since the connection was already broken at 4
mins mark anyway!

To fully convince myself, I wrote a test script to test with & without the keepalive socket options (mentioned below) &
ran it on the production environment.

```python
# probe every ~60s (< the NAT's 4 min idle timeout) to keep the mapping alive
opts = [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]
opts += [
    (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60),
    (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15),
    (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4),
]
transport = httpx.HTTPTransport(socket_options=opts)
```

And indeed did it confirmed the issue! The keepalive socket options worked perfectly. With the fix, the success rate
reached almost 100% & the jobs that sometimes took over a day, are all now completing within a couple of hours.

### Failing Loudly!

The most annoying thing about this is how silent the failure. I don't mind things failing, but they should fail loudly!
The NAT Gateways dropped the connection silently (I am sure its by design for a good reason, but still), the client
raising a `ReadTimeout` indicating that it was the server that failed to respond in time (From its perspective, its
completely
correct), and the fixes that didn't address the root cause: retries masked the errors & increased processing time,
streaming response seemed to work (reducing time to first byte/token)  further
validating my belief that it was indeed an issue with the calls being too heavy for Gemini to process & sending
me off in the wrong direction. While this behaviour of NAT Gateways & the use of TCP keepalive probes for the same seems
to be well documented, I doubt, it would be on anyone's list of possible root cause unless they have
experienced it earlier, Especially when working on a far distant domain like I was. If I didn't have claude, I am not
sure if I would have ever been able to pinpoint this issue. On the bright sider, most LLM providers have (very recently)
started providing some sort of polling/offloading capabilities for heavy jobs, like Gemini's [background
execution](https://ai.google.dev/gemini-api/docs/background-execution),
OpenAI's [background mode](https://developers.openai.com/api/docs/guides/background) etc.