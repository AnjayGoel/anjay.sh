---
title: "When the stack trace lies"
publishDate: 2026-07-16 01:30:47 +0530
tags: [ programming ]
description: "A bug that hid behind a perfectly normal-looking failure for months"
---

I've written a few RCA-themed posts here in the past. They're pretty fun to write about & give a chance to look back and
tell the whole story. This is one of them. What makes this one interesting is how long it took me to even realize there
*was* an issue in the first place. The bug masked itself behind a perfectly normal failure mode, silently influencing a
lot of the architectural decisions and got progressively worse over time.

## The background story

Early this year, I started working on something new, quite different from my day-to-day work on our consumer apps. The
project relied heavily on multimodal LLMs, particularly Gemini 3.1, which unfortunately is still the best model for
analysing large videos. Until this point, I'd had fairly limited experience working with these LLM APIs. All I'd done
was use them for small bits of a larger system: summarising text, generating embeddings, ranking documents etc.
Nothing where they were the core of the system, nothing that pushed them to the limits of their context windows &
thinking levels.

## Just add retries!

Within a few weeks I had a POC, and within a month it was in production. The initial version was primitive & shabby,
with a success rate (percentage of the batch jobs that actually completed and produced outputs) well under 70%. While I
chipped away at most of the failures over time, one category stuck around: the Gemini API calls failing, for all sorts
of reasons: rate-limits, timeouts, valid but incorrect structured responses. So I turned to folks in the company with
far more LLM experience than me. The advice I got was reasonable: add a timeout to the client, set `vertexai=True`, add
a proper`ThinkingConfig`, validate the json outputs. And if it still fails? Just add retries! And it was good advice,
you
can't expect an API running trillion-parameter models to work perfectly every time, they're bound to glitch once in a
while, right? So I did, wrapping every Gemini call in a tenacity retry decorator. And it worked, the success rate shot
up.

## Death by a thousand retries

Over a month or two, the quality of the results improved, and with it the requirements grew. This forced me to add a few
pipeline steps that fed Gemini a whole video at once, often up to two hours long. To make that fit, I leaned on hacks
like speeding the video up and dropping the `MediaResolution`, etc. Many of these calls timed out by throwing a
`ReadTimeout`. But it worked, or at least it worked *once*, given the absurd number of retries I had put in
place.

Those retries also made the account hit rate-limits more often, so naturally the next thing I did was to add exponential
backoff, bump up the client timeouts even further, etc. But now a job that could finish in under an hour
sometimes took a full day. Since it was a `ReadTimeout`, I also switched to `generate_content_stream` with
`include_thoughts` set to true, which bought a little breathing room and cut down the number of retries needed. Clearly
it was my fault for pushing Gemini past its limits. A while later, Gemini tipped over for good, most if not all calls
started failing outright; no amount of retries would save them.

## Attempts at a fix

Now, I decided to do the long-pending thing: fix my own code. Instead of feeding Gemini the whole video, I'd split it
into chunks, process each, & reconcile the results later. Reconciliation was the harder task, and the merged output was
never quite as good as one-shotting the whole video, but it was what needed to be done. This change worked pretty well
in all the test runs on my PC. But once it hit production, I started seeing the same issue again. The `ReadTimeout`s got
less frequent, but more chunks just meant more single points of failure. Ultimately it didn't help much. It was an
architecturally sound decision, one that would let us scale beyond just two hours of input, it just didn't fix the
actual problem.

At this point I could sense something was wrong. The inputs I was giving to Gemini was now far less than its
capabilities, it should not be timing out. And I'd always felt the pipeline worked better on my local setup somehow;
all my local testing ran perfectly fine, and took few to none retries. Now that feeling was too strong to ignore.
Clearly, there was a mismatch between my local and production. I searched online, found a single possibly-related
ticket, tried its solutions in vain. After brainstorming, I came up with a few ideas of my own (btw, claude didn't think
much of them): setting `max_keepalive_connections` to 0 to force a new connection every time, initialising a
client per call, etc. My thinking was, if this was an issue with the client or the connection pool it's holding, maybe I
could isolate it to a single call. As claude expected, this didn't work at all.

## The gotcha

Defeated, I went back to claude. One of the things it kept persistently telling me to try was to set some socket options
in the underlying code. I hadn't given it a proper read, because blaming it on the client was already ridiculous; going
down to TCP-level options to fix it felt absurd, to say the least. Surely it can't be the client? Millions of people
must be using it, if there was an issue, someone would have found it by now.

Anyway, after eliminating all other options, I finally gave what claude was saying a proper read. The more I read, the
more it made sense. It said that since I was deploying the job in a k8s cluster on a cloud, my egress was most likely
via
a NAT gateway, and NAT gateways typically have an idle-timeout that closes connections that have been idle for a while.
Indeed, I was behind a NAT gateway. I knew that, but I'd never thought of them having an idle-timeout. On second
thought,
it made sense, why wouldn't they? But apparently, most often, they do it silently, i.e. without sending any `RST`/`FIN`
to either the client or the server! This means the client has no idea the connection is broken at all! And the way
around it is to set TCP keepalive socket options. Again, something I'd read about but never thought to use.

This seemed to explain all my issues perfectly. It would also explain why moving to a streaming response with
`include_thoughts` set to true had helped a bit. And indeed, the NAT gateway's idle-timeout was the default 4 minutes.
But it still seemed too good to be true. If this was it, how was it working at all until now? How did no one else know,
or tell me this? It meant all the tweaks I'd been doing with timeouts, setting them beyond 15-20 mins, were completely
useless, since the connection was already broken at the 4 min mark anyway!

To fully convince myself, I wrote a test script that ran the same job with & without the keepalive socket options (
below)
on the production pods.

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

And indeed it did confirm the issue! The keepalive socket options worked perfectly. With the fix, the success rate
reached almost 100% & the jobs that sometimes took over a day are all now completing within a couple of hours.

## Failing Loudly!

The most annoying thing about this whole saga is how silent the failure was. I don't mind things failing, but they
should fail loudly! Instead, every layer misled me. The NAT gateway dropped the connection silently (I'm sure it's by
design for a good reason, but still). The client raised a `ReadTimeout`, pinning the blame on the server for failing to
respond in time (from its perspective, completely correct). And none of my "fixes" addressed the root cause, yet each
seemed to help just enough to keep me looking in the wrong place: retries masked the errors (at the cost of processing
time), and switching to a streaming response genuinely sped things up (lower time to first byte), further convincing me
the real problem was that my calls were simply too heavy for Gemini to handle.

This behaviour of NAT gateways, and the TCP keepalive probes that work around it, seems to be well documented. But I
doubt it would be on anyone's list of likely root causes unless they'd hit it before, especially when working in a
far-flung domain like I was. If I hadn't had claude, I'm not sure I'd ever have pinpointed it. On the bright side, most
LLM providers have (very recently) started offering some sort of polling/offloading for heavy jobs, like Gemini's
[background execution](https://ai.google.dev/gemini-api/docs/background-execution) and OpenAI's
[background mode](https://developers.openai.com/api/docs/guides/background).