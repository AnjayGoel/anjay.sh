---
title: "The bug that blamed everyone but itself"
publishDate: 2026-07-21 01:30:47 +0530
tags: [ programming, rca ]
description: "RCA of a bug that hid behind a perfectly normal-looking failure for months"
---

I've written a few RCA-themed posts here in the past. They're pretty fun to write about & give a chance to look back and
tell the whole story. This is one of them. What makes this one interesting is how long it took me to even realize there
*was* an issue in the first place. The bug masked itself behind a perfectly normal failure mode, silently influencing a
lot of the architectural decisions and got progressively worse over time.

## The backstory

Early this year, I started working on something new, quite different from my day-to-day work on our consumer apps. The
project relied heavily on multimodal LLMs, particularly Gemini 3.1, which unfortunately is still the best model for
analysing large videos. Until this point, I'd had fairly limited experience working with these LLM APIs. All I'd done
was use them for small bits of a larger system: summarising text, generating embeddings, ranking documents etc.
Nothing where they were the core of the system, nothing that pushed them to the limits of their context windows &
thinking levels.

## Just add retries!

Within a few weeks I had a POC, and within a month it was in production. The initial version was primitive & shabby,
with a success rate (the % of jobs that ran end to end and produced usable output) well under 70%. While I
chipped away at most of the failures over time, one category stuck around: the Gemini API calls failing, for all sorts
of reasons: rate-limits, timeouts, valid but incorrect structured responses. So I turned to folks in the company with
far more LLM experience than me. The advice I got was reasonable: add a timeout to the client, set `vertexai=True`, add
a proper`ThinkingConfig`, validate the json outputs. And if it still fails? Just add retries! And it was good advice,
you can't expect an API running trillion-parameter models to work perfectly every time, they're bound to glitch once in
a while, right? So I did, wrapping every Gemini call in a tenacity retry decorator. And it worked, the success rate shot
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

## Fixing the wrong things

Now, I decided to do the long-pending thing: fix my own code. Instead of feeding Gemini the whole video, I'd split it
into chunks, process each, & reconcile the results later. Reconciliation was the harder task, and the merged output was
never quite as good as one-shotting the whole video, but it was what needed to be done. This change worked pretty well
in all the test runs on my PC. But once it hit production, I started seeing the same issue again. The `ReadTimeout`s got
less frequent, but more chunks just meant more single points of failure. Ultimately it didn't help much. It was an
architecturally sound decision, one that would let us scale beyond just two hours of input, it just didn't fix the
actual problem.

At this point I could sense something was wrong. The inputs I was feeding Gemini were now well within its capabilities;
it shouldn't have been timing out at all. And I'd always had a nagging feeling the pipeline ran better on my local
setup, all my local testing worked perfectly and took few to no retries. Now that feeling was too strong to ignore:
clearly, there was a mismatch between the local and production environments. I searched online, found a single
possibly-related [Github Issue](https://github.com/googleapis/python-genai/issues/1893), tried its solutions in vain. After brainstorming, I came up with a few ideas of my own (
btw, claude didn't like most of them): setting `max_keepalive_connections` to 0 to force a new connection every time,
initialising a fresh client per call, etc. My idea being: if this is an issue with a stale client or a pooled connection
gone bad, forcing a brand-new connection each time might fix it. As claude expected, this didn't work at all.

## The smoking gun

Defeated, I went back to claude. One thing it kept pushing me to try was setting some socket options on the client's
underlying HTTP transport. I'd been brushing it off: blaming the client was already a stretch, and going all the way
down to TCP-level options felt absurd. Surely it can't be the client? Millions of people must be using it; if there were
a bug, someone would've found it by now.

Anyway, having eliminated everything else, I finally read what claude was saying properly. The more I read, the more it
made sense. Its argument: since the job ran in a k8s cluster on the cloud, my egress almost certainly went out through a
NAT gateway, and NAT gateways usually have an idle-timeout that drops connections after they've been idle for a while.
Sure enough, our egress did go through a NAT gateway, I knew that. But it had never occurred to me, that they'd have an
idle-timeout. On second thought, of course they do, why wouldn't they? The catch though is, they usually drop the
connection silently, without sending an `RST` or `FIN` to either side, so the client has no idea the connection is even
dead. To avoid the idle-timeouts, one needs to enable TCP keepalive socket options. Again, something I'd read about but
never had a reason to use.

This explained everything. It even explained why switching to a streaming response with `include_thoughts` had helped a
little: the stream kept sending data over the connection, so it never sat idle long enough to get dropped. So I went and
checked our NAT gateway's config, and sure enough, its idle-timeout was set to the default 4 minutes. It almost seemed
too good to be true. If this was really it, how had it ever worked at all? And how did no one else knew, or tell me? It
also meant all the tweaks I had done, cranking the timeout up past 15-20 minutes were pointless, the connection was
already dead at the 4-minute mark regardless!

To fully convince myself, I wrote a test script that ran on the same production enviornment, with & without the
keepalive socket options (see below).

```python
# probe every ~60s (< the NAT's 4 min idle timeout) to keep the connection alive
opts = [
    (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
    (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60),
    (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15),
    (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4),
]
transport = httpx.HTTPTransport(socket_options=opts)
```

And indeed this confirmed the issue! The keepalive socket options worked perfectly. With the fix, the success rate
reached almost 100% & the jobs that sometimes took over a day are all now completing within a couple of hours.

## Red herrings all the way down!

The most annoying thing about this whole fiasco is how every layer seems to have misled me. The NAT gateway dropped the
connection silently (I'm sure it's by design for a good reason, but still). The client raised a `ReadTimeout`, pinning
the blame on the server for failing to respond in time (from its perspective, completely correct). And none of my "
fixes" addressed the root cause, yet each seemed to help just enough to keep me looking in the wrong place: retries
masked the errors (at the cost of processing time), and switching to a streaming response genuinely sped things up (
lower time to first byte), further convincing me the real problem was that my calls were simply too heavy for Gemini to
handle.

Apparently, this behaviour of NAT gateways, and the use of TCP keepalive probes for the same seems to be well
documented. But I doubt it would be on anyone's shortlist of likely causes unless they've experienced it before,
especially when the bug sits so far from the domain you're actually working in. I'm not sure if I'd
ever have pinpointed it without Claude's help. On the bright side, most LLM providers have (very recently) started
offering some sort of polling/offloading for heavy jobs, like
Gemini's [background execution](https://ai.google.dev/gemini-api/docs/background-execution) and
OpenAI's[background mode](https://developers.openai.com/api/docs/guides/background).