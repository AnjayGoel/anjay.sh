---
title: "The bug that blamed everyone but itself"
publishDate: 2026-07-20 11:10:00 +0530
tags: [ programming, rca ]
description: "An interesting RCA of a bug that hid behind a perfectly normal-looking failure for months"
---

I've written a few of these RCA posts before, they're a fun chance to look back & tell the whole story. This one's
interesting for a slightly different reason though: how long it took to even realize there *was* a bug in the first
place. It hid behind a perfectly normal-looking failure mode, silently influenced a bunch of the architectural
decisions, and just kept getting worse the whole time.

## The backstory

Early this year, I started working on something new, quite different from my day-to-day work on our consumer apps. The
project relied heavily on multimodal LLMs, particularly Gemini 3.1, which unfortunately is still the best model for
analysing large videos. Until this point, my experience with these LLM APIs had been limited to using them in small bits
of a larger system: summarising text, generating embeddings, ranking documents, etc. Nothing where they were the core,
nothing that pushed them to the limits of their context windows & thinking levels.

## Just add retries!

Within a few weeks I had a POC, and within a month it was in production. The initial version was primitive & shabby,
with a success rate (the % of jobs that ran end to end and produced usable output) well under 70%. While I
chipped away at most of the failures over time, one category stuck around: the Gemini API calls failing, for all sorts
of reasons: rate-limits, timeouts, valid but incorrect structured responses.

So I turned to folks in the company with far more LLM experience than me. The advice was reasonable: add a timeout to
the client, set `vertexai=True`, add a proper `ThinkingConfig`, validate the JSON outputs. And if it still fails? Just
add retries! And it was good advice. You can't expect an API running trillion-parameter models to work perfectly every
time, they're bound to glitch once in a while, right? So every Gemini call went behind a tenacity retry decorator. And
it worked, the success rate shot up.

## Death by a thousand retries

Over a month or two, the quality of the results improved, and with it the requirements (and the team) grew. This forced
me (now us) to add a few pipeline steps that fed Gemini a whole video at once, often up to two hours long. To make that
fit, we leaned on hacks like speeding the video up and dropping the `MediaResolution`, etc. Many of these calls timed
out, throwing a `ReadTimeout`. But it worked, or at least it worked *once*, given the absurd number of retries in
place.

Those retries also made the account hit rate-limits more often, so naturally the next step was to add exponential
backoff, bump up the client timeouts even further, etc. But now a job that could finish in under an hour
sometimes took a full day. Since it was a `ReadTimeout`, we also switched to `generate_content_stream` with
`include_thoughts` set to true, which bought a little breathing room and cut down the number of retries needed. Clearly
it was my fault for pushing Gemini past its limits. A while later, Gemini tipped over for good: most if not all calls
started failing outright; no amount of retries would save them.

## Fixing the wrong things

Now, we decided to do the long-pending thing: fixing our own code. Instead of feeding the whole video to Gemini, we'd
split it into chunks, process them and then reconcile the results later. Reconciliation was the harder task, and the
merged output was never quite as good as one-shotting the whole video, but it was what needed to be done. This change
worked pretty well in all the test runs on my PC. But once it hit production, we started seeing the same `ReadTimeout`
failures again. The timeouts got less frequent, but more chunks just meant more single points of failure. Ultimately it
didn't help much. It was an architecturally sound decision, one that would let us scale beyond just two hours of input,
it just didn't fix the actual problem.

At this point I could sense something was wrong. The inputs now being fed to Gemini were well within its capabilities;
it shouldn't have been timing out at all. And I'd always had a nagging feeling that somehow the pipeline ran better on
my local setup; all my local testing worked perfectly and took few to no retries. Now that feeling was too strong to
ignore: clearly, there was a mismatch between the local and production environments.

I searched online, found a single
possibly-related [Github Issue](https://github.com/googleapis/python-genai/issues/1893), tried its solutions in vain.
After brainstorming, I came up with a few ideas of my own (btw, Claude didn't like most of them): setting
`max_keepalive_connections` to 0 to force a new connection every time, initialising a fresh client per call, etc. The
hypothesis: if this was an issue with a stale client or a pooled connection gone bad, forcing a brand-new connection
each time might fix it. As Claude expected, this didn't work at all.

## The smoking gun

Defeated, I went back to Claude. One thing it kept pushing was to try setting some socket options on the client's
underlying HTTP transport. I'd been brushing it off: blaming the client was already a stretch, and going all the way
down to TCP-level options felt absurd. Surely it can't be the client? Millions of people must be using it; if there were
a bug, someone would've found it by now.

Anyway, having eliminated everything else, I finally read what Claude was saying properly. The more I read, the more it
made sense. Its argument: since the job ran in a K8s cluster on the cloud, the egress almost certainly went out through
a NAT gateway, and NAT gateways usually have a "TCP idle-timeout" that drops connections after they've been idle for a
while.

Sure enough, our egress did go through a NAT gateway; I knew that. But it had never occurred to me that they'd have an
idle-timeout. On second thought, of course they do, why wouldn't they? The catch is that they usually drop the
connection silently, without sending an `RST` or `FIN` to either side, so the client has no idea the connection is even
dead. The fix for this is to enable TCP keepalive socket options. Again, something I'd read about but never had a reason
to use.

This explained almost everything. The TCP connection was dying mid-call, while Gemini was still thinking, long before
the client's own timeout kicked in. But the client had no way to know that; it would keep waiting until its timeout
finally expired and then raise a `ReadTimeout`. This is why forcing a fresh connection per call did nothing. The
connection wasn't dying between calls; it was dying mid-call, going idle while Gemini thought. A brand-new one would
just meet the same fate. Switching to a streaming response helped a little, because the stream kept data flowing, so the
connection never sat idle long enough to get dropped.

So I went and checked our NAT gateway's config, and sure enough, its idle-timeout was set to the default 4 minutes. It
almost seemed too good to be true. If this was really it, how did it work at all until now? And how did no one else
know, or tell me? It also meant all the tweaks we had done, cranking the timeout up past 15-20 minutes, were pointless,
the connection was already dead at the 4-minute mark regardless!

To fully convince myself, I wrote a test script that ran on the same production environment, with & without the
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

The most annoying thing about this whole fiasco is how every layer seems to have misled us. The NAT gateway dropped the
connection silently (surely by design for a good reason, but still). The client raised a `ReadTimeout`, pinning
the blame on the server for failing to respond in time (from its perspective, completely correct). And none of our "
fixes" addressed the root cause, yet each seemed to help just enough to keep us looking in the wrong place: retries
masked the errors (at the cost of processing time), and switching to a streaming response actually sped things up (
lower time to first byte). All of it convinced us that the real problem was that the calls were simply too heavy for
Gemini to handle.

Apparently, this behaviour of NAT gateways, and the use of TCP keepalive probes for the same are fairly well
documented. But it's unlikely to be on anyone's shortlist of possible causes unless you've experienced it before,
especially when the bug sits so far from the domain you're actually working in. I'm not sure if I'd ever have pinpointed
it without Claude's help.

On the bright side, most LLM providers have (very recently) started moving away from the ancient 2023-style synchronous
chat-completion focused APIs to more "agent-friendly" APIs with some sort of polling/offloading for heavy jobs, like
Gemini's [background execution](https://ai.google.dev/gemini-api/docs/background-execution) and
OpenAI's [background mode](https://developers.openai.com/api/docs/guides/background).