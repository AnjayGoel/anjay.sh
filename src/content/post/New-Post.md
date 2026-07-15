---
title: "TBD"
publishDate: 2026-07-16 01:30:47 +0530
tags: [ programming ]
description: "TBD"
---

In the past, I have written a few posts about interesting RCAs I have done/encountered. They are pretty fun to write
about, take a look back & to tell the whole story. This is one of them. What's interesting about this is how long it
took me to figure out that there is an issue in the first place. The bug masked itself behind a perfectly normal failure
mode. Only that it got progressively worse over time.

### The background story

Early this year, I started working on something new, that's quite different from the things I have been doing for
our consumer apps. This project involves heavy use of multimodal LLMs, particular Gemini 3.1,
which unfortunately is still the best model for analysing large videos. Until this point, I had fairly limited
experience of working with these LLM APIs. All I had done was to use them for a few parts of a larger system, things
like generating a few embeddings, summarising a few things etc. Nothing that centered on it. Nothing that would push
them to max of their context windows & thinking levels. Anyway, withing a few weeks, I had a POC, and in a month I had
deployed it to production (although pretty primitive & shabby).

### The abysmal success rate

The initial version had a less than 70% success rate. Over time, I fixed most of them, what remained were issues with
the Gemini client (<insert-sdk-here>) calls failing for various reasons. I didn't really have ideas of how to fix it, so
I asked around, asked people in my team who had more experience with it. And I got quite useful tips like "add timeout
to gemini client", "use vertex-ai=True", set the thinking config, validate the outputs etc. And what if it still fails?
Just add retries! And this was a good advice. These are pretty heavy operations, running trillion parameter models
behind the scene, surely they are bound to fail sometimes, right! So I did, just like other repos in the org. All my
gemini calls were now wrapped in a tenacity retry decorator. And it worked, the success rate improved drastically.

### Progressive decline

Over the course of a month or two, the quality of results improved, and with that the requirements expanded
as well. This forced me to introduce a few steps in the pipeline that would call Gemini to understand & respond using a
video often longer than two hours! Also using hacks like speeding up the video. But it worked or at-least it worked once
given the decent no of retires we had in place. With these retries, we would hit the rate-limits more often. So naturally,
the next thing was to add backoff to retries, increase the timeouts etc.