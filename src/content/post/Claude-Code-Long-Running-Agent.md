---
title: "Letting Claude Code Run Wild For A Few Days"
publishDate: 2026-05-02 03:20:00 +0530
tags: [ programming,opinion ]
description: "I left Claude Code on autopilot for two days. It migrated our whole app from Flutter to KMP"
---

Late last Sunday night, I'd just wrapped up some work, and in my half-sleepy state I got an itch to do something "fun".
While it's not unusual to feel that way from time to time, what's changed is that putting together a shabby piece of code that
just works is a single prompt away now. So I decided to do something I'd been wanting to do for a while: migrating our entire
app from Flutter to KMP.

To give a bit of context, when we started three years ago, Flutter fit our use case very well. Over time, we launched
a few more apps. Our requirements & constraints changed and Flutter didn't feel like the best fit anymore, but it stuck.
Switching would have meant learning a framework and rebuilding an entire app under a short deadline, which was too expensive
to justify.

So in my sleep-induced creativity, I prompted claude code to make a KMP app, cloning the most basic functionality:
the home screen & the video player screen (reels screen, as we call it). I gave it access to the original codebase,
seeded it with some screenshots of the app, spun up an emulator & let it do its thing. And in 10 mins, it got back
to me with a working clone, obviously with very limited functionality, but it worked. The home screen populated via
API calls; the reels screen worked with basic player controls. And the video playback felt smoother than in our Flutter app!

I spent the next half an hour or so adding more features, prompting it, giving it references, etc. It was making real
progress. By this time, I was fully convinced it would be able to migrate the whole thing. But telling claude how to
align a button got boring quickly & I was sleepy. The progress it had made in those 30-40 mins was crazy, not
something I'd have imagined three years ago.

So I said f**k it, let me automate myself away as well. I spun up another emulator, started the original app on
it, asked claude to migrate everything feature by feature, screenshotting the original app and verifying it worked on
the new one. After a few iterations of trial and error, I ended up with the setup described below, with claude
obviously writing most of it.

## The Long-Running Agent Setup

Claude Code recently introduced a `loop` feature to schedule automated tasks. I combined it with `caffeinate`, the
`remote-control` Claude Code feature & `pmset displaysleepnow` (to turn off my Mac's display), making Claude Code a
perfect long-running agent, doing stuff while I slept. The setup had a few markdown files that became the entire
state of the run. Since the state lives in files, it survives a multi-day run, and the next iteration picks up exactly
where the last one stopped.

### `CLAUDE.md`

It tells claude how the new codebase is laid out, the tech stack, its coding conventions. Stuff like "Flutter is
a reference, not a template, migrate behavior not architecture" or "files under 300 LOC, no business logic in
Composables". It also includes details of the original Flutter project, its structure, features, the APIs,
conventions, etc.

### `TODO.md`

The progress tracker for the migration. claude would spawn subagents to discover features, break them down into smaller
tasks & add them to the TODO. Every finding, every subagent report, every blocker logged here before the next
dispatch. A `## Requires human assistance` section for things genuinely outside the agent's reach.
By the end it was ~1200 lines long.

### `LOOP.md`

This is the heart of the whole execution: a ~200 line recurring prompt that claude re-read on every fire. It had the
following structure:

* Mission: a short one-paragraph statement of what we are doing, the north star, etc.
* The iteration recipe: pick a task → migrate → verify on emulator side-by-side → tick todo → commit → schedule.
* Standing directives: a huge list of rules like:
    * Keep the loop alive, never stall on blockers.
    * State lives in markdown entirely.
    * Cover breadth over depth.
    * Don't simply copy the code; adapt to KMP/Compose.
    * Dispatch multiple subagents each working on different tasks.
    * Original codebase is messy, think like a senior engineer would 😄
* The guardrails: every ~20 commits, dispatch a code-review subagent + UI-verification subagent.
* The "what if X happens" branches: explicit rules for handling things that could derail the loop, like transient
  errors, rate limits, stuck subagents, etc.
* Codebase hygiene: basic sections on how to maintain code quality, what patterns to follow, etc.
* The re-audit step: walk the original repo for anything missed, log it in `TODO.md` and continue.

## The Results

After a few iterations of fine-tuning the loop, the TODO, etc. (which BTW claude did itself with some prompting), I
went to sleep. When I woke up, claude was still working! It had almost migrated half of the entire app. I left
it running for the next day, until it decided it had completed the migration. By the time it was done, the TODO file had
grown to ~1200 lines and the codebase had ~40K lines spread across ~500 files. *None of it written by hand.*

And the result? I'll let you decide. One half of the video below is the original app & the other is the KMP port made
by claude.

Can you tell which is which? (Hint: Check the video URL)

<video src="/videos/new-vs-original.mp4" autoplay loop muted playsinline></video>

I have been using it for the past week. The UI is pretty much identical. All the user-facing features are fully
functional, and owing to it being "native", the app is substantially smoother. It's almost there!

Now, I am not saying the codebase is perfect, or that the app is ready to ship to production. It's not. It couldn't
get quite a few things to work correctly. But more often than not, the parts it had trouble migrating were heavily
tech debt ridden with various nuances that were not documented properly in the original codebase. I also have no working knowledge
of KMP either. The instructions I gave were pretty much just "follow the best practices". I'm pretty sure it would have done an
even better job if someone with experience in KMP and a fairly opinionated idea of how the codebase should look prompted
it. Still, most of the generated codebase is better than what I would have written if I were given a short deadline to
do the same.

This is a far, far better starting point for when we actually decide to do it. And a single Claude Code instance did
it in two days! A small traditional engineering team working on it full-time would have easily taken a month or two.
And I didn't even hit my weekly usage limits! Granted, this is somewhat of an "easy task" for claude. LLMs are, after
all, good at following instructions, and taking one codebase & copying it over to another language is a fairly
structured task, with comparatively less ambiguity and decision-making involved.

But it should still force us to take a hard look at how engineering decisions get made and executed. The whole reason we
stuck with Flutter is that switching was too expensive to justify. Once you factor in LLMs/Coding Assistants, calls like that don't look
the same anymore, and most of the processes built around the old answers don't either.