---
title: "I Left Claude Code Run Wild For A Few Days"
publishDate: 2026-04-28 01:50:00 +0530
tags: [ programming ]
description: "Long running agents are powerful"
---


Late night last sunday, I just wrapped up some work, And in my half sleepy state, I get an itch to do something "fun"
While it's not unusual to feel so from time to time, what's changed is that code is cheap now, putting togather a shabby
piece of code that just works is one prompt away. So I decided to do something, that I have been wanting to do for a
while: Porting our entire app from Flutter to KMP.

To give a bit of context, When we started three years ago, we had different
requirements & constrains, and flutter fit well into the picture. Over time, those requirements & constrained
changed, and now flutter didn't feel like the best fit, but it stuck. The expertise we had built &
the time & bandwidth it would take to learn a new framework & build an entire app from scratch with a tight deadline
made it infeasible to switch.

So in my sleep induced creativity, I prompted claude code to make a KMP app, clone the very basic functionalities: The
home screen & the video player screen (reels screen, as we call it). I gave it access to the original codebase & seeded
it with some screenshots of the app, spawned up an emulator & let it do its thing. And in 10 mins, it got back to me
with a working clone. obviously with very limited functionality, but it worked, the homescreen populated via the API
calls, the reels screen working with basic player controls. And it performed better than our flutter app!

I spent the next half an hour or so, adding more features, prompting it, giving it references, etc. While it was making
real progress, but telling claude how to align a button gets boring quickly & I was sleepy. But I had seen the progress
it made in that 30-40 mins or so, it was crazy to say in the least, not something I would have imaging three years ago.
So I said f**k it, let me automate myself away as well. I spawned up another emulator, started the original app on it,
asked claude to port everything, maintain a todo list, go feature by feature & port everything.

The Long Running Agent Setup:
Claude code has recently introduced a loop feature to schedule automated tasks. I combined it with a loop.md file with
detailed instructions about what to do in each iteration & a todo.md tracking the progress of the port. I also explained
the basic structure of the original flutter app. Using these two + a claude md file ensured that the entire state of the
jobs live in markdown fine and subsequent runs can easily pick it up.

The loop.md file had several instructions:

* Covering breadth first, ensuring all user facing features are ported.
* Port the logics, completely ignoring flutter implementation, adapting to KMP best practices.
* Spawn subagents to do the multiple tasks in each run.
* Every 10 commits or so, dispatch a code-review subagent & a UI-verification subagent
* Never break the loop on transient errors, rate limits, 5xx.
* Parking features that require human assistance & moving forward

What's interesting is that overtime, claude code observed & improved the loop.md itself, adding more instructions, refining logics as
well.