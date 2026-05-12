---
title: "A Bug That Drove a 10x Surge in Concurrent Users"
publishDate: 2025-01-16 01:50:00 +0530
tags: [ programming ]
description: "A unique bug where receiving push notifications triggered background app launches"
coverImage:
  src: '../../assets/images/background-app-launch/cover.webp'
  alt: 'Background App Launch'
---

Once in a while, you encounter a bug in production where your first thought is, *"How the heck is this possible?"* What
follows is hours of debugging, trying to figure out how this happened. This incident was one of them for me.

It started with a rise in alerts overnight and a sharp increase in DAU. My first thought was,
*"How can a bug cause a rise in DAU? An app can't possibly open by itself!"*. Well, As it turns out, it can.

Breaking down the metrics by OS and app version, revealed that the issue only impacted Android users on the latest
release. The only change capable of causing this was a new third-party plugin. After digging more, we discovered that
PNs seemed to trigger the issue. It seemed contradictory; we haven't changed anything related to notifications! But, it
was also more probable since notifications are handled by a different background service. We finally found the problem
by scrolling through the GitHub issues of the newly added plugin.

The push notification service runs on a separate isolate (think of it as a thread in Flutter) with its own separate
`FlutterEngine` (the flutter container/runtime). This isolate called the `onAttachedToEngine` method of the newly added
plugin to install it into the FlutterEngine. Which, in turn, initialized the main isolate, *starting the app without any
Activity attached to it!*

This was problematic for two reasons:

- The startup is probably the most expensive operation an app does, from serving a personalized home screen to
  initializing a bunch of different features, not to mention the third-party libraries and SDKs. It is bound to create a
  sudden burst of API calls.

* The push notification logic was unintentionally designed to send out a large batch of notifications to every reachable
  user around a particular time.

As a result, it *triggered a simultaneous background app launch for every Android user on the latest app version*. Thus
leading to a ~10x surge in concurrent users and RPS!

The fix was relatively simple and would have been much quicker if we were developing a web app. However, mistakes are
much more painful to fix in the app development world. Play Console doesn't allow you to halt updates once a new version
is fully released (without rollouts). You cannot patch native code changes (be it a Flutter, React Native, or Kotlin
app) either. The only option left was to push a fix quickly and wait for the users to update! We ultimately resorted to
pausing PNs until most users were on the patched app versions.

**Fun fact:** You may be wondering if this bug only affected users with notification permission enabled. Well, no. Apps
can receive messages in the background irrespective of the notification permission status! These silent notifications
are helpful if the app wants to perform routine tasks, fetch some updates from the server, etc. The notification
permission usually asked by apps is to display notifications, not receive them.
