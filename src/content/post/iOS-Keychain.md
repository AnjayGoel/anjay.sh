---
title: "iOS Keychain: It's Not a Bug It's a Feature"
publishDate: 2024-09-07 19:30:00 +0530
tags: [ til, iOS, programming ]
description: "Unintended behavior of iOS keychain that lets apps persist data even after uninstallation"
coverImage:
  src: '../../assets/images/ios-keychain/cover.png'
  alt: 'iOS Keychain'
---

A while ago at work, I ran into a situation where we had to disable backup & restore for our app. We had to make
sure a fresh install didn't restore the user account from a previous installation.
Doing this is pretty straightforward on Android. Just set `allowBackup` to false in the manifest.

```xml

<application
  android:allowBackup="false"
/>
```

For iOS, things weren't that simple. I tried clearing the Shared Preference/UserDefaults, excluding folders from
backup & even disabling iCloud backup on the whole device. Nothing worked. Reinstalling the app logged in the old user.

Digging deeper into Stackoverflow & other developer forums, I found out that Firebase authentication credentials are
stored in the iOS keychain, as they should be. But **iOS actually persists the app's keychain data, even after you
uninstall it!**

Apparently, this undocumented & unintended behavior has existed for a long time, even though it might be a privacy
concern. Apple tried to fix it way back in 2017 (iOS 10.3 Beta), but it broke so many apps relying on this behavior that
they had to roll back the fix. And the bug/feature still remains untouched today.

Anyway, the workaround for me was to
simply check if it's a fresh installation using a key in UserDefaults. If it is, then log out the current user.
