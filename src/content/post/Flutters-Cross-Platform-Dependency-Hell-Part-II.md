---
title: "Flutter's Cross Platform Dependency Hell - Part II"
publishDate: 2024-05-12 00:00:01 +0530
tags: [ flutter,programming ]
description: "Flutter pub doesn't play well with CocoaPods"
slug: Flutters-Cross-Platform-Dependency-Hell-Part-II
coverImage:
  src: '../../assets/images/flutter-dependency/flutter.png'
  alt: 'Flutter'
---

In the last blog post, I wrote about how flutter includes all the platform-specific implementations in the dependency
tree even when you don't target those platforms. Thus causing unnecessary dependency conflicts. In this post, I will show
another annoying issue about how flutter handles native dependencies, particular in iOS.

If you add the following packages in your project and do a `flutter pub get`:

```
flutter_facebook_app_links: ^3.0.2
flutter_facebook_auth: ^6.2.0
```

It will resolve successfully and even run perfectly on android. But when you try to build for iOS you will get the
following error:

```
[!] CocoaPods could not find compatible versions for pod "FBSDKCoreKit":
  In Podfile:
    flutter_facebook_app_links (from `.symlinks/plugins/flutter_facebook_app_links/ios`) was resolved to 3.0.0, which depends on
      FBSDKCoreKit (~> 16.0)

    flutter_facebook_auth (from `.symlinks/plugins/flutter_facebook_auth/ios`) was resolved to 6.2.0, which depends on
      FBSDKLoginKit (~> 17.0.0) was resolved to 17.0.0, which depends on
        FBSDKCoreKit (= 17.0.0)
```

What's happening here is that both the packages depend on a different major versions of native `FBSDKCoreKit`
CocoaPod (The native facebook iOS SDK). Since flutter is only resolving the dart dependencies, it didn't even know
about the dependency conflict in the native packages. If a package updates the major versions of a native dependency in
a minor/patch update, such issues may break your builds the next time you run `flutter pub upgrade`
