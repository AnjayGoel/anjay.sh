---
title:  "My Linux Setup"
publishDate:   2021-07-18 18:33:00 +0530
tags: [linux]
description: "Sharing My Linux Desktop Setup"
coverImage:
  src: "../../assets/images/my-linux-setup/cover.jpg"
  alt: "My Linux Desktop"
---

<!--end_excerpt-->

When it comes to using Linux as a daily driver, the sheer number of choices available can be quite baffling. It's hard to not be tempted by other distros/desktop managers than what you are currently on, leading to an endless cycle of distro-hopping. And every time you think, "This is it. I am not gonna switch anymore.", you find yourself installing another distro soon enough. But this is the setup I have been using for a while now. And I don't see myself switching anytime soon. So I thought it will be worth sharing.

## Choosing The Distro

I am currently using Xubuntu. Yes, the good ol' flavor of Ubuntu using Xfce. Say what you want about Ubuntu. But at the end of the day, It is still the most popular distro. And it fricking works. I never had any significant issues when using a Ubuntu-based distro. However, Gnome is a resource hog and too much for my old junk laptop with 4GB of RAM. I contemplated switching from a full-blown desktop environment to a windows manager, but the hassle of configuring the tons of programs and dot-files was unconvincing. So Xfce was the next best option. And it's fantastic.

![Startup](../../assets/images/my-linux-setup/startup.png)

Xubuntu uses around ~550 MB on boot. And easily handles running an IDE, 10s of tabs on Firefox and Spotify simultaneously on my PC without any lag whatsoever. Whereas Ubuntu will start lagging at this point and eventually stop responding.

## Customising XFCE

While the default Xfce desktop looks pretty outdated, it is pretty easy to customise. It uses gtk. So the usual gnome gtk themes work. I choose the [Nord theme](https://www.nordtheme.com/). It has ports for all the popular apps you probably use, giving a consistent and modern feel across all apps.

### Keyboard shortcuts

XFCE has a decent no of keyboard shortcuts. I configured a bunch of them for easy titling and workspace switching.

### Ulauncher

![Ulauncher](../../assets/images/my-linux-setup/ulauncher.png)

The default Xfce launcher works well. However, it feels outdated, and alternatives like Ulauncher offer much more features. So I replaced it with [Ulauncher](https://ulauncher.io/) and installed a bunch of useful extensions. It's pretty lightweight and doesn't use any significant resources.

### Panel

![Panel](../../assets/images/my-linux-setup/panel.png)

Since I am using a launcher and have already configured the keyboard shortcuts, there isn't a need for a panel occupying permanent space. So I shrank it to a dock and set it to auto-hide.

### Guake

![Guake](../../assets/images/my-linux-setup/guake.jpg)

A top-down terminal is probably the first thing you should install after a fresh Linux install. Using a top-down terminal makes the desktop much more cleaner. No more tons of open terminals along with your primary windows. And [Guake](http://guake-project.org/) is perhaps the best of them all. It also supports features like multiple and split tabs that are pretty useful.

### Conky

![Conky](../../assets/images/my-linux-setup/conky.png)

[Conky](https://github.com/brndnmtthws/conky) is a system monitor. It can be used to display some pretty helpful information about the system. You can install additional scripts to show weather, network usage, etc. Unfortunately, it doesn't support Wayland. But I am sure that alternatives for Wayland will pop up soon.

## The Final Result

![Desktop](../../assets/images/my-linux-setup/desktop.jpg)

Xfce isn't as feature-rich as Gnome or KDE. You would probably need to spend around an hour or more configuring it on a fresh install. But it's worth it.  With a few minor tweaks, you have a setup customised to your own needs that looks great and is pretty smooth and lightweight. And probably that's all you need.
