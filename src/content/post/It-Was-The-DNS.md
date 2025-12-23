---
title: "Debugging in the dark"
publishDate: 2025-12-20 01:10:00 +0530
tags: [ dns, networking ]
description: "TL;DR: It was the DNS, it's always the DNS."
src: '../../assets/images/anatomy-of-containers/cover.png'
alt: 'DNS'
---


TL;DR: It was the DNS, it's always the DNS. Looking back, it's easy to say how obviously, it was, but
hindsight is always 20/20. How do you debug an issue that doesn't show up in any of your logs, crashes, analytics and
has no visible impact on any of the product metrics?

This happened a couple of weeks ago. Out of nowhere, we started getting a lot of complaints from
users about the videos not loading at all. One, two, three and soon we had a flood of support tickets. Usually when
something like this happens, it's your own mess-up and most often in the latest app release. But this particular
instance was different, and it would end up taking us several days to figure out and resolve.

See, there was no trace of the issue, nothing popped up in Crashlytics, nothing in our backend logs. And given the
volume of tickets we were getting, it should have had an impact on some of our product metrics as well, but nothing
there either. Even the CDN showed no drop in traffic! It was as if the issue didn't exist, except for the flood of
support tickets we were getting. The only thing we could figure out was that none of the users who
raised a support ticket had any events in mixpanel! This was too big a coincidence to ignore.

We then tried to replicate the issue in multiple ways, thinking maybe an issue with the latest release, and nothing.
Everything worked fine. Different devices, OS versions, networks, we couldn't replicate it. Another common pattern was
emerging though. Most if not all the impacted users were on JIO network. We tried to replicate it on quite
a few devices on JIO networks. Nothing again! The fact that we couldn't replicate it shook our confidence about
this being an ISP specific issue. We had a hunch, but no way to prove it.

With nothing else to go on, we decided to revert the latest release, even though tickets from older app versions were
starting to popup as well. In the meantime, we checked every PR, every small change, either in the app or the backend
that could have caused this, but found nothing.

After two days of debugging, we were back to square one, completely blind. Not only did we not know why this was
happening, we also had no idea about the scale of the issue. Slowly, we would start seeing some tickets where this would
happen on and off for the users, again a same pattern emerging. It would work when the user switched to a different
network, and we would start getting their mixpanel events again as well. With nothing else to go on, we decided to call
some of the impacted users and ask them a set of questions. Going as far as giving them direct video links to see if it
worked for them, ruling out any app or backend issues. This has mixed results, but strong enough to re-enforce our hunch
that this is indeed an ISP specific issue. But we didn't have any concrete proof yet. And even if we did, what next?
Would we be able to do anything about it? You cannot just ring the ISP and ask them to fix their own stuff, right?

As a final Hail Mary, we decided to push an app release adding some instrumentation around what IPs a few of our the
critical host names were resolving to on the user's devices. And that's when, we found it. For some small single digit
percentage of our users sitting in India, the CDN host was resolving to an IP address that didn't look very
familiar. It was located in the US and WHOIS records showed that it didn't belong to our CDN provider. Not only that,
the resolved IP was not even reachable on the users network. Mixpanel too was resolving to 0.0.0.0 for these users.

After a bit of a to-and-fro with our CDN provider, we found out that the IP did indeed belong to one of their edge nodes
in US, but the DNS was not supposed to resolve to that node for Indian users. They couldn't replicate the DNS resolution
issue using a few public DNS servers either. But they were kind enough to change the routing configuration to remove the
US node from the DNS itself. And that seemed to do the trick.

As for why it happened in the first place, we still don't know. Why didn't the host un-reachability error bubble up from
the video player? an oversight on our part, sure. But, nevertheless, I finally understand when people joke and say "It's always the DNS". Its ubiquitous, sneaky and not
something you would think of adding instrumentation for, until it breaks, that is.

I do have a few hunches about how this could have happened. There are two popular ways CDNs route traffic to the nearest
Point of Presence (POPs as in the servers closest to the user), either using GeoDNS, where the DNS server itself
resolves the hostname to an IP address of servers closest to the client, or using anycast routing, where multiple
servers advertise the same IP address and some routing magic delivers the traffic to the nearest one. Upon thinking
carefully about the first approach, you would realise something that I got to know only after this incident. How does
the authoritative DNS server know where the client is? Does the DNS resolver pass the client IP to the authoritative DNS
server? Well it doesn't in most cases. Except when you are using EDNS (or extended DNS) which allows the DNS resolver to
pass a client subnet to the DNS sever. Because of privacy concerns, most public DNS severs don't pass this info to the
resolvers (Except Google's DNS ofcourse.). So how does GeoDNS work then? It relies on the IP of the DNS resolver itself!
that it your DNS being close to you geographically! But what if you are not? Is this what happened here? I don't know.
Is it possible, yeah.   