---
title: "Debugging In The Dark"
publishDate: 2025-12-24 11:24:00 +0530
tags: [ dns, networking ]
description: "TL;DR: It was the DNS, it's always the DNS."
---


**TL;DR:** It was the DNS. It's always the DNS.

Looking back, it's easy to see how obvious it was, but hindsight is always 20/20. How do you debug an issue that doesn't
show up in any of your logs, crashes, or analytics, and has no visible impact on any product metrics?

## The Problem

This happened a couple of weeks ago. Out of nowhere, we started getting a lot of complaints from users about videos not
loading at all. One, two, three, and soon we had a flood of support tickets. Usually, when something like this happens,
it's our own mess-up, most often in the latest app release. But this particular instance was different, and it would
end up taking us several days to figure out and resolve.

## The Issue We Couldn't Just See

See, there was no trace of the issue. Nothing out of the ordinary popped up in Crashlytics, nor in our backend logs. And
given the volume of tickets we were getting, it should have had an impact on some of our product metrics as well, but
nope, it didn't. Even the CDN showed no drop in traffic! It was as if the issue didn't exist, except for the flood of
support tickets we were getting. We tried to replicate the issue across different devices, OS versions, and
networks. Not a single failure. Everything worked fine.

The only thing we could figure out was that none of the users who raised a support ticket had any events in Mixpanel! It
was too big a coincidence to ignore. It also further complicated things, as we had no way to figure out the user journey
that could have helped in replicating the issue.

## Days Of Debugging

Eventually, we also observed another common pattern: Almost all of the users who raised a support ticket were using Jio
as their ISP! We attempted to replicate it on several devices using Jio, but still no luck! The fact that we couldn't
replicate it shook our confidence about this being an ISP-specific issue. We had a hunch, but no way to prove it.

Out of options, we decided to roll back the last release, even though tickets from older app versions were starting to
pop up as well. In the meantime, we checked every PR, every small change, either in the app or the backend that could
have caused this, but came up empty.

After two days of debugging, we were back to square one, completely at a loss. Not only did we not know why this was
happening, but we also had no idea about the scale of the issue. Eventually, we would start seeing some tickets where
this would happen intermittently for the users. Again, the same pattern. It would work when the user
switched to a different network from Jio, and we would start getting their Mixpanel events again as well.

Desperate for some clues, we decided to call some of the impacted users and ask them a set of questions, going as far as
giving them raw video links to see if it worked for them, ruling out any app or backend issues. This had mixed
results, but was strong enough to reinforce our hunch that this was indeed an ISP-specific issue.

But we didn't have any concrete proof yet. And even if we did, what next? Can we even do anything? You cannot just ring
the ISP and ask them to fix their own stuff.

## The Breakthrough

As a final Hail Mary, we decided to push an app release with some instrumentation to track what IPs our critical
hostnames were resolving to on user devices. And that's when we found it. For some small single-digit percentage
of our users in India, the CDN host was resolving to an IP address that didn't look very familiar. It was located in the
US and WHOIS records showed that it didn't belong to our CDN provider. Not only that, the resolved IP was not even
reachable on the user's network. Further, Mixpanel was also resolving to 0.0.0.0 for these users.

After some back-and-forth with our CDN provider, we found out that the IP did indeed belong to one of their edge nodes
in the US. Still, the DNS was not supposed to resolve to that node for Indian users. They couldn't replicate the DNS
resolution issue using a few public DNS servers either. But they were kind enough to change the routing configuration to
remove the US node from the DNS itself. And that did the trick.

As for why it happened in the first place, we still don't know. The fact that the host unreachability error never
surfaced anywhere in the app is surely an oversight on our part. Nevertheless, I finally understand why people joke
that "It's always the DNS." It's ubiquitous, sneaky, and not something you'd think to add instrumentation for, until
it breaks, that is.

## Who Was The Culprit?

I do have a few hunches about how this could have happened. There are two popular ways CDNs route traffic to the nearest
Point of Presence (PoPs, i.e., edge location closest to the user):

1. **[GeoDNS](https://en.wikipedia.org/wiki/GeoDNS)**: The DNS server itself resolves the hostname to an IP address of
   servers closest to the client
2. **[Anycast](https://en.wikipedia.org/wiki/Anycast)**: Multiple servers advertise the same IP address, and some
   routing magic delivers the traffic to the
   nearest one

There's something subtle about this first approach that's not very obvious, something I learned only after this
incident. How does the authoritative DNS server know where the client is? Does the DNS resolver pass the client IP to
the authoritative DNS server?

In most cases, it doesn't. The only exception is
when [EDNS Client Subnet (ECS)](https://en.wikipedia.org/wiki/EDNS_Client_Subnet) is used, which allows the resolver to
include a truncated client subnet in the DNS
query [for better routing](https://engineering.salesforce.com/why-is-edns-important-for-content-delivery-85f5690744ba/).
Due to privacy concerns, many DNS servers, particularly those owned by ISPs, don't use it.

So how does GeoDNS work then? It relies on the IP address of the DNS resolver itself; in other words, it assumes that
your DNS resolver is geographically close to you! But what if it's not? Is this what happened here? I don't know, but
it's the best possible explanation I could come up with.