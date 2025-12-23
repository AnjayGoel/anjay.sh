---
title: "Debugging in the dark"
publishDate: 2025-12-20 01:10:00 +0530
tags: [ dns, networking ]
description: "TL;DR: It was the DNS, it's always the DNS."
src: '../../assets/images/anatomy-of-containers/cover.png'
alt: 'DNS'
---


**TL;DR:** It was the DNS. It's always the DNS.

Looking back, it's easy to see how obvious it was, but hindsight is always 20/20. How do you debug an issue that doesn't
show up in any of your logs, crashes, or analytics, and has no visible impact on any product metrics?

## The Problem

This happened a couple of weeks ago. Out of nowhere, we started getting a lot of complaints from users about videos not
loading at all. One, two, three, and soon we had a flood of support tickets. Usually when something like this happens,
it's our own mess-up, most often in the latest app release. But this particular instance was different, and it would
end up taking us several days to figure out and resolve.

### The Issue We Couldn't Just See

See, there was no trace of the issue. Nothing popped up in Crashlytics, nothing in our backend logs. And given the
volume of
tickets we were getting, it should have had an impact on some of our product metrics as well, but nothing there either.
Even the CDN showed no drop in traffic! It was as if the issue didn't exist, except for the flood of support tickets we
were getting.

The only thing we could figure out was that none of the users who raised a support ticket had any events in Mixpanel!
This was too big a coincidence to ignore.

We tried to replicate the issue across different devices, OS versions, and networks. Nothing. Everything worked fine.

However, another common pattern was emerging: most, if not all, of the impacted users were on the Jio network. We tried
to replicate it on quite a few devices on Jio networks. Nothing again! The fact that we couldn't replicate it shook our
confidence about this being an ISP-specific issue. We had a hunch, but no way to prove it.

## Days of Debugging

With nothing else to go on, we decided to revert the latest release, even though tickets from older app versions were
starting to pop up as well. In the meantime, we checked every PR, every small change, either in the app or the backend
that could have caused this, but found nothing.

After two days of debugging, we were back to square one, completely blind. Not only did we not know why this was
happening, we also had no idea about the scale of the issue. We would eventually start seeing some tickets where this
would happen intermittently for the users. Again, the same pattern emerging. It would work when the user switched to a
different network from Jio, and we would start getting their Mixpanel events as well.

With nothing else to go on, we decided to call some of the impacted users and ask them a set of questions, going as far
as giving them raw video links to see if it worked for them, ruling out any app or backend issues. This had mixed
results, but was strong enough to reinforce our hunch that this was indeed an ISP-specific issue.

But we didn't have any concrete proof yet. And even if we did, what next? Would we be able to do anything about it? You
cannot just ring the ISP and ask them to fix their own stuff, right?

## The Breakthrough

As a final Hail Mary, we decided to push an app release adding some instrumentation around what IPs our critical
hostnames were resolving to on the user's devices. And that's when we found it. For some small single-digit percentage
of our users in India, the CDN host was resolving to an IP address that didn't look very familiar. It was located in the
US and WHOIS records showed that it didn't belong to our CDN provider. Not only that, the resolved IP was not even
reachable on the user's network. Further, Mixpanel was also resolving to 0.0.0.0 for these users.

After some back-and-forth with our CDN provider, we found out that the IP did indeed belong to one of their edge nodes
in the US, but the DNS was not supposed to resolve to that node for Indian users. They couldn't replicate the DNS
resolution issue using a few public DNS servers either. But they were kind enough to change the routing configuration to
remove the US node from the DNS itself. And that seemed to do the trick.

As for why it happened in the first place, we still don't know. The fact that the host unreachability error never
surfaced anywhere in the app is surely an oversight on our part. But nevertheless, I finally understand when people joke
and say "It's always the DNS." It's ubiquitous, sneaky, and not something you would think of adding instrumentation for,
until it breaks, that is.

### Who Was The Culprit?

I do have a few hunches about how this could have happened. There are two popular ways CDNs route traffic to the nearest
Point of Presence (PoPs, the servers closest to the user):

1. **GeoDNS**: The DNS server itself resolves the hostname to an IP address of servers closest to the client
2. **Anycast**: Multiple servers advertise the same IP address and routing magic delivers the traffic to the
   nearest one

There is something you would realize only upon thinking carefully about the first approach, something I only learned
after this incident: How does the authoritative DNS server know where the client is? Does the DNS resolver pass the
client IP to the authoritative DNS server? Well, it doesn't in most cases, except when you are using EDNS (Extended
DNS), which allows the DNS resolver to pass a client subnet to the DNS server. Because of privacy concerns, most public
DNS servers don't pass this info to the resolvers (except Google's DNS, of course).

So how does GeoDNS work then? It relies on the IP of the DNS resolver itself, that is, your DNS resolver being close to
you geographically! But what if it's not? Is this what happened here? I don't know. Is it possible? Yes.