---
title: "Containers Part II: The stuff that makes containers \"fancy\""
publishDate: 2025-10-16 01:30:47 +0530
tags: [ containers, docker, kubernetes, til ]
description: "Yes, containers are, at their core, just processes. Let's dig into Linux primitives that make it possible"
---

In part one, we built a bare-bones container. To make it more useful, we need to configure quite a few things
like networking, storage, security, etc. In this post, I want to explore how a few of these are
implemented in practice and try to do it ourselves wherever possible, and then validate our approach with how
docker handles them.

Before we get started, take a look at the output of `docker inspect <container_id>` to see all the configurations docker
does for a container. Notice stuff like `HostConfig`, `Mounts`, `NetworkSettings`, `GraphDriver` etc.

## Networking

Networking works in containers via a virtual network interface
called [veth](https://man7.org/linux/man-pages/man4/veth.4.html) (Virtual Ethernet). It's quite similar to an
ethernet cable joining two devices. Packets going into one end of veth appears on the other. The special
thing about it though is that ends of the veth pair can be moved to different network namespaces, essentially allowing
us to connect the container’s namespace to the host namespace as if they were joined by a physical cable.

### Setting up a network interface

Using the veth network interface, we can now set up a small subnet containing our host & container, allowing them to
communicate with each other. Then, we can configure NAT
using [iptables](https://linux.die.net/man/8/iptables), allowing the container to access
internet through the host’s network interface.

Let's see how to set it up:

1. First, find the PID of the container process (from part one) and set it as a variable `CONTAINER_PID`.
2. Define some other variables for interface names, host & container IP, subnet etc.

```shell
HOST_IF=veth-host
CONT_IF=veth-container
SUBNET=10.200.0.0/24
HOST_IP=10.200.0.1
CONT_IP=10.200.0.2
```

3. Create a veth pair:

```shell
sudo ip link add $HOST_IF type veth peer name $CONT_IF
```

4. Move one end of the veth pair to the container's network namespace:

```shell
sudo ip link set $CONT_IF netns $CONTAINER_PID
```

5. On the host, assign IP to the host end of veth and bring up the interface:

```shell
sudo ip addr add $HOST_IP/24 dev $HOST_IF
sudo ip link set $HOST_IF up
```

6. Do the same inside the container using `nsenter` to enter its network namespace. Also bring up the loopback
   interface:

```shell
sudo nsenter -t $CONTAINER_PID -n ip addr add $CONT_IP/24 dev $CONT_IF
sudo nsenter -t $CONTAINER_PID -n ip link set $CONT_IF up
sudo nsenter -t $CONTAINER_PID -n ip link set lo up
```

7. Add a default route in the container via the host IP. A default route is used to send packets to destinations outside
   the local subnet, for example to the internet:

```shell
sudo nsenter -t $CONTAINER_PID -n ip route add default via $HOST_IP
```

8. Enable IP forwarding on the host. This allows the host to forward packets between interfaces. In our case between the
   container's veth interface and the host's main network interface:

```shell
sudo sysctl -w net.ipv4.ip_forward=1
```

9. In case [iptables](https://linux.die.net/man/8/iptables) is being used for firewall rules, we need to explicitly set
   iptables FORWARD rules to allow forwarding packets between the container and the host's network interface. So, we
   first find the host's default/main network interface:

 ```shell
 HOST_NET_IF=$(ip route | grep default | awk '{print $5}')
 ```

10. Then, add the FORWARD rules to allow traffic to flow between the container and the host's network interface:

```shell
 sudo iptables -A FORWARD -i $HOST_IF -o $HOST_NET_IF -j ACCEPT
 sudo iptables -A FORWARD -i $HOST_NET_IF -o $HOST_IF -m state --state RELATED,ESTABLISHED -j ACCEPT
```

11. Finally we need to set up NAT, so that packets from the container can be routed to the internet via the host's IP:

```shell
sudo iptables -t nat -A POSTROUTING -s $SUBNET -o $HOST_NET_IF -j MASQUERADE
```

We now have a fully functional network interface for our container! You can verify this by pinging the container IP from
the host
vice versa, and also by trying accessing the internet from within the container using `curl` or `wget` etc.

### The Bridge

There is another virtual interface typically used in container networking
called [bridge](https://wiki.archlinux.org/title/Network_bridge). A bridge is like a virtual
switch that allows us to connect multiple network interfaces togather. This enables communication between containers.
Docker for example, creates a default bridge network called `docker0` on the host machine. When a container is started,
It creates a veth pair, attaches one end to the container's network namespace, and the other end to the `docker0` (by
default) bridge on the host. The bridge could be further connected to the host's main network interface like we did
above.

### Mapping a port

Once we have a network interface set up for the container, we can simply do add a DNAT rule in the host's iptables to
forward traffic from a specific port on the host to the container's IP and port. Extending our previous example, let's
say we want to map port `8080` of the container to port `80` on the host, All we have to do is add the following
iptables rule on the host:

```shell
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $CONT_IP:8080
```

Now, any incoming traffic to port `80` on the host will be forwarded to port `8080` on the container.

### Docker's Networking in action

Now let's validate that this is indeed what Docker does under the hood. For this, we will start a simple HTTP server
container and access it from another container using docker's default bridge network:

1. Start a simple HTTP server container in detached mode:

```shell
docker run -d --name server -p 80:8080 python:3-slim python -m http.server 8080
```

2. Start a busybox container to access the server:

```shell
docker run -it --rm busybox sh
```

3. Get the server container's IP using

```shell
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server
```

4. Finally, inside the busybox container, use `wget` to access the server:

```shell
wget -qO- http://<ip>:5000
```

5. At the same time, run `ip link show` on the host, you will see `docker0` bridge & two veth interfaces created for the
   server & busybox container, like below:

```shell
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:22:48:6e:89:8f brd ff:ff:ff:ff:ff:ff
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
    link/ether b6:cf:f2:e4:2f:63 brd ff:ff:ff:ff:ff:ff
53: vethd615595@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default
    link/ether 36:a6:48:12:2c:b8 brd ff:ff:ff:ff:ff:ff link-netnsid 0
64: vethf0b5df8@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default
    link/ether 1a:c9:a7:ef:a0:95 brd ff:ff:ff:ff:ff:ff link-netnsid 1
```

6. Run `brctl show docker0` on the host to verify that the veth interfaces are indeed attached to the bridge:

```shell
bridge name	bridge id		STP enabled	interfaces
docker0		8000.b6cff2e42f63	no	  vethd615595
							                     vethf0b5df8
```

7. Also run `ip addr show` on both containers & the host, you will are part of the same subnet.
8. Running `sudo  iptables -t nat -L` on the host will also show the all the NAT rules docker has set up. Notice how the
   port we mapped earlier shows up as a DNAT rule:

  ```shell

Chain DOCKER (2 references)
target     prot opt source               destination
RETURN     all  --  anywhere             anywhere
DNAT       tcp  --  anywhere             anywhere             tcp dpt:http to:172.17.0.2:8080
```

### DNS Resolution

DNS resolution is another piece of the puzzle. Docker, Kubernetes, and other platforms usually have their own DNS
servers to handle name resolution for containers. In Docker's case, it's
an [embedded DNS server](https://docs.docker.com/engine/network/) that runs on the host. In kubernetes, it's typically
a dedicated DNS service (like [CoreDNS](https://kubernetes.io/docs/tasks/administer-cluster/coredns/)) running within
the cluster. This enables features like service discovery when
orchestrating multiple containers. Take a look at the `/etc/resolv.conf` inside a container, you will see the IP of the
DNS server being used.

## Filesystems & Storage

Earlier, we saw how we can isolate mounts inside a container using the mount namespace. In practice, the mount namespace
has quite a few quirks about how mounts are shared & propagated between different
namespaces (
see [lwn article](https://lwn.net/Articles/689856/), [man page](https://man7.org/linux/man-pages/man8/mount.8.html)).
Anyway, If you list all the mounts using `mount` command inside a container, you will see a few special ones like
below:

* `overlay on / type overlay (rw...`: The overlay root filesystem, which we will discuss shortly.
* `proc on /proc type proc (rw..`: The proc filesystem mounted on `/proc` to provide process & kernel information.
* `/dev/root on /etc/resolv.conf`, and others on `/etc/hostname`, `/etc/hosts`: These are bind mounts from the host to
  provide DNS resolution, hostname, and hosts file inside the container.
* `sysfs on /sys type sysfs (ro..`: The sysfs filesystem mounted on `/sys` to expose kernel & device
  information. Notice the `ro` flag, indicating it's mounted read-only to modifications from within the container.

### Bind Mounts And Persistent Storage

Persistent storage used by containers, be it in Docker or Kubernetes, is typically implemented using bind mounts.
A bind mount is essentially a re-mapping of a directory or file from one location to another, achieved with the
`mount --bind` syscall. In containers, this provides persistent storage by bind-mounting a directory on the
host system into a location inside the container's filesystem. Docker volumes work the same way internally, they're
managed bind mounts created and managed by Docker, typically stored under `/var/lib/docker/volumes/` on the host
machine.

### The Overlay Filesystem

In our container implementation from previous blog, we simply extracted the root filesystem from an existing base image
and chroot into it. If we keep doing the same for each and every container, we'll end up with multiple redundant copies
of the same base image, consuming space and also increase the container startup time because of this overhead. In
practice, container's root filesystem consists of multiple read only layers with a finale writable layer stacked on
top of each other. These are the same layers you see when building or fetching a docker image. Each layer records a set
of diffs / changes. These layers are merged into a single view using a union mount filesystem
like [OverlayFS](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html).

This enables sharing common read-only layers between multiple containers, saving disk space and improving startup time.
When something is written to the container's filesystem, the changes are recorded in the top writable layer, leaving the
underlying read-only layers unchanged. If you try to modify parts of the lower read-only layers, changes are "copied up"
to the top writable layer, this is called the "copy-on-write" strategy.

The overlay filesystem can be setup using the `mount` syscall as well:

```shell
mount -t overlay overlay -o lowerdir=/lower1:/lower2:/lower3,upperdir=/upper,workdir=/work /merged
```

Here, `/lower1`, `/lower2`, `/lower3` are the read-only layers, topmost on left to bottom on right, `/upper` is the
writable top layer, `/work` is a working directory for OverlayFS, and `/merged` is the final merged view. You can try
modifying the container code from part one to mount an overlay filesystem for the container's rootfs using the same
mount syscall.

### Docker's OverlayFS in action

The entries listed by `mount` command earlier had a line like this:

```shell
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/....
```

Implying that the container's root filesystem itself is an overlay filesystem as expected. You can also check out the
lower and upper dirs mentioned in the output. These layers are typically under `/var/lib/docker/overlay2/` on the host.
If you run two containers from the same image, notice that they share the lower dirs but have different
upper dirs. Try modifying files inside these containers, the changes will appear only in their respective upper layers,
leaving the shared lower layers untouched.

## What's Next?

In the next post, I want to explore one final big piece of the puzzle: security. We'll look at how root privileges work
in Linux, dive into concepts like Linux capabilities, syscall filtering, user namespaces, and rootless containers, and
understand how containers leverage these mechanisms to enhance security and isolation.

## References

- [Deep Dive into Docker Internals - Union Filesystem](https://martinheinz.dev/blog/44)
- [Overlay Filesystem - The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html)
- [Overlay filesystem - ArchWiki](https://wiki.archlinux.org/title/Overlay_filesystem)
- [Introduction to Linux interfaces for virtual networking](https://developers.redhat.com/blog/2018/10/22/introduction-to-linux-interfaces-for-virtual-networking)
- [ Container Networking From Scratch - Kristen Jacobs, Oracle](https://www.youtube.com/watch?v=jeTKgAEyhsA)
- [Understanding Kubernetes Networking: Pods](https://medium.com/google-cloud/understanding-kubernetes-networking-pods-7117dd28727)
- [Mount namespaces and shared subtrees](https://lwn.net/Articles/689856/)
