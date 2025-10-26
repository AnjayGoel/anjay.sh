---
title: "Containers Part II: The stuff that makes containers \"fancy\""
publishDate: 2025-10-16 01:30:47 +0530
tags: [ containers, docker, kubernetes, til ]
description: "Yes, containers are, at their core, just processes. Let's dig into Linux primitives that make it possible"
---

In part one, we built a plain & bare-bones container. To make it more useful, we need to configure quite a few things
like networking (obviously), storage, security, etc. In this post, I want to explore how a few of these are
implemented in practice and try to implement them ourselves wherever possible, comparing our approach with how Docker
handles them.

Before we get started, take a look at the output of `docker inspect <container_id>` to see all the configurations Docker
does for a container. Notice stuff like `HostConfig`, `Mounts`, `NetworkSettings`, `GraphDriver` (File System) etc.

## Networking

Now, let's first take a look at how networking works in containers. This is done via a virtual network interface
called [veth](https://man7.org/linux/man-pages/man4/veth.4.html) (Virtual Ethernet). It's quite similar to an
ethernet cable joining two devices. The special thing about it though is that ends of the veth pair can be moved to
different network namespaces. We can create a veth pair using the `ip`, then setup firewall & NAT using `iptables` as
done below:

<div style="max-height: min(75vh, 1000px); overflow: scroll;">

```shell
#!/bin/bash
# Usage: ./script.sh <container_pid>
if [ -z "$1" ]; then
  echo "Usage: $0 <container_pid>"
  exit 1
fi

CONTAINER_PID=$1
HOST_IF=veth-host
CONT_IF=veth-container
SUBNET=10.200.0.0/24
HOST_IP=10.200.0.1
CONT_IP=10.200.0.2

echo "[*] Creating veth pair..."
sudo ip link add $HOST_IF type veth peer name $CONT_IF

echo "[*] Moving one side of veth to container namespace..."
sudo ip link set $CONT_IF netns $CONTAINER_PID

echo "[*] Assigning IP to host interface..."
sudo ip addr add $HOST_IP/24 dev $HOST_IF
sudo ip link set $HOST_IF up

echo "[*] Assigning IP to container interface..."
sudo nsenter -t $CONTAINER_PID -n ip addr add $CONT_IP/24 dev $CONT_IF
sudo nsenter -t $CONTAINER_PID -n ip link set $CONT_IF up
sudo nsenter -t $CONTAINER_PID -n ip link set lo up

echo "[*] Adding default route inside container..."
sudo nsenter -t $CONTAINER_PID -n ip route add default via $HOST_IP

echo "[*] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

HOST_NET_IF=$(ip route | grep default | awk '{print $5}')
echo "[*] Explicitly setting iptables FORWARD rules..."
sudo iptables -A FORWARD -i $HOST_IF -o $HOST_NET_IF -j ACCEPT
sudo iptables -A FORWARD -i $HOST_NET_IF -o $HOST_IF -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "[*] Setting iptables NAT rule..."
sudo iptables -t nat -A POSTROUTING -s $SUBNET -o $HOST_NET_IF -j MASQUERADE

echo "[*] Done! Container should now have internet access."
```

</div>


There is another virtual interface typically used in container networking
called [bridge](https://wiki.archlinux.org/title/Network_bridge). A bridge is like a virtual
switch that allows us to connect multiple network interfaces. Docker creates a default bridge network called `docker0`
on the host machine. When a container is started, Docker creates a veth pair, attaches one end to the container's
network namespace, and the other end to the `docker0` (by default) bridge on the host.

Try creating a simple HTTP server container and accessing it from another container using Docker's default networking:

```shell
docker run -d --name server python:3-slim python -m http.server 5000
docker run -it --rm busybox sh
```

Then get the server containers IP using
`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server` then access it from the busybox
using `wget -qO- http://<ip>:5000`

At the same time, if you run `ip link show` on the host, you will see `docker0` & two veth interfaces created for the
server & busybox container, like below:

```shell
$ ip link show
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

## Storage

In part one, we saw how mount namespaces allow us to isolate mounts inside a container. For the root filesystem however,
we simply extracted it from a docker image. In practice, container's root filesystem consists of multiple
read only layers with a finale writable layer stacked on top of each other. These are the same layers you see when
building or fetching a docker image. Each layer records a set of diffs / changes. These layers are merged into a single
view using a union mount filesystem like [OverlayFS](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html).

This enables sharing common layers between multiple containers, saving disk space and improving startup time. When a
container writes to its filesystem, the changes are recorded in the top writable layer, leaving the underlying read-only
layers unchanged. When something is changed in the lower read-only layers, it is "copied up" to the top writable layer,
this is called the"copy-on-write" strategy.

The overlay filesystem can be setup using the `mount` command as shown below:

```shell
# mount -t overlay overlay -o lowerdir=/lower1:/lower2:/lower3,upperdir=/upper,workdir=/work /merged
```

Here, `/lower1`, `/lower2`, `/lower3` are the read-only layers, topmost on left to bottom on right, `/upper` is the
writable top layer, `/work` is a working directory for OverlayFS, and `/merged` is the final merged view. You can try
modifying the container code from part one to mount an overlay filesystem for the container's rootfs using the same
mount syscall.

Similarly, docker stores this layers under `/var/lib/docker/overlay2/` on the host. You can find these layers using
`docker inspect -f '{{json .GraphDriver}}' <container-id> | jq`. If you run two containers from the same image, you’ll
notice that they share the `LowerDir` but have different `UpperDir`. Try modifying / add some files inside these
containers. you’ll see that the changes appear only in their respective `UpperDir`, leaving the shared lower layers
untouched.

* Rootless: User namespace, user mapping, root & capabilities
* Restricting syscalls

* SELinux, AppArmor, seccomp -> ?

https://martinheinz.dev/blog/44
https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html
https://wiki.archlinux.org/title/Overlay_filesystem


https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/
https://kubernetes.io/docs/tutorials/security/seccomp/
https://lwn.net/Articles/978846/
https://www.cloudfoundry.org/blog/route-rootless-containers/
