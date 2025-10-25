---
title: "Containers Part II: The stuff that makes containers \"fancy\""
publishDate: 2025-10-16 01:30:47 +0530
tags: [ containers, docker, kubernetes, til ]
description: "Yes, containers are, at their core, just processes. Let's dig into Linux primitives that make it possible"
---


In part one, we built a plain & dumb container. To make it more useful, we need to configure a few things like
networking (obviously), storage, security, etc.

## Networking

Let's first take a look at how networking works in containers. This is done via a virtual network interface
called [veth](https://man7.org/linux/man-pages/man4/veth.4.html) (Virtual Ethernet). It's quite similar to an
ethernet cable joining two devices. The special thing it though is that ends of the veth pair can be moved to different
network namespaces. We can create a veth pair using the `ip`, then setup firewall & NAT using `iptables` as done below:

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


There is another virtual interface typically used in container networking called `bridge`. A bridge is like a virtual
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
server & busybox containers, like below:

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



* Rootless: User namespace, user mapping, root & capabilities
* Restricting syscalls
* Overlay FS, Copy on write
* SELinux, AppArmor, seccomp -> ?
