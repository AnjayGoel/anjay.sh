---
title: "Containers Part I: They are just fancy processes"
publishDate: 2025-10-15 01:30:47 +0530
tags: [ containers, docker, kubernetes, til ]
description: "Containers are, at their core, just processes. Let's deep dive into Linux primitives that make it possible"
---

A while ago, I stumbled upon some LinkedIn copy-pasta about Go 1.25 finally making `GOMAXPROCS` 'container-aware'.
Indeed, for some reason, if you try to get cpu or memory info from within a container, you get the host's total
resources. This is probably the one of the few instances where containers behave differently, and I didn't really
understand why.

Despite relying on k8s almost daily for quite a while now, my understanding of how containers work had been fairly
limited. Partly because these abstractions work so well and there is so much to learn about simply using k8s itself that
I never tough of looking beneath the abstraction layers. The broad statements I came across while learning Docker like
"containers don't do virtualization," "they don't have a hypervisor layer like VMs," and "they sit directly on the host
OS kernel" didn't offer much real insight either.

So for that reason, the statement "containers are just fancy processes" really put things into perspective for me. As I
have come to understand, at the risk of over-simplifying, containers essentially pack up the whole application along
with all its user-space dependencies and run them as isolated processes on the host's kernel.

In this series of blogs, I hope to share an anatomy of containers that I have learnt by tinkering around in the
past few weeks. Rather than taking a deep dive into specific topics, its meant to provide a bird's eye view of
containers and the surrounding ecosystem. I will of course attach resources to dive deeper into specific topics. A lot
if not all of this was new to me, so feel free to correct me if I goof something up.

Much of this first blog is borrowed from this highly recommended series
of [videos by Liz Rice](https://www.youtube.com/watch?v=8fi7uSYlOdc&vl=en). So I won't explain these concepts in very
detail.

## The kernel features that allow containerisation

At the core of containers are two Linux kernel
features: "[namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)"
and "[cgroups](https://man7.org/linux/man-pages/man7/cgroups.7.html)".

* **Namespaces** isolate system resources, so processes inside a container see only their own view of resources
  like files, processes, and network interfaces.
* **Cgroups** (control groups) limit the amount of resources (CPU, memory, disk I/O, network, etc.) that a
  group of processes can use.

Both namespaces & cgroups are inherited by child processes, meaning that when a process spawns another, the child
process remain in the same namespace and cgroup as the parent unless explicitly changed. As you’ve probably gathered by
now, if we use these two features together, we should be able to run and manage a set isolated processes on the same
host
system. And that's what containers are all about! Let's take a look at both of these concepts in a bit more detail.

### Namespaces

Namespaces allow the processes inside it to have their own private view of certain resources of the system
such as process IDs, filesystems, network interfaces, and hostnames etc. This is what makes it possible for multiple
containers to run on the same host without interfering with each other, even though they share the same kernel. The way
to enter/create a namespace is to pass appropriate flags during process creation using the `clone` syscall
or via the `setns` syscall to join an existing namespace. The namespaces of a process are visible in the `proc` fs as
symlinks under`/proc/<pid>/ns`. A few important namespaces for isolation are:

* PID (`pid`): Isolates the set of process & PIDs. Process can only see other processes in the same or child namespace.
  The first process inside this namespace starts with PID 1 in
  the new namespace and is considered as the [init process](https://en.wikipedia.org/wiki/Init) in this new namespace.
  All
  the signals (SIGTERM, SIGINT, SIGQUIT etc.) sent to the container are received by this init process. So its important
  that this process handles these signals properly to manage the lifecycle of the container.

* UTS (`uts`): Isolates the hostname so that processes in different processes can have different hostnames and NIS
  domain names. Fun fact: the pod names you set in k8s are actually the hostname inside the pod's UTS namespace!

* Mount (`mnt`): Isolates the set of filesystem mount points. You start off with a copy of the host's mount points, but
  can add, remove, or change mount points without affecting the host or other namespaces. More on filesystems in part
  two.

* Network (`net`): Isolates the whole network stack, including interfaces, routing tables, firewall rules etc. More on
  this in part two as well.

* User (`user`): Isolates user and group IDs. Inside a user namespace a process can have a different mapped UID/GID
  than outside. Also allowing unprivileged users on the host to become uid 0 (root) inside this namespace. We
  will see how user namespace works in part three.

There are few other namespaces like IPC (`ipc`), cgroups (`cgroup`) & time (`time`) for (`CLOCK_MONOTONIC` and
`CLOCK_BOOTTIME`) etc.

### Cgroups

As mentioned earlier, cgroups allows to restrict the resource usage (CPU, memory, max processes etc.) of a set of
process. This is what allows us to set resource limits in k8s & docker. It works via a pseudo-filesystem usually mounted
at `/sys/fs/cgroup`. Similar to namespaces, the file `/proc/<pid>/cgroup` in the `proc` fs contains the cgroup of a
process. There are two versions of cgroups, we will use cgroups v2. To create a cgroup, we have to create a folder with
its name in this filesystem, then add pid's in a file `cgroup.procs` inside it. Files like `memory.max`, `cpu.max` in
this folder describes the max amount of resources this process can use. Similarly, the `cpuset.cpus` restricts which cpu
core the processes are allowed to run.

One interesting realisation I had from this is the CPU limits specified are shared across the cores of the host. Setting
a containers CPU limit to 1000m in k8s doesn't mean it will have a whole core available, it simply means that it will
have one core's worth of CPU time available! So it's possible that your container might actually be utilizing multiple
cores & running parallel threads even with very small low cpu limit, it would simply exhaust the limit quickly. The fact
that resource limits are set via cgroups is also one of the biggest reasons why programs need to be container-aware.
Traditionally, programs use the proc filesystem (e.g., `/proc/meminfo` or `/proc/cpuinfo`), which reflects the host's
resources rather than the container's actual limits.

## Building our own simple container

Hopefully, now we have a rough idea of how to create a simple container ourselves. We need to start
a process with its own namespaces, set up cgroups for resource
limits, [mount](https://man7.org/linux/man-pages/man2/mount.2.html) a few special filesystems like [
`proc`](https://docs.kernel.org/filesystems/proc.html),
`tmp` etc. and finally [`chroot`](https://wiki.archlinux.org/title/Chroot) (change the root dir of the process) to the
new root filesystem. There is obviously tons of details missing from this sketch like networking, security
considerations etc., which I hope to cover in the next part.

### Making a root filesystem

First we first need a root filesystem. We can get this by extracting it from any existing image. Lets extracts it
from BusyBox image:

1. Make the `mount` directory to hold the root filesystem.

```shell
mkdir -p "mount"
```

2. Create a temporary container from the BusyBox image, export its filesystem and extract it to the `mount` directory.

```shell
docker create --name "busybox-temp" "busybox:latest"
docker export "busybox-temp" | tar -C "mount" -xvf -
```

3. Remove the temporary container.

```shell
docker rm "busybox-temp"
```

### The step-by-step process

Let's first look at what the code given below is going to do:

1. Starts the program, parses the command to run in container, its args etc.
2. Sets up a new cgroup by writing to `/sys/fs/cgroup/`.
3. Clones a new child container process from the current process with new namespaces for mount, PID, UTS etc.
4. Adds the container process to the cgroup created earlier.
5. Inside the cloned process, it sets up the new hostname, mounts a few special filesystem like proc, temp etc., while
   also [bind mounts](https://unix.stackexchange.com/questions/198590/what-is-a-bind-mount) the host dev devices like
   `/dev/null`, `/dev/zero` to the container.
6. Finally, it does a `chroot` to the new root filesystem and execs the command passed from the parent process.

### The code

<div style="max-height: min(75vh, 1000px); overflow: scroll;">

```go
package main

import (
  "fmt"
  "os"
  "os/exec"
  "path/filepath"
  "strconv"
  "syscall"
)

var (
  rootfs          string
  cgroupPath      = "/sys/fs/cgroup/container"
  defaultHostname = "container"
)

func main() {
  if len(os.Args) < 2 {
    panic("usage: run <cmd> or child <cmd>")
  }

  wd, _ := os.Getwd()
  rootfs = filepath.Join(wd, "mount")

  //Print current pid & command
  cmd := os.Args[1]
  pid := os.Getpid()
  fmt.Printf("PID: %d, CMD: %s\n", pid, cmd)

  //Handle setup parent & child process
  switch os.Args[1] {
  case "run":
    run()
  case "child":
    child()
  default:
    panic("unknown command")
  }
}

// run sets up namespaces and re-executes itself as "child"
func run() {
  //Find the current executable
  bin, _ := os.Executable()

  //Re-run it with different args
  cmd := exec.Command(bin, append([]string{"child"}, os.Args[2:]...)...)

  //Connect std streams to child to parent process
  cmd.Stdin = os.Stdin
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr

  //Flags passed to clone syscall to create new namespaces for the process
  cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWNS |
      syscall.CLONE_NEWUTS |
      syscall.CLONE_NEWPID |
      syscall.CLONE_NEWNET |
      syscall.CLONE_NEWIPC |
      syscall.CLONE_NEWCGROUP,
  }

  // Setup cgroups before starting child process
  setupCgroups()

  check(cmd.Start())

  // Add child process to cgroup
  addToCgroup(cmd.Process.Pid)

  // Wait for child to complete
  err := cmd.Wait()
  cleanupCgroups()
  check(err)
}

// child executes inside the containerized namespaces
func child() {
  fmt.Println("Inside container, PID:", os.Getpid())
  fmt.Printf("uid: %d gid: %d\n", os.Getuid(), os.Getgid())

  // Setup mounts and dev character devices before chroot
  setupMounts()
  bindDevMounts()

  // Now chroot into the rootfs
  check(syscall.Chroot(rootfs))
  check(os.Chdir("/"))

  check(syscall.Sethostname([]byte(defaultHostname)))

  cmd := exec.Command(os.Args[2], os.Args[3:]...)
  cmd.Stdin = os.Stdin
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr
  check(cmd.Run())
}

// mounts special filesystems like /proc, /tmp
func setupMounts() {
  // Make mount propagation private to prevent mounts from leaking to host
  check(syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""))

  procPath := filepath.Join(rootfs, "proc")
  tmpPath := filepath.Join(rootfs, "tmp")

  check(os.MkdirAll(procPath, 0755))
  check(os.MkdirAll(tmpPath, 0755))

  check(syscall.Mount("proc", procPath, "proc", 0, ""))
  check(syscall.Mount("tmpfs", tmpPath, "tmpfs", 0, ""))
}

// Bind host character devices to container
func bindDevMounts() {
  devPath := filepath.Join(rootfs, "dev")
  check(os.MkdirAll(devPath, 0755))

  devices := []string{"null", "zero", "random", "urandom"}

  for _, dev := range devices {
    hostDev := filepath.Join("/dev", dev)
    contDev := filepath.Join(devPath, dev)

    // Make sure parent directory exists
    check(os.MkdirAll(filepath.Dir(contDev), 0755))

    // Create an empty file as mount target
    f, err := os.Create(contDev)
    check(err)
    check(f.Close())

    check(syscall.Mount(hostDev, contDev, "", syscall.MS_BIND, ""))
  }
}

// setupCgroups creates a simple v2 cgroup with limits
func setupCgroups() {
  fmt.Printf("Setting up cgroup at: %s\n", cgroupPath)

  // Create the cgroup directory
  check(os.MkdirAll(cgroupPath, 0755))

  // Enable controllers by writing to cgroup.subtree_control
  // This may fail if we don't have permissions, so we ignore errors
  check(os.WriteFile(filepath.Join("/sys/fs/cgroup", "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0644))

  // Set resource limits (these may fail without proper permissions)
  check(os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("50M"), 0644))

  check(os.WriteFile(filepath.Join(cgroupPath, "pids.max"), []byte("20"), 0644))
  check(os.WriteFile(filepath.Join(cgroupPath, "cpu.weight"), []byte("100"), 0644))
}

// addToCgroup adds a process to the container cgroup
func addToCgroup(pid int) {
  check(os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644))
}

// cleanupCgroups removes the cgroup directory
func cleanupCgroups() {
  check(os.RemoveAll(cgroupPath))
}

func check(err error) {
  if err != nil {
    panic(err)
  }
}

```

</div>

### Steps to compile & run

1. Save this as `main.go`. Note that the work directory should also contain the `mount` directory
   created earlier with the root filesystem.
2. Compile it using `go build main.go`.
3. Run the binary with sudo, passing the command to run in the container, for example the shell:
   `sudo ./main run /bin/sh`

And voilà! Now you should see yourself inside a shell in the container! We have a simple container running a bash shell.
You can try exploring the container using commands like
`ps`, `ip`, `ls` to convince yourself that it is indeed isolated from the host system. Try removing a few
namespaces to see how isolation is affected. Also on the host, you can try checking the cgroup & ns using the proc
filesystem (`/proc/<pid>/cgroup` and `/proc/<pid>/ns`). Also try making fork bomb inside the container to see if its
limit to the no of processes we specified in cgroups.

## Seeing it in action with docker

Let's run a Docker container with memory and CPU limits to convince ourselves that this is indeed how containers are
implemented in practice:

```shell
docker run -it --rm --memory="128m" --cpus="0.5" busybox sh
```

Looking at the output of `ps -e -o pid,user,cmd --forest`, we can find the container process

```shell
    705 root     /usr/bin/python3 -u /usr/sbin/waagent -daemon
    927 root      \_ /usr/bin/python3 -u bin/WALinuxAgent-2.15.0.1-py3.12.egg -run-exthandlers
    712 root     /usr/sbin/cron -f -P
    744 root     /sbin/agetty -o -p -- \u --keep-baud 115200,57600,38400,9600 - vt220
    750 root     /usr/bin/containerd
    755 root     /sbin/agetty -o -p -- \u --noclear - linux
    788 root     /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
    806 _chrony  /usr/sbin/chronyd -F 1
    816 _chrony   \_ /usr/sbin/chronyd -F 1
    808 root     /usr/sbin/ModemManager
    838 syslog   /usr/sbin/rsyslogd -n -iNONE
    897 root     /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
  97639 silverb+ /usr/lib/systemd/systemd --user
  97641 silverb+  \_ (sd-pam)
  98362 silverb+  \_ /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
 159253 root     /usr/bin/containerd-shim-runc-v2 -namespace moby -id 265e0a69b69a65aa2e9c036433810fb1693efbb45908abe957307ea1648ecc6e -address /run/containerd/containerd.sock
 159276 root      \_ sh
```

The pid `159276` is the actual docker container process. Each docker container also has a shim process (pid `159253`)
which we will discuss later.

Now using the `proc` filesystem, we can confirm that this process has a cgroup & different namespace from other
processes.

#### Namespaces

The namespaces of a process are visible in the `proc` fs as symlinks under `/proc/<pid>/ns`. Doing
`sudo ls -al /proc/<pid>/ns` gives
us something like following

```shell
total 0
lrwxrwxrwx 1 root root 0 Oct 21 08:00 cgroup -> 'cgroup:[4026532163]'
lrwxrwxrwx 1 root root 0 Oct 21 08:00 ipc -> 'ipc:[4026532161]'
lrwxrwxrwx 1 root root 0 Oct 21 07:50 mnt -> 'mnt:[4026532158]'
lrwxrwxrwx 1 root root 0 Oct 21 07:50 net -> 'net:[4026532164]'
lrwxrwxrwx 1 root root 0 Oct 21 08:00 pid -> 'pid:[4026532162]'
lrwxrwxrwx 1 root root 0 Oct 21 08:00 pid_for_children -> 'pid:[4026532162]'
lrwxrwxrwx 1 root root 0 Oct 21 08:00 time -> 'time:[4026531834]'
lrwxrwxrwx 1 root root 0 Oct 21 08:00 time_for_children -> 'time:[4026531834]'
lrwxrwxrwx 1 root root 0 Oct 21 08:00 user -> 'user:[4026531837]'
lrwxrwxrwx 1 root root 0 Oct 21 08:00 uts -> 'uts:[4026532159]'
```

You can do the same for normal process to confirm that the namespaces for the container process is indeed different from
the default namespaces used by other processes. We can enter a particular namespace of the process by using the
`nsenter` utility. Let's enter all its namespaces by doing

```shell
sudo nsenter -t 137649 -a
```

Explore using `ls`, `ip` etc., we are indeed inside the docker container!.

#### Cgroups

Similar to namespaces, `cat /proc/<pid>/cgroup` gives the name of cgroup. It typically looks like this:

```shell
0::/system.slice/docker-<container-id>.scope
```

The corresponding cgroups folder can be found under:

```shell
/sys/fs/cgroup/system.slice/docker-<container-id>.scope
```

Opening files such as `memory.max` and `cpu.max` in that directory confirms that this is where the process's resource
limits are enforced using cgroups.

## What next?

So far, we have implemented a basic container ourselves and seen Docker containers in action using the same Linux
primitives. Kubernetes pods are built on similar concepts. By default, containers in a pod share the `ipc`, `network`,
and `uts` namespaces. It is also possible
to [share the PID namespace](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/) between
containers in a pod. Meanwhile, cgroups are applied at the individual container level.

This should be enough to digest the fact that containers are, at their core, just processes. But calling them "fancy"
feels like an understatement. They are indeed much more sophisticated than a typical process. In the next part, I hope
to dive into even fancier aspects like networking, filesystems & security.

## References

- [Namespaces in operation, part 1: namespaces overview](https://lwn.net/Articles/531114/)
- [Digging into Linux namespaces - part 1](https://blog.quarkslab.com/digging-into-linux-namespaces-part-1.html)
- [The 7 most used Linux namespaces](https://www.redhat.com/en/blog/7-linux-namespaces)
- [Control Group v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [A Linux sysadmin's introduction to cgroups](https://www.redhat.com/en/blog/cgroups-part-one)
