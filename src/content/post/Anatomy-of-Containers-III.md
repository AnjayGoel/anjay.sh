---
title: "Anatomy of Containers, Part III: What's root, really?"
publishDate: 2025-11-25 01:10:00 +0530
tags: [ containers, docker, linux, kubernetes, til ]
description: "Understanding how root privileges works in Linux and what it means for containers."
---

In [part one](https://anjay.sh/posts/anatomy-of-containers-i/)
and [part two](https://anjay.sh/posts/anatomy-of-containers-ii/), we ran our implementation of containers
with root privileges. Despite all the isolation provided by namespaces and cgroups, the process is still running as
root on the host. This is an issue because some things by their nature cannot be isolated by namespaces or cgroups.
This includes kernel configurations, loading/unloading kernel modules, and system-wide settings like the [real-time
clock](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) (
`CLOCK_REALTIME`). A containerized process running as root can modify these settings, affecting the host and all other
containers and processes.

To handle this, Linux provides a few tools. Let's start with understanding what root access
really means.

## Capabilities

I always assumed root was a binary state; either you are root, or you are not. However, Linux breaks down the
privileges of root into smaller sets called [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html).
Each capability allows a process to perform some specific
privileged operation. For example, loading kernel modules requires `CAP_SYS_MODULE`, configuring network interfaces
needs `CAP_NET_ADMIN`, and binding to low-numbered ports (like 80 or 443) needs `CAP_NET_BIND_SERVICE`. These
capabilities are
associated with the current process and can be inherited by child processes. You can view the capabilities of all
running processes using `pscap` (from the `libcap-ng-utils` package) or by checking the `CapEff` field in
`/proc/[pid]/status` (note: it's a
hexadecimal bitmask).

Interestingly, capabilities can also be applied to files using `setcap`, allowing non-root users to execute them with
specific elevated privileges without granting full root access! For example, if we check the capabilities of the `ping`
binary using `getcap $(which ping)`, we can see that it has the `CAP_NET_RAW` capability. The capabilities of a process
are divided into four sets:

- **Permitted**: The capabilities that the process can use.
- **Effective**: The capabilities that are currently active for the process.
- **Inheritable**: The capabilities that can be inherited by child processes.
- **Bounding**: The maximum set of capabilities that the process and its children can have.

Let's try this ourselves by dropping the capability to change the system time (`CAP_SYS_TIME`) from our container.

1. First, run the container from parts one and two. Inside the shell, try changing the system time
   using `date -s "2025-12-01 10:00:00"`. You should see that the command executes successfully and the time changes on
   the host as well.

2. Now, let's drop the `CAP_SYS_TIME` capability by adding the following code in the child process:

```go
package main

import (
  "kernel.org/pub/linux/libs/security/libcap/cap"
)

// removes the specified capabilities from the current process and its children
func dropCapabilities(remove []cap.Value) error {
  working := cap.GetProc()
  for _, c := range remove {
    check(working.SetFlag(cap.Permitted, false, c))
    check(working.SetFlag(cap.Effective, false, c))
    check(working.SetFlag(cap.Inheritable, false, c))
    check(cap.DropBound(c))

  }
  check(working.SetProc())
  return nil
}

func child() {
  // Child process code
  check(dropCapabilities([]cap.Value{
    cap.SYS_TIME,
  }))
  //Now exec the desired command
}
```

3. Now, try changing the system time again. You should see an `Operation not permitted` error, indicating that, despite
   being root, we cannot change the time!

By default, Docker
only grants a [minimal set of capabilities](https://dockerlabs.collabnix.com/advanced/security/capabilities/) to
containers, but you can customize this using the
`--cap-add` and `--cap-drop` flags when running a container. You can use the `pscap` tool to list all the processes and
their capabilities on the host. K8S inherits these defaults from the underlying container runtime and drops additional
capabilities. This is configurable using the [
`securityContext`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) in the pod spec.

## Seccomp

To have more fine-grained control over what a process can do, containers also
use [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html). Seccomp (short for secure
computing) is a Linux kernel feature that allows you to restrict the syscalls a process can
make. Seccomp works by attaching a Berkeley Packet Filter (BPF) to the process. It runs inside the kernel every time the
process makes a syscall. The filter can match on the syscall and its arguments, and then decide whether to allow
the syscall, block it with an errno, or kill the process entirely. Once a seccomp filter is installed, it cannot be
removed or relaxed, only tightened. Similar to capabilities, it is also inherited by child processes.

To see this in action, let's use the same example of changing the system time. This time, instead of dropping the
`CAP_SYS_TIME` capability, we will use seccomp to block the [
`clock_settime`](https://www.man7.org/linux/man-pages/man3/clock_settime.3.html) syscall.

1. First, you might need to install the seccomp package on the host:

```shell
sudo apt-get update
sudo apt-get install -y libseccomp-dev pkg-config
```

2. Now, add the following code to the container implementation to install a seccomp filter in the child process:

```go
package main

import (
  seccomp "github.com/seccomp/libseccomp-golang"
)

func installSeccomp(syscalls []string) error {
  // Default action: allow everything
  filter, err := seccomp.NewFilter(seccomp.ActAllow)
  if err != nil {
    return err
  }

  // block the time syscalls by returning EPERM
  deny := seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM))

  for _, name := range syscalls {
    sc, err := seccomp.GetSyscallFromName(name)
    if err != nil {
      log.Printf("seccomp: syscall %s not found: %v", name, err)
      continue
    }
    check(filter.AddRule(sc, deny))
  }

  //Load the filter into the kernel
  err = filter.Load()
  return err
}

func child() {
  // Child process code

  //Disallow changing system time
  check(installSeccomp([]string{
    "clock_settime",
  }))
  //Now exec the desired command
}
```

3. Now, try changing the system time again. You should see the same `Operation not permitted` error, indicating that the
   syscall was blocked by seccomp.

You can get information about a running
process's seccomp by looking at the `Seccomp` field in `/proc/[pid]/status` (0 means no seccomp, 1 means strict mode, 2
means filter mode) and the number of filters attached using the `Seccomp_filters` field. More details on Docker's
seccomp profile can be found [here](https://docs.docker.com/engine/security/seccomp/).
K8S also allows you to fine-tune the seccomp profile using the securityContext's `seccompProfile` field
as described [here](https://kubernetes.io/docs/tutorials/security/seccomp/).

## Rootless containers

So far, we have been focused on reducing the privileges of root inside the container. But there is another approach
called "rootless containers". Rootless containers allow you to run containers as unprivileged users by leveraging
the [user namespace](https://man7.org/linux/man-pages/man7/user_namespaces.7.html). A user namespace isolates the
user/group IDs and capabilities. So a process inside
the user namespace can be root (UID 0) and have all capabilities, but on the host, it is mapped to an unprivileged user
and has no capabilities at all.

To run our container as a rootless user, we need to make some changes to the way we configure the child process as
follows:

```go
package main

func run() {
  bin, _ := os.Executable()

  cmd := exec.Command(bin, append([]string{"child"}, os.Args[2:]...)...)

  cmd.Stdin = os.Stdin
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr

  cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUSER | // create a new user namespace
      syscall.CLONE_NEWNS |
      syscall.CLONE_NEWUTS |
      syscall.CLONE_NEWPID |
      syscall.CLONE_NEWNET |
      syscall.CLONE_NEWIPC |
      syscall.CLONE_NEWCGROUP,
    Credential: &syscall.Credential{Uid: 0, Gid: 0}, // run as root inside the container
    UidMappings: []syscall.SysProcIDMap{
      {ContainerID: 0, HostID: 1000, Size: 1}, // map container's root (UID 0) -> host UID 1000 (first non-root user)
    },
    GidMappings: []syscall.SysProcIDMap{
      {ContainerID: 0, HostID: 1000, Size: 1}, //map container GID 0 -> host GID 1000 (first non-root user's primary group)
    },
  }
  //Rest of the code remains the same
}

```

This does a couple of things:

* Adds the `CLONE_NEWUSER` flag to create a new user namespace.
* Sets the `Credential` field to run the process as root (UID 0) inside the new user namespace.
* Maps the UID and GID inside the container to the host's unprivileged user. The mapping can be viewed in
  `/proc/[pid]/uid_map` and `/proc/[pid]/gid_map` on the host. It will show something like `0 1000 1` meaning: map UID 0
  inside the container to UID 1000 on the host, for a range of the next 1 UID.

Note that you will still need to run the binary itself with `sudo`, as we need root privileges for operations such as
setting up cgroups in the parent process/namespace. However, when you run `ps aux --forest` on the host, you will see
that the actual containerized process is running as the unprivileged user, as shown below:

```shell
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root       21445  0.0  0.1  17140  6888 pts/3    S+   22:23   0:00              \_ sudo ./main run /bin/bash
root       21446  0.0  0.0  17140  2604 pts/4    Ss   22:23   0:00                  \_ sudo ./main run /bin/bash
root       21447  0.0  0.0 1225536 3812 pts/4    Sl   22:23   0:00                      \_ ./main run /bin/bash
silverb+   21452  0.0  0.0 1225792 3812 pts/4    Sl   22:23   0:00                          \_ /home/silverbug/containers/main child /bin/bash
silverb+   21457  0.0  0.1   8004  4108 pts/4    S+   22:23   0:00                              \_ /bin/bash
```

More info on Docker's rootless mode can be found [here](https://docs.docker.com/engine/security/rootless/), and for
K8S [here](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-in-userns/). There are a few other popular
approaches to securing containers
like [AppArmor and SELinux](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-5/). There
is also [gVisor](https://gvisor.dev/docs/) that goes one step beyond to intercept all system calls and act as a guest
kernel, all while running in the user space!

## What's next?

I'll stop here before this blog series becomes a whole reference guide. My goal was to understand the absolute
fundamental building blocks of containers, and we're pretty much there. In practice, the container ecosystem goes much
deeper. There are the [OCI specs](https://specs.opencontainers.org/) (the standardized format for container
images) which describe how to build container images, the
low-level ([runc](https://github.com/opencontainers/runc), crun) and high-level runtimes (containerd, CRI-O) which
actually run the containers from the images and manage their lifecycle, and then there is K8S which delegates these
responsibilities via standardized interfaces like the CRI for container runtimes, CNI for networking, and CSI for
storage.
