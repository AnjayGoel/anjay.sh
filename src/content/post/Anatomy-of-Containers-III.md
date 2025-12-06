---
title: "Anatomy of Containers, Part III: What's root access, really?"
publishDate: 2025-11-25 01:10:00 +0530
tags: [ containers, docker, linux, kubernetes, til ]
description: "Understanding how root works in linux and what it means for containers."
---

In [part one](https://anjay.sh/posts/anatomy-of-containers-i/)
and [part two](https://anjay.sh/posts/anatomy-of-containers-ii/), we ran our implementation of containers
using root privileges. Despite all the isolation provided by namespaces and cgroups, the process is still running as
root on the host. This is an issue because something's by their very nature cannot be isolated by namespaces or cgroups.
This
includes stuff like kernel configurations, loading / unloading kernel modules, and even the clock (`CLOCK_REALTIME`). A
containerized process running as root can modify these settings, affecting the host and all other containers and
processes.

To handle this, We have a few tools at our disposal, thanks to Linux. Let's start with understanding what root access
really means.

### Capabilities

I always assumed root as being a binary state, either you are root, or you are not. However, Linux breaks down the
privileges of root into smaller sets called capabilities. Each capability allows a process to perform some specific
privileged operation. For example, loading kernel modules requires `CAP_SYS_MODULE`, configuring network interfaces
needs `CAP_NET_ADMIN`, and binding to low-numbered ports (like 80 or 443) needs `CAP_NET_BIND_SERVICE`. These
capabilities are
associated with the current process and can be inherited by child processes. You can view the capabilities of all the
running process using `pscap` (from the `libcap-ng-utils` package) or by checking the `CapEff` field in
`/proc/[pid]/status` (Note: It's a
hexadecimal bitmask). Interestingly, capabilities can also be applied to files using `setcap`, allowing non-root users
to execute them with
specific elevated privileges without granting full root access. For example, if we check the capabilities of the `ping`
binary using `getcap $(which ping)`, we can see that it has the `CAP_NET_RAW` capability. The capabilities of a process
are divided into four sets:

- **Permitted**: The capabilities that the process can use.
- **Effective**: The capabilities that are currently active for the process.
- **Inheritable**: The capabilities that can be inherited by child processes.
- **Bounding**: The maximum set of capabilities that the process and its children can have.

Lets try this ourself.

1. First, run the container from the part one & two. Inside the shell, try changing the system time
   using `date -s "2025-12-01 10:00:00"`. You should see that the command executes successfully and the time changes
   even on the host.

2. Now, lets drop the `CAP_SYS_TIME` capability by adding the following code
   before executing the command in the child process:

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

3. Now, try changing the system time again. You should see a `Operation not permitted` error, indicating that despite
   being root, we cannot change the time!.

```c

```shell
# 1. Create & run container and install packages (container stays after exit)
docker run --name ubuntu-temp -it mcr.microsoft.com/devcontainers/base:ubuntu bash -c "\
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y kmod iproute2 net-tools procps curl wget git vim && \
  apt-get clean && rm -rf /var/lib/apt/lists/* && \
  exit"

# 2. Export the container filesystem and extract into ./mount
mkdir -p mount
docker export ubuntu-temp | tar -C mount -xvf -

```

```shell
/proc/sys/vm/* & /proc/sys/fs/*
fs.file-max vm.swappiness
```

```echo c > /proc/sysrq-trigger```

```grep Cap /proc/3401/status```
```sudo apt install libcap-ng-utils```  ```pscap```
`getcap`
`capsh`

	err := dropCapabilities([]cap.Value{
		cap.SYS_TIME,
	})

```c
#include <sys/reboot.h>
#include <linux/reboot.h>

int main() {
    return reboot(LINUX_REBOOT_CMD_RESTART);
}
```

### Seccomp

```
sudo apt-get update
sudo apt-get install -y libseccomp-dev pkg-config
```

### User namespaces

### Rootless containers
