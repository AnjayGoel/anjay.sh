---
title: "Anatomy of Containers, Part III: Whats root?"
publishDate: 2025-11-25 01:10:00 +0530
tags: [ containers, docker, linux, kubernetes, til ]
description: "Whats root?"
---

### Capabilities
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
