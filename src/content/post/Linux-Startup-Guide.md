---
title:  "Linux Startup Guide"
publishDate:   2020-03-17 09:13:47 +0530
description: "Windows To Linux Migration Guide"
tags: [how-to, linux, programming]
---
<!--end_excerpt-->

        I have been using Linux for quite a while now and I have become pretty comfortable with the operating system to an extent that I rarely use windows nowadays, apart from the occasional photoshop and gaming stuff. Once you get used to Linux, you realize how awesome it is and why people especially developers prefer it over Windows.

        But using Linux has a bit of a learning curve. Migrating from Windows to Linux, I often got stuck at several points like how do i install softwares, where are all my drives (C: , D: etc. ), Why does this OS look so ugly and how do I customize it, how do I use this command line etc. So I am writing this post to make Linux beginners a bit more familiar with the Linux environment.



## **The Terminal**

        The terminal is probably the most used application of any Linux user. You might have seen someone use the Linux Terminal and got intimidated by it, wondering what the heck are they doing and whats with the crazy amount of input / output going on. But you will eventually get familiar with the terminal realize that it actually make things easier.

#### **List of some handy commands**

| Command      | Description                                        |
| ------------ | -------------------------------------------------- |
| `pwd` | Prints the full pathname of the current working directory |
| `ls` | **Lists all files in current directory**               |
| `cd`   | **Changes the working directory** |
|`mkdir`|Makes new directories|
|`rmdir`|Removes empty directories|
|`touch`|**Creates a file without any content**|
|`mv`|Move one or more directories from one place to another|
|`cp`|Copy one or more directories from one place to another|
|`sudo`|**Sudo is used to execute another command as superuser ( Similar to administrator in windows ).**|
|`echo`|Displays text/string passed as argument|
|`grep`|Searches a file for a particular pattern of characters, and displays all lines that contain that pattern.|
|`chmod`|**Used to change the access permissions of file system(More about permissions below)**|
|`export`|Used to export/set environment variables. Changes do not persist after terminal is closed|
|`env`|Lists all environment variables|
|`ps`|Displays information about running processes.|
|`exit`|Exits the terminal|
|`find`|Used to find files and directories|
|`passwd`|Change password of the current user|
|`curl`|Curl is a command-line utility for transferring data from or to a server.|
|`shutdown`|Shuts down the system|
|`cat`|Allows you to view contents, concatenate, create files as well as redirect output in terminal or files|
|`kill`|Used to terminate a process|
|`df`|Displays information related to file systems about total space and available space.|

[Further References](https://linuxhint.com/100_essential_linux_commands/)

Useful Tips:

- Use `--help` option or `man <command>` to view the documentation, options and examples of a command. For ex. `ls --help`
- Use tab to auto-complete and up/down keys to go through previously executed commands.
- Use Ctrl+C to stop execution of current command.
- ./ refers to current directory and ~/ refers to home directory.

[Further References](https://help.ubuntu.com/community/UsingTheTerminal)

#### **Shell Scripts**

        Shell scripts (files with .sh extension) are similar to batch scripts (files with .bat extension) in Windows. A shell scripts is simply a text file that contains sequence of commands that can be executed in the shell (the terminal). To run a shell script simply type `bash /path/to/script.sh` or make the script executable using `chmod` and run it directly.

## **How to install softwares**

        Most of the Linux distributions come with their own application stores such as *Software Center* in Ubuntu. These stores have plenty of popular softwares. Apart from that you can also install softwares via installation packages such as .deb files (for Debian based distributions such as Ubuntu) or .rpm files or by using command line utilities such as apt or yum.

#### **Using apt to install softwares**

        Using `apt` to install softwares is by probably the most popular method on Debian based distros such as Ubuntu. `apt` stands for Advanced Packaging Tool. It is a command line tool to install, update and remove packages.

##### **Install a package**:

To install a software package using apt, use the following command

`sudo apt install <package_name>`

for example:

`sudo apt install vlc`

##### **Remove a package:**

To remove a package use the following command:

`sudo apt remove <package_name>`

##### **Update the package index:**

The package index is basically a list of available software packages from the repositories defined in the */etc/apt/sources.list* file. To update this list use

`sudo apt update`

##### **Upgrading packages:**

You can use the following command  to update the installed packages to their latest version.

`sudo apt upgrade`

##### **Searching for packages:**

To find a package use can use the search flag:

`apt search name_or_description`

you can also use `apt show <package_name>` to get the description of the package. Note that you don't need to run this commands as sudo.

Note: Only one instance of apt can be working at any time. If you try to use multiple instances of apt you will get error like

[Further References](https://itsfoss.com/apt-command-guide/)

## **Executables in Linux**

        Unlike Windows where executable files have .exe extension, there is no such extension which makes a file executable. In fact in Linux any file can be executed. Linux uses file permissions to check if a file is executable.

#### **What are these file permissions?**

        Linux is a multi-user operating system. It uses the concept of users and permissions to control what different user can do with a file or a directory.

In Linux there are three type of users

- Owner (u) : Owner of a file
- Group (g) : Group contains multiple users who have same permissions to the file
- Everyone else (o) : Any other user


Types of permissions:

- Read (r) : read contents of a file (cat) or list directory content (ls)

- Write (w) : change contents of a file or create, modify or delete files in a directory
- Execute (x): execute the file or enter the directory (cd).

	You can use `ls -l` option to view permissions of all files or folders in the current directory for different users.  Also use `chmod <users>+<permissions> <file>`  to change permissions for a file.  For example `chmod ugo+rwx hello.sh` to give read, write, execute permissions to everyone. Use `chmod +x` to make a file executable for everyone.

	To execute a file simply double-click it or type its path in the terminal. For example, steps to execute `hello.sh` shell script in current directory:

- `chmod +x hello.sh` : To make it executable if its not already
- `./hello.sh`: To execute it. Note: ./ refers to current working directory.
- `sudo ./hello.sh`: If something like `'Permission denied'` appears. It implies that you need administrative or superuser access.

## **Where are my disk drives?**

      Unlike windows, Linux doesn't mount drives at different drive letters instead all partitions are mounted as folders withing root (top-level directory) usually in the media or mnt folder. Though you can easily access them using file browsers such as dolphin.

##### **Why can't I see my Linux partition in Windows?**

Linux uses ext4 filesystem which is not supported by windows. Hence the Linux partition won't be visible among other drives. Though you can use softwares like *ext2fsd* if necessary.

##### **Why can't I open Windows partition in Linux?**

If you are dual-booting Linux alongside Windows you will often encounter problems opening windows partition in Linux. To solve this problem you need to do a full shutdown in Windows (do not hibernate) and disable fast boot.



### **Other FAQ's**

- How do I fix time difference in Linux and Windows dual-boot?

  simply execute the following command:

  `timedatectl set-local-rtc 1 --adjust-system-clock`

  It will make Linux use local time like Windows does

- How do I permanently export/edit environment variables?

  - System-wide variables across all users:

         Simply add the variables to `/etc/enviornment` file.

  - System-wide variable for current user:

    Add the variables to `~/.profile`

- How do I find my local ip address?

  use `hostname -I` command.

- How do I find or kill a process ?

  use `ps -ef | grep <name>` to find a process and `killall <name>` to kill a process

- How do I set proxy?

  Most Linux distributions will have an option to set proxy in the networking section of the settings panel. You can set also export environment variables such as http_proxy, https_proxy to set command line proxy. For example `export HTTP_PROXY=user:pass@proxyserver:8080`.

  	Note: Utilities such as apt have their own proxy settings. To skip the hassle of setting several different proxies you can use [[this script]](https://github.com/thealphadollar/set_proxy).



PS: Will add more stuff later
