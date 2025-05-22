---
title: "How Does Async / Non-Blocking IO Actually Work?"
publishDate: 2025-05-24 01:50:00 +0530
tags: [ til, programming,linux ]
description: "Deep dive into the OS internals to understand how async/non-blocking IO actually works."
---


Some time ago at work, I stumbled upon a simple question: what actually makes some I/O non-blocking? Concepts
like async/await, non-blocking I/O and event loops are so common, yet I had never thought about how they work under the
hood. So, I decided to do a deep dive and summarize it in this (somewhat lengthy) blog.

The internals of non-blocking I/O are complex but fascinating. To understand it, this blog will start with a key
Linux concept: "Everything is a file." then, briefly explore the lifecycle of a process in Linux, go over a few
system calls like `select`, `poll`, `epoll` & `fnctl`, and finally build a simple single-threaded non-blocking echo
server in C to see these ideas in action.

### "Everything Is a File" in Linux

This Unix philosophy that allows us to treat almost every resource on the system like devices,
socket connections, pipes, and more as a file. It gives us a simple and consistent way to interact with these resources:
by
reading from and writing to them, just like regular files! This is done via something called a file descriptor (FD).
File descriptors are process-unique identifiers that reference a particular resource. Every process starts with three
default FDs for the standard streams: 0 (stdin), 1 (stdout), and 2 (stderr).

Let's see this by running the following simple C program that listens on a port and opens a txt file:

<div style="max-height: min(75vh, 1000px); overflow: scroll;">

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

int main() {
    //Open a file for writing
    FILE *file = fopen("output.txt", "w");

    int sockfd, clientfd;
    struct sockaddr_in addr = {0};
    char *msg = "Hello from server!\n";

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8000);

    //Bind the socket to the address and listen for incoming connections
    bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    listen(sockfd, 1);

    //Accept a connection and send a message
    clientfd = accept(sockfd, NULL, NULL);
    send(clientfd, msg, strlen(msg), 0);

    close(clientfd);
    close(sockfd);
    fclose(file);
    return 0;
}
```

</div>

Now, We can use the `lsof -p <pid>` command (Which literally stands for list open files) to see the program's
file descriptors. Notice how the program has a file descriptor for the opened socket (FD: 4u) and the text file
"output.txt" (FD: 3w) apart from the three standard streams and some other stuff.

```text
COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME
workspace 9710 root  cwd    DIR   0,43      416     39 /workspace/cmake-build-debug
workspace 9710 root  rtd    DIR   0,63     4096 142371 /
workspace 9710 root  txt    REG   0,43    13312    144 /workspace/cmake-build-debug/workspace
workspace 9710 root  mem    REG   0,45             144 /workspace/cmake-build-debug/workspace (path dev=0,43)
workspace 9710 root  mem    REG   0,63  1637400 121195 /usr/lib/aarch64-linux-gnu/libc.so.6
workspace 9710 root  mem    REG   0,63   187776 121177 /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
workspace 9710 root    0u   CHR  136,3      0t0      6 /dev/pts/3
workspace 9710 root    1u   CHR  136,3      0t0      6 /dev/pts/3
workspace 9710 root    2u   CHR  136,4      0t0      7 /dev/pts/4
workspace 9710 root    3w   REG   0,43        0    131 /workspace/cmake-build-debug/output.txt
workspace 9710 root    4u  IPv4 664311      0t0    TCP *:8000 (LISTEN)
```

Since most of the IO on a typical server relies on a socket, The idea that we can treat it as a file is really
powerful, as we will see later. Further, Linux also has a `/proc` virtual filesystem that allows access to a lot of
information about the running processes. For example, we can do `ls /proc/<pid>/fd/` to see the open file descriptors.
`cat /proc/<pid>/status` to get process status (name & current state etc.), `cat /proc/<pid>/environ` for
its environment variables, etc. Heck, the process's entire virtual memory is laid out via `/proc/<pid>/mem`. Likewise,
the `/sys` filesystem is an interface to the kernel

### The Linux process lifecycle and what does blocking actually means:

A typical process lifecycle in linux looks like this:

* A task is started (`TASK_RUNNING`).
* It requests some IO operation.
* Kernel instructs the IO device to perform the operation & suspends the task (`TASK_INTERRUPTIBLE`/
  `TASK_UNINTERRUPTIBLE`).
* Once the operation is done, the device triggers an [interrupt (IRQ)](https://en.wikipedia.org/wiki/Interrupt_request).
* The kernel runs the interrupt's
  corresponding [interrupt's handler (ISR)](https://en.wikipedia.org/wiki/Interrupt_handler), which
  wakes up the task that requested the IO  (`TASK_RUNNING`).
* The task eventually completes execution and enters the zombie state until the parent process reads its exit status
  (`TASK_ZOMBIE`).

See this for a detailed overview of the Linux process
lifecycle: [Linux Process Lifecycle](https://www.baeldung.com/linux/process-states).

**Note:** using the term process because [linux kernel doesn't differentiate between a process and a
thread!](https://litux.nl/mirror/kerneldevelopment/0672327201/ch03lev1sec3.html)

**Note 2:** There are actually multiple ways a device can communicate with the kernel; see: interrupts, polling, DMA,
etc.

To be honest, I don't really understand how interrupts & ISR works, but it's out of scope for this post anyway. Now,
remember the proc filesystem? If we execute the above program and run `cat /proc/<pid>/status`, the third line in the
output will show us the current state of the process. It's `State:  S (sleeping)` because the process is blocked,
waiting for a client connection.

After accepting the connection, it will further get blocked when reading from the socket and writing to it. Effectively
meaning that it can handle only one client at a time. Other connections will be in the queue, and when the queue is
filled up, the rest of the connections will be dropped.

We can think of a few workarounds to this, such as spawning a new thread for each connection, but that will be expensive
when dealing with thousands of connections. Maybe we can use a thread pool, but that will still run
into the same problem when all the threads are blocked on some IO. What if somehow we can bundle these blocking calls
together and be notified when any of them complete? If we can do that, we can use a single thread to handle multiple
connections, triggering IO calls & being notified when they are done later. This is what IO Multiplexing actually does!

### IO Multiplexing: Select, Poll & Epoll

`select`, `poll` & `epoll` are a bunch of sys-calls that allows us to monitor multiple file descriptors at once
to see if IO is possible on any of them. They are all similar in functionality but differ in implementation and
performance. `select` and `poll` are legacy sys-calls that are POSIX & available on all Unix systems. Both of them have
O(N) complexity, i.e. they do a linear scan of all given FDs. While `epoll` is a Linux specific syscall and has O(1)
complexity. Note that there are other sys-calls like `kqueue` (BSD, i.e. macOS) and `IOCP` (Windows) that are similar to
`epoll`.

`epoll` consists of three sys-calls:

1. `epoll_create`: creates an epoll instance and returns a file descriptor for it.
2. `epoll_ctl`: adds, modifies or removes file descriptors from the epoll instance. It also allows us to attach some
   data to the event that's returned later via `epoll_wait`. This is useful for some basic state management.
3. `epoll_wait`: waits for events on the file descriptors in the epoll instance.

I won't be explaining all the parameters of the calls to keep this brief. Also, there are some nuances like
edge triggers & level triggers. But, you can
browse [its linux man pages](https://man7.org/linux/man-pages/man7/epoll.7.html) for more details.

### Building a simple non-blocking echo server

Let's see how we can use these concepts to build a simple non-blocking echo server. Consider the example of a
simple blocking echo server that does the following:

1. Binds & starts listening on port 8080.
2. Waits for a client connection.
3. Reads the client's name.
4. Sleeps for 2 seconds to simulate blocking I/O (like a slow database or network call)
5. Sends back a greeting: "Hello $name"

<div style="max-height: min(75vh, 1000px); overflow: scroll;">

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define PORT 8080
#define NAME_LEN 256
#define SLEEP_DURATION 2

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *) &address, sizeof(address));
    listen(server_fd, 10);

    printf("[Server]: Listening on port %d...\n", PORT);

    while (1) {
        // Accept a new connection
        int client_fd = accept(server_fd, NULL, NULL);
        char buffer[NAME_LEN] = {0};
        read(client_fd, buffer, sizeof(buffer));
        printf("[Server]: Received request: %s\n", buffer);

        //Sleep for 2 seconds to simulate work
        sleep(SLEEP_DURATION);

        // Send a response back to the client & close the connection
        char response[1024];
        snprintf(response, sizeof(response), "Hello %s", buffer);
        write(client_fd, response, strlen(response));
        close(client_fd);
        printf("[Server]: Sent response: %s\n", response);
    }

    return 0;
}
```

</div>

Since this server is blocking, it handles one connection at a time. We can observe this behavior by connecting to it
2-3 times in parallel from different terminals. Run `echo "Name" | nc localhost 8080`, and see the logs.

```
[Server]: Listening on port 8080...
[Server]: Received request: Alice
[Server]: Sent response: Hello Alice
[Server]: Received request: Bob
[Server]: Sent response: Hello Bob
[Server]: Received request: Eve
[Server]: Sent response: Hello Eve
```

As we can see, requests are handled one after another, confirming the server is blocking.

Now let’s see how we can use epoll to make this server non-blocking. To do this, we’ll make a few modifications to the
code above:

1. Create an epoll instance using `epoll_create`.
2. Make all the sockets non-blocking using `fcntl` sys-call & `O_NONBLOCK` flag. So read/write operations return
   immediately if they cannot be completed.
3. Instead of the blocking `sleep` call, use `timerfd` sys-call to wait for 2 seconds, simulating some non-blocking IO.
4. Define an enum event_type: "SERVER_READ" (New client connection), "CLIENT_READ" (Incoming data from client
   connection) and "TIMER_READ" (Completion of our simulated IO).
5. Use the `epoll_ctl` syscall to register interest in read events (`EPOLLIN`) on these sockets and timers. Pass a struct
   called "event_data", which includes the event_type and some additional data, to the syscall for basic bookkeeping.
6. Finally, use `epoll_wait` in an infinite loop to wait for events on the file descriptors and handle them accordingly.


<div style="max-height: min(75vh, 1000px); overflow: scroll;">

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#define PORT        8081
#define MAX_EVENTS  16
#define NAME_LEN    256
#define SLEEP_DURATION 2
#define MAX_QUEUE 10

typedef enum {
    SERVER_READ,
    CLIENT_READ,
    TIMER_READ
} event_type;

typedef struct {
    int client_fd;
    int timer_fd;
    char name[NAME_LEN];
} client_state;

typedef struct {
    event_type type;
    client_state *client;
    int fd;
} event_data;


// Make a file descriptor non-blocking
static void make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Initialize listening socket and add it to epoll
static int setup_server(int epfd) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT)
    };

    bind(sfd, (struct sockaddr *) &addr, sizeof(addr));
    listen(sfd, MAX_QUEUE);
    make_nonblocking(sfd);

    event_data *ev_data = malloc(sizeof(event_data));
    ev_data->type = SERVER_READ;
    ev_data->fd = sfd;

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = ev_data
    };

    epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
    printf("[Server]: listening on port %d\n", PORT);

    return sfd;
}

// Accept a new client and register its socket with epoll
static void handle_new_connection(int epfd, int server_fd) {
    int cfd = accept(server_fd, NULL, NULL);
    make_nonblocking(cfd);

    event_data *ev_data = malloc(sizeof(event_data));
    ev_data->type = CLIENT_READ;
    ev_data->fd = cfd;

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = ev_data
    };
    epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);
}

// Read the client’s name, start a 2s timer, and store state
static void handle_client_read(int epfd, int cfd) {
    //Read, strip newline, and store name in the buffer
    char buf[NAME_LEN] = {0};
    int n = read(cfd, buf, sizeof(buf) - 1);

    if (n <= 0) {
        close(cfd);
        return;
    }
    buf[strcspn(buf, "\r\n")] = 0;

    printf("[Server]: Received request: %s\n", buf);

    //Create a new client state
    client_state *st = calloc(1, sizeof(*st));
    st->client_fd = cfd;
    strncpy(st->name, buf, NAME_LEN - 1);

    //Create a timer for 2 seconds, passing the client state as data in the epoll event
    st->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    struct itimerspec ts = {.it_value.tv_sec = SLEEP_DURATION};
    timerfd_settime(st->timer_fd, 0, &ts, NULL);

    //Wraps the client state in an event_data struct and passes it to epoll
    event_data *ev_data = malloc(sizeof(event_data));
    ev_data->type = TIMER_READ;
    ev_data->client = st;

    struct epoll_event tev = {
        .events = EPOLLIN,
        .data.ptr = ev_data
    };

    epoll_ctl(epfd, EPOLL_CTL_ADD, st->timer_fd, &tev);
}

// On timer expiry, send greeting and clean up
static void handle_timer_event(client_state *st) {
    //Read the timer expiration count
    uint64_t expirations;
    read(st->timer_fd, &expirations, sizeof(expirations));

    char msg[NAME_LEN + 16];
    snprintf(msg, sizeof(msg), "Hello %s\n", st->name);

    //Write to the client socket & close the connection
    write(st->client_fd, msg, strlen(msg));
    printf("[Server]: Sent response: %s\n", msg);

    close(st->client_fd);
    close(st->timer_fd);
}

int main(void) {
    int epfd = epoll_create1(0);
    int server_fd = setup_server(epfd);

    struct epoll_event events[MAX_EVENTS];
    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; ++i) {
            event_data *data = events[i].data.ptr;
            if (!data) continue;

            switch (data->type) {
                case SERVER_READ:
                    handle_new_connection(epfd, data->fd);
                    break;
                case CLIENT_READ:
                    handle_client_read(epfd, data->fd);
                    free(data);
                    break;
                case TIMER_READ:
                    handle_timer_event(data->client);
                    free(data->client);
                    free(data);
                    break;
            }
        }
    }

    return 0;
}
```

</div>

If we run this program and connect to it using `echo "<Name>" | nc localhost 8081` as earlier, we get the following
output:

```text
[Server]: listening on port 8081
[Server]: Received request: Alice
[Server]: Received request: Bob
[Server]: Received request: Eve
[Server]: Sent response: Hello Alice
[Server]: Sent response: Hello Bob
[Server]: Sent response: Hello Eve

```

The logs appear out of order, with all requests being received first before sending any response. Implying that this
single-threaded server can now handle multiple requests concurrently!

This is in-fact a very basic example of an event loop using `epoll`. Despite its simplicity, this pattern is
fundamentally how event loops work in systems like Node.js (using libuv), Redis, and Nginx. The underlying sys-calls are
also how non-blocking IO is implemented in languages like Java (NIO), Python (asyncio) etc.

