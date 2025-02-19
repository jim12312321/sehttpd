#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "http.h"
#include "logger.h"
#include "timer.h"

/* the length of the struct epoll_events array pointed to by *events */
#define MAXEVENTS 1024

#define LISTENQ 1024

static int open_listenfd(int port)
{
    int listenfd, optval = 1;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminate "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval,
                   sizeof(int)) < 0)
        return -1;

    /* Listenfd will be an endpoint for all requests to given port. */
    struct sockaddr_in serveraddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((unsigned short) port),
        .sin_zero = {0},
    };
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;

    return listenfd;
}

/* set a socket non-blocking. If a listen socket is a blocking socket, after
 * it comes out from epoll and accepts the last connection, the next accpet
 * will block unexpectedly.
 */
static int sock_set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_err("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    int s = fcntl(fd, F_SETFL, flags);
    if (s == -1) {
        log_err("fcntl");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    /* when a fd is closed by remote, writing to this fd will cause system
     * send SIGPIPE to this process, which exit the program
     */
    if (sigaction(SIGPIPE,
                  &(struct sigaction){.sa_handler = SIG_IGN, .sa_flags = 0},
                  NULL)) {
        log_err("Failed to install sigal handler for SIGPIPE");
        return 0;
    }
    /* handling the params
     * -t: select level trigger or edge trigger.
     *     If level trigger type l for level trigger otherwise type e for edge
     * trigger. default edge trigger -p: enter PORT,default 8081 -w: enter
     * webroot,default ./www
     */
    int port = 8081;
    int trigger = EPOLLET;
    char *webroot = "./www";
    if (!(argc & 1)) { /* if argc is even,user must forget enter some params */
        log_err("Failed due to missing params");
        return 0;
    }
    for (int idx = 1; idx < argc; idx += 2) {
        if (strcmp(argv[idx], "-t") == 0) {        /* trigger mode */
            if (strcmp(argv[idx + 1], "l") == 0) { /* level trigger */
                trigger = 0;
            } else if (strcmp(argv[idx + 1], "e") == 0) { /* edge trigger */
                trigger = EPOLLET;
            } else { /* error */
                log_err("Failed due to incorrect param \"-t\"");
                return 0;
            }
        } else if (strcmp(argv[idx], "-p") == 0) { /* port */
            port = atoi(argv[idx + 1]);
            if (port == 0) {
                log_err("Failed due to incorrect param \"-p\"");
                return 0;
            }
        } else if (strcmp(argv[idx], "-w") == 0) { /* webroot */
            if (strcmp(argv[idx + 1], "-t") == 0 ||
                strcmp(argv[idx + 1], "-p") == 0) {
                log_err("Failed due to incorrect param \"-w\"");
                return 0;
            }
            /* TODO: figure out what is webroot for and set exception handling
             * correctly */
            webroot = argv[idx + 1];
        } else {
            log_err("Failed due to undefined param \"%s\"", argv[idx]);
            return 0;
        }
    }

    int listenfd = open_listenfd(port);
    int rc UNUSED = sock_set_non_blocking(listenfd);
    assert(rc == 0 && "sock_set_non_blocking");

    /* create epoll and add listenfd */
    int epfd = epoll_create1(0 /* flags */);
    assert(epfd > 0 && "epoll_create1");

    struct epoll_event *events = malloc(sizeof(struct epoll_event) * MAXEVENTS);
    assert(events && "epoll_event: malloc");

    http_request_t *request = malloc(sizeof(http_request_t));
    init_http_request(request, listenfd, epfd, webroot);

    struct epoll_event event = {
        .data.ptr = request,
        .events = EPOLLIN | trigger,
    };
    epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &event);

    timer_init();

    printf("Web server started.\n");

    /* epoll_wait loop */
    while (1) {
        int time = find_timer();
        debug("wait time = %d", time);
        int n = epoll_wait(epfd, events, MAXEVENTS, time);
        handle_expired_timers();

        for (int i = 0; i < n; i++) {
            http_request_t *r = events[i].data.ptr;
            int fd = r->fd;
            if (listenfd == fd) {
                /* we have one or more incoming connections */
                while (1) {
                    socklen_t inlen = 1;
                    struct sockaddr_in clientaddr;
                    int infd = accept(listenfd, (struct sockaddr *) &clientaddr,
                                      &inlen);
                    if (infd < 0) {
                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                            /* we have processed all incoming connections */
                            break;
                        }
                        log_err("accept");
                        break;
                    }

                    rc = sock_set_non_blocking(infd);
                    assert(rc == 0 && "sock_set_non_blocking");

                    request = malloc(sizeof(http_request_t));
                    if (!request) {
                        log_err("malloc");
                        break;
                    }

                    init_http_request(request, infd, epfd, webroot);
                    event.data.ptr = request;
                    event.events = EPOLLIN | trigger | EPOLLONESHOT;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &event);

                    add_timer(request, TIMEOUT_DEFAULT, http_close_conn);
                }
            } else {
                if ((events[i].events & EPOLLERR) ||
                    (events[i].events & EPOLLHUP) ||
                    (!(events[i].events & EPOLLIN))) {
                    log_err("epoll error fd: %d", r->fd);
                    close(fd);
                    continue;
                }

                do_request(events[i].data.ptr);
            }
        }
    }

    return 0;
}
