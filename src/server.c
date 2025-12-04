/*
 * Copyright 2025 shadowy-pycoder
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <buffer.h>
#include <protocol.h>
#include <server.h>

#define ADDR_SIZE  50
#define MAX_EVENTS 500

atomic_bool shutting_down = false;

typedef const struct sockaddr_in SockAddr;

struct Address {
    int port;
    char addr_str[ADDR_SIZE];
};

struct Socket {
    int fd;
    KevueConnection *c;
};

struct KevueConnection {
    Socket *sock;
    bool closed;
    Address addr;
    Buffer *rbuf;
    Buffer *wbuf;
    uint64_t written;
};

typedef struct EpollServerArgs {
    int *ssock;
    int *esock;
} EpollServerArgs;

static int kevue_setnonblocking(int fd);
static int kevue_epoll_add(int epfd, Socket *sock, uint32_t events);
static int kevue_epoll_del(int epfd, Socket *sock);
static void *kevue_handle_server_epoll(void *args);
static int kevue_create_server_sock(char *host, int port);
static bool kevue_connection_new(KevueConnection *c, int sock, SockAddr addr);
static void kevue_connection_destroy(KevueConnection *c);
static bool kevue_setup_connection(int epfd, int sock, SockAddr addr);
static void kevue_dispatch_client_events(Socket *sock, uint32_t events, bool closing);
static bool kevue_handle_read(KevueConnection *c);
static bool kevue_handle_write(KevueConnection *c);
static void kevue_connection_cleanup(int epfd, Socket *sock, struct epoll_event *events, int idx, int nready);
static void kevue_singal_handler(int sig);

int kevue_setnonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void *kevue_handle_server_epoll(void *args)
{
    pid_t tid = gettid();
    struct epoll_event *events = malloc(sizeof(struct epoll_event) * MAX_EVENTS);
    if (events == NULL)
        exit(EXIT_FAILURE);

    EpollServerArgs *esargs = (EpollServerArgs *)args;
    int server_sock = *esargs->ssock;
    int esock = *esargs->esock;
    free(esargs);
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        printf("ERROR: [%d] Creating epoll file descriptor failed %s\n", tid, strerror(errno));
        free(events);
        exit(EXIT_FAILURE);
    }

    KevueConnection *sc = (KevueConnection *)malloc(sizeof(KevueConnection));
    if (sc == NULL)
        exit(EXIT_FAILURE);
    sc->sock = (Socket *)malloc(sizeof(Socket));
    sc->sock->fd = server_sock;
    sc->sock->c = sc;
    if (kevue_epoll_add(epfd, sc->sock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding server socket to epoll failed: %s\n", tid, strerror(errno));
        close(server_sock);
        free(events);
        free(sc->sock);
        free(sc);
        exit(EXIT_FAILURE);
    }
    KevueConnection *ec = (KevueConnection *)malloc(sizeof(KevueConnection));
    if (ec == NULL)
        exit(EXIT_FAILURE);
    ec->sock = (Socket *)malloc(sizeof(Socket));
    ec->sock->fd = esock;
    ec->sock->c = ec;
    if (kevue_epoll_add(epfd, ec->sock, EPOLLIN | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding event socket to epoll failed: %s\n", tid, strerror(errno));
        free(events);
        free(ec->sock);
        free(ec);
        exit(EXIT_FAILURE);
    }
    int nready;
    bool closing = false;
    while (true) {
        nready = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TIMEOUT);
        if (nready < 0) {
            printf("ERROR: [%d] Waiting for epoll failed: %s\n", tid, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (closing && nready == 0)
            break;
        for (int i = 0; i < nready; i++) {
            if (events[i].events == 0)
                continue;
            Socket *sock = (Socket *)events[i].data.ptr;
            if (sock->fd == server_sock && !closing) {
                if (!(events[i].events & EPOLLIN)) {
                    printf("INFO: [%d] Server is not ready to accept connections %d\n", tid, events[i].events);
                    continue;
                }
                while (true) {
                    struct sockaddr_in client_addr = { 0 };
                    client_addr.sin_family = AF_INET;
                    socklen_t addr_len = sizeof(client_addr);
                    int client_sock = accept(sock->fd, (struct sockaddr *)&client_addr, &addr_len);
                    if (client_sock < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        printf("ERROR: [%d] Accept connection failed: %s\n", tid, strerror(errno));
                        break;
                    }
                    if (!kevue_setup_connection(epfd, client_sock, client_addr)) {
                        break;
                    }
                }
            } else if (sock->fd == esock) {
                closing = true;
                if (kevue_epoll_del(epfd, sc->sock) < 0) {
                    printf("ERROR: [%d] Removing server socket from epoll failed: %s\n", tid, strerror(errno));
                }
                if (kevue_epoll_del(epfd, ec->sock) < 0) {
                    printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
                }
                close(server_sock);
                free(sc->sock);
                free(sc);
                free(ec->sock);
                free(ec);
            } else {
                kevue_dispatch_client_events(sock, events[i].events, closing);
                kevue_connection_cleanup(epfd, sock, events, i, nready);
            }
        }
    }
#ifdef DEBUG
    printf("DEBUG: [%d] server closed\n", tid);
#endif
    free(events);
    pthread_exit(NULL);
    return NULL;
}

bool kevue_setup_connection(int epfd, int sock, SockAddr addr)
{
    pid_t tid = gettid();
    if (kevue_setnonblocking(sock) < 0) {
        printf("ERROR: [%d] Set nonblockong failed: %s\n", tid, strerror(errno));
        close(sock);
        return false;
    }
    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: [%d] Setting SOL_SOCKET option for client failed: %s\n", tid, strerror(errno));
        close(sock);
        return false;
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: [%d] Setting TCP_NODELAY option for client failed: %s\n", tid, strerror(errno));
        close(sock);
        return false;
    }
    KevueConnection *c = (KevueConnection *)malloc(sizeof(KevueConnection));
    if (c == NULL) {
        printf("ERROR: [%d] Allocating memory for client failed: %s\n", tid, strerror(errno));
        close(sock);
        return false;
    }
    if (!kevue_connection_new(c, sock, addr)) {
        printf("ERROR: [%d] Client creation failed: %s\n", tid, strerror(errno));
        close(sock);
        return false;
    }
    if (kevue_epoll_add(epfd, c->sock, EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET) < 0) {
        printf("ERROR: [%d] Adding client socket to epoll failed: %s\n", tid, strerror(errno));
        close(sock);
        kevue_connection_destroy(c);
        free(c);
        return false;
    }
    printf("INFO: [%d] New connection %s:%d\n", tid, c->addr.addr_str, c->addr.port);
    return true;
}

void kevue_dispatch_client_events(Socket *sock, uint32_t events, bool closing)
{
    pid_t tid = gettid();
    KevueConnection *c = sock->c;
    if ((events & EPOLLHUP) || (events & EPOLLERR)) {
        c->closed = true;
    } else if (closing || (events & EPOLLRDHUP)) {
        if (shutdown(c->sock->fd, SHUT_WR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
        }
        kevue_handle_read(c);
        c->closed = true;
    } else if (events & EPOLLIN) {
        if (c->closed || !kevue_handle_read(c)) {
            if (shutdown(c->sock->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
            }
            c->closed = true;
        } else {
            static KevueRequest req = { 0 };
            ParseErr err = kevue_deserialize_request(&req, c->rbuf);
            if (err == ERR_OK) {
                kevue_print_request(&req);
            } else {
                printf("%s\n", kevue_error_to_string(err));
            }
            char *message = "Hello world\r\n";
            memcpy(c->wbuf->ptr, message, strlen(message));
            c->wbuf->size = strlen(message);
            if (!kevue_handle_write(c)) {
                if (shutdown(c->sock->fd, SHUT_WR) < 0) {
                    if (errno != ENOTCONN)
                        printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
                }
                c->closed = true;
            } else {
                buffer_reset(c->rbuf);
            }
        }
    } else if (events & EPOLLOUT) {
        char *message = "Hello world\r\n";
        memcpy(c->wbuf->ptr, message, strlen(message));
        c->wbuf->size = strlen(message);
        if (!kevue_handle_write(c)) {
            if (shutdown(c->sock->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    printf("ERROR: [%d] Shutting down failed: %s\n", tid, strerror(errno));
            }
            c->closed = true;
        } else {
            // buffer_reset(c->rbuf);
        }
    }
    return;
}

bool kevue_handle_read(KevueConnection *c)
{
    pid_t tid = gettid();
    while (true) {
        int nr = read(c->sock->fd, c->rbuf->ptr + c->rbuf->size, c->rbuf->capacity - c->rbuf->size);
        if (nr < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break;
            if (errno == EINTR)
                continue;
            printf("ERROR: [%d] Reading message from %s:%d failed: %s\n", tid, c->addr.addr_str, c->addr.port, strerror(errno));
            return false;
        } else if (nr == 0) {
#ifdef DEBUG
            printf("DEBUG: [%d] %s:%d:EOF\n", tid, c->addr.addr_str, c->addr.port);
#endif
            return false;
        } else {
            c->rbuf->size += nr;
#ifdef DEBUG
            printf("DEBUG: [%d] Read %d bytes from client %s:%d\n", tid, nr, c->addr.addr_str, c->addr.port);
#endif
            if (c->rbuf->size >= c->rbuf->capacity) {
                break;
            }
        }
    }
    return true;
}

bool kevue_handle_write(KevueConnection *c)
{
    pid_t tid = gettid();
    while (true) {
        int nw = write(c->sock->fd, c->wbuf->ptr + c->wbuf->offset, c->wbuf->size - c->wbuf->offset);
        if (nw < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break;
            if (errno == EINTR)
                continue;
            printf("ERROR: [%d] Writing message -> %s:%d failed: %s\n", tid, c->addr.addr_str, c->addr.port, strerror(errno));
            return false;
        } else if (nw == 0) {
            break;
        } else {
            c->written += nw;
            c->wbuf->offset += nw;
#ifdef DEBUG
            printf("DEBUG: [%d] Written %d bytes -> %s:%d\n", tid, nw, c->addr.addr_str, c->addr.port);
#endif
            if (c->wbuf->offset >= c->wbuf->size) {
                buffer_reset(c->wbuf);
                break;
            }
        }
    }
    return true;
}

void kevue_connection_cleanup(int epfd, Socket *sock, struct epoll_event *events, int idx, int nready)
{
    KevueConnection *c = sock->c;
    if (c->closed) {
        for (int i = idx + 1; i < nready; i++) {
            Socket *nsock = (Socket *)events[i].data.ptr;
            if (nsock->fd == c->sock->fd)
                return;
        }
        pid_t tid = gettid();
        if (kevue_epoll_del(epfd, c->sock) < 0) {
            printf("ERROR: [%d] Removing client socket from epoll failed: %s\n", tid, strerror(errno));
        }
        if (shutdown(c->sock->fd, SHUT_RDWR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: [%d] Shutting down failed for %s:%d: %s\n", tid, c->addr.addr_str, c->addr.port, strerror(errno));
        }
        kevue_connection_destroy(c);
    }
}

int kevue_epoll_add(int epfd, Socket *sock, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = sock;
    ev.events = events;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, sock->fd, &ev);
}

int kevue_epoll_del(int epfd, Socket *sock)
{
    return epoll_ctl(epfd, EPOLL_CTL_DEL, sock->fd, NULL);
}

bool kevue_connection_new(KevueConnection *c, int sock, SockAddr addr)
{
    pid_t tid = gettid();
    memset(c, 0, sizeof(*c));
    c->sock = (Socket *)malloc(sizeof(Socket));
    if (c->sock == NULL) {
        printf("ERROR: [%d] Allocating memory for socket failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->sock->c = c;
    c->sock->fd = sock;
    if (c->sock->fd < 0) {
        printf("ERROR: [%d] Creating socket failed: %s\n", tid, strerror(errno));
        return false;
    }
    c->closed = false;
    char *temp_ip = inet_ntoa(addr.sin_addr);
    memset(c->addr.addr_str, 0, ADDR_SIZE);
    memcpy(c->addr.addr_str, temp_ip, strlen(temp_ip));
    c->addr.port = ntohs(addr.sin_port);
    c->rbuf = buffer_create(BUF_SIZE);
    c->wbuf = buffer_create(BUF_SIZE);
    return true;
}

void kevue_connection_destroy(KevueConnection *c)
{
    pid_t tid = gettid();
    printf("INFO: [%d] Closing connection %s:%d\n", tid, c->addr.addr_str, c->addr.port);
    if (close(c->sock->fd) < 0) {
        printf("ERROR: [%d] Closing socket failed for %s:%d: %s\n", tid, c->addr.addr_str, c->addr.port, strerror(errno));
    } else {
        printf("INFO: [%d] Connection to %s:%d closed\n", tid, c->addr.addr_str, c->addr.port);
    }
    free(c->sock);
    buffer_destroy(c->rbuf);
    buffer_destroy(c->wbuf);
}

void kevue_singal_handler(int sig)
{
    if (!shutting_down) {
        shutting_down = true;
        signal(sig, SIG_DFL);
    } else {
        exit(1);
    }
}

KevueServer *kevue_server_create(char *host, uint16_t port)
{
    KevueServer *ks = (KevueServer *)malloc(sizeof(KevueServer));
    memset(ks, 0, sizeof(KevueServer));
    ks->host = host;
    ks->port = port;
    ks->efd = eventfd(0, EFD_NONBLOCK);
    for (int i = 0; i < SERVER_WORKERS; i++) {
        ks->fds[i] = kevue_create_server_sock(host, port);
        pthread_t thread = { 0 };
        ks->threads[i] = thread;
    }
    struct sigaction new_action;
    new_action.sa_handler = kevue_singal_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;
    sigaction(SIGINT, &new_action, NULL);
    sigaction(SIGTERM, &new_action, NULL);
    sigaction(SIGHUP, &new_action, NULL);
    return ks;
}

void kevue_server_start(KevueServer *ks)
{
    for (int i = 0; i < SERVER_WORKERS; i++) {
        EpollServerArgs *esargs = (EpollServerArgs *)malloc(sizeof(EpollServerArgs));
        esargs->ssock = &ks->fds[i];
        esargs->esock = &ks->efd;
        pthread_create(&ks->threads[i], NULL, kevue_handle_server_epoll, esargs);
    }
    while (!shutting_down)
        pause();
    printf("INFO: Shutting down %d servers on %s:%d... Please wait\n", SERVER_WORKERS, ks->host, ks->port);
    uint64_t one = 1;
    if (write(ks->efd, &one, sizeof(one)) < 0) {
        printf("ERROR: writing to eventfd failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < SERVER_WORKERS; i++) {
        pthread_join(ks->threads[i], NULL);
    }
}
void kevue_server_destroy(KevueServer *ks)
{
    printf("INFO: %d servers on %s:%d gracefully shut down\n", SERVER_WORKERS, ks->host, ks->port);
    close(ks->efd);
    free(ks);
}

int kevue_create_server_sock(char *host, int port)
{
    int server_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server_sock < 0) {
        printf("ERROR: Creating socket failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int enable = 1;
    if (setsockopt(server_sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting TCP_DEFER_ACCEPT option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting SO_REUSEADDR option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting SO_REUSEPORT option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int send_buffer_size = SND_BUF_SIZE;
    int recv_buffer_size = RECV_BUF_SIZE;
    if (setsockopt(server_sock, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) < 0) {
        printf("ERROR: Setting SO_SNDBUF option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVBUF, &recv_buffer_size, sizeof(recv_buffer_size)) < 0) {
        printf("ERROR: Setting SO_RCVBUF option failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr = { 0 };
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) < 0) {
        printf("ERROR: %s is not valid IP address\n", host);
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("ERROR: Binding to address failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (listen(server_sock, MAX_CONNECTIONS) < 0) {
        printf("ERROR: Listening on address failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("INFO: kevue listening on %s:%d\n", host, port);
    return server_sock;
}
