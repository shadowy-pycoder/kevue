/*
 * Copyright 2025-2026 shadowy-pycoder
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
/**
 * @file server.c
 * @brief kevue server implementation.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <allocator.h>
#include <buffer.h>
#include <common.h>
#include <protocol.h>
#include <server.h>
#include <threaded_hashmap.h> // TODO: guard by macro

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#ifdef USE_TCMALLOC
#include <tcmalloc_allocator.h>
#endif
#ifdef USE_JEMALLOC
#include <jemalloc_allocator.h>
#endif

#define MAX_EVENTS    500
#define EPOLL_TIMEOUT (30 * 1000)

bool shutting_down = false;

typedef struct sockaddr_storage SockAddr;
typedef struct Address Address;
typedef struct Socket Socket;
typedef struct KevueConnection KevueConnection;

struct Address {
    int port;
    char addr_str[INET6_ADDRSTRLEN];
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
    KevueAllocator *ma;
    HashMap *hm;
    Buffer *hmbuf;
};

typedef struct EpollServerArgs {
    int *ssock;
    int *esock;
    KevueAllocator *ma;
    HashMap *hm;
} EpollServerArgs;

static int kevue__setnonblocking(int fd);
static int kevue__epoll_add(int epfd, Socket *sock, uint32_t events);
static int kevue__epoll_del(int epfd, Socket *sock);
static void *kevue__handle_server_epoll(void *args);
static int kevue__create_server_sock(char *host, char *port, bool check);
static bool kevue__connection_new(KevueConnection *c, int sock, SockAddr addr, KevueAllocator *ma, HashMap *hm);
static void kevue__connection_destroy(KevueConnection *c);
static bool kevue__setup_connection(int epfd, int sock, SockAddr addr, KevueAllocator *ma, HashMap *hm);
static void kevue__response_populate_from_hashmap(KevueRequest *req, KevueResponse *resp, HashMap *hm, Buffer *hmbuf);
static void kevue__dispatch_client_events(Socket *sock, uint32_t events, bool closing);
static bool kevue__handle_read(KevueConnection *c);
static bool kevue__handle_read_exactly(KevueConnection *c, size_t n);
static bool kevue__handle_write(KevueConnection *c);
static void kevue__connection_cleanup(int epfd, Socket *sock, struct epoll_event *events, int idx, int nready);
static void kevue__signal_handler(int sig);
static void kevue__usage(void);

static int kevue__setnonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void *kevue__handle_server_epoll(void *args)
{
    pid_t tid = gettid();

    EpollServerArgs *esargs = (EpollServerArgs *)args;
    int server_sock = *esargs->ssock;
    int esock = *esargs->esock;
    KevueAllocator *ma = esargs->ma;
    HashMap *hm = esargs->hm;
    ma->free(esargs, ma->ctx);
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        print_err("[%d] Creating epoll file descriptor failed %s", tid, strerror(errno));
        close(server_sock);
        goto server_close;
    }
    struct epoll_event *events = (struct epoll_event *)ma->malloc(sizeof(struct epoll_event) * MAX_EVENTS, ma->ctx);
    if (events == NULL) {
        close(epfd);
        close(server_sock);
        goto server_close;
    }
    KevueConnection *sc = (KevueConnection *)ma->malloc(sizeof(KevueConnection), ma->ctx);
    if (sc == NULL) {
        close(epfd);
        close(server_sock);
        ma->free(events, ma->ctx);
        goto server_close;
    }
    sc->ma = ma;
    sc->sock = (Socket *)ma->malloc(sizeof(Socket), ma->ctx);
    sc->sock->fd = server_sock;
    sc->sock->c = sc;
    sc->hm = hm;
    if (kevue__epoll_add(epfd, sc->sock, EPOLLIN | EPOLLET) < 0) {
        print_err("[%d] Adding server socket to epoll failed: %s", tid, strerror(errno));
        close(epfd);
        close(server_sock);
        ma->free(events, ma->ctx);
        ma->free(sc->sock, ma->ctx);
        ma->free(sc, ma->ctx);
        goto server_close;
    }
    KevueConnection *ec = (KevueConnection *)ma->malloc(sizeof(KevueConnection), ma->ctx);
    if (ec == NULL) {
        close(epfd);
        close(server_sock);
        ma->free(events, ma->ctx);
        ma->free(sc->sock, ma->ctx);
        ma->free(sc, ma->ctx);
        goto server_close;
    }
    ec->sock = (Socket *)ma->malloc(sizeof(Socket), ma->ctx);
    if (ec->sock == NULL) {
        close(epfd);
        close(server_sock);
        ma->free(events, ma->ctx);
        ma->free(sc->sock, ma->ctx);
        ma->free(sc, ma->ctx);
        goto server_close;
    }
    ec->sock->fd = esock;
    ec->sock->c = ec;
    ec->hm = hm;
    if (kevue__epoll_add(epfd, ec->sock, EPOLLIN | EPOLLET) < 0) {
        print_err("[%d] Adding event socket to epoll failed: %s", tid, strerror(errno));
        close(epfd);
        close(server_sock);
        ma->free(events, ma->ctx);
        ma->free(sc->sock, ma->ctx);
        ma->free(sc, ma->ctx);
        ma->free(ec->sock, ma->ctx);
        ma->free(ec, ma->ctx);
        goto server_close;
    }
    int nready;
    bool closing = false;
    while (true) {
        // NOTE: memory leak when EPOLL_TIMEOUT occurs with pending connections
        nready = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TIMEOUT);
        if (nready < 0) {
            if (errno == EINTR) continue;
            print_err("[%d] Waiting for epoll failed: %s", tid, strerror(errno));
            close(epfd);
            close(server_sock);
            ma->free(events, ma->ctx);
            ma->free(sc->sock, ma->ctx);
            ma->free(sc, ma->ctx);
            ma->free(ec->sock, ma->ctx);
            ma->free(ec, ma->ctx);
            goto server_close;
        }
        if (closing && nready == 0) {
            close(epfd);
            ma->free(events, ma->ctx);
            goto server_close;
        }
        for (int i = 0; i < nready; i++) {
            if (events[i].events == 0)
                continue;
            Socket *sock = (Socket *)events[i].data.ptr;
            if (sock->fd == server_sock && !closing) {
                if (!(events[i].events & EPOLLIN)) {
                    print_info("[%d] Server is not ready to accept connections %d", tid, events[i].events);
                    continue;
                }
                while (true) {
                    struct sockaddr_storage client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    int client_sock = accept(sock->fd, (struct sockaddr *)&client_addr, &addr_len);
                    if (client_sock < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        print_err("[%d] Accept connection failed: %s", tid, strerror(errno));
                        break;
                    }
                    if (!kevue__setup_connection(epfd, client_sock, client_addr, ma, hm)) {
                        break;
                    }
                }
            } else if (sock->fd == esock) {
                closing = true;
                if (kevue__epoll_del(epfd, sc->sock) < 0) {
                    print_err("[%d] Removing server socket from epoll failed: %s", tid, strerror(errno));
                }
                if (kevue__epoll_del(epfd, ec->sock) < 0) {
                    print_err("[%d] Removing client socket from epoll failed: %s", tid, strerror(errno));
                }
                close(server_sock);
                ma->free(sc->sock, ma->ctx);
                ma->free(sc, ma->ctx);
                ma->free(ec->sock, ma->ctx);
                ma->free(ec, ma->ctx);
            } else {
                kevue__dispatch_client_events(sock, events[i].events, closing);
                kevue__connection_cleanup(epfd, sock, events, i, nready);
            }
        }
    }
server_close:
    print_debug("[%d] server closed", tid);
    pthread_exit(NULL);
    return NULL;
}

static bool kevue__setup_connection(int epfd, int sock, SockAddr addr, KevueAllocator *ma, HashMap *hm)
{
    pid_t tid = gettid();
    if (kevue__setnonblocking(sock) < 0) {
        print_err("[%d] Set nonblockong failed: %s", tid, strerror(errno));
        close(sock);
        return false;
    }
    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char *)&enable, sizeof(enable)) < 0) {
        print_err("[%d] Setting SOL_SOCKET option for client failed: %s", tid, strerror(errno));
        close(sock);
        return false;
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
        print_err("[%d] Setting TCP_NODELAY option for client failed: %s", tid, strerror(errno));
        close(sock);
        return false;
    }
    KevueConnection *c = (KevueConnection *)ma->malloc(sizeof(KevueConnection), ma->ctx);
    if (c == NULL) {
        print_err("[%d] Allocating memory for client failed", tid);
        close(sock);
        return false;
    }
    if (!kevue__connection_new(c, sock, addr, ma, hm)) {
        print_err("[%d] Client creation failed", tid);
        close(sock);
        ma->free(c, ma->ctx);
        return false;
    }
    if (kevue__epoll_add(epfd, c->sock, EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET) < 0) {
        print_err("[%d] Adding client socket to epoll failed: %s", tid, strerror(errno));
        close(sock);
        kevue__connection_destroy(c);
        return false;
    }
    print_info("[%d] New connection %s:%d", tid, c->addr.addr_str, c->addr.port);
    return true;
}

// TODO: split this mess into several functions
static void kevue__response_populate_from_hashmap(KevueRequest *req, KevueResponse *resp, HashMap *hm, Buffer *hmbuf)
{
    resp->err_code = KEVUE_ERR_OK;
    switch (req->cmd) {
    case HELLO:
        resp->val_len = (uint16_t)strlen(kevue_command_to_string(HELLO));
        kevue_buffer_write(hmbuf, kevue_command_to_string(HELLO), resp->val_len);
        resp->val = hmbuf;
        break;
    case GET:
        if (!hm->ops->kevue_hm_get(hm, req->key, req->key_len, hmbuf)) {
            resp->err_code = KEVUE_ERR_NOT_FOUND;
        } else {
            resp->val_len = (uint16_t)hmbuf->size;
            resp->val = hmbuf;
        }
        break;
    case SET:
        if (!hm->ops->kevue_hm_put(hm, req->key, req->key_len, req->val, req->val_len)) {
            resp->err_code = KEVUE_ERR_OPERATION;
        }
        break;
    case DEL:
        if (!hm->ops->kevue_hm_del(hm, req->key, req->key_len)) {
            resp->err_code = KEVUE_ERR_NOT_FOUND;
        }
        break;
    case PING:
        if (req->key_len > 0) {
            resp->val_len = req->key_len;
            kevue_buffer_write(hmbuf, req->key, req->key_len);
        } else {
            resp->val_len = 4;
            kevue_buffer_write(hmbuf, "PONG", resp->val_len);
        }
        resp->val = hmbuf;
        break;
    case KEVUE_CMD_MAX:
        UNREACHABLE("Possibly a bug in request serialization");
    default:
        UNREACHABLE("Possibly forgot to add new command to switch case");
    }
    kevue_response_print(resp);
}

static void kevue__dispatch_client_events(Socket *sock, uint32_t events, bool closing)
{
    pid_t tid = gettid();
    KevueConnection *c = sock->c;
    if ((events & EPOLLHUP) || (events & EPOLLERR)) {
        c->closed = true;
    } else if (closing || (events & EPOLLRDHUP)) {
        if (shutdown(c->sock->fd, SHUT_WR) < 0) {
            if (errno != ENOTCONN)
                print_err("[%d] Shutting down failed: %s", tid, strerror(errno));
        }
        kevue__handle_read(c);
        c->closed = true;
    } else if (events & EPOLLIN) {
        if (!kevue__handle_read(c)) {
            if (shutdown(c->sock->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    print_err("[%d] Shutting down failed: %s", tid, strerror(errno));
            }
            c->closed = true;
        }
        KevueRequest req = { 0 };
        KevueResponse resp = { 0 };
        KevueErr err = kevue_request_deserialize(&req, c->rbuf);
        if (err == KEVUE_ERR_INCOMPLETE_READ) return;
        if (err == KEVUE_ERR_OK) {
            kevue_request_print(&req);
            kevue__response_populate_from_hashmap(&req, &resp, c->hm, c->hmbuf);
            kevue_response_serialize(&resp, c->wbuf);
            kevue_buffer_move_unread_bytes(c->rbuf);
            kevue_buffer_reset(c->hmbuf);
        } else {
            print_err("[%d] %s", tid, kevue_error_code_to_string(err));
            resp.err_code = err;
            kevue_response_serialize(&resp, c->wbuf);
            c->closed = true;
        }
        if ((c->wbuf->size > 0 && !kevue__handle_write(c)) || c->closed) {
            if (shutdown(c->sock->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    print_err("[%d] Shutting down failed: %s", tid, strerror(errno));
            }
            c->closed = true;
        }
    } else if (events & EPOLLOUT) {
        // TODO: handle EPOLLOUT
        if (!kevue__handle_write(c)) {
            if (shutdown(c->sock->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    print_err("[%d] Shutting down failed: %s", tid, strerror(errno));
            }
            c->closed = true;
        }
    }
    return;
}

static bool kevue__handle_read_exactly(KevueConnection *c, size_t n)
{
    kevue_buffer_grow(c->rbuf, n);
    pid_t tid = gettid();
    while (c->rbuf->size < n) {
        ssize_t nr = read(c->sock->fd, c->rbuf->ptr + c->rbuf->size, n - c->rbuf->size);
        if (nr < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) break;
            if (errno == EINTR) continue;
            print_err("[%d] Reading message from %s:%d failed: %s", tid, c->addr.addr_str, c->addr.port, strerror(errno));
            return false;
        } else if (nr == 0) {
            print_debug("[%d] %s:%d:EOF", tid, c->addr.addr_str, c->addr.port);
            return false;
        } else {
            c->rbuf->size += (size_t)nr;
            print_debug("[%d] Read %ld bytes from client %s:%d", tid, nr, c->addr.addr_str, c->addr.port);
        }
    }
    return true;
}

static bool kevue__handle_read(KevueConnection *c)
{
    pid_t tid = gettid();
    while (true) {
        ssize_t nr = read(c->sock->fd, c->rbuf->ptr + c->rbuf->size, c->rbuf->capacity - c->rbuf->size);
        if (nr < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break;
            if (errno == EINTR)
                continue;
            print_err("[%d] Reading message from %s:%d failed: %s", tid, c->addr.addr_str, c->addr.port, strerror(errno));
            return false;
        } else if (nr == 0) {
            print_debug("[%d] %s:%d:EOF", tid, c->addr.addr_str, c->addr.port);
            return false;
        } else {
            c->rbuf->size += (size_t)nr;
            print_debug("[%d] Read %zu bytes from client %s:%d", tid, nr, c->addr.addr_str, c->addr.port);
        }
    }
    return true;
}

static bool kevue__handle_write(KevueConnection *c)
{
    pid_t tid = gettid();
    while (true) {
        ssize_t nw = write(c->sock->fd, c->wbuf->ptr + c->wbuf->offset, c->wbuf->size - c->wbuf->offset);
        if (nw < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) break;
            if (errno == EINTR) continue;
            print_err("[%d] Writing message -> %s:%d failed: %s", tid, c->addr.addr_str, c->addr.port, strerror(errno));
            return false;
        } else if (nw == 0) {
            break;
        } else {
            c->wbuf->offset += (size_t)nw;
            print_debug("[%d] Written %ld bytes -> %s:%d", tid, nw, c->addr.addr_str, c->addr.port);
            if (c->wbuf->offset >= c->wbuf->size) {
                kevue_buffer_reset(c->wbuf);
                break;
            }
        }
    }
    return true;
}

static void kevue__connection_cleanup(int epfd, Socket *sock, struct epoll_event *events, int idx, int nready)
{
    KevueConnection *c = sock->c;
    if (c->closed) {
        for (int i = idx + 1; i < nready; i++) {
            Socket *nsock = (Socket *)events[i].data.ptr;
            if (nsock->fd == c->sock->fd)
                return;
        }
        pid_t tid = gettid();
        if (kevue__epoll_del(epfd, c->sock) < 0) {
            print_err("[%d] Removing client socket from epoll failed: %s", tid, strerror(errno));
        }
        if (shutdown(c->sock->fd, SHUT_RDWR) < 0) {
            if (errno != ENOTCONN)
                print_err("[%d] Shutting down failed for %s:%d: %s", tid, c->addr.addr_str, c->addr.port, strerror(errno));
        }
        kevue__connection_destroy(c);
    }
}

static int kevue__epoll_add(int epfd, Socket *sock, uint32_t events)
{
    struct epoll_event ev;
    ev.data.ptr = sock;
    ev.events = events;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, sock->fd, &ev);
}

static int kevue__epoll_del(int epfd, Socket *sock)
{
    return epoll_ctl(epfd, EPOLL_CTL_DEL, sock->fd, NULL);
}

static bool kevue__connection_new(KevueConnection *c, int sock, SockAddr addr, KevueAllocator *ma, HashMap *hm)
{
    pid_t tid = gettid();
    memset(c, 0, sizeof(*c));
    c->ma = ma;
    c->sock = (Socket *)c->ma->malloc(sizeof(Socket), c->ma->ctx);
    if (c->sock == NULL) {
        print_err("[%d] Allocating memory for socket failed", tid);
        return false;
    }
    c->sock->c = c;
    c->sock->fd = sock;
    if (c->sock->fd < 0) {
        print_err("[%d] Creating socket failed", tid);
        c->ma->free(c->sock, c->ma->ctx);
        return false;
    }
    c->closed = false;
    inet_ntop2(&addr, c->addr.addr_str, (socklen_t)sizeof(c->addr.addr_str));
    c->addr.port = ntohs2(&addr);
    if (c->addr.port == 0) {
        print_err("[%d] Extracting port failed", tid);
        c->ma->free(c->sock, c->ma->ctx);
        return false;
    }
    c->rbuf = kevue_buffer_create(BUF_SIZE, ma);
    if (c->rbuf == NULL) return false;
    c->wbuf = kevue_buffer_create(BUF_SIZE, ma);
    if (c->wbuf == NULL) return false;
    c->hmbuf = kevue_buffer_create(BUF_SIZE, ma);
    if (c->hmbuf == NULL) return false;
    c->hm = hm;
    return true;
}

static void kevue__connection_destroy(KevueConnection *c)
{
    pid_t tid = gettid();
    print_info("[%d] Closing connection %s:%d", tid, c->addr.addr_str, c->addr.port);
    if (close(c->sock->fd) < 0) {
        print_err("[%d] Closing socket failed for %s:%d: %s", tid, c->addr.addr_str, c->addr.port, strerror(errno));
    } else {
        print_info("[%d] Connection to %s:%d closed", tid, c->addr.addr_str, c->addr.port);
    }
    c->ma->free(c->sock, c->ma->ctx);
    kevue_buffer_destroy(c->rbuf);
    kevue_buffer_destroy(c->wbuf);
    kevue_buffer_destroy(c->hmbuf);
    c->ma->free(c, c->ma->ctx);
}

static void kevue__signal_handler(int sig)
{
    if (!shutting_down) {
        shutting_down = true;
        signal(sig, SIG_DFL);
    } else {
        exit(1);
    }
}

static int kevue__create_server_sock(char *host, char *port, bool check)
{
    int server_sock;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) < 0) {
        print_err("getaddrinfo failed: %s", gai_strerror(rv));
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((server_sock = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol)) < 0) {
            print_err("Creating socket failed: %s", strerror(errno));
            continue;
        }
        int enable = 1;
        if (setsockopt(server_sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, (const char *)&enable, sizeof(enable)) < 0) {
            print_err("Setting TCP_DEFER_ACCEPT option failed: %s", strerror(errno));
            close(server_sock);
            freeaddrinfo(servinfo);
            return -1;
        }
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable)) < 0) {
            print_err("Setting SO_REUSEADDR option failed: %s", strerror(errno));
            close(server_sock);
            freeaddrinfo(servinfo);
            return -1;
        }
        if (!check) {
            if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&enable, sizeof(enable)) < 0) {
                print_err("Setting SO_REUSEPORT option failed: %s", strerror(errno));
                close(server_sock);
                freeaddrinfo(servinfo);
                return -1;
            }
        }
        int send_buffer_size = SND_BUF_SIZE;
        int recv_buffer_size = RECV_BUF_SIZE;
        if (setsockopt(server_sock, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) < 0) {
            print_err("Setting SO_SNDBUF option failed: %s", strerror(errno));
            close(server_sock);
            freeaddrinfo(servinfo);
            return -1;
        }
        if (setsockopt(server_sock, SOL_SOCKET, SO_RCVBUF, &recv_buffer_size, sizeof(recv_buffer_size)) < 0) {
            print_err("Setting SO_RCVBUF option failed: %s", strerror(errno));
            close(server_sock);
            freeaddrinfo(servinfo);
            return -1;
        }
        if (bind(server_sock, p->ai_addr, p->ai_addrlen) < 0) {
            print_err("Binding to address failed: %s", strerror(errno));
            close(server_sock);
            continue;
        }
        break;
    }
    if (p == NULL) {
        print_err("Failed creating socket");
        close(server_sock);
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);
    if (listen(server_sock, MAX_CONNECTIONS) < 0) {
        print_err("Listening on address failed: %s", strerror(errno));
        close(server_sock);
        return -1;
    }
    if (!check) print_info("kevue server listening on %s:%s", host, port);
    return server_sock;
}

static void kevue__usage(void)
{
    printf("Usage: kevue-server <host> <port>\n");
}

KevueServer *kevue_server_create(char *host, char *port, KevueAllocator *ma)
{
    int server_sock;
    if ((server_sock = kevue__create_server_sock(host, port, true)) < 0) {
        return NULL;
    }
    close(server_sock);
    if (ma == NULL) ma = &kevue_default_allocator;
    KevueServer *ks = (KevueServer *)ma->malloc(sizeof(KevueServer), ma->ctx);
    if (ks == NULL) return NULL;
    memset(ks, 0, sizeof(KevueServer));
    ks->ma = ma;
    ks->host = host;
    ks->port = port;
    ks->efd = eventfd(0, EFD_NONBLOCK);
    if (ks->efd < 0) {
        print_err("Creating eventfd failed: %s", strerror(errno));
        ks->ma->free(ks, ks->ma->ctx);
        return NULL;
    }
    for (int i = 0; i < SERVER_WORKERS; i++) {
        ks->fds[i] = kevue__create_server_sock(host, port, false);
        if (ks->fds[i] < 0) {
            ks->ma->free(ks, ks->ma->ctx);
            return NULL;
        }
        pthread_t thread = { 0 };
        ks->threads[i] = thread;
    }
    HashMap *hm = kevue_hm_threaded_create(ks->ma);
    if (hm == NULL) {
        ks->ma->free(ks, ks->ma->ctx);
        return NULL;
    }
    ks->hm = hm;
    struct sigaction new_action;
    new_action.sa_handler = kevue__signal_handler;
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
        EpollServerArgs *esargs = (EpollServerArgs *)ks->ma->malloc(sizeof(EpollServerArgs), ks->ma->ctx);
        esargs->ssock = &ks->fds[i];
        esargs->esock = &ks->efd;
        esargs->ma = ks->ma;
        esargs->hm = ks->hm;
        pthread_create(&ks->threads[i], NULL, kevue__handle_server_epoll, esargs);
    }
    while (!shutting_down)
        pause();
    print_info("Shutting down %d servers on %s:%s... Please wait", SERVER_WORKERS, ks->host, ks->port);
    uint64_t one = 1;
    if (write(ks->efd, &one, sizeof(one)) < 0) {
        print_err("Writing to eventfd failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < SERVER_WORKERS; i++) {
        pthread_join(ks->threads[i], NULL);
    }
}

void kevue_server_destroy(KevueServer *ks)
{
    print_info("%d servers on %s:%s gracefully shut down", SERVER_WORKERS, ks->host, ks->port);
    close(ks->efd);
    ks->hm->ops->kevue_hm_destroy(ks->hm);
    ks->ma->free(ks, ks->ma->ctx);
}

int main(int argc, char **argv)
{
    char *host, *port;
    if (argc == 3) {
        host = argv[1];
        int port_num = atoi(argv[2]);
        if (port_num < 0 || port_num > 65535) {
            kevue__usage();
            exit(EXIT_FAILURE);
        }
        host = argv[1];
        port = argv[2];
    } else if (argc > 1) {
        kevue__usage();
        exit(EXIT_FAILURE);
    } else {
        host = HOST;
        port = PORT;
    }
    KevueAllocator *ma = NULL;
#if defined(USE_TCMALLOC)
    ma = &kevue_tcmalloc_allocator;
#elif defined(USE_JEMALLOC)
    ma = &kevue_jemalloc_allocator;
#endif
    KevueServer *ks = kevue_server_create(host, port, ma);
    if (ks == NULL) exit(EXIT_FAILURE);
    kevue_server_start(ks);
    kevue_server_destroy(ks);
    return 0;
}
