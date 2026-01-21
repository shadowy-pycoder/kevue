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
 * @file client.c
 * @brief kevue client implementation.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <allocator.h>
#include <buffer.h>
#include <client.h>
#include <common.h>
#include <protocol.h>

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#if defined(USE_TCMALLOC)
#include <tcmalloc_allocator.h>
#elif defined(USE_JEMALLOC)
#include <jemalloc_allocator.h>
#endif

static int kevue__create_client_sock(const char *host, const char *port, int read_timeout, int write_timeout);
static bool kevue__make_request(KevueClient *kc, KevueRequest *req, KevueResponse *resp);
static bool kevue__handle_read_exactly(KevueClient *kc, size_t n);
static bool kevue__handle_read(KevueClient *kc);
static bool kevue__handle_write(KevueClient *kc);

struct KevueClient {
    int                fd;
    struct sockaddr_in server_addr;
    Buffer            *rbuf;
    Buffer            *wbuf;
    KevueAllocator    *ma;
};

static int kevue__create_client_sock(const char *host, const char *port, int read_timeout, int write_timeout)
{
    int             client_sock;
    struct addrinfo hints, *servinfo, *p;
    int             rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) < 0) {
        print_err(generate_timestamp(), "getaddrinfo failed: %s", gai_strerror(rv));
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((client_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
            print_err(generate_timestamp(), "Creating socket failed: %s", strerror(errno));
            continue;
        }
        int enable = 1;
        if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
            print_err(generate_timestamp(), "Setting TCP_NODELAY option for client failed: %s", strerror(errno));
            close(client_sock);
            freeaddrinfo(servinfo);
            return -1;
        }
        if (read_timeout > 0) {
            struct timeval tv;
            tv.tv_sec = read_timeout;
            tv.tv_usec = 0;
            if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
                print_err(generate_timestamp(), "Setting SO_RCVTIMEO option for client failed: %s", strerror(errno));
                close(client_sock);
                freeaddrinfo(servinfo);
                return -1;
            }
        }
        if (write_timeout > 0) {
            struct timeval tv;
            tv.tv_sec = write_timeout;
            tv.tv_usec = 0;
            if (setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
                print_err(generate_timestamp(), "Setting SO_SNDTIMEO option for client failed: %s", strerror(errno));
                close(client_sock);
                freeaddrinfo(servinfo);
                return -1;
            }
        }
        if (connect(client_sock, p->ai_addr, p->ai_addrlen) < 0) {
            if (errno == EINPROGRESS)
                print_err(generate_timestamp(), "Connecting to %s:%s failed", host, port);
            else
                print_err(generate_timestamp(), "Connecting to %s:%s failed: %s", host, port, strerror(errno));
            close(client_sock);
            continue;
        }
        break;
    }
    if (p == NULL) {
        if (errno == EINPROGRESS)
            print_err(generate_timestamp(), "Connect failed");
        else
            print_err(generate_timestamp(), "Connect failed: %s", strerror(errno));
        close(client_sock);
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);
    return client_sock;
}

static bool kevue__handle_read_exactly(KevueClient *kc, size_t n)
{
    kevue_buffer_grow(kc->rbuf, n);
    while (kc->rbuf->size < n) {
        ssize_t nr = read(kc->fd, kc->rbuf->ptr + kc->rbuf->size, n - kc->rbuf->size);
        if (nr < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return false;
            if (errno == EINTR)
                continue;
            return false;
        } else if (nr == 0) {
            return false;
        } else {
            kc->rbuf->size += (size_t)nr;
        }
    }
    return true;
}
static bool kevue__handle_read(KevueClient *kc)
{
    while (true) {
        if (kc->rbuf->size >= kc->rbuf->capacity)
            kevue_buffer_grow(kc->rbuf, kc->rbuf->capacity * 2);
        ssize_t nr = read(
            kc->fd,
            kc->rbuf->ptr + kc->rbuf->size,
            kc->rbuf->capacity - kc->rbuf->size);

        if (nr > 0) {
            kc->rbuf->size += (size_t)nr;
            return true;
        }

        if (nr == 0) {
            return false;
        }

        if (errno == EINTR)
            continue;

        return false;
    }
}

static bool kevue__handle_write(KevueClient *kc)
{
    while (kc->wbuf->offset < kc->wbuf->size) {
        ssize_t nw = write(kc->fd, kc->wbuf->ptr + kc->wbuf->offset, kc->wbuf->size - kc->wbuf->offset);
        if (nw < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return false;
            if (errno == EINTR)
                continue;
            return false;
        } else if (nw == 0) {
            continue;
        } else {
            kc->wbuf->offset += (size_t)nw;
        }
    }
    kevue_buffer_reset(kc->wbuf);
    return true;
}

static bool kevue__make_request(KevueClient *kc, KevueRequest *req, KevueResponse *resp)
{
    KevueErr err = kevue_request_serialize(req, kc->wbuf);
    if (err != KEVUE_ERR_OK) {
        resp->err_code = err;
        return false;
    }
    if (!kevue__handle_write(kc)) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            resp->err_code = KEVUE_ERR_WRITE_TIMEOUT;
        } else {
            resp->err_code = KEVUE_ERR_WRITE_FAILED;
        }
        shutdown(kc->fd, SHUT_WR);
        return false;
    }
    while (true) {
        if (!kevue__handle_read(kc)) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                resp->err_code = KEVUE_ERR_READ_TIMEOUT;
            } else {
                resp->err_code = KEVUE_ERR_READ_FAILED;
            }
            shutdown(kc->fd, SHUT_WR);
            kevue_buffer_reset(kc->rbuf);
            return false;
        }
        err = kevue_response_deserialize(resp, kc->rbuf);
        if (err == KEVUE_ERR_INCOMPLETE_READ) {
            continue;
        }
        kevue_buffer_reset(kc->rbuf);
        if (err != KEVUE_ERR_OK) {
            resp->err_code = err;
            return false;
        }
        return true;
    }
}

bool kevue_client_hello(KevueClient *kc, KevueResponse *resp)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = HELLO;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    if (!kevue__make_request(kc, &req, resp) || resp->cmd != HELLO) {
        resp->err_code = KEVUE_ERR_HANDSHAKE;
        return false;
    }
    return true;
}

bool kevue_client_get(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = GET;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    req.key_len = key_len;
    req.key = key;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_set(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len, const void *val, uint16_t val_len)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = SET;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    req.key_len = key_len;
    req.key = key;
    req.val_len = val_len;
    req.val = val;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_del(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = DEL;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    req.key_len = key_len;
    req.key = key;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_ping_with_message(KevueClient *kc, KevueResponse *resp, const void *message, uint16_t message_len)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = PING;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    req.key_len = message_len;
    req.key = message;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_ping(KevueClient *kc, KevueResponse *resp)
{
    return kevue_client_ping_with_message(kc, resp, "", 0);
}

bool kevue_client_count(KevueClient *kc, KevueResponse *resp)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = COUNT;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_items(KevueClient *kc, KevueResponse *resp)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = ITEMS;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_keys(KevueClient *kc, KevueResponse *resp)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = KEYS;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_values(KevueClient *kc, KevueResponse *resp)
{
    KevueRequest req = { 0 };
    KevueCommand cmd = VALUES;
    req.cmd_len = kevue_command_length[cmd];
    req.cmd = cmd;
    return kevue__make_request(kc, &req, resp);
}

KevueClient *kevue_client_create(KevueClientConfig *conf)
{
    if (!conf->host) conf->host = KEVUE_HOST;
    if (!conf->port) conf->port = KEVUE_PORT;
    if (conf->read_timeout == 0) conf->read_timeout = READ_TIMEOUT;
    if (conf->write_timeout == 0) conf->write_timeout = WRITE_TIMEOUT;
    if (conf->ma == NULL) {
        KevueAllocator *ma = &kevue_default_allocator;
#if defined(USE_TCMALLOC)
        ma = &kevue_tcmalloc_allocator;
#elif defined(USE_JEMALLOC)
        ma = &kevue_jemalloc_allocator;
#endif
        conf->ma = ma;
    }
    if (!is_valid_ip(conf->host)) {
        print_err(generate_timestamp(), "Server host is not a valid IP address");
        return NULL;
    }
    if (!is_valid_port(conf->port)) {
        print_err(generate_timestamp(), "Server port is not valid number");
        return NULL;
    }
    KevueClient *kc = (KevueClient *)conf->ma->malloc(sizeof(*kc), conf->ma->ctx);
    if (kc == NULL) return NULL;
    kc->ma = conf->ma;
    kc->fd = kevue__create_client_sock(conf->host, conf->port, conf->read_timeout, conf->write_timeout);
    if (kc->fd < 0) {
        kc->ma->free(kc, kc->ma->ctx);
        return NULL;
    }
    kc->rbuf = kevue_buffer_create(BUF_SIZE, kc->ma);
    if (kc->rbuf == NULL) {
        kevue_client_destroy(kc);
        return NULL;
    }
    kc->wbuf = kevue_buffer_create(BUF_SIZE, kc->ma);
    if (kc->wbuf == NULL) {
        kevue_client_destroy(kc);
        return NULL;
    }
    return kc;
}

void kevue_client_destroy(KevueClient *kc)
{
    if (kc == NULL) return;
    close(kc->fd);
    kevue_buffer_destroy(kc->rbuf);
    kevue_buffer_destroy(kc->wbuf);
    kc->ma->free(kc, kc->ma->ctx);
}
