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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <buffer.h>
#include <client.h>
#include <common.h>
#include <protocol.h>

static void kevue__usage(void);
static int kevue__create_client_sock(int read_timeout, int write_timeout);
static bool kevue__handle_read_exactly(KevueClient *c, size_t n);
static bool kevue__handle_write(KevueClient *c);
static bool kevue__make_request(KevueClient *kc, KevueResponse *resp);

struct KevueClient {
    int fd;
    struct sockaddr_in server_addr;
    Buffer *rbuf;
    Buffer *wbuf;
    int read_timeout;
    int write_timeout;
};

int kevue__create_client_sock(int read_timeout, int write_timeout)
{
    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0) {
        printf("ERROR: Creating socket failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int enable = 1;
    if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting TCP_NODELAY option for client failed: %s\n", strerror(errno));
        close(client_sock);
        exit(EXIT_FAILURE);
    }
    if (read_timeout > 0) {
        struct timeval tv;
        tv.tv_sec = read_timeout;
        tv.tv_usec = 0;
        if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
            printf("ERROR: Setting SO_RCVTIMEO option for client failed: %s\n", strerror(errno));
            close(client_sock);
            exit(EXIT_FAILURE);
        }
    }
    if (write_timeout > 0) {
        struct timeval tv;
        tv.tv_sec = write_timeout;
        tv.tv_usec = 0;
        if (setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
            printf("ERROR: Setting SO_SNDTIMEO option for client failed: %s\n", strerror(errno));
            close(client_sock);
            exit(EXIT_FAILURE);
        }
    }
    return client_sock;
}

void kevue__usage(void)
{
    printf("Usage: kevue-client <host> <port>\n");
}

bool kevue__handle_read_exactly(KevueClient *c, size_t n)
{
    kevue_buffer_grow(c->rbuf, n);
    while (c->rbuf->size < n) {
        int nr = read(c->fd, c->rbuf->ptr + c->rbuf->size, n - c->rbuf->size);
        if (nr < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                // TODO: deal with timeout
                return false;
            if (errno == EINTR)
                continue;
            return false;
        } else if (nr == 0) {
            return false;
        } else {
            c->rbuf->size += nr;
        }
    }
    return true;
}

bool kevue__handle_write(KevueClient *kc)
{
    while (kc->wbuf->offset < kc->wbuf->size) {
        int nw = write(kc->fd, kc->wbuf->ptr + kc->wbuf->offset, kc->wbuf->size - kc->wbuf->offset);
        if (nw < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                // TODO: deal with timeout
                return false;
            if (errno == EINTR)
                continue;
            return false;
        } else if (nw == 0) {
            continue;
        } else {
            kc->wbuf->offset += nw;
        }
    }
    kevue_buffer_reset(kc->wbuf);
    return true;
}

bool kevue__make_request(KevueClient *kc, KevueResponse *resp)
{
    if (!kevue__handle_write(kc)) {
        if (shutdown(kc->fd, SHUT_WR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: Shutting down failed: %s\n", strerror(errno));
        }
        return false;
    }
    KevueMessageHeader h = { 0 };
    while (true) {
        h = kevue_read_message_header(kc->fd, kc->rbuf);
        if (h.err_code != KEVUE_ERR_OK) {
            if (h.err_code == KEVUE_ERR_INCOMPLETE_READ) {
                continue;
            }
            if (shutdown(kc->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    printf("ERROR: Shutting down failed: %s\n", strerror(errno));
            }
            return false;
        } else {
            break;
        }
    }
    if (!kevue__handle_read_exactly(kc, h.total_len)) {
        if (shutdown(kc->fd, SHUT_WR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: Shutting down failed: %s\n", strerror(errno));
        }
        return false;
    }
    resp->total_len = h.total_len;
    KevueErr err = kevue_deserialize_response(resp, kc->rbuf);
    if (err == KEVUE_ERR_OK) kevue_print_response(resp);
    kevue_buffer_move_unread_bytes(kc->rbuf);
    return true;
}

bool kevue_client_get(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 3;
    req.cmd = GET;
    req.key_len = key_len;
    req.key = key;
    kevue_serialize_request(&req, kc->wbuf);
    return kevue__make_request(kc, resp);
}

bool kevue_client_set(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len, char *val, uint16_t val_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 3;
    req.cmd = SET;
    req.key_len = key_len;
    req.key = key;
    req.val_len = val_len;
    req.val = val;
    kevue_serialize_request(&req, kc->wbuf);
    return kevue__make_request(kc, resp);
}

bool kevue_client_delete(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 6;
    req.cmd = DELETE;
    req.key_len = key_len;
    req.key = key;
    kevue_serialize_request(&req, kc->wbuf);
    return kevue__make_request(kc, resp);
}

KevueClient *kevue_client_create(char *host, uint16_t port)
{
    KevueClient *kc = (KevueClient *)malloc(sizeof(KevueClient));
    struct sockaddr_in server_addr = { 0 };
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) < 0) {
        printf("ERROR: %s is not valid IP address\n", host);
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    kc->server_addr = server_addr;
    // TODO: make timeouts configurable
    kc->read_timeout = READ_TIMEOUT;
    kc->write_timeout = WRITE_TIMEOUT;
    kc->fd = kevue__create_client_sock(kc->read_timeout, kc->write_timeout);
    kc->rbuf = kevue_buffer_create(BUF_SIZE);
    kc->wbuf = kevue_buffer_create(BUF_SIZE);
    if (connect(kc->fd, (struct sockaddr *)&kc->server_addr, sizeof(kc->server_addr)) < 0) {
        printf("ERROR: connecting to %s:%d failed: %s\n", host, port, strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("INFO: connected to %s:%d\n", host, port);
    return kc;
}

void kevue_client_destroy(KevueClient *kc)
{
    close(kc->fd);
    kevue_buffer_destroy(kc->rbuf);
    kevue_buffer_destroy(kc->wbuf);
    free(kc);
    kc = NULL;
}

int main(int argc, char **argv)
{
    char *host;
    int port;
    if (argc == 3) {
        host = argv[1];
        port = atoi(argv[2]);
        if (port < 0 || port > 65535) {
            kevue__usage();
        }
    } else if (argc > 1) {
        kevue__usage();
        exit(EXIT_FAILURE);
    } else {
        host = HOST;
        port = PORT;
    }
    KevueClient *kc = kevue_client_create(host, port);
    KevueResponse *resp = (KevueResponse *)malloc(sizeof(KevueResponse));
    while (true) {
        kevue_client_get(kc, resp, "random", 6);
        kevue_client_get(kc, resp, "random2", 7);
        kevue_client_get(kc, resp, "random222", 9);
        kevue_client_get(kc, resp, "random2222", 10);
        kevue_client_set(kc, resp, "random", 6, "wasd", 4);
        kevue_client_delete(kc, resp, "random", 6);
        sleep(10);
    }
    kevue_destroy_response(resp);
    kevue_client_destroy(kc);
}
