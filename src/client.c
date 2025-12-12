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
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <buffer.h>
#include <client.h>
#include <common.h>
#include <linenoise.h>
#include <protocol.h>

static void kevue__usage(void);
static int kevue__create_client_sock(char *host, char *port, int read_timeout, int write_timeout);
static bool kevue__client_hello(KevueClient *kc, KevueResponse *resp);
static bool kevue__handle_read_exactly(KevueClient *c, size_t n);
static bool kevue__handle_write(KevueClient *c);
static bool kevue__make_request(KevueClient *kc, KevueRequest *req, KevueResponse *resp);

struct KevueClient {
    int fd;
    struct sockaddr_in server_addr;
    Buffer *rbuf;
    Buffer *wbuf;
    int read_timeout;
    int write_timeout;
};

static bool kevue__compare_command(char *data, uint8_t len, KevueCommand cmd)
{
    const char *cmd_name = kevue_command_to_string(cmd);
    return strlen(cmd_name) == len && strncasecmp(data, cmd_name, len) == 0;
}

static int kevue__create_client_sock(char *host, char *port, int read_timeout, int write_timeout)
{
    int client_sock;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) < 0) {
        printf("ERROR: getaddrinfo failed: %s\n", gai_strerror(rv));
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((client_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
            printf("ERROR: Creating socket failed: %s\n", strerror(errno));
            continue;
        }
        int enable = 1;
        if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
            printf("ERROR: Setting TCP_NODELAY option for client failed: %s\n", strerror(errno));
            close(client_sock);
            return -1;
        }
        if (read_timeout > 0) {
            struct timeval tv;
            tv.tv_sec = read_timeout;
            tv.tv_usec = 0;
            if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
                printf("ERROR: Setting SO_RCVTIMEO option for client failed: %s\n", strerror(errno));
                close(client_sock);
                return -1;
            }
        }
        if (write_timeout > 0) {
            struct timeval tv;
            tv.tv_sec = write_timeout;
            tv.tv_usec = 0;
            if (setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
                printf("ERROR: Setting SO_SNDTIMEO option for client failed: %s\n", strerror(errno));
                close(client_sock);
                return -1;
            }
        }
        if (connect(client_sock, p->ai_addr, p->ai_addrlen) < 0) {
            printf("ERROR: connecting to %s:%s failed: %s\n", host, port, strerror(errno));
            continue;
        }
        break;
    }
    if (p == NULL) {
        printf("ERROR: Connect failed: %s\n", strerror(errno));
        close(client_sock);
        return -1;
    }
    freeaddrinfo(servinfo);
    return client_sock;
}

static void kevue__usage(void)
{
    printf("Usage: kevue-client <host> <port>\n");
}

static bool kevue__handle_read_exactly(KevueClient *c, size_t n)
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

static bool kevue__handle_write(KevueClient *kc)
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

static bool kevue__make_request(KevueClient *kc, KevueRequest *req, KevueResponse *resp)
{
    kevue_serialize_request(req, kc->wbuf);
    if (!kevue__handle_write(kc)) {
        if (shutdown(kc->fd, SHUT_WR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: Shutting down failed: %s\n", strerror(errno));
        }
        return false;
    }
    uint32_t total_len;
    while (true) {
        KevueErr err = kevue_read_message_length(kc->fd, kc->rbuf, &total_len);
        if (err != KEVUE_ERR_OK) {
            if (err == KEVUE_ERR_INCOMPLETE_READ) {
                printf("ERROR: failed reading message length: timeout\n");
            } else {
                printf("ERROR: failed reading message length: %s\n", kevue_error_to_string(err));
            }
            if (shutdown(kc->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    printf("ERROR: Shutting down failed: %s\n", strerror(errno));
            }
            kevue_buffer_reset(kc->rbuf);
            return false;
        } else {
            break;
        }
    }
    if (!kevue__handle_read_exactly(kc, total_len)) {
        if (shutdown(kc->fd, SHUT_WR) < 0) {
            if (errno != ENOTCONN)
                printf("ERROR: Shutting down failed: %s\n", strerror(errno));
        }
        kevue_buffer_reset(kc->rbuf);
        return false;
    }
    resp->total_len = total_len;
    KevueErr err = kevue_deserialize_response(resp, kc->rbuf);
    kevue_buffer_move_unread_bytes(kc->rbuf);
    if (err != KEVUE_ERR_OK) return false;
    kevue_print_response(resp);
    return true;
}

static bool kevue__client_hello(KevueClient *kc, KevueResponse *resp)
{
    KevueRequest req = { 0 };
    req.cmd_len = 5;
    req.cmd = HELLO;
    if (!kevue__make_request(kc, &req, resp) || !kevue_compare_command(resp->val, resp->val_len, HELLO)) {
        resp->err_code = KEVUE_ERR_HANDSHAKE;
        return false;
    }
    return true;
}

bool kevue_client_get(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 3;
    req.cmd = GET;
    req.key_len = key_len;
    req.key = key;
    return kevue__make_request(kc, &req, resp);
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
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_delete(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 6;
    req.cmd = DELETE;
    req.key_len = key_len;
    req.key = key;
    return kevue__make_request(kc, &req, resp);
}

KevueClient *kevue_client_create(char *host, char *port)
{
    KevueClient *kc = (KevueClient *)malloc(sizeof(KevueClient));
    kc->read_timeout = READ_TIMEOUT;
    kc->write_timeout = WRITE_TIMEOUT;
    kc->fd = kevue__create_client_sock(host, port, kc->read_timeout, kc->write_timeout);
    if (kc->fd < 0) {
        free(kc);
        return NULL;
    }
    kc->rbuf = kevue_buffer_create(BUF_SIZE);
    kc->wbuf = kevue_buffer_create(BUF_SIZE);
    KevueResponse resp = { 0 };
    if (!kevue__client_hello(kc, &resp)) {
        printf("%s\n", kevue_error_to_string(resp.err_code));
        free(kc);
        return NULL;
    }
    return kc;
}

void completion(const char *buf, linenoiseCompletions *lc)
{
    if (buf[0] == 'h') {
        linenoiseAddCompletion(lc, "hello");
        linenoiseAddCompletion(lc, "hello there");
    }
}

char *hints(const char *buf, int *color, int *bold)
{
    if (!strcasecmp(buf, "hello")) {
        *color = 90;
        *bold = 0;
        return " World";
    }
    return NULL;
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
    // TODO: make CLI application to parse client requests
    char *host, *port;
    char *line;
    if (argc == 3) {
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
    KevueClient *kc = kevue_client_create(host, port);
    if (kc == NULL) exit(EXIT_FAILURE);
    printf("INFO: connected to %s:%s\n", host, port);
    KevueResponse *resp = (KevueResponse *)malloc(sizeof(KevueResponse));
    linenoiseSetCompletionCallback(completion);
    linenoiseSetHintsCallback(hints);
    linenoiseHistoryLoad("history.txt");
    char prompt[INET6_ADDRSTRLEN + 7 + 1];
    int n = snprintf(prompt, INET6_ADDRSTRLEN + 7, "%s:%s> ", host, port);
    prompt[n] = '\0';
    while (1) {
        line = linenoise(prompt);
        if (line == NULL) break;
        if (!strncmp(line, "exit", 4)) {
            break;
        }
        if (line[0] != '\0' && line[0] != '/') {
            printf("echo: '%s'\n", line);
            linenoiseHistoryAdd(line); /* Add to the history. */
            linenoiseHistorySave("history.txt"); /* Save the history on disk. */
        } else if (!strncmp(line, "/historylen", 11)) {
            /* The "/historylen" command will change the history len. */
            int len = atoi(line + 11);
            linenoiseHistorySetMaxLen(len);
        } else if (!strncmp(line, "/mask", 5)) {
            linenoiseMaskModeEnable();
        } else if (!strncmp(line, "/unmask", 7)) {
            linenoiseMaskModeDisable();
        } else if (line[0] == '/') {
            printf("Unreconized command: %s\n", line);
        }
        free(line);
    }
    while (true) {
        if (!kevue_client_get(kc, resp, "random", 6)) break;
        if (!kevue_client_get(kc, resp, "random2", 7)) break;
        if (!kevue_client_get(kc, resp, "random222", 9)) break;
        if (!kevue_client_get(kc, resp, "random2222", 10)) break;
        if (!kevue_client_set(kc, resp, "random", 6, "wasd", 4)) break;
        if (!kevue_client_delete(kc, resp, "random", 6)) break;
        sleep(10);
    }
    kevue_destroy_response(resp);
    kevue_client_destroy(kc);
}
