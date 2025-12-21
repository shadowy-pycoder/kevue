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
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <allocator.h>
#include <buffer.h>
#include <client.h>
#include <common.h>
#include <linenoise.h>
#include <protocol.h>

#ifdef USE_TCMALLOC
#include <tcmalloc_allocator.h>
#endif

#define PROMPT_LENGTH INET6_ADDRSTRLEN + 7 + 1

typedef struct KevueClientParseResult KevueClientParseResult;

static void kevue__usage(void);
static int kevue__create_client_sock(char *host, char *port, int read_timeout, int write_timeout);
static bool kevue__client_hello(KevueClient *kc, KevueResponse *resp);
static bool kevue__handle_read_exactly(KevueClient *kc, size_t n);
static bool kevue__handle_write(KevueClient *kc);
static bool kevue__make_request(KevueClient *kc, KevueRequest *req, KevueResponse *resp);
static bool kevue__parse_chunk(Buffer *buf, Buffer *out);
static void kevue__trim_left(Buffer *buf);
static KevueClientParseResult *kevue__parse_command_line(Buffer *buf);
static void kevue__client_parse_result_destroy(KevueClientParseResult *pr);
static void completion(const char *buf, linenoiseCompletions *lc);
static char *hints(const char *buf, int *color, int *bold);

struct KevueClient {
    int fd;
    struct sockaddr_in server_addr;
    Buffer *rbuf;
    Buffer *wbuf;
    int read_timeout;
    int write_timeout;
    KevueAllocator *ma;
};

struct KevueClientParseResult {
    KevueCommand cmd;
    Buffer *key;
    Buffer *value;
    KevueAllocator *ma;
};

static void kevue__client_parse_result_destroy(KevueClientParseResult *pr)
{
    if (pr->key != NULL) kevue_buffer_destroy(pr->key);
    if (pr->value != NULL) kevue_buffer_destroy(pr->value);
    pr->ma->free(pr, pr->ma->ctx);
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
        print_err("getaddrinfo failed: %s", gai_strerror(rv));
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((client_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
            print_err("Creating socket failed: %s", strerror(errno));
            continue;
        }
        int enable = 1;
        if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
            print_err("Setting TCP_NODELAY option for client failed: %s", strerror(errno));
            close(client_sock);
            freeaddrinfo(servinfo);
            return -1;
        }
        if (read_timeout > 0) {
            struct timeval tv;
            tv.tv_sec = read_timeout;
            tv.tv_usec = 0;
            if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
                print_err("Setting SO_RCVTIMEO option for client failed: %s", strerror(errno));
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
                print_err("Setting SO_SNDTIMEO option for client failed: %s", strerror(errno));
                close(client_sock);
                freeaddrinfo(servinfo);
                return -1;
            }
        }
        if (connect(client_sock, p->ai_addr, p->ai_addrlen) < 0) {
            print_err("Connecting to %s:%s failed: %s", host, port, strerror(errno));
            continue;
        }
        break;
    }
    if (p == NULL) {
        print_err("Connect failed: %s", strerror(errno));
        close(client_sock);
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);
    return client_sock;
}

static void kevue__usage(void)
{
    printf("Usage: kevue-client <host> <port>\n");
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
            print_debug("Read %ld bytes", nr);
        }
    }
    return true;
}

static bool kevue__handle_write(KevueClient *kc)
{
    while (kc->wbuf->offset < kc->wbuf->size) {
        ssize_t nw = write(kc->fd, kc->wbuf->ptr + kc->wbuf->offset, kc->wbuf->size - kc->wbuf->offset);
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
            kc->wbuf->offset += (size_t)nw;
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
                print_err("Shutting down failed: %s", strerror(errno));
        }
        return false;
    }
    uint32_t total_len;
    while (true) {
        KevueErr err = kevue_read_message_length(kc->fd, kc->rbuf, &total_len);
        if (err != KEVUE_ERR_OK) {
            if (err == KEVUE_ERR_INCOMPLETE_READ) {
                print_err("Failed reading message length: timeout");
            } else {
                print_err("Failed reading message length: %s", kevue_error_to_string(err));
            }
            if (shutdown(kc->fd, SHUT_WR) < 0) {
                if (errno != ENOTCONN)
                    print_err("Shutting down failed: %s", strerror(errno));
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
                print_err("Shutting down failed: %s", strerror(errno));
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
    if (!kevue__make_request(kc, &req, resp) || !kevue_compare_command(resp->val->ptr, (uint8_t)resp->val_len, HELLO)) {
        resp->err_code = KEVUE_ERR_HANDSHAKE;
        kevue_buffer_destroy(resp->val);
        return false;
    }
    kevue_buffer_destroy(resp->val);
    return true;
}

static void completion(const char *buf, linenoiseCompletions *lc)
{
    switch (buf[0]) {
    case 'g':
    case 'G':
        linenoiseAddCompletion(lc, "GET");
        break;
    case 's':
    case 'S':
        linenoiseAddCompletion(lc, "SET");
        break;
    case 'd':
    case 'D':
        linenoiseAddCompletion(lc, "DELETE");
        break;
    default:
    }
    return;
}

static char *hints(const char *buf, int *color, int *bold)
{
    if (!strncasecmp(buf, "GET ", 4)) {
        *color = 90;
        *bold = 0;
        return "key";
    }
    if (!strncasecmp(buf, "SET ", 4)) {
        *color = 90;
        *bold = 0;
        return "key value";
    }
    if (!strncasecmp(buf, "DELETE ", 7)) {
        *color = 90;
        *bold = 0;
        return "key";
    }
    return NULL;
}

static bool kevue__parse_chunk(Buffer *buf, Buffer *out)
{
    char c = (char)kevue_buffer_peek_byte(buf);
    switch (c) {
    case '"':
    case '\'':
        kevue_buffer_read_advance(buf);
        kevue_buffer_read_until(buf, out, c);
        if (kevue_buffer_peek_byte(buf) != c) return false;
        kevue_buffer_read_advance(buf);
        break;
    default:
        kevue_buffer_read_until(buf, out, ' ');
    }
    return true;
}

static void kevue__trim_left(Buffer *buf)
{
    while (isspace((unsigned char)kevue_buffer_peek_byte(buf))) kevue_buffer_read_advance(buf);
}

static KevueClientParseResult *kevue__parse_command_line(Buffer *buf)
{
    KevueAllocator *ma = buf->ma;
    KevueClientParseResult *pr = (KevueClientParseResult *)ma->malloc(sizeof(KevueClientParseResult), ma->ctx);
    if (pr == NULL) return NULL;
    memset(pr, 0, sizeof(*pr));
    pr->ma = ma;
    pr->key = kevue_buffer_create(BUF_SIZE, pr->ma);
    kevue__trim_left(buf);
    if (kevue_buffer_at_eof(buf)) {
        printf("ERROR: Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (!kevue__parse_chunk(buf, pr->key)) {
        printf("ERROR: Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (kevue_compare_command(pr->key->ptr, (uint8_t)pr->key->size, GET)) {
        pr->cmd = GET;
    } else if (kevue_compare_command(pr->key->ptr, (uint8_t)pr->key->size, SET)) {
        pr->cmd = SET;
    } else if (kevue_compare_command(pr->key->ptr, (uint8_t)pr->key->size, DELETE)) {
        pr->cmd = DELETE;
    } else {
        printf("ERROR: Wrong command\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    size_t offset = buf->offset;
    kevue__trim_left(buf);
    if (buf->offset == offset) {
        printf("ERROR: Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (kevue_buffer_at_eof(buf)) {
        printf("ERROR: Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    kevue_buffer_reset(pr->key);
    if (!kevue__parse_chunk(buf, pr->key)) {
        printf("ERROR: Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    offset = buf->offset;
    kevue__trim_left(buf);
    if (buf->offset == offset && pr->cmd == SET) {
        printf("ERROR: Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (kevue_buffer_at_eof(buf)) {
        if (pr->cmd == SET) {
            printf("ERROR: Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
    } else {
        if (pr->cmd != SET) {
            printf("ERROR: Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
    }
    pr->value = kevue_buffer_create(BUF_SIZE, pr->ma);
    kevue_buffer_reset(pr->value);
    if (!kevue__parse_chunk(buf, pr->value)) {
        printf("ERROR: Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    kevue__trim_left(buf);
    if (!kevue_buffer_at_eof(buf)) {
        printf("ERROR: Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    return pr;
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

KevueClient *kevue_client_create(char *host, char *port, KevueAllocator *ma)
{
    if (ma == NULL) ma = &kevue_default_allocator;
    KevueClient *kc = (KevueClient *)ma->malloc(sizeof(KevueClient), ma->ctx);
    assert(kc != NULL);
    kc->ma = ma;
    kc->read_timeout = READ_TIMEOUT;
    kc->write_timeout = WRITE_TIMEOUT;
    kc->fd = kevue__create_client_sock(host, port, kc->read_timeout, kc->write_timeout);
    if (kc->fd < 0) {
        kc->ma->free(kc, kc->ma->ctx);
        return NULL;
    }
    kc->rbuf = kevue_buffer_create(BUF_SIZE, kc->ma);
    kc->wbuf = kevue_buffer_create(BUF_SIZE, kc->ma);
    KevueResponse resp = { 0 };
    if (!kevue__client_hello(kc, &resp)) {
        print_err("%s", kevue_error_to_string(resp.err_code));
        kevue_client_destroy(kc);
        return NULL;
    }
    return kc;
}

void kevue_client_destroy(KevueClient *kc)
{
    close(kc->fd);
    kevue_buffer_destroy(kc->rbuf);
    kevue_buffer_destroy(kc->wbuf);
    kc->ma->free(kc, kc->ma->ctx);
}

int main(int argc, char **argv)
{
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
    KevueAllocator *ma = NULL; // kevue_default_allocator
#ifdef USE_TCMALLOC
    ma = &kevue_tcmalloc_allocator;
#endif
    KevueClient *kc = kevue_client_create(host, port, ma);
    if (kc == NULL) exit(EXIT_FAILURE);
    print_info("Connected to %s:%s", host, port);
    KevueResponse *resp = (KevueResponse *)kc->ma->malloc(sizeof(KevueResponse), kc->ma->ctx);
    memset(resp, 0, sizeof(*resp));
    linenoiseSetCompletionCallback(completion);
    linenoiseSetHintsCallback(hints);
    linenoiseHistoryLoad("history.txt");
    linenoiseSetMultiLine(1);
    char prompt[PROMPT_LENGTH];
    int n = snprintf(prompt, PROMPT_LENGTH - 1, "%s:%s> ", host, port);
    prompt[n] = '\0';
    Buffer *cmdline = kevue_buffer_create(BUF_SIZE, kc->ma);
    while (true) {
        line = linenoise(prompt);
        if (line == NULL) break;
        if (line[0] == '\0') {
            free(line);
            continue;
        }
        if (!strncmp(line, "exit", 4) || !strncmp(line, "quit", 4) || !strncmp(line, "q", 1)) {
            free(line);
            break;
        }
        kevue_buffer_write(cmdline, line, strlen(line));
        KevueClientParseResult *pr = kevue__parse_command_line(cmdline);
        if (pr == NULL) {
            free(line);
            kevue_buffer_reset(cmdline);
            continue;
        }
        switch (pr->cmd) {
        case GET:
            if (kevue_client_get(kc, resp, pr->key->ptr, (uint16_t)pr->key->size)) {
                fwrite(resp->val->ptr, sizeof(*resp->val->ptr), resp->val_len, stdout);
                fputc('\n', stdout);
                fflush(stdout);
            }
            break;
        case SET:
            if (kevue_client_set(kc, resp, pr->key->ptr, (uint16_t)pr->key->size, pr->value->ptr, (uint16_t)pr->value->size)) {
                printf("OK\n");
            }
            break;
        case DELETE:
            if (kevue_client_delete(kc, resp, pr->key->ptr, (uint16_t)pr->key->size)) {
                printf("OK\n");
            }
            break;
        default:
            UNREACHABLE("Possibly forgot to add new command to switch case");
        }
        kevue_buffer_reset(cmdline);
        kevue__client_parse_result_destroy(pr);
        linenoiseHistoryAdd(line); /* Add to the history. */
        linenoiseHistorySave("history.txt"); /* Save the history on disk. */
        free(line);
    }
    kevue_buffer_destroy(cmdline);
    kevue_buffer_destroy(resp->val);
    kc->ma->free(resp, kc->ma->ctx);
    kevue_client_destroy(kc);
}
