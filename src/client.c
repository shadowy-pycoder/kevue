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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include <linenoise.h>

#include <allocator.h>
#include <buffer.h>
#include <client.h>
#include <common.h>
#include <dyna.h>
#include <protocol.h>

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#ifdef USE_TCMALLOC
#include <tcmalloc_allocator.h>
#endif
#ifdef USE_JEMALLOC
#include <jemalloc_allocator.h>
#endif

#define PING_INTERVAL_SECONDS 15
#define PROMPT_LENGTH         INET6_ADDRSTRLEN + 7 + 1
#define MAX_EVENTS            2

typedef struct KevueClientParseResult KevueClientParseResult;

static void kevue__usage(void);
static int kevue__create_client_sock(const char *host, const char *port, int read_timeout, int write_timeout);
static bool kevue__client_hello(KevueClient *kc, KevueResponse *resp);
static bool kevue__handle_read_exactly(KevueClient *kc, size_t n);
static bool kevue__handle_read(KevueClient *kc);
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
    kevue_buffer_destroy(pr->key);
    kevue_buffer_destroy(pr->value);
    pr->ma->free(pr, pr->ma->ctx);
}

static int kevue__create_client_sock(const char *host, const char *port, int read_timeout, int write_timeout)
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
            close(client_sock);
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
        }
    }
    return true;
}

static bool kevue__handle_read(KevueClient *kc)
{
    while (true) {
        ssize_t nr = read(kc->fd, kc->rbuf->ptr + kc->rbuf->size, kc->rbuf->capacity - kc->rbuf->size);
        if (nr < 0) {
            if (errno == EINTR) continue;
            return false;
        } else if (nr == 0) {
            return false;
        } else {
            kc->rbuf->size += (size_t)nr;
            return true;
        }
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
    kevue_request_serialize(req, kc->wbuf);
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
        KevueErr err = kevue_response_deserialize(resp, kc->rbuf);
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

static bool kevue__client_hello(KevueClient *kc, KevueResponse *resp)
{
    KevueRequest req = { 0 };
    req.cmd_len = 5;
    req.cmd = HELLO;
    if (!kevue__make_request(kc, &req, resp) || !kevue_command_compare((char *)resp->val->ptr, (uint8_t)resp->val_len, HELLO)) {
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
        linenoiseAddCompletion(lc, "DEL");
        break;
    case 'p':
    case 'P':
        linenoiseAddCompletion(lc, "PING");
        break;
    default:
        linenoiseAddCompletion(lc, "GET");
        break;
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
    if (!strncasecmp(buf, "DEL ", 4)) {
        *color = 90;
        *bold = 0;
        return "key";
    }
    if (!strncasecmp(buf, "PING ", 5)) {
        *color = 90;
        *bold = 0;
        return "[message]";
    }
    return NULL;
}

static bool kevue__parse_chunk(Buffer *buf, Buffer *out)
{
    char c = (char)kevue_buffer_peek_byte(buf);
    switch (c) {
    case '"':
    case '\'':
    case '`':
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
    // TODO: improve command dispatching
    KevueAllocator *ma = buf->ma;
    KevueClientParseResult *pr = (KevueClientParseResult *)ma->malloc(sizeof(KevueClientParseResult), ma->ctx);
    if (pr == NULL) return NULL;
    memset(pr, 0, sizeof(*pr));
    pr->ma = ma;
    pr->key = kevue_buffer_create(BUF_SIZE, pr->ma);
    if (pr->key == NULL) {
        printf("ERROR: Out of memory\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
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
    if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, GET)) {
        pr->cmd = GET;
    } else if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, SET)) {
        pr->cmd = SET;
    } else if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, DEL)) {
        pr->cmd = DEL;
    } else if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, PING)) {
        pr->cmd = PING;
    } else {
        printf("ERROR: Wrong command\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    size_t offset = buf->offset;
    kevue__trim_left(buf);
    if (buf->offset == offset && pr->cmd != PING) {
        printf("ERROR: Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (kevue_buffer_at_eof(buf) && pr->cmd != PING) {
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
    if (pr->value == NULL) {
        printf("ERROR: Out of memory\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
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

bool kevue_client_get(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 3;
    req.cmd = GET;
    req.key_len = key_len;
    req.key = key;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_set(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len, const void *val, uint16_t val_len)
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

bool kevue_client_del(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 3;
    req.cmd = DEL;
    req.key_len = key_len;
    req.key = key;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_ping_with_message(KevueClient *kc, KevueResponse *resp, const void *message, uint16_t message_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 4;
    req.cmd = PING;
    req.key_len = message_len;
    req.key = message;
    return kevue__make_request(kc, &req, resp);
}

bool kevue_client_ping(KevueClient *kc, KevueResponse *resp)
{
    return kevue_client_ping_with_message(kc, resp, "", 0);
}

KevueClient *kevue_client_create(const char *host, const char *port, KevueAllocator *ma)
{
    if (ma == NULL) ma = &kevue_default_allocator;
    KevueClient *kc = (KevueClient *)ma->malloc(sizeof(KevueClient), ma->ctx);
    if (kc == NULL) return NULL;
    kc->ma = ma;
    kc->read_timeout = READ_TIMEOUT;
    kc->write_timeout = WRITE_TIMEOUT;
    kc->fd = kevue__create_client_sock(host, port, kc->read_timeout, kc->write_timeout);
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
    if (kc == NULL) return;
    close(kc->fd);
    kevue_buffer_destroy(kc->rbuf);
    kevue_buffer_destroy(kc->wbuf);
    kc->ma->free(kc, kc->ma->ctx);
}

int main(int argc, char **argv)
{
    char *host, *port;
    char *line;
    // TODO: add more args and use something like flag.h for parsing
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
#if defined(USE_TCMALLOC)
    ma = &kevue_tcmalloc_allocator;
#elif defined(USE_JEMALLOC)
    ma = &kevue_jemalloc_allocator;
#endif
    KevueClient *kc = kevue_client_create(host, port, ma);
    if (kc == NULL) exit(EXIT_FAILURE);
    print_info("Connected to %s:%s", host, port);
    struct epoll_event *events = kc->ma->malloc(sizeof(struct epoll_event) * MAX_EVENTS, kc->ma->ctx);
    if (events == NULL) {
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        print_err("Creating epoll file descriptor failed %s", strerror(errno));
        kc->ma->free(events, kc->ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (tfd < 0) {
        print_err("Creating timer socket failed: %s", strerror(errno));
        close(epfd);
        kc->ma->free(events, kc->ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    struct itimerspec timer = { 0 };
    timer.it_value.tv_sec = PING_INTERVAL_SECONDS;
    timer.it_interval.tv_sec = PING_INTERVAL_SECONDS;
    if (timerfd_settime(tfd, 0, &timer, NULL) < 0) {
        print_err("Setting timer failed: %s", strerror(errno));
        close(epfd);
        close(tfd);
        kc->ma->free(events, kc->ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    struct epoll_event ev;
    ev.data.fd = tfd;
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) < 0) {
        print_err("Adding timer socket to epoll failed: %s", strerror(errno));
        close(epfd);
        close(tfd);
        kc->ma->free(events, kc->ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
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
    if (cmdline == NULL) {
        print_err("Creating buffer for command line failed");
        close(epfd);
        close(tfd);
        kc->ma->free(events, kc->ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    int nready;
    bool unrecoverable_error_occured = false;
    while (true) {
        if (unrecoverable_error_occured) goto client_close_fail;
        struct linenoiseState ls;
        char buf[BUF_SIZE];
        linenoiseEditStart(&ls, -1, -1, buf, sizeof(buf), prompt);
        ev.data.fd = ls.ifd;
        ev.events = EPOLLIN;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, ls.ifd, &ev) < 0) {
            print_err("Adding ifd socket to epoll failed: %s", strerror(errno));
            linenoiseHide(&ls);
            goto client_close_fail;
        }
        bool editing_finished = false;
        while (!editing_finished) {
            errno = 0;
            nready = epoll_wait(epfd, events, MAX_EVENTS, -1);
            if (nready < 0) {
                if (errno == EINTR) continue;
                print_err("Waiting for epoll failed: %s", strerror(errno));
                linenoiseHide(&ls);
                goto client_close_fail;
            }
            for (int i = 0; i < nready; i++) {
                if (events[i].events == 0) continue;
                if (events[i].events & EPOLLERR) {
                    linenoiseHide(&ls);
                    goto client_close_fail;
                }
                if (events[i].data.fd == tfd) {
                    if (!kevue_client_ping(kc, resp)) {
                        print_err("%s", kevue_error_to_string(resp->err_code));
                        linenoiseHide(&ls);
                        goto client_close_fail;
                    }
                    uint64_t exp;
                    ssize_t res = read(tfd, &exp, sizeof(exp));
                    UNUSED(res);
                    continue;
                }
                line = linenoiseEditFeed(&ls);
                if (line != linenoiseEditMore) {
                    // these errno are set by linenoise
                    if (errno == EAGAIN || errno == ENOENT) { // Ctrl+C  Ctrl+D hit
                        linenoiseHide(&ls);
                        fprintf(stdout, "Exit? [Y/n]: ");
                        fflush(stdout);
                        int c = getchar();
                        if (c == 'Y' || c == 'y' || c == '\n') {
                            linenoiseHide(&ls);
                            goto client_close;
                        }
                        linenoiseShow(&ls);
                    } else {
                        editing_finished = true;
                    }
                }
            }
        }
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, ls.ifd, NULL) < 0) {
            print_err("Deleting ifd socket from epoll failed: %s", strerror(errno));
            linenoiseHide(&ls);
            goto client_close_fail;
        }
        linenoiseEditStop(&ls);
        if (line == NULL) break;
        if (line[0] == '\0') {
            free(line);
            continue;
        }
        if (!strncmp(line, "exit", 4) || !strncmp(line, "quit", 4) || !strncmp(line, "q", 1)) {
            free(line);
            goto client_close;
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
            } else {
                print_err("%s", kevue_error_to_string(resp->err_code));
                if (resp->err_code != KEVUE_ERR_NOT_FOUND) unrecoverable_error_occured = true;
            }
            break;
        case SET:
            if (kevue_client_set(kc, resp, pr->key->ptr, (uint16_t)pr->key->size, pr->value->ptr, (uint16_t)pr->value->size)) {
                printf("OK\n");
            } else {
                print_err("%s", kevue_error_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        case DEL:
            if (kevue_client_del(kc, resp, pr->key->ptr, (uint16_t)pr->key->size)) {
                printf("OK\n");
            } else {
                print_err("%s", kevue_error_to_string(resp->err_code));
                if (resp->err_code != KEVUE_ERR_NOT_FOUND) unrecoverable_error_occured = true;
            }
            break;
        case PING:
            if (kevue_client_ping_with_message(kc, resp, pr->key->ptr, (uint16_t)pr->key->size)) {
                fwrite(resp->val->ptr, sizeof(*resp->val->ptr), resp->val_len, stdout);
                fputc('\n', stdout);
                fflush(stdout);
            } else {
                print_err("%s", kevue_error_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        default:
            UNREACHABLE("Possibly forgot to add new command to switch case");
        }
        kevue_buffer_reset(cmdline);
        kevue__client_parse_result_destroy(pr);
        linenoiseHistoryAdd(line); /* Add to the history. */
        // TODO: save history to another location
        linenoiseHistorySave("history.txt"); /* Save the history on disk. */
        free(line);
    }
client_close:
    close(epfd);
    close(tfd);
    kc->ma->free(events, kc->ma->ctx);
    kevue_buffer_destroy(cmdline);
    kevue_buffer_destroy(resp->val);
    kc->ma->free(resp, kc->ma->ctx);
    kevue_client_destroy(kc);
    return 0;
client_close_fail:
    close(epfd);
    close(tfd);
    kc->ma->free(events, kc->ma->ctx);
    kevue_buffer_destroy(cmdline);
    kevue_buffer_destroy(resp->val);
    kc->ma->free(resp, kc->ma->ctx);
    kevue_client_destroy(kc);
    exit(EXIT_FAILURE);
}
