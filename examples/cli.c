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
 * @file cli.c
 * @brief kevue client CLI example.
 */

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <linenoise.h>

#include <allocator.h>
#include <client.h>
#include <common.h>

#define PING_INTERVAL_SECONDS 15
#define PROMPT_LENGTH         INET6_ADDRSTRLEN + 7 + 1
#define MAX_EVENTS            2

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#ifdef USE_TCMALLOC
#include <tcmalloc_allocator.h>
#endif
#ifdef USE_JEMALLOC
#include <jemalloc_allocator.h>
#endif

typedef struct KevueClientParseResult {
    KevueCommand    cmd;
    Buffer         *key;
    Buffer         *value;
    KevueAllocator *ma;
} KevueClientParseResult;

static void kevue__usage(void);
static bool kevue__parse_chunk(Buffer *buf, Buffer *out);
static void kevue__trim_left(Buffer *buf);
static KevueClientParseResult *kevue__parse_command_line(Buffer *buf);
static void kevue__client_parse_result_destroy(KevueClientParseResult *pr);
static void kevue__completion(const char *buf, linenoiseCompletions *lc);
static char *kevue__hints(const char *buf, int *color, int *bold);

static void kevue__usage(void)
{
    printf("Usage: kevue-client <host> <port>\n");
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

static void kevue__completion(const char *buf, linenoiseCompletions *lc)
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
    case 'c':
    case 'C':
        linenoiseAddCompletion(lc, "COUNT");
        break;
    case 'i':
    case 'I':
        linenoiseAddCompletion(lc, "ITEMS");
        break;
    case 'k':
    case 'K':
        linenoiseAddCompletion(lc, "KEYS");
        break;
    case 'v':
    case 'V':
        linenoiseAddCompletion(lc, "VALUES");
        break;
    default:
        linenoiseAddCompletion(lc, "GET");
        break;
    }
    return;
}

static char *kevue__hints(const char *buf, int *color, int *bold)
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

static KevueClientParseResult *kevue__parse_command_line(Buffer *buf)
{
    // TODO: improve command dispatching
    KevueAllocator         *ma = buf->ma;
    KevueClientParseResult *pr = (KevueClientParseResult *)ma->malloc(sizeof(KevueClientParseResult), ma->ctx);
    if (pr == NULL) return NULL;
    memset(pr, 0, sizeof(*pr));
    pr->ma = ma;
    pr->key = kevue_buffer_create(BUF_SIZE, pr->ma);
    if (pr->key == NULL) {
        fprintf(stdout, "(error): Out of memory\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    kevue__trim_left(buf);
    if (kevue_buffer_at_eof(buf)) {
        fprintf(stdout, "(error): Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (!kevue__parse_chunk(buf, pr->key)) {
        fprintf(stdout, "(error): Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    switch ((uint8_t)pr->key->size) {
    case 3:
        if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, GET)) {
            pr->cmd = GET;
        } else if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, SET)) {
            pr->cmd = SET;
        } else if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, DEL)) {
            pr->cmd = DEL;
        } else {
            fprintf(stdout, "(error): Wrong command\n");
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
        break;
    case 4:
        if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, PING)) {
            pr->cmd = PING;
        } else if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, KEYS)) {
            pr->cmd = KEYS;
        } else {
            fprintf(stdout, "(error): Wrong command\n");
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
        break;
    case 5:
        if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, COUNT)) {
            pr->cmd = COUNT;
        } else if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, ITEMS)) {
            pr->cmd = ITEMS;
        } else {
            fprintf(stdout, "(error): Wrong command\n");
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
        break;
    case 6:
        if (kevue_command_compare((char *)pr->key->ptr, (uint8_t)pr->key->size, VALUES)) {
            pr->cmd = VALUES;
        } else {
            fprintf(stdout, "(error): Wrong command\n");
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
        break;
    default:
        fprintf(stdout, "(error): Wrong command\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    size_t offset = buf->offset;
    kevue__trim_left(buf);
    if (buf->offset == offset && (pr->cmd != PING && pr->cmd != COUNT && pr->cmd != ITEMS && pr->cmd != KEYS && pr->cmd != VALUES)) {
        fprintf(stdout, "(error): Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (kevue_buffer_at_eof(buf) && (pr->cmd != PING && pr->cmd != COUNT && pr->cmd != ITEMS && pr->cmd != KEYS && pr->cmd != VALUES)) {
        fprintf(stdout, "(error): Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    kevue_buffer_reset(pr->key);
    // parse first argument
    offset = buf->offset;
    if (!kevue__parse_chunk(buf, pr->key)) {
        fprintf(stdout, "(error): Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    // check for commands with 0 arguments
    if (buf->offset != offset && (pr->cmd == COUNT || pr->cmd == ITEMS || pr->cmd == KEYS || pr->cmd == VALUES)) {
        fprintf(stdout, "(error): Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    offset = buf->offset;
    kevue__trim_left(buf);
    if (buf->offset == offset && pr->cmd == SET) {
        fprintf(stdout, "(error): Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    if (kevue_buffer_at_eof(buf)) {
        if (pr->cmd == SET) {
            fprintf(stdout, "(error): Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
    } else {
        if (pr->cmd != SET) {
            fprintf(stdout, "(error): Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
            kevue__client_parse_result_destroy(pr);
            return NULL;
        }
    }
    pr->value = kevue_buffer_create(BUF_SIZE, pr->ma);
    if (pr->value == NULL) {
        fprintf(stdout, "(error): Out of memory\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    kevue_buffer_reset(pr->value);
    if (!kevue__parse_chunk(buf, pr->value)) {
        fprintf(stdout, "(error): Wrong arguments\n");
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    kevue__trim_left(buf);
    if (!kevue_buffer_at_eof(buf)) {
        fprintf(stdout, "(error): Wrong number of arguments for '%s' command\n", kevue_command_to_string(pr->cmd));
        kevue__client_parse_result_destroy(pr);
        return NULL;
    }
    return pr;
}

static void kevue__client_parse_result_destroy(KevueClientParseResult *pr)
{
    kevue_buffer_destroy(pr->key);
    kevue_buffer_destroy(pr->value);
    pr->ma->free(pr, pr->ma->ctx);
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
    KevueAllocator *ma = &kevue_default_allocator;
#if defined(USE_TCMALLOC)
    ma = &kevue_tcmalloc_allocator;
#elif defined(USE_JEMALLOC)
    ma = &kevue_jemalloc_allocator;
#endif
    KevueClient *kc = kevue_client_create(host, port, ma);
    if (kc == NULL) exit(EXIT_FAILURE);
    print_info(generate_timestamp(), "Connected to %s:%s", host, port);
    KevueResponse *resp = (KevueResponse *)ma->malloc(sizeof(KevueResponse), ma->ctx);
    if (resp == NULL) {
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    memset(resp, 0, sizeof(*resp));
    if (!kevue_client_hello(kc, resp)) {
        print_err(generate_timestamp(), "%s", kevue_error_code_to_string(resp->err_code));
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    struct epoll_event *events = ma->malloc(sizeof(struct epoll_event) * MAX_EVENTS, ma->ctx);
    if (events == NULL) {
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        print_err(generate_timestamp(), "Creating epoll file descriptor failed %s", strerror(errno));
        ma->free(events, ma->ctx);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (tfd < 0) {
        print_err(generate_timestamp(), "Creating timer socket failed: %s", strerror(errno));
        close(epfd);
        ma->free(events, ma->ctx);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    struct itimerspec timer = { 0 };
    timer.it_value.tv_sec = PING_INTERVAL_SECONDS;
    timer.it_interval.tv_sec = PING_INTERVAL_SECONDS;
    if (timerfd_settime(tfd, 0, &timer, NULL) < 0) {
        print_err(generate_timestamp(), "Setting timer failed: %s", strerror(errno));
        close(epfd);
        close(tfd);
        ma->free(events, ma->ctx);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    struct epoll_event ev;
    ev.data.fd = tfd;
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) < 0) {
        print_err(generate_timestamp(), "Adding timer socket to epoll failed: %s", strerror(errno));
        close(epfd);
        close(tfd);
        ma->free(events, ma->ctx);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    linenoiseSetCompletionCallback(kevue__completion);
    linenoiseSetHintsCallback(kevue__hints);
    linenoiseHistoryLoad("history.txt");
    linenoiseSetMultiLine(1);
    char prompt[PROMPT_LENGTH];
    int  n = snprintf(prompt, PROMPT_LENGTH - 1, "%s:%s> ", host, port);
    prompt[n] = '\0';
    Buffer *cmdline = kevue_buffer_create(BUF_SIZE, ma);
    if (cmdline == NULL) {
        print_err(generate_timestamp(), "Creating buffer for command line failed");
        close(epfd);
        close(tfd);
        ma->free(events, ma->ctx);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    int  nready;
    bool unrecoverable_error_occured = false;
    while (true) {
        if (unrecoverable_error_occured) goto client_close_fail;
        struct linenoiseState ls;
        char                  buf[BUF_SIZE];
        linenoiseEditStart(&ls, -1, -1, buf, sizeof(buf), prompt);
        ev.data.fd = ls.ifd;
        ev.events = EPOLLIN;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, ls.ifd, &ev) < 0) {
            fprintf(stdout, "(error): Adding ifd socket to epoll failed: %s\n", strerror(errno));
            linenoiseHide(&ls);
            goto client_close_fail;
        }
        bool editing_finished = false;
        while (!editing_finished) {
            errno = 0;
            nready = epoll_wait(epfd, events, MAX_EVENTS, -1);
            if (nready < 0) {
                if (errno == EINTR) continue;
                fprintf(stdout, "(error): Waiting for epoll failed: %s\n", strerror(errno));
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
                        fprintf(stdout, "(error): Server closed connection\n");
                        linenoiseHide(&ls);
                        goto client_close_fail;
                    }
                    uint64_t exp;
                    ssize_t  res = read(tfd, &exp, sizeof(exp));
                    UNUSED(res);
                    continue;
                }
                line = linenoiseEditFeed(&ls);
                if (line != linenoiseEditMore) {
                    // these errno are set by linenoise
                    if (errno == EAGAIN || errno == ENOENT) { // Ctrl+C  Ctrl+D hit
                        linenoiseHide(&ls);
                        fprintf(stdout, "Exit? (Y/n): ");
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
            fprintf(stdout, "(error): Deleting ifd socket from epoll failed: %s\n", strerror(errno));
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
        linenoiseHide(&ls);
        switch (pr->cmd) {
        case GET:
            if (kevue_client_get(kc, resp, pr->key->ptr, (uint16_t)pr->key->size)) {
                fwrite(resp->val->ptr, sizeof(*resp->val->ptr), resp->val_len, stdout);
                fwrite("\n", 1, 1, stdout);
            } else {
                if (resp->err_code == KEVUE_ERR_NOT_FOUND) {
                    fprintf(stdout, "(not found)\n");
                } else {
                    fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                    unrecoverable_error_occured = true;
                }
            }
            break;
        case SET:
            if (kevue_client_set(kc, resp, pr->key->ptr, (uint16_t)pr->key->size, pr->value->ptr, (uint16_t)pr->value->size)) {
                fprintf(stdout, "(ok)\n");
            } else {
                fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        case DEL:
            if (kevue_client_del(kc, resp, pr->key->ptr, (uint16_t)pr->key->size)) {
                fprintf(stdout, "(ok)\n");
            } else {
                if (resp->err_code == KEVUE_ERR_NOT_FOUND) {
                    fprintf(stdout, "(not found)\n");
                } else {
                    fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                    unrecoverable_error_occured = true;
                }
            }
            break;
        case PING:
            if (kevue_client_ping_with_message(kc, resp, pr->key->ptr, (uint16_t)pr->key->size)) {
                fwrite(resp->val->ptr, sizeof(*resp->val->ptr), resp->val_len, stdout);
                fwrite("\n", 1, 1, stdout);
            } else {
                fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        case COUNT:
            if (kevue_client_count(kc, resp)) {
                uint64_t count;
                memcpy(&count, resp->val->ptr, sizeof(count));
                fprintf(stdout, "%lu\n", count);
            } else {
                fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        case ITEMS:
            if (kevue_client_items(kc, resp)) {
                if (resp->val_len == 0) {
                    fprintf(stdout, "(empty)\n");
                } else {
                    uint64_t v;
                    size_t   size_v = sizeof(v);
                    size_t   count = 0;
                    while (resp->val->offset + size_v < resp->val_len) {
                        memcpy(&v, resp->val->ptr + resp->val->offset, size_v);
                        resp->val->offset += size_v;
                        char c[64];
                        int  clen = snprintf(c, sizeof(c), "%zu) ", count);
                        fwrite(c, 1, (size_t)clen, stdout);
                        fwrite(resp->val->ptr + resp->val->offset, sizeof(*resp->val->ptr), v, stdout);
                        fwrite("\n", 1, 1, stdout);
                        resp->val->offset += v;
                        memcpy(&v, resp->val->ptr + resp->val->offset, size_v);
                        resp->val->offset += size_v;
                        clen = snprintf(c, sizeof(c), "%zu) ", count);
                        fwrite(c, 1, (size_t)clen, stdout);
                        fwrite(resp->val->ptr + resp->val->offset, sizeof(*resp->val->ptr), v, stdout);
                        fwrite("\n", 1, 1, stdout);
                        resp->val->offset += v;
                        count++;
                    }
                }
            } else {
                fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        case KEYS:
            if (kevue_client_keys(kc, resp)) {
                if (resp->val_len == 0) {
                    fprintf(stdout, "(empty)\n");
                } else {
                    uint64_t v;
                    size_t   size_v = sizeof(v);
                    size_t   count = 0;
                    while (resp->val->offset + size_v < resp->val_len) {
                        memcpy(&v, resp->val->ptr + resp->val->offset, size_v);
                        resp->val->offset += size_v;
                        char c[64];
                        int  clen = snprintf(c, sizeof(c), "%zu) ", count);
                        fwrite(c, 1, (size_t)clen, stdout);
                        fwrite(resp->val->ptr + resp->val->offset, sizeof(*resp->val->ptr), v, stdout);
                        fwrite("\n", 1, 1, stdout);
                        resp->val->offset += v;
                        count++;
                    }
                }
            } else {
                fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        case VALUES:
            if (kevue_client_values(kc, resp)) {
                if (resp->val_len == 0) {
                    fprintf(stdout, "(empty)\n");
                } else {
                    uint64_t v;
                    size_t   size_v = sizeof(v);
                    size_t   count = 0;
                    while (resp->val->offset + size_v < resp->val_len) {
                        memcpy(&v, resp->val->ptr + resp->val->offset, size_v);
                        resp->val->offset += size_v;
                        char c[64];
                        int  clen = snprintf(c, sizeof(c), "%zu) ", count);
                        fwrite(c, 1, (size_t)clen, stdout);
                        fwrite(resp->val->ptr + resp->val->offset, sizeof(*resp->val->ptr), v, stdout);
                        fwrite("\n", 1, 1, stdout);
                        resp->val->offset += v;
                        count++;
                    }
                }
            } else {
                fprintf(stdout, "(error): %s\n", kevue_error_code_to_string(resp->err_code));
                unrecoverable_error_occured = true;
            }
            break;
        case HELLO:
            UNREACHABLE("HELLO command shouldn't be handled in parser");
        case KEVUE_CMD_MAX:
            UNREACHABLE("KEVUE_CMD_MAX command shouldn't be handled in parser");
        default:
            UNREACHABLE("Possibly forgot to add new command to switch case");
        }
        fflush(stdout);
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
    ma->free(events, ma->ctx);
    kevue_buffer_destroy(cmdline);
    kevue_buffer_destroy(resp->val);
    ma->free(resp, ma->ctx);
    kevue_client_destroy(kc);
    return 0;
client_close_fail:
    close(epfd);
    close(tfd);
    ma->free(events, ma->ctx);
    kevue_buffer_destroy(cmdline);
    kevue_buffer_destroy(resp->val);
    ma->free(resp, ma->ctx);
    kevue_client_destroy(kc);
    exit(EXIT_FAILURE);
}
