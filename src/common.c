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
 * @file common.c
 * @brief Helper functions implementation.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <threads.h>
#include <time.h>

#include <common.h>

char *to_upper(char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        s[i] = (char)toupper(s[i]);
    return s;
}

// https://beej.us/guide/bgnet/html/split/slightly-advanced-techniques.html#poll
const char *inet_ntop2(void *addr, char *buf, size_t size)
{
    struct sockaddr_storage *sas = addr;
    struct sockaddr_in      *sa4;
    struct sockaddr_in6     *sa6;
    void                    *src;

    switch (sas->ss_family) {
    case AF_INET:
        sa4 = addr;
        src = &(sa4->sin_addr);
        break;
    case AF_INET6:
        sa6 = addr;
        src = &(sa6->sin6_addr);
        break;
    default:
        return NULL;
    }
    return inet_ntop(sas->ss_family, src, buf, (socklen_t)size);
}

uint16_t ntohs2(void *addr)
{
    struct sockaddr_storage *sas = addr;
    struct sockaddr_in      *sa4;
    struct sockaddr_in6     *sa6;
    uint16_t                 port = 0;
    switch (sas->ss_family) {
    case AF_INET:
        sa4 = addr;
        port = sa4->sin_port;
        break;
    case AF_INET6:
        sa6 = addr;
        port = sa6->sin6_port;
        break;
    default:
        return 0;
    }
    return ntohs(port);
}

size_t round_up_pow2(size_t x)
{
    if (x <= 1)
        return 1;

    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
#if SIZE_MAX > UINT32_MAX
    x |= x >> 32;
#endif
    return x + 1;
}

bool random_u64(uint64_t *x)
{
    ssize_t n;
    do {
        n = getrandom(x, sizeof(*x), 0);
    } while (n < 0 && errno == EINTR);

    if (n != sizeof(*x)) return false;

    return true;
}

uint64_t nsec_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

const char *generate_timestamp(void)
{
    static thread_local char buf[32];

    struct timespec ts;
    struct tm       tm;

    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);

    size_t n = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(buf + n, sizeof(buf) - n, ".%09ldZ", ts.tv_nsec);

    return buf;
}

bool is_valid_port(char *port)
{
    char         *end;
    unsigned long val;
    errno = 0;
    val = strtoul(port, &end, 10);
    if (errno) return false;
    if (end == port || *end != '\0') return false;
    if (val == 0 || val > 65535) return false;
    return true;
}

bool is_valid_ip(const char *addr)
{
    return inet_pton(AF_INET, addr, &(struct in_addr) {}) == 1 || inet_pton(AF_INET6, addr, &(struct in6_addr) {}) == 1;
}
