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
 * @file common.h
 * @brief Helper functions and macro.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define KEVUE_HOST           "0.0.0.0"
#define KEVUE_PORT           "12111"
#define KEVUE_UNIX_SOCK_PATH "/tmp/kevue.sock"
#define BUF_SIZE             (32 * 1024)
#define READ_TIMEOUT         10
#define WRITE_TIMEOUT        10

#if !defined(VERSION)
#define VERSION "0.0.1"
#endif

#if defined(__linux__)
#define OS "Linux"
#elif defined(_WIN32) || defined(_WIN64)
#define OS "Windows"
#elif defined(__APPLE__) && defined(__MACH__)
#define OS "macOS"
#elif defined(__FreeBSD__)
#define OS "FreeBSD"
#elif defined(__NetBSD__)
#define OS "NetBSD"
#elif defined(__OpenBSD__)
#define OS "OpenBSD"
#elif defined(__DragonFly__)
#define OS "DragonFly BSD"
#elif defined(__unix__)
#define OS "Unix"
#else
#define OS "Unknown OS"
#endif

#if defined(__x86_64__) || defined(_M_X64)
#define ARCH "x86_64"
#elif defined(__i386__) || defined(_M_IX86)
#define ARCH "x86"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define ARCH "arm64"
#elif defined(__arm__) || defined(_M_ARM)
#define ARCH "arm"
#elif defined(__riscv) && (__riscv_xlen == 64)
#define ARCH "riscv64"
#elif defined(__riscv) && (__riscv_xlen == 32)
#define ARCH "riscv32"
#elif defined(__ppc64__) || defined(__powerpc64__)
#define ARCH "ppc64"
#elif defined(__ppc__) || defined(__powerpc__)
#define ARCH "ppc"
#elif defined(__s390x__)
#define ARCH "s390x"
#else
#define ARCH "Unknown arch"
#endif

// stolen from https://github.com/tsoding/nob.h
#define UNREACHABLE(where)                                                                  \
    do {                                                                                    \
        fprintf(stderr, "%s:%d:%s UNREACHABLE: %s\n", __FILE__, __LINE__, __func__, where); \
        exit(EXIT_FAILURE);                                                                 \
    } while (0)

#define TODO(what)                                                                  \
    do {                                                                            \
        fprintf(stderr, "%s:%d:%s TODO: %s\n", __FILE__, __LINE__, __func__, what); \
        exit(EXIT_FAILURE);                                                         \
    } while (0)

#define UNUSED(v) ((void)v)

#define print_err(ts, fmt, ...) \
    fprintf(stderr, "[%s] ERROR: %s: " fmt "\n", ts, __func__, ##__VA_ARGS__)

#ifdef DEBUG
#define print_debug(ts, fmt, ...) \
    fprintf(stdout, "[%s] DEBUG: %s:%d:%s: " fmt "\n", ts, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define print_debug(ts, fmt, ...) ((void)0)
#endif

#define print_info(ts, fmt, ...) fprintf(stdout, "[%s] INFO: " fmt "\n", ts, ##__VA_ARGS__)

#if defined(__GNUC__) || defined(__clang__)
#define max(a, b) ({        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
})
#define min(a, b) ({        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
})
#else
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#define is_pow2(x) ((x) && (((x) & ((x) - 1)) == 0))

/**
 *  Convert string @p s to upper case and return it.
 */
char *to_upper(char *s, size_t n);

/**
 * Wrapper for @c inet_ntop with dispatching for IPv4 and IPv6 addresses.
 */
const char *inet_ntop2(void *addr, char *buf, size_t size);

/**
 * Wrapper for @c ntohs with dispatching for IPv4 and IPv6 addresses and ports.
 */
uint16_t ntohs2(void *addr);

/**
 * Round up @p x to the nearest power of 2.
 */
size_t round_up_pow2(size_t x);

/**
 * @brief Generates a random 64-bit value.
 *
 * @param x  Receives the random value.
 *
 * @return true on success, false on failure.
 *
 * @note Uses a system entropy source.
 * @note On Linux, failures originate from getrandom(2) and
 *       set errno accordingly.
 */
bool random_u64(uint64_t *x);

/**
 * @brief Returns the current monotonic time in nanoseconds.
 *
 * @return Current time in nanoseconds.
 *
 * @note Uses a monotonic clock source not subject to wall-clock changes.
 * @note On Linux, this is backed by clock_gettime(CLOCK_MONOTONIC_RAW).
 * @note Suitable for interval measurement and benchmarking.
 */
uint64_t nsec_now(void);

/**
 * @brief Generates a formatted timestamp string.
 *
 * @note Format is "YYYY-MM-DD HH:MM:SS.nnnnnnnnnZ"
 */
const char *generate_timestamp(void);

/**
 * @brief Check if provided port string is within (0, 65535] range.
 */
bool is_valid_port(char *port);

/**
 * @brief Check if provided addr string is valid IPv4/IPv6.
 */
bool is_valid_ip(const char *addr);
