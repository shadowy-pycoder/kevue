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
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define HOST           "0.0.0.0"
#define PORT           "6973"
#define BUF_SIZE       (32 * 1024)
#define READ_TIMEOUT   10
#define WRITE_TIMEOUT  10
#define SERVER_WORKERS 10

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

#define UNUSED(v) (void)v

#define print_err(fmt, ...) \
    fprintf(stderr, "ERROR: %s: " fmt "\n", __func__, ##__VA_ARGS__)

#ifdef DEBUG
#define print_debug(fmt, ...) \
    fprintf(stdout, "DEBUG: %s:%d:%s: " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define print_debug(fmt, ...) ((void)0)
#endif

#define print_info(fmt, ...) fprintf(stdout, "INFO: " fmt "\n", ##__VA_ARGS__)

char *to_upper(char *s, size_t n);
const char *inet_ntop2(void *addr, char *buf, size_t size);
uint16_t ntohs2(void *addr);
size_t round_up_pow2(size_t x);
