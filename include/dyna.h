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

#include <assert.h>
#include <stddef.h>
#include <string.h>

// typedef struct DynamicArray {
//     T *ptr;
//     size_t len;
//     size_t cap;
//     KevueAllocator *ma;
// } DynamicArray;

#define kevue_dyna_init(dyna, capacity, alloc)                                                \
    do {                                                                                      \
        assert((dyna) != NULL);                                                               \
        memset((dyna), 0, sizeof(*(dyna)));                                                   \
        (dyna)->ma = (alloc);                                                                 \
        (dyna)->ptr = (dyna)->ma->malloc((capacity) * sizeof(*(dyna)->ptr), (dyna)->ma->ctx); \
        assert((dyna)->ptr != NULL);                                                          \
        (dyna)->cap = (capacity);                                                             \
    } while (0)

#define kevue_dyna_deinit(dyna)                         \
    do {                                                \
        assert((dyna) != NULL);                         \
        assert((dyna)->ptr != NULL);                    \
        (dyna)->ma->free((dyna)->ptr, (dyna)->ma->ctx); \
        (dyna)->ptr = NULL;                             \
    } while (0)

// stolen from https://github.com/tsoding/nob.h
#define kevue_dyna_append(dyna, item)                                                                            \
    do {                                                                                                         \
        size_t initial_cap = (dyna)->cap;                                                                        \
        while ((dyna)->cap <= (dyna)->len + 1) (dyna)->cap *= 2;                                                 \
        if ((dyna)->cap > initial_cap) {                                                                         \
            (dyna)->ptr = (dyna)->ma->realloc((dyna)->ptr, (dyna)->cap * sizeof(*(dyna)->ptr), (dyna)->ma->ctx); \
            assert((dyna)->ptr != NULL);                                                                         \
        }                                                                                                        \
        (dyna)->ptr[(dyna)->len++] = (item);                                                                     \
    } while (0)

#define kevue_dyna_remove(dyna, index)                             \
    do {                                                           \
        size_t index_to_remove = (index);                          \
        assert(index_to_remove < (dyna)->len);                     \
        (dyna)->ptr[index_to_remove] = (dyna)->ptr[--(dyna)->len]; \
    } while (0)

#if defined(__GNUC__) || defined(__clang__)
#if __clang__
#define kevue_dyna_foreach(dyna, it) for (__typeof__((dyna)->ptr) it = (dyna)->ptr; it < (dyna)->ptr + (dyna)->len; it++)
#else
#define kevue_dyna_foreach(dyna, it) for (typeof((dyna)->ptr) it = (dyna)->ptr; it < (dyna)->ptr + (dyna)->len; it++)
#endif
#else
#define kevue_dyna_foreach(dyna, T, it) for (T *it = (dyna)->ptr; it < (dyna)->ptr + (dyna)->len; it++)
#endif

#define kevue_dyna_grow(dyna, n)                                                                         \
    do {                                                                                                 \
        if ((dyna)->cap < (n)) {                                                                         \
            (dyna)->ptr = (dyna)->ma->realloc((dyna)->ptr, (n) * sizeof(*(dyna)->ptr), (dyna)->ma->ctx); \
            assert((dyna)->ptr != NULL);                                                                 \
            (dyna)->cap = (n);                                                                           \
        }                                                                                                \
    } while (0)
