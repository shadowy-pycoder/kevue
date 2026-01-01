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

#include <stdbool.h>
#include <stddef.h>

#include <allocator.h>
#include <buffer.h>

typedef struct HashMap HashMap;

HashMap *kevue_hm_create(KevueAllocator *ma);
void kevue_hm_destroy(HashMap *hm);
bool kevue_hm_put(HashMap *hm, const void *key, size_t key_len, const void *val, size_t val_len);
bool kevue_hm_get(HashMap *hm, const void *key, size_t key_len, Buffer *buf);
bool kevue_hm_del(HashMap *hm, const void *key, size_t key_len);

// https://danielchasehooper.com/posts/typechecked-generic-c-data-structures/
#define HashMapTS(KT, VT) \
    union {               \
        HashMap *hm;      \
        KT *ktype;        \
        VT *vtype;        \
    }

#define map_value_ptr(x)   \
    _Generic((x),          \
        char *: (x),       \
        const char *: (x), \
        default: &(x))

#define kevue_hmts_create(ma) { .hm = kevue_hm_create(ma) }

#define kevue_hmts_destroy(hmts) kevue_hm_destroy((hmts)->hm);

#define kevue_hmts_put(hmts, key, key_len, val, val_len)                                              \
    kevue_hm_put((hmts)->hm, ((1 ? &(key) : (hmts)->ktype) ? map_value_ptr((key)) : NULL), (key_len), \
        ((1 ? &(val) : (hmts)->vtype) ? map_value_ptr((val)) : NULL), (val_len))

#define kevue_hmts_get(hmts, key, key_len, buf) \
    kevue_hm_get((hmts)->hm, ((1 ? &(key) : (hmts)->ktype) ? map_value_ptr((key)) : NULL), (key_len), (buf))

#define kevue_hmts_del(hmts, key, key_len) \
    kevue_hm_del((hmts)->hm, ((1 ? &(key) : (hmts)->ktype) ? map_value_ptr((key)) : NULL), (key_len))
