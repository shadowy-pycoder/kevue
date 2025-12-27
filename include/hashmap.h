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
bool kevue_hm_put(HashMap *hm, char *key, size_t key_len, char *val, size_t val_len);
bool kevue_hm_get(HashMap *hm, char *key, size_t key_len, Buffer *buf);
bool kevue_hm_del(HashMap *hm, char *key, size_t key_len);
