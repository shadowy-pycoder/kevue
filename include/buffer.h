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

typedef struct Buffer {
    char *ptr;
    size_t size;
    size_t offset;
    size_t capacity;
} Buffer;

Buffer *buffer_create(size_t capacity);
size_t buffer_append(Buffer *buf, char *data, size_t n);
void buffer_grow(Buffer *buf, size_t n);
void buffer_reset(Buffer *buf);
void buffer_destroy(Buffer *buf);
void buffer_move_unread_bytes(Buffer *buf);
