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

typedef struct Buffer {
    char *ptr;
    size_t size;
    size_t offset;
    size_t capacity;
    KevueAllocator *ma;
} Buffer;

Buffer *kevue_buffer_create(size_t capacity, KevueAllocator *ma);
size_t kevue_buffer_append(Buffer *buf, void *data, size_t n);
size_t kevue_buffer_write(Buffer *buf, void *data, size_t n);
int kevue_buffer_read_byte(Buffer *buf);
void kevue_buffer_read_advance(Buffer *buf);
int kevue_buffer_peek_byte(Buffer *buf);
void kevue_buffer_read_until(Buffer *buf, Buffer *out, char until);
bool kevue_buffer_at_eof(Buffer *buf);
void kevue_buffer_grow(Buffer *buf, size_t n);
void kevue_buffer_reset(Buffer *buf);
void kevue_buffer_destroy(Buffer *buf);
void kevue_buffer_move_unread_bytes(Buffer *buf);
void kevue_buffer_print_hex(Buffer *buf);
