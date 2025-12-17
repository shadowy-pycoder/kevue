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
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <allocator.h>
#include <buffer.h>

Buffer *kevue_buffer_create(size_t capacity, KevueAllocator *ma)
{
    Buffer *buf = (Buffer *)ma->malloc(sizeof(Buffer), ma->ctx);
    assert(buf != NULL);
    memset(buf, 0, sizeof(Buffer));
    buf->ma = ma;
    buf->ptr = (char *)buf->ma->malloc(sizeof(char) * capacity, buf->ma->ctx);
    assert(buf->ptr != NULL);
    buf->capacity = capacity;
    return buf;
}

void kevue_buffer_reset(Buffer *buf)
{
    buf->size = 0;
    buf->offset = 0;
}

void kevue_buffer_destroy(Buffer *buf)
{
    if (buf == NULL) return;
    buf->ma->free(buf->ptr, buf->ma->ctx);
    buf->ma->free(buf, buf->ma->ctx);
}

void kevue_buffer_grow(Buffer *buf, size_t n)
{
    if (buf->capacity >= n) return;
    buf->ptr = (char *)buf->ma->realloc(buf->ptr, n * sizeof(*buf->ptr), buf->ma->ctx);
    assert(buf->ptr != NULL);
    buf->capacity = n;
}

size_t kevue_buffer_append(Buffer *buf, void *data, size_t n)
{
    size_t initial_capacity = buf->capacity;
    while (buf->capacity <= buf->size + n) {
        buf->capacity *= 2;
    }
    if (buf->capacity > initial_capacity) {
        buf->ptr = (char *)buf->ma->realloc(buf->ptr, buf->capacity * sizeof(*buf->ptr), buf->ma->ctx);
        assert(buf->ptr != NULL);
    }
    memcpy(buf->ptr + buf->size, data, n * sizeof(*buf->ptr));
    buf->size += n;
    return n;
}

size_t kevue_buffer_write(Buffer *buf, void *data, size_t n)
{
    size_t initial_capacity = buf->capacity;
    while (buf->capacity <= n) {
        buf->capacity *= 2;
    }
    if (buf->capacity > initial_capacity) {
        buf->ptr = (char *)buf->ma->realloc(buf->ptr, buf->capacity * sizeof(*buf->ptr), buf->ma->ctx);
        assert(buf->ptr != NULL);
    }
    memcpy(buf->ptr, data, n * sizeof(*buf->ptr));
    buf->size = n;
    return n;
}

int kevue_buffer_read_byte(Buffer *buf)
{
    if (kevue_buffer_at_eof(buf)) return EOF;
    return buf->ptr[buf->offset++];
}

void kevue_buffer_read_advance(Buffer *buf)
{
    buf->offset++;
}

int kevue_buffer_peek_byte(Buffer *buf)
{
    if (kevue_buffer_at_eof(buf)) return EOF;
    return buf->ptr[buf->offset];
}

void kevue_buffer_read_until(Buffer *buf, Buffer *out, char until)
{
    char c;
    while ((c = kevue_buffer_peek_byte(buf)) != EOF) {
        if (c == until) break;
        kevue_buffer_append(out, &c, sizeof(char));
        kevue_buffer_read_advance(buf);
    }
}

bool kevue_buffer_at_eof(Buffer *buf)
{
    return buf->offset >= buf->size;
}

void kevue_buffer_move_unread_bytes(Buffer *buf)
{
    if (kevue_buffer_at_eof(buf)) {
        kevue_buffer_reset(buf);
        return;
    }
    if (buf->size == 0 || buf->offset == 0) return;
    memmove(buf->ptr, buf->ptr + buf->offset, (buf->size - buf->offset) * sizeof(*buf->ptr));
    buf->size = buf->size - buf->offset;
    buf->offset = 0;
}

void kevue_buffer_print_hex(Buffer *buf)
{
    for (size_t i = 0; i < buf->size; i++) printf("%02x ", buf->ptr[i]);
    printf("\n");
}
