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
 * @file buffer.c
 * @brief Bytes buffer implementation.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <allocator.h>
#include <buffer.h>
#include <common.h>

Buffer *kevue_buffer_create(u64 capacity)
{
    if (capacity == 0) capacity = KEVUE_INIT_CAP;
    KevueAllocator *ma = kevue_allocator();
    Buffer         *buf = (Buffer *)ma->malloc(sizeof(Buffer), ma->ctx);
    if (buf == NULL) return NULL;
    memset(buf, 0, sizeof(Buffer));
    buf->ptr = (u8 *)ma->malloc(sizeof(*buf->ptr) * capacity, ma->ctx);
    if (buf->ptr == NULL) {
        ma->free(buf, ma->ctx);
        return NULL;
    }
    buf->capacity = capacity;
    return buf;
}

void kevue_buffer_reset(Buffer *buf)
{
    if (buf == NULL) return;
    buf->size = 0;
    buf->offset = 0;
}

void kevue_buffer_destroy(Buffer *buf)
{
    if (buf == NULL) return;
    KevueAllocator *ma = kevue_allocator();
    ma->free(buf->ptr, ma->ctx);
    ma->free(buf, ma->ctx);
}

void kevue_buffer_grow(Buffer *buf, u64 n)
{
    if (buf == NULL) return;
    if (n == 0 || buf->capacity >= n) return;
    KevueAllocator *ma = kevue_allocator();
    buf->ptr = (u8 *)ma->realloc(buf->ptr, n * sizeof(*buf->ptr), ma->ctx);
    buf->capacity = n;
}

u64 kevue_buffer_append(Buffer *buf, const void *data, u64 n)
{
    if (buf == NULL || n == 0) return 0;
    if (buf->capacity == 0) buf->capacity = KEVUE_INIT_CAP;
    u64 initial_capacity = buf->capacity;
    while (buf->capacity < buf->size + n) {
        buf->capacity *= 2;
    }
    if (buf->ptr == NULL || buf->capacity > initial_capacity) {
        KevueAllocator *ma = kevue_allocator();
        buf->ptr = (u8 *)ma->realloc(buf->ptr, buf->capacity * sizeof(*buf->ptr), ma->ctx);
    }
    memcpy(buf->ptr + buf->size, data, n * sizeof(*buf->ptr));
    buf->size += n;
    return n;
}

u64 kevue_buffer_appendf(Buffer *buf, const char *fmt, ...)
{
    if (buf == NULL) return 0;
    if (buf->capacity == 0) buf->capacity = KEVUE_INIT_CAP;
    u64     initial_capacity = buf->capacity;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n <= 0) return 0;
    u64 len = (u64)n;
    while (buf->capacity < buf->size + len + 1) {
        buf->capacity *= 2;
    }
    if (buf->ptr == NULL || buf->capacity > initial_capacity) {
        KevueAllocator *ma = kevue_allocator();
        buf->ptr = (u8 *)ma->realloc(buf->ptr, buf->capacity * sizeof(*buf->ptr), ma->ctx);
    }
    va_start(ap, fmt);
    n = vsnprintf((char *)buf->ptr + buf->size, (size_t)(len + 1), fmt, ap);
    va_end(ap);
    if (n < 0) {
        return 0;
    }
    buf->size += len;
    return len;
}

u64 kevue_buffer_write(Buffer *buf, const void *data, u64 n)
{
    if (buf == NULL || n == 0) return 0;
    if (buf->capacity == 0) buf->capacity = KEVUE_INIT_CAP;
    u64 initial_capacity = buf->capacity;
    while (buf->capacity < n) {
        buf->capacity *= 2;
    }
    if (buf->ptr == NULL || buf->capacity > initial_capacity) {
        KevueAllocator *ma = kevue_allocator();
        buf->ptr = (u8 *)ma->realloc(buf->ptr, buf->capacity * sizeof(*buf->ptr), ma->ctx);
    }
    memcpy(buf->ptr, data, n * sizeof(*buf->ptr));
    buf->size = n;
    return n;
}

u64 kevue_buffer_writef(Buffer *buf, const char *fmt, ...)
{
    if (buf == NULL) return 0;
    if (buf->capacity == 0) buf->capacity = KEVUE_INIT_CAP;
    u64     initial_capacity = buf->capacity;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n <= 0) return 0;
    u64 len = (u64)n;
    while (buf->capacity < len + 1) {
        buf->capacity *= 2;
    }
    if (buf->ptr == NULL || buf->capacity > initial_capacity) {
        KevueAllocator *ma = kevue_allocator();
        buf->ptr = (u8 *)ma->realloc(buf->ptr, buf->capacity * sizeof(*buf->ptr), ma->ctx);
    }
    va_start(ap, fmt);
    n = vsnprintf((char *)buf->ptr, (size_t)(len + 1), fmt, ap);
    va_end(ap);
    if (n < 0) {
        return 0;
    }
    buf->size = len;
    return len;
}

int kevue_buffer_read_byte(Buffer *buf)
{
    if (kevue_buffer_at_eof(buf)) return EOF;
    return buf->ptr[buf->offset++];
}

void kevue_buffer_read_advance(Buffer *buf)
{
    if (buf == NULL) return;
    buf->offset++;
}

int kevue_buffer_peek_byte(Buffer *buf)
{
    if (kevue_buffer_at_eof(buf)) return EOF;
    return buf->ptr[buf->offset];
}

void kevue_buffer_read_until(Buffer *buf, Buffer *out, char until)
{
    if (buf == NULL || out == NULL) return;
    char c;
    while ((c = (char)kevue_buffer_peek_byte(buf)) != EOF) {
        if (c == until) break;
        kevue_buffer_append(out, &c, sizeof(char));
        kevue_buffer_read_advance(buf);
    }
}

bool kevue_buffer_at_eof(Buffer *buf)
{
    if (buf == NULL) return true;
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
    if (buf == NULL) return;
    for (u64 i = 0; i < buf->size; i++) printf("%02x ", buf->ptr[i]);
    printf("\n");
}
