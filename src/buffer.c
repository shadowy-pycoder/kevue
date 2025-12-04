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
#include <stdlib.h>
#include <string.h>

#include <buffer.h>

Buffer *buffer_create(size_t capacity)
{
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    assert(buf != NULL);
    memset(buf, 0, sizeof(Buffer));
    buf->ptr = (char *)malloc(sizeof(char) * capacity);
    assert(buf->ptr != NULL);
    buf->capacity = capacity;
    return buf;
}

void buffer_reset(Buffer *buf)
{
    buf->size = 0;
    buf->offset = 0;
}

void buffer_destroy(Buffer *buf)
{
    free(buf->ptr);
    free(buf);
    buf = NULL;
}

void buffer_grow(Buffer *buf, size_t n)
{
    buf->ptr = (char *)realloc(buf->ptr, buf->capacity + n);
    assert(buf->ptr != NULL);
    buf->capacity += n;
}

size_t buffer_append(Buffer *buf, char *data, size_t n)
{
    size_t initial_capacity = buf->capacity;
    while (buf->capacity <= buf->size + n) {
        buf->capacity *= 2;
    }
    if (buf->capacity > initial_capacity) {
        buf->ptr = (char *)realloc(buf->ptr, buf->capacity);
        assert(buf->ptr != NULL);
    }
    memcpy(buf->ptr + buf->size, data, n);
    buf->size += n;
    return n;
}

void buffer_move_unread_bytes(Buffer *buf)
{
    if (buf->size == 0 || buf->offset == 0 || buf->offset == buf->size) return;
    memmove(buf->ptr, buf->ptr + buf->offset, buf->size - buf->offset);
    buf->size = buf->size - buf->offset;
    buf->offset = 0;
}
