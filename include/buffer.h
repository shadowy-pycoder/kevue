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
 * @file buffer.h
 * @brief Bytes buffer API.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <allocator.h>

typedef struct Buffer {
    uint8_t        *ptr;
    size_t          size;
    size_t          offset;
    size_t          capacity;
    KevueAllocator *ma;
} Buffer;

/**
 * @brief Creates a new buffer with the specified initial capacity.
 *
 * Memory is allocated using the provided allocator.
 *
 * @param capacity  Initial buffer capacity in bytes.
 * @param ma        Allocator to use for memory management.
 *
 * @return Pointer to a newly created buffer, or NULL on failure.
 */
Buffer *kevue_buffer_create(size_t capacity, KevueAllocator *ma);

/**
 * @brief Destroys a buffer and releases all associated resources.
 *
 * @param buf  Buffer to destroy.
 */
void kevue_buffer_destroy(Buffer *buf);

/**
 * @brief Appends data to the end of the buffer.
 *
 * The buffer grows automatically if necessary.
 *
 * @param buf   Target buffer.
 * @param data  Data to append.
 * @param n     Number of bytes to append.
 *
 * @return Number of bytes appended.
 * @pre Capacity must be greater than 0
 */
size_t kevue_buffer_append(Buffer *buf, const void *data, size_t n);

/**
 * @brief Writes data to the start of the buffer.
 *
 * Advances the buffer size by @p n bytes.
 *
 * @param buf   Target buffer.
 * @param data  Data to write.
 * @param n     Number of bytes to write.
 *
 * @return Number of bytes written.
 * @pre Capacity must be greater than 0
 */
size_t kevue_buffer_write(Buffer *buf, const void *data, size_t n);

/**
 * @brief Reads a single byte from the buffer.
 *
 * Advances the read position by one byte.
 *
 * @param buf  Source buffer.
 *
 * @return The byte read or EOF if no data is available.
 */
int kevue_buffer_read_byte(Buffer *buf);

/**
 * @brief Advances the read position by one byte.
 *
 * @param buf  Source buffer.
 */
void kevue_buffer_read_advance(Buffer *buf);

/**
 * @brief Peeks at the next byte in the buffer without advancing the read position.
 *
 * @param buf  Source buffer.
 *
 * @return The next byte or EOF if no data is available.
 */
int kevue_buffer_peek_byte(Buffer *buf);

/**
 * @brief Reads bytes from the buffer until a delimiter is encountered.
 *
 * Bytes are copied into @p out until the character @p until is found
 * or the buffer is exhausted. Caller should check the first unread byte from source buffer
 * (e.g. with `kevue_buffer_peek_byte`) to determine if `until` was encountered.
 *
 * @param buf    Source buffer.
 * @param out    Output buffer receiving the data.
 * @param until  Delimiter character.
 */
void kevue_buffer_read_until(Buffer *buf, Buffer *out, char until);

/**
 * @brief Checks whether the buffer has no unread data remaining.
 *
 * @param buf  Buffer to check.
 *
 * @return true if at EOF, false otherwise.
 */
bool kevue_buffer_at_eof(Buffer *buf);

/**
 * @brief Grows the buffer capacity to at least the specified amount.
 *
 * Existing data is preserved.
 *
 * @param buf  Buffer to grow.
 * @param n    Total number of bytes required.
 * @pre Capacity must be greater than 0
 */
void kevue_buffer_grow(Buffer *buf, size_t n);

/**
 * @brief Resets the buffer to an empty state.
 *
 * Read and write positions are reset, but allocated memory is retained.
 *
 * @param buf  Buffer to reset.
 */
void kevue_buffer_reset(Buffer *buf);

/**
 * @brief Move unread bytes to the beginning of @p buf.
 */
void kevue_buffer_move_unread_bytes(Buffer *buf);

/**
 * @brief Prints the contents of the buffer in hexadecimal form.
 *
 * @param buf  Buffer to print.
 */
void kevue_buffer_print_hex(Buffer *buf);
