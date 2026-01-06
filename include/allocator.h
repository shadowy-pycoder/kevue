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
 * @file allocator.h
 * @brief Default allocator.
 */
#pragma once

#include <stddef.h>

/**
 * @brief Memory allocators interface.
 */
typedef struct KevueAllocator {
    void *(*malloc)(size_t, void *ctx);
    void *(*realloc)(void *, size_t, void *ctx);
    void (*free)(void *, void *ctx);
    void *ctx;
} KevueAllocator;

/**
 * @brief Default allocator using the C standard library.
 *
 * Uses @c malloc, @c realloc, and @c free from <stdlib.h>.
 * The context pointer is unused and set to NULL.
 */
extern KevueAllocator kevue_default_allocator;
