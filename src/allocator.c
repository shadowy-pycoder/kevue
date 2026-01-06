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
#include <stddef.h>
#include <stdlib.h>

#include <allocator.h>
#include <common.h>

static void *kevue_malloc(size_t size, void *ctx);
static void *kevue_realloc(void *ptr, size_t size, void *ctx);
static void kevue_free(void *ptr, void *ctx);

static void *kevue_malloc(size_t size, void *ctx)
{
    UNUSED(ctx);
    return malloc(size);
}

static void *kevue_realloc(void *ptr, size_t size, void *ctx)
{
    UNUSED(ctx);
    return realloc(ptr, size);
}

static void kevue_free(void *ptr, void *ctx)
{
    UNUSED(ctx);
    free(ptr);
}

KevueAllocator kevue_default_allocator = { .malloc = kevue_malloc, .realloc = kevue_realloc, .free = kevue_free, .ctx = NULL };
