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
 * @file arena_allocator.c
 * @brief arena allocator implementation.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <arena_allocator.h>
#include <common.h>

#define KEVUE_ARENA_HEADER_SIZE (u64)sizeof(Arena)

static u32 get_page_size();
static void *memory_reserve(size_t size);
static bool memory_commit(void *ptr, size_t size);
static bool memory_decommit(void *ptr, size_t size);
static bool memory_free(void *ptr, size_t size);
static void *kevue_malloc(size_t size, size_t align, void *ctx);
static void *kevue_calloc(size_t n, size_t size, size_t align, void *ctx);
static void *kevue_realloc(void *ptr, size_t size, size_t old_size, size_t align, void *ctx);
static void kevue_free(void *ptr, void *ctx);

struct Arena {
    u64 res_size;
    u64 cmt_chunk;

    u64 pos;
    u64 cmt_pos;
};

static u32 get_page_size()
{
    return (u32)sysconf(_SC_PAGE_SIZE);
}

static void *memory_reserve(size_t size)
{
    void *out = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return out == MAP_FAILED ? NULL : out;
}

static bool memory_commit(void *ptr, size_t size)
{
    return mprotect(ptr, size, PROT_READ | PROT_WRITE) == 0;
}

static bool memory_decommit(void *ptr, size_t size)
{
    if (madvise(ptr, size, MADV_DONTNEED) != 0) return false;
    return mprotect(ptr, size, PROT_NONE) == 0;
}

static bool memory_free(void *ptr, size_t size)
{
    return munmap(ptr, size) == 0;
}

Arena *kevue_arena_create(u64 reserve_size, u64 commit_size)
{
    if (commit_size > reserve_size) return NULL;
    u32 page_size = get_page_size();

    reserve_size = align_up_pow2(reserve_size, page_size);
    commit_size = align_up_pow2(commit_size, page_size);

    Arena *arena = memory_reserve(reserve_size);
    if (arena == NULL) return NULL;

    if (!memory_commit(arena, commit_size)) {
        return NULL;
    }

    arena->res_size = reserve_size;
    arena->cmt_chunk = commit_size;
    arena->pos = KEVUE_ARENA_HEADER_SIZE;
    arena->cmt_pos = commit_size;
    return arena;
}

void kevue_arena_destroy(Arena *arena)
{
    memory_free(arena, arena->res_size);
}

void *kevue_arena_push(Arena *arena, u64 size, bool non_zero)
{
    return kevue_arena_push_aligned(arena, size, KEVUE_ARENA_ALIGN_DEFAULT, non_zero);
}

void *kevue_arena_push_aligned(Arena *arena, u64 size, u64 align, bool non_zero)
{
    // move pos so new item is aligned accordingly
    u64 prev_pos = align_up_pow2(arena->pos, align);
    u64 next_pos = prev_pos + size;
    if (next_pos > arena->res_size) {
        return NULL;
    }

    u64 size_to_zero = 0;
    if (!non_zero && prev_pos < arena->cmt_pos) {
        // zero memory in between prev_pos and next_pos, consider future zero paging by OS
        size_to_zero = min(arena->cmt_pos, next_pos) - prev_pos;
    }
    if (arena->cmt_pos < next_pos) {
        // align commit position up to page chunk boundary
        u64 new_cmt_pos = next_pos;
        u64 new_cmt_pos_aligned = new_cmt_pos + arena->cmt_chunk - 1;
        new_cmt_pos_aligned -= new_cmt_pos_aligned % arena->cmt_chunk;
        u64 new_cmt_pos_clamped = min(new_cmt_pos_aligned, arena->res_size);
        u8 *new_ptr = (u8 *)arena + arena->cmt_pos;
        u64 cmt_size = new_cmt_pos_clamped - arena->cmt_pos;
        if (!memory_commit(new_ptr, cmt_size)) {
            return NULL;
        }
        arena->cmt_pos = new_cmt_pos_clamped;
    }
    void *out = NULL;
    if (arena->cmt_pos >= next_pos) {
        out = (u8 *)arena + prev_pos;
        arena->pos = next_pos;
        if (size_to_zero > 0) {
            memset(out, 0, size_to_zero);
        }
    }
    return out;
}

void kevue_arena_pop(Arena *arena, u64 size)
{
    size = min(size, arena->pos - KEVUE_ARENA_HEADER_SIZE);
    arena->pos -= size;
}

void kevue_arena_pop_to(Arena *arena, u64 pos)
{
    u64 size = pos < arena->pos ? arena->pos - pos : 0;
    kevue_arena_pop(arena, size);
}

void kevue_arena_clear(Arena *arena)
{
    kevue_arena_pop_to(arena, KEVUE_ARENA_HEADER_SIZE);
}

static void *kevue_malloc(size_t size, size_t align, void *ctx)
{
    if (ctx == NULL) return NULL;
    return kevue_arena_push_aligned((Arena *)ctx, size, align, true);
}

static void *kevue_calloc(size_t n, size_t size, size_t align, void *ctx)
{
    if (ctx == NULL) return NULL;
    return kevue_arena_push_aligned((Arena *)ctx, n * size, align, false);
}

static void *kevue_realloc(void *ptr, size_t size, size_t old_size, size_t align, void *ctx)
{
    if (ctx == NULL) return NULL;
    if (ptr == NULL && size > 0) return kevue_arena_push_aligned((Arena *)ctx, size, align, true);
    if (ptr == NULL || size == 0 || old_size == 0) return NULL;
    if (size <= old_size) return ptr;
    u8 *new_ptr;
    new_ptr = kevue_arena_push_aligned((Arena *)ctx, size, align, true);
    if (new_ptr != NULL) {
        memcpy(new_ptr, ptr, old_size);
    }
    return new_ptr;
}

static void *kevue_alloc_aligned(size_t size, size_t align, void *ctx)
{
    if (ctx == NULL) return NULL;
    return kevue_arena_push_aligned((Arena *)ctx, size, align, true);
}

static void kevue_free(void *ptr, void *ctx)
{
    UNUSED(ctx);
    UNUSED(ptr);
}

KevueAllocator kevue_allocator_from_arena(Arena *arena)
{
    return (KevueAllocator) {
        .malloc = kevue_malloc,
        .calloc = kevue_calloc,
        .realloc = kevue_realloc,
        .alloc_aligned = kevue_alloc_aligned,
        .free = kevue_free,
        .ctx = arena,
    };
}

KevueAllocator kevue_allocator_from_arena_sizes(u64 reserve_size, u64 commit_size)
{
    return (KevueAllocator) {
        .malloc = kevue_malloc,
        .calloc = kevue_calloc,
        .realloc = kevue_realloc,
        .alloc_aligned = kevue_alloc_aligned,
        .free = kevue_free,
        .ctx = kevue_arena_create(reserve_size, commit_size)
    };
}
