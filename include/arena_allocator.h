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
 * @file arena_allocator.h
 * @brief arena allocator.
 * Inspired by https://www.dgtlgrove.com/p/untangling-lifetimes-the-arena-allocator
 * and https://github.com/EpicGames/raddebugger
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <allocator.h>
#include <kevue_types.h>

#ifndef KEVUE_ARENA_ALIGN_DEFAULT
#define KEVUE_ARENA_ALIGN_DEFAULT (u64)sizeof(uintptr_t)
#endif
#ifndef KEVUE_ARENA_RESERVE_SIZE_DEFAULT
#define KEVUE_ARENA_RESERVE_SIZE_DEFAULT GiB(5)
#endif
#ifndef KEVUE_ARENA_COMMIT_SIZE_DEFAULT
#define KEVUE_ARENA_COMMIT_SIZE_DEFAULT MiB(32)
#endif
#ifndef KEVUE_ARENA_SCRATCH_RESERVE_SIZE_DEFAULT
#define KEVUE_ARENA_SCRATCH_RESERVE_SIZE_DEFAULT MiB(64)
#endif
#ifndef KEVUE_ARENA_SCRATCH_COMMIT_SIZE_DEFAULT
#define KEVUE_ARENA_SCRATCH_COMMIT_SIZE_DEFAULT MiB(1)
#endif

#define kevue_arena_push_struct(arena, T)              (T *)kevue_arena_push((arena), sizeof(T), false)
#define kevue_arena_push_struct_nz(arena, T)           (T *)kevue_arena_push((arena), sizeof(T), true)
#define kevue_arena_push_struct_aligned(arena, T)      (T *)kevue_arena_push_aligned((arena), sizeof(T), kevue_alignof(T), false)
#define kevue_arena_push_struct_aligned_nz(arena, T)   (T *)kevue_arena_push_aligned((arena), sizeof(T), kevue_alignof(T), true)
#define kevue_arena_push_array(arena, T, n)            (T *)kevue_arena_push((arena), sizeof(T) * (n), false)
#define kevue_arena_push_array_nz(arena, T, n)         (T *)kevue_arena_push((arena), sizeof(T) * (n), true)
#define kevue_arena_push_array_aligned(arena, T, n)    (T *)kevue_arena_push_aligned((arena), sizeof(T) * (n), kevue_alignof(T), false)
#define kevue_arena_push_array_aligned_nz(arena, T, n) (T *)kevue_arena_push_aligned((arena), sizeof(T) * (n), kevue_alignof(T), true)

typedef struct Arena     Arena;
typedef struct TempArena TempArena;
struct TempArena {
    Arena *arena;
    u64    pos;
};

Arena *kevue_arena_create(u64 reserve_size, u64 commit_size);
void kevue_arena_destroy(Arena *arena);
void *kevue_arena_push(Arena *arena, u64 size, bool non_zero);
void *kevue_arena_push_aligned(Arena *arena, u64 size, u64 align, bool non_zero);
void kevue_arena_pop(Arena *arena, u64 size);
void kevue_arena_pop_to(Arena *arena, u64 pos);
void kevue_arena_clear(Arena *arena);
void kevue_arena_shrink(Arena *arena);
Arena *kevue_arena_clone(Arena *src);
bool kevue_arena_copy(Arena *dst, Arena *src);
KevueAllocator kevue_allocator_from_arena(Arena *arena);
KevueAllocator kevue_allocator_from_arena_sizes(u64 reserve_size, u64 commit_size);
KevueAllocator kevue_allocator_from_arena_ctx(void *ctx);
TempArena kevue_arena_temp_begin(Arena *arena);
void kevue_arena_temp_end(TempArena temp);
TempArena kevue_arena_scratch_get(Arena **conflicts, u32 num_conflicts);
void kevue_arena_scratch_release(TempArena scratch);
