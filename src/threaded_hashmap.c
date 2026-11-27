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
 * @file threaded_hashmap.c
 * @brief Implementation of HashMap API for threaded hashmap.
 */
#include <pthread.h>
#include <stddef.h>
#include <string.h>

#include <rapidhash.h>

#include <allocator.h>
#include <buffer.h>
#include <common.h>
#include <dyna.h>
#include <hashmap.h>
#include <threaded_hashmap.h>

#define HASHMAP_BUCKET_INITIAL_COUNT       128U
#define HASHMAP_BUCKET_MAX_COUNT           8388608U
#define HASHMAP_BUCKET_ENTRY_INITIAL_COUNT 2U
#define HASHMAP_MAX_LOAD                   0.75f
#define HASHMAP_MIN_LOAD                   0.25f
#define HASHMAP_RESIZE_FACTOR              4
#define HASHMAP_SLOT_MAX_COUNT             (HASHMAP_BUCKET_MAX_COUNT * HASHMAP_BUCKET_ENTRY_INITIAL_COUNT) // 16777216

#ifdef __HASHMAP_SINGLE_THREADED
#define HASHMAP_BUCKET_LOCK_COUNT 1U
#define mutex_lock(l)             ((void)0)
#define mutex_unlock(l)           ((void)0)
#define mutex_init(l, f)          ((void)0)
#define mutex_destroy(l)          ((void)0)
#else
#define HASHMAP_BUCKET_LOCK_COUNT 1024U
#define mutex_lock(l)             pthread_mutex_lock((l))
#define mutex_unlock(l)           pthread_mutex_unlock((l))
#define mutex_init(l, f)          pthread_mutex_init((l), (f))
#define mutex_destroy(l)          pthread_mutex_destroy((l))
#endif

_Static_assert(is_pow2(HASHMAP_BUCKET_INITIAL_COUNT), "HASHMAP_BUCKET_INITIAL_COUNT must be a power of two");
_Static_assert(is_pow2(HASHMAP_BUCKET_MAX_COUNT), "HASHMAP_BUCKET_MAX_COUNT must be a power of two");
_Static_assert(is_pow2(HASHMAP_BUCKET_LOCK_COUNT), "HASHMAP_BUCKET_LOCK_COUNT must be a power of two");
_Static_assert(is_pow2(HASHMAP_RESIZE_FACTOR), "HASHMAP_RESIZE_FACTOR must be a power of two");
_Static_assert(is_pow2(HASHMAP_SLOT_MAX_COUNT), "HASHMAP_SLOT_MAX_COUNT must be a power of two");

typedef struct HashMapThreaded HashMapThreaded;

static void kevue__hm_threaded_destroy(HashMap *hm);
static bool kevue__hm_threaded_put(HashMap *hm, const void *key, u64 key_len, const void *val, u64 val_len);
static bool kevue__hm_threaded_get(HashMap *hm, const void *key, u64 key_len, Buffer *buf);
static bool kevue__hm_threaded_del(HashMap *hm, const void *key, u64 key_len);
static void kevue__hm_threaded_seed(HashMap *hm, u64 seed);
static bool kevue__hm_threaded_items(HashMap *hm, Buffer *buf);
static bool kevue__hm_threaded_keys(HashMap *hm, Buffer *buf);
static bool kevue__hm_threaded_values(HashMap *hm, Buffer *buf);
static u64 kevue__hm_threaded_len(HashMap *hm);
static void kevue__hm_threaded_resize(HashMapThreaded *hm_internal, u64 new_size);
static inline pthread_mutex_t *kevue__hm_threaded_bucket_lock(HashMapThreaded *hm_internal, u64 bucket_idx);

typedef struct Entry {
    u64 hash;
    u64 key_len;
    u64 val_len;
    u8  data[];
} Entry;

typedef struct Bucket {
    Entry **ptr;
    u32     len;
    u32     cap;
} Bucket;

struct HashMapThreaded {
    Bucket *buckets; // static array
#if defined(USE_ARENA)
    KevueAllocator  new_buckets;
    KevueAllocator  old_buckets;
    KevueAllocator *resize_buckets; // arena for new bucket allocations
#endif
    u64             bucket_count;
    u64             initial_bucket_count;
    u64             slots_taken;
    KevueAllocator *ma; // passed by caller, keep hashmap entries here (stable objects)
    KevueAllocator *dma; // allocator for dynamic objects (buckets, dynamic arrays, etc)
    pthread_mutex_t bucket_locks[HASHMAP_BUCKET_LOCK_COUNT];
    pthread_mutex_t resize_lock;
    u64             seed;
};

static const HashMapOps hm_ops = {
    .kevue_hm_destroy = kevue__hm_threaded_destroy,
    .kevue_hm_get = kevue__hm_threaded_get,
    .kevue_hm_put = kevue__hm_threaded_put,
    .kevue_hm_del = kevue__hm_threaded_del,
    .kevue_hm_seed = kevue__hm_threaded_seed,
    .kevue_hm_len = kevue__hm_threaded_len,
    .kevue_hm_items = kevue__hm_threaded_items,
    .kevue_hm_keys = kevue__hm_threaded_keys,
    .kevue_hm_values = kevue__hm_threaded_values,
};

static inline pthread_mutex_t *kevue__hm_threaded_bucket_lock(HashMapThreaded *hm_internal, u64 bucket_idx)
{
    return &hm_internal->bucket_locks[bucket_idx & (HASHMAP_BUCKET_LOCK_COUNT - 1)];
}

HashMap *kevue_hm_threaded_create(KevueAllocator *ma)
{
    HashMap *hm = (HashMap *)ma->malloc(sizeof(*hm), kevue_alignof(HashMap), ma->ctx);
    if (hm == NULL) return NULL;
    hm->ops = &hm_ops;
    HashMapThreaded *hm_internal = (HashMapThreaded *)ma->malloc(sizeof(*hm_internal), kevue_alignof(HashMapThreaded), ma->ctx);
    if (hm_internal == NULL) {
        ma->free(hm, ma->ctx);
        return NULL;
    }
    memset(hm_internal, 0, sizeof(*hm_internal));
    hm_internal->ma = ma;
    hm_internal->dma = ma;
#if defined(USE_ARENA)
    Arena         *new_buckets_arena = kevue_arena_create(MiB(512), MiB(32));
    KevueAllocator new_buckets = kevue_allocator_from_arena(new_buckets_arena);
    hm_internal->new_buckets = new_buckets;
    hm_internal->resize_buckets = &hm_internal->new_buckets;
    Arena         *old_buckets_arena = kevue_arena_create(MiB(512), MiB(32));
    KevueAllocator old_buckets = kevue_allocator_from_arena(old_buckets_arena);
    hm_internal->old_buckets = old_buckets;
    hm_internal->dma = &hm_internal->old_buckets;
#endif
    u64 bucket_count = HASHMAP_BUCKET_INITIAL_COUNT;
    hm_internal->bucket_count = bucket_count;
    hm_internal->initial_bucket_count = bucket_count;
    hm_internal->slots_taken = 0;
    hm_internal->buckets = (Bucket *)hm_internal->dma->malloc(bucket_count * sizeof(Bucket), kevue_alignof(Bucket), hm_internal->dma->ctx);
    if (hm_internal->buckets == NULL) {
        ma->free(hm_internal, ma->ctx);
        return NULL;
    }
    for (u64 bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        kevue_dyna_init(hm_internal->dma, &hm_internal->buckets[bucket], HASHMAP_BUCKET_ENTRY_INITIAL_COUNT);
    }
    mutex_init(&hm_internal->resize_lock, NULL);
    for (u64 lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_init(&hm_internal->bucket_locks[lock], NULL);
    }
    hm->internal = hm_internal;
    return hm;
}

static void kevue__hm_threaded_destroy(HashMap *hm)
{
    if (hm == NULL) return;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    for (u64 lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_destroy(&hm_internal->bucket_locks[lock]);
    }
    mutex_destroy(&hm_internal->resize_lock);
#if defined(USE_ARENA)
    kevue_arena_destroy(hm_internal->new_buckets.ctx);
    kevue_arena_destroy(hm_internal->old_buckets.ctx);
#else
    KevueAllocator *ma = hm_internal->ma;
    KevueAllocator *dma = hm_internal->dma;
    for (u64 bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len > 0) {
            kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr) ma->free(*entry_ptr, ma->ctx);
        }
        kevue_dyna_deinit(dma, &hm_internal->buckets[bucket]);
    }
    dma->free(hm_internal->buckets, dma->ctx);
    ma->free(hm_internal, ma->ctx);
    ma->free(hm, ma->ctx);
#endif
}

static bool kevue__hm_threaded_put(HashMap *hm, const void *key, u64 key_len, const void *val, u64 val_len)
{
    if (hm == NULL || hm->internal == NULL || key_len == 0 || val_len == 0) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    if (hm_internal->slots_taken >= HASHMAP_SLOT_MAX_COUNT) {
        mutex_unlock(&hm_internal->resize_lock);
        return false;
    }
    if (hm_internal->bucket_count < HASHMAP_BUCKET_MAX_COUNT) {
        if ((f64)hm_internal->bucket_count * HASHMAP_MAX_LOAD < (f64)hm_internal->slots_taken) {
            kevue__hm_threaded_resize(hm_internal, hm_internal->bucket_count * HASHMAP_RESIZE_FACTOR);
        }
    }
    u64 hash = rapidhash_withSeed(key, key_len, hm_internal->seed);
    u64 idx = hash & (hm_internal->bucket_count - 1);
    mutex_lock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
    mutex_unlock(&hm_internal->resize_lock);
    if (hm_internal->buckets[idx].len > 0) {
        // check if key already exist
        kevue_dyna_foreach(&hm_internal->buckets[idx], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            if (entry->hash == hash && entry->key_len == key_len && memcmp(entry->data, key, key_len) == 0) {
                if (val_len > entry->val_len) {
                    ptrdiff_t eidx = entry_ptr - hm_internal->buckets[idx].ptr;
                    Entry    *new_ptr = (Entry *)hm_internal->ma->realloc(
                        hm_internal->buckets[idx].ptr[eidx],
                        sizeof(*entry) + key_len + val_len,
                        sizeof(*entry) + key_len + entry->val_len,
                        kevue_alignof(Entry),
                        hm_internal->ma->ctx);
                    if (new_ptr == NULL) {
                        mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
                        return false;
                    }
                    hm_internal->buckets[idx].ptr[eidx] = new_ptr;
                    entry = hm_internal->buckets[idx].ptr[eidx];
                }
                entry->val_len = val_len;
                memcpy(entry->data + key_len, val, val_len);
                mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
                return true;
            }
        }
    }
    Entry *entry = hm_internal->ma->malloc(sizeof(*entry) + key_len + val_len, kevue_alignof(Entry), hm_internal->ma->ctx);
    if (entry == NULL) {
        mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
        return false;
    }
    entry->hash = hash;
    entry->key_len = key_len;
    entry->val_len = val_len;
    memcpy(entry->data, key, key_len);
    memcpy(entry->data + key_len, val, val_len);
    kevue_dyna_append(hm_internal->dma, &hm_internal->buckets[idx], entry);
    mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
    mutex_lock(&hm_internal->resize_lock);
    hm_internal->slots_taken++;
    mutex_unlock(&hm_internal->resize_lock);
    return true;
}

static bool kevue__hm_threaded_get(HashMap *hm, const void *key, u64 key_len, Buffer *buf)
{
    if (hm == NULL || hm->internal == NULL || key_len == 0) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    u64 hash = rapidhash_withSeed(key, key_len, hm_internal->seed);
    u64 idx = hash & (hm_internal->bucket_count - 1);
    mutex_lock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
    mutex_unlock(&hm_internal->resize_lock);
    if (hm_internal->buckets[idx].len == 0) {
        mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
        return false;
    }
    kevue_dyna_foreach(&hm_internal->buckets[idx], entry_ptr)
    {
        Entry *entry = *entry_ptr;
        if (entry->hash == hash && entry->key_len == key_len && memcmp(entry->data, key, key_len) == 0) {
            kevue_buffer_write(buf, entry->data + entry->key_len, entry->val_len);
            mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
            return true;
        }
    }
    mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
    return false;
}

static bool kevue__hm_threaded_del(HashMap *hm, const void *key, u64 key_len)
{
    if (hm == NULL || hm->internal == NULL || key_len == 0) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    if (hm_internal->bucket_count > hm_internal->initial_bucket_count) {
        if ((f64)hm_internal->bucket_count * HASHMAP_MIN_LOAD > (f64)hm_internal->slots_taken) {
            kevue__hm_threaded_resize(hm_internal, max(hm_internal->initial_bucket_count, hm_internal->bucket_count / HASHMAP_RESIZE_FACTOR));
        }
    }
    u64 hash = rapidhash_withSeed(key, key_len, hm_internal->seed);
    u64 idx = hash & (hm_internal->bucket_count - 1);
    mutex_lock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
    mutex_unlock(&hm_internal->resize_lock);
    if (hm_internal->buckets[idx].len == 0) {
        mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
        return false;
    }
    kevue_dyna_foreach(&hm_internal->buckets[idx], entry_ptr)
    {
        Entry *entry = *entry_ptr;
        if (entry->hash == hash && entry->key_len == key_len && memcmp(entry->data, key, key_len) == 0) {
            ptrdiff_t eidx = entry_ptr - hm_internal->buckets[idx].ptr;
            hm_internal->ma->free(*entry_ptr, hm_internal->ma->ctx);
            kevue_dyna_remove(&hm_internal->buckets[idx], (u64)eidx);
            mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
            mutex_lock(&hm_internal->resize_lock);
            hm_internal->slots_taken--;
            mutex_unlock(&hm_internal->resize_lock);
            return true;
        }
    }
    mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
    return false;
}

static void kevue__hm_threaded_seed(HashMap *hm, u64 seed)
{
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    hm_internal->seed = seed;
}

static u64 kevue__hm_threaded_len(HashMap *hm)
{
    if (hm == NULL || hm->internal == NULL) return 0;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    u64 hm_len = (u64)hm_internal->slots_taken;
    mutex_unlock(&hm_internal->resize_lock);
    return hm_len;
}

static bool kevue__hm_threaded_items(HashMap *hm, Buffer *buf)
{
    if (hm == NULL || hm->internal == NULL) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    for (u64 lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    kevue_buffer_grow(buf, BUF_SIZE);
    kevue_buffer_reset(buf);
    for (u64 bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            u64    key_len = (u64)entry->key_len;
            u64    val_len = (u64)entry->val_len;
            // TODO: check for return value from appends
            kevue_buffer_append(buf, &key_len, sizeof(key_len));
            kevue_buffer_append(buf, entry->data, key_len);
            kevue_buffer_append(buf, &val_len, sizeof(val_len));
            kevue_buffer_append(buf, entry->data + key_len, val_len);
        }
    }
    mutex_unlock(&hm_internal->resize_lock);
    return true;
}

static bool kevue__hm_threaded_keys(HashMap *hm, Buffer *buf)
{
    if (hm == NULL || hm->internal == NULL) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    for (u64 lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    kevue_buffer_grow(buf, BUF_SIZE);
    kevue_buffer_reset(buf);
    for (u64 bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            u64    key_len = (u64)entry->key_len;
            kevue_buffer_append(buf, &key_len, sizeof(key_len));
            kevue_buffer_append(buf, entry->data, key_len);
        }
    }
    mutex_unlock(&hm_internal->resize_lock);
    return true;
}

static bool kevue__hm_threaded_values(HashMap *hm, Buffer *buf)
{

    if (hm == NULL || hm->internal == NULL) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    for (u64 lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    kevue_buffer_grow(buf, BUF_SIZE);
    kevue_buffer_reset(buf);
    for (u64 bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            u64    key_len = (u64)entry->key_len;
            u64    val_len = (u64)entry->val_len;
            kevue_buffer_append(buf, &val_len, sizeof(val_len));
            kevue_buffer_append(buf, entry->data + key_len, val_len);
        }
    }
    mutex_unlock(&hm_internal->resize_lock);
    return true;
}

static void kevue__hm_threaded_resize(HashMapThreaded *hm_internal, u64 new_size)
{
    print_debug(generate_timestamp(), "HashMap %s %zu -> %zu", new_size > hm_internal->bucket_count ? "grows" : "shrinks", hm_internal->bucket_count, new_size);
#if defined(USE_ARENA)
    KevueAllocator *ma = hm_internal->resize_buckets;
#else
    KevueAllocator *ma = hm_internal->dma;
#endif
    Bucket *new_buckets = ma->malloc(new_size * sizeof(Bucket), kevue_alignof(Bucket), ma->ctx);
    if (new_buckets == NULL) {
        return;
    }
    // this ensures that all bucket locks are released by getters and setters
    for (u64 lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    for (u64 bucket = 0; bucket < new_size; bucket++) {
        kevue_dyna_init(ma, &new_buckets[bucket], HASHMAP_BUCKET_ENTRY_INITIAL_COUNT);
    }
    for (u64 bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            u64    idx = entry->hash & (new_size - 1);
            kevue_dyna_append(ma, &new_buckets[idx], entry);
        }
    }
#if defined(USE_ARENA)
    // TODO: add separate arenas for entry compaction (combat shrinks, reallocations, etc)
    // maybe a separate function that server can call periodically
    hm_internal->buckets = new_buckets;
    hm_internal->dma = hm_internal->resize_buckets;
    if (hm_internal->resize_buckets == &hm_internal->new_buckets) {
        hm_internal->resize_buckets = &hm_internal->old_buckets;
        kevue_arena_clear(hm_internal->old_buckets.ctx);
        kevue_arena_shrink(hm_internal->old_buckets.ctx);
        if (new_size < hm_internal->bucket_count) {
            kevue_arena_shrink(hm_internal->new_buckets.ctx);
        }
    } else {
        hm_internal->resize_buckets = &hm_internal->new_buckets;
        kevue_arena_clear(hm_internal->new_buckets.ctx);
        kevue_arena_shrink(hm_internal->new_buckets.ctx);
        if (new_size < hm_internal->bucket_count) {
            kevue_arena_shrink(hm_internal->old_buckets.ctx);
        }
    }
#else
    u64     old_size = hm_internal->bucket_count;
    Bucket *old_buckets = hm_internal->buckets;
    hm_internal->buckets = new_buckets;
    for (u64 bucket = 0; bucket < old_size; bucket++) {
        kevue_dyna_deinit(ma, &old_buckets[bucket]);
    }
    ma->free(old_buckets, ma->ctx);
#endif
    hm_internal->bucket_count = new_size;
}
