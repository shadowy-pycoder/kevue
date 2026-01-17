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
#include <stdint.h>
#include <string.h>

#include <rapidhash.h>

#include <allocator.h>
#include <buffer.h>
#include <common.h>
#include <dyna.h>
#include <hashmap.h>
#include <threaded_hashmap.h>

#define HASHMAP_BUCKET_INITIAL_COUNT       (SERVER_WORKERS * 8U) // rounded up to the power of two
#define HASHMAP_BUCKET_MAX_COUNT           8388608U
#define HASHMAP_BUCKET_ENTRY_INITIAL_COUNT 2U
#define HASHMAP_MAX_LOAD                   1.0f
#define HASHMAP_MIN_LOAD                   0.25f
#define HASHMAP_RESIZE_FACTOR              2
#define HASHMAP_SLOT_MAX_COUNT             (HASHMAP_BUCKET_MAX_COUNT * HASHMAP_BUCKET_ENTRY_INITIAL_COUNT) // 16777216

#ifdef __HASHMAP_SINGLE_THREADED
#define HASHMAP_BUCKET_LOCK_COUNT 0U
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

typedef struct HashMapThreaded HashMapThreaded;

static void kevue__hm_threaded_destroy(HashMap *hm);
static bool kevue__hm_threaded_put(HashMap *hm, const void *key, size_t key_len, const void *val, size_t val_len);
static bool kevue__hm_threaded_get(HashMap *hm, const void *key, size_t key_len, Buffer *buf);
static bool kevue__hm_threaded_del(HashMap *hm, const void *key, size_t key_len);
static void kevue__hm_threaded_seed(HashMap *hm, uint64_t seed);
static bool kevue__hm_threaded_items(HashMap *hm, Buffer *buf);
static bool kevue__hm_threaded_keys(HashMap *hm, Buffer *buf);
static bool kevue__hm_threaded_values(HashMap *hm, Buffer *buf);
static size_t kevue__hm_threaded_len(HashMap *hm);
static void kevue__hm_threaded_resize(HashMapThreaded *hm_internal, size_t new_size);
static inline pthread_mutex_t *kevue__hm_threaded_bucket_lock(HashMapThreaded *hm_internal, size_t bucket_idx);

typedef struct Entry {
    uint64_t hash;
    size_t   key_len;
    size_t   val_len;
    uint8_t  data[];
} Entry;

typedef struct Bucket {
    Entry         **ptr;
    size_t          len;
    size_t          cap;
    KevueAllocator *ma;
} Bucket;

struct HashMapThreaded {
    Bucket         *buckets; // static array
    size_t          bucket_count;
    size_t          initial_bucket_count;
    size_t          slots_taken;
    KevueAllocator *ma;
    pthread_mutex_t bucket_locks[HASHMAP_BUCKET_LOCK_COUNT];
    pthread_mutex_t resize_lock;
    uint64_t        seed;
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

static inline pthread_mutex_t *kevue__hm_threaded_bucket_lock(HashMapThreaded *hm_internal, size_t bucket_idx)
{
    return &hm_internal->bucket_locks[bucket_idx % HASHMAP_BUCKET_LOCK_COUNT];
}

HashMap *kevue_hm_threaded_create(KevueAllocator *ma)
{
    HashMap *hm = (HashMap *)ma->malloc(sizeof(*hm), ma->ctx);
    if (hm == NULL) return NULL;
    hm->ops = &hm_ops;
    HashMapThreaded *hm_internal = (HashMapThreaded *)ma->malloc(sizeof(*hm_internal), ma->ctx);
    if (hm_internal == NULL) {
        ma->free(hm, ma->ctx);
        return NULL;
    }
    memset(hm_internal, 0, sizeof(*hm_internal));
    hm_internal->ma = ma;
    size_t bucket_count = round_up_pow2(HASHMAP_BUCKET_INITIAL_COUNT);
    hm_internal->buckets = hm_internal->ma->malloc(bucket_count * sizeof(Bucket), hm_internal->ma->ctx);
    if (hm_internal->buckets == NULL) {
        hm_internal->ma->free(hm_internal, hm_internal->ma->ctx);
        return NULL;
    }
    mutex_init(&hm_internal->resize_lock, NULL);
    hm_internal->bucket_count = bucket_count;
    hm_internal->initial_bucket_count = bucket_count;
    hm_internal->slots_taken = 0;
    for (size_t bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        kevue_dyna_init(&hm_internal->buckets[bucket], HASHMAP_BUCKET_ENTRY_INITIAL_COUNT, hm_internal->ma);
    }
    for (size_t lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_init(&hm_internal->bucket_locks[lock], NULL);
    }
    hm->internal = hm_internal;
    return hm;
}

static void kevue__hm_threaded_destroy(HashMap *hm)
{
    if (hm == NULL) return;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    for (size_t bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len > 0) {
            kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr) hm_internal->ma->free(*entry_ptr, hm_internal->ma->ctx);
        }
        kevue_dyna_deinit(&hm_internal->buckets[bucket]);
    }
    for (size_t lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_destroy(&hm_internal->bucket_locks[lock]);
    }
    hm_internal->ma->free(hm_internal->buckets, hm_internal->ma->ctx);
    mutex_destroy(&hm_internal->resize_lock);
    KevueAllocator *ma = hm_internal->ma;
    hm_internal->ma->free(hm_internal, hm_internal->ma->ctx);
    ma->free(hm, ma->ctx);
}

static bool kevue__hm_threaded_put(HashMap *hm, const void *key, size_t key_len, const void *val, size_t val_len)
{
    if (hm == NULL || hm->internal == NULL || key_len == 0 || val_len == 0) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    if (hm_internal->slots_taken >= HASHMAP_SLOT_MAX_COUNT) {
        mutex_unlock(&hm_internal->resize_lock);
        return false;
    }
    if (hm_internal->bucket_count < HASHMAP_BUCKET_MAX_COUNT) {
        if ((double)hm_internal->slots_taken / (double)hm_internal->bucket_count > HASHMAP_MAX_LOAD) {
            kevue__hm_threaded_resize(hm_internal, hm_internal->bucket_count * HASHMAP_RESIZE_FACTOR);
        }
    }
    uint64_t hash = rapidhash_withSeed(key, key_len, hm_internal->seed);
    size_t   idx = hash % hm_internal->bucket_count;
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
                    hm_internal->buckets[idx].ptr[eidx] = hm_internal->ma->realloc(
                        hm_internal->buckets[idx].ptr[eidx],
                        sizeof(*entry) + key_len + val_len,
                        hm_internal->ma->ctx);
                    entry = hm_internal->buckets[idx].ptr[eidx];
                }
                entry->val_len = val_len;
                memcpy(entry->data, key, key_len);
                memcpy(entry->data + key_len, val, val_len);
                mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
                return true;
            }
        }
    }
    Entry *entry = hm_internal->ma->malloc(sizeof(*entry) + key_len + val_len, hm_internal->ma->ctx);
    if (entry == NULL) {
        mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
        return false;
    }
    entry->hash = hash;
    entry->key_len = key_len;
    entry->val_len = val_len;
    memcpy(entry->data, key, key_len);
    memcpy(entry->data + key_len, val, val_len);
    kevue_dyna_append(&hm_internal->buckets[idx], entry);
    mutex_unlock(kevue__hm_threaded_bucket_lock(hm_internal, idx));
    mutex_lock(&hm_internal->resize_lock);
    hm_internal->slots_taken++;
    mutex_unlock(&hm_internal->resize_lock);
    return true;
}

static bool kevue__hm_threaded_get(HashMap *hm, const void *key, size_t key_len, Buffer *buf)
{
    if (hm == NULL || hm->internal == NULL || key_len == 0) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    uint64_t hash = rapidhash_withSeed(key, key_len, hm_internal->seed);
    size_t   idx = hash % hm_internal->bucket_count;
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

static bool kevue__hm_threaded_del(HashMap *hm, const void *key, size_t key_len)
{
    if (hm == NULL || hm->internal == NULL || key_len == 0) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    if (hm_internal->bucket_count > hm_internal->initial_bucket_count) {
        if ((double)hm_internal->slots_taken / (double)hm_internal->bucket_count < HASHMAP_MIN_LOAD) {
            kevue__hm_threaded_resize(hm_internal, max(hm_internal->initial_bucket_count, hm_internal->bucket_count / HASHMAP_RESIZE_FACTOR));
        }
    }
    uint64_t hash = rapidhash_withSeed(key, key_len, hm_internal->seed);
    size_t   idx = hash % hm_internal->bucket_count;
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
            kevue_dyna_remove(&hm_internal->buckets[idx], (size_t)eidx);
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

static void kevue__hm_threaded_seed(HashMap *hm, uint64_t seed)
{
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    hm_internal->seed = seed;
}

static uint64_t kevue__hm_threaded_len(HashMap *hm)
{
    if (hm == NULL || hm->internal == NULL) return 0;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    uint64_t hm_len = (uint64_t)hm_internal->slots_taken;
    mutex_unlock(&hm_internal->resize_lock);
    return hm_len;
}

static bool kevue__hm_threaded_items(HashMap *hm, Buffer *buf)
{
    if (hm == NULL || hm->internal == NULL) return false;
    HashMapThreaded *hm_internal = (HashMapThreaded *)hm->internal;
    mutex_lock(&hm_internal->resize_lock);
    for (size_t lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    kevue_buffer_grow(buf, BUF_SIZE);
    kevue_buffer_reset(buf);
    for (size_t bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry   *entry = *entry_ptr;
            uint64_t key_len = (uint64_t)entry->key_len;
            uint64_t val_len = (uint64_t)entry->val_len;
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
    for (size_t lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    kevue_buffer_grow(buf, BUF_SIZE);
    kevue_buffer_reset(buf);
    for (size_t bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry   *entry = *entry_ptr;
            uint64_t key_len = (uint64_t)entry->key_len;
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
    for (size_t lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    kevue_buffer_grow(buf, BUF_SIZE);
    kevue_buffer_reset(buf);
    for (size_t bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry   *entry = *entry_ptr;
            uint64_t key_len = (uint64_t)entry->key_len;
            uint64_t val_len = (uint64_t)entry->val_len;
            kevue_buffer_append(buf, &val_len, sizeof(val_len));
            kevue_buffer_append(buf, entry->data + key_len, val_len);
        }
    }
    mutex_unlock(&hm_internal->resize_lock);
    return true;
}

static void kevue__hm_threaded_resize(HashMapThreaded *hm_internal, size_t new_size)
{
    print_debug(generate_timestamp(), "HashMap %s %zu -> %zu", new_size > hm_internal->bucket_count ? "grows" : "shrinks", hm_internal->bucket_count, new_size);
    Bucket *new_buckets = hm_internal->ma->malloc(new_size * sizeof(Bucket), hm_internal->ma->ctx);
    if (new_buckets == NULL) {
        return;
    }
    // this ensures that all bucket locks are released by getters and setters
    for (size_t lock = 0; lock < HASHMAP_BUCKET_LOCK_COUNT; lock++) {
        mutex_lock(&hm_internal->bucket_locks[lock]);
        mutex_unlock(&hm_internal->bucket_locks[lock]);
    }
    for (size_t bucket = 0; bucket < new_size; bucket++) {
        kevue_dyna_init(&new_buckets[bucket], HASHMAP_BUCKET_ENTRY_INITIAL_COUNT, hm_internal->ma);
    }
    for (size_t bucket = 0; bucket < hm_internal->bucket_count; bucket++) {
        if (hm_internal->buckets[bucket].len == 0) continue;
        kevue_dyna_foreach(&hm_internal->buckets[bucket], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            size_t idx = entry->hash % new_size;
            kevue_dyna_append(&new_buckets[idx], entry);
        }
    }
    size_t old_size = hm_internal->bucket_count;
    hm_internal->bucket_count = new_size;
    Bucket *old_buckets = hm_internal->buckets;
    hm_internal->buckets = new_buckets;
    for (size_t bucket = 0; bucket < old_size; bucket++) {
        kevue_dyna_deinit(&old_buckets[bucket]);
    }
    hm_internal->ma->free(old_buckets, hm_internal->ma->ctx);
}
