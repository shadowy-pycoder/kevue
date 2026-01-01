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
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <rapidhash.h>

#include <allocator.h>
#include <buffer.h>
#include <common.h>
#include <dyna.h>
#include <hashmap.h>

#define HASHMAP_BUCKET_INITIAL_COUNT       (SERVER_WORKERS * 8U) // rounded up to the power of two
#define HASHMAP_BUCKET_ENTRY_INITIAL_COUNT 4U
#define HASHMAP_MAX_LOAD                   1.0f
#define HASHMAP_MIN_LOAD                   0.25f
#define HASHMAP_RESIZE_FACTOR              2

#if SERVER_WORKERS == 1
#define mutex_lock(l)   ((void)0)
#define mutex_unlock(l) ((void)0)
#else
#define mutex_lock(l)   pthread_mutex_lock(l)
#define mutex_unlock(l) pthread_mutex_unlock(l)
#endif

static void kevue__hm_resize(HashMap *hm, size_t new_size);

typedef struct Entry {
    uint64_t hash;
    size_t key_len;
    size_t val_len;
    uint8_t data[];
} Entry;

typedef struct Bucket {
    Entry **ptr;
    size_t len;
    size_t cap;
    KevueAllocator *ma;
    pthread_mutex_t lock;
} Bucket;

struct HashMap {
    Bucket *buckets; // static array
    size_t bucket_count;
    atomic_size_t slots_taken;
    KevueAllocator *ma;
    pthread_mutex_t resize_lock;
};

HashMap *kevue_hm_create(KevueAllocator *ma)
{
    HashMap *hm = (HashMap *)ma->malloc(sizeof(*hm), ma->ctx);
    if (hm == NULL) return NULL;
    memset(hm, 0, sizeof(*hm));
    hm->ma = ma;
    size_t bucket_count = round_up_pow2(HASHMAP_BUCKET_ENTRY_INITIAL_COUNT);
    hm->buckets = hm->ma->malloc(bucket_count * sizeof(Bucket), hm->ma->ctx);
    if (hm->buckets == NULL) {
        hm->ma->free(hm, hm->ma->ctx);
        return NULL;
    }
    hm->bucket_count = bucket_count;
    for (size_t bucket = 0; bucket < hm->bucket_count; bucket++) {
        hm->buckets[bucket].ptr = NULL;
    }
    return hm;
}

void kevue_hm_destroy(HashMap *hm)
{
    if (hm == NULL) return;
    for (size_t bucket = 0; bucket < hm->bucket_count; bucket++) {
        if (hm->buckets[bucket].ptr != NULL) {
            kevue_dyna_foreach(&hm->buckets[bucket], entry_ptr) hm->ma->free(*entry_ptr, hm->ma->ctx);
            kevue_dyna_deinit(&hm->buckets[bucket]);
        }
    }
    hm->ma->free(hm->buckets, hm->ma->ctx);
    hm->ma->free(hm, hm->ma->ctx);
}

bool kevue_hm_put(HashMap *hm, const void *key, size_t key_len, const void *val, size_t val_len)
{
    if (hm == NULL || hm->ma == NULL || key_len == 0 || val_len == 0) return false;
    mutex_lock(&hm->resize_lock);
    if ((double)atomic_load(&hm->slots_taken) / (double)hm->bucket_count > HASHMAP_MAX_LOAD) {
        kevue__hm_resize(hm, hm->bucket_count * HASHMAP_RESIZE_FACTOR);
    }
    uint64_t hash = rapidhash(key, key_len);
    size_t idx = hash % hm->bucket_count;
    mutex_lock(&hm->buckets[idx].lock);
    mutex_unlock(&hm->resize_lock);
    bool bucket_init = false;
    if (hm->buckets[idx].ptr != NULL) {
        // check if key already exist
        kevue_dyna_foreach(&hm->buckets[idx], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            if (entry->hash == hash && entry->key_len == key_len && memcmp(entry->data, key, key_len) == 0) {
                if (val_len > entry->val_len) {
                    ptrdiff_t eidx = entry_ptr - hm->buckets[idx].ptr;
                    hm->buckets[idx].ptr[eidx] = hm->ma->realloc(hm->buckets[idx].ptr[eidx], sizeof(*entry) + key_len + val_len, hm->ma->ctx);
                    entry = hm->buckets[idx].ptr[eidx];
                }
                entry->val_len = val_len;
                memcpy(entry->data, key, key_len);
                memcpy(entry->data + key_len, val, val_len);
                mutex_unlock(&hm->buckets[idx].lock);
                return true;
            }
        }
    } else {
        bucket_init = true;
        kevue_dyna_init(&hm->buckets[idx], HASHMAP_BUCKET_ENTRY_INITIAL_COUNT, hm->ma);
    }
    Entry *entry = hm->ma->malloc(sizeof(*entry) + key_len + val_len, hm->ma->ctx);
    if (entry == NULL) {
        if (bucket_init) kevue_dyna_deinit(&hm->buckets[idx]);
        mutex_unlock(&hm->buckets[idx].lock);
        return false;
    }
    entry->hash = hash;
    entry->key_len = key_len;
    entry->val_len = val_len;
    memcpy(entry->data, key, key_len);
    memcpy(entry->data + key_len, val, val_len);
    kevue_dyna_append(&hm->buckets[idx], entry);
    mutex_unlock(&hm->buckets[idx].lock);
    atomic_fetch_add(&hm->slots_taken, 1);
    return true;
}

bool kevue_hm_get(HashMap *hm, const void *key, size_t key_len, Buffer *buf)
{
    if (hm == NULL || hm->ma == NULL || key_len == 0) return false;
    // NOTE: make sure resize lock is not needed here
    // mutex_lock(&hm->resize_lock);
    uint64_t hash = rapidhash(key, key_len);
    size_t idx = hash % hm->bucket_count;
    mutex_lock(&hm->buckets[idx].lock);
    // mutex_unlock(&hm->resize_lock);
    if (hm->buckets[idx].ptr == NULL) {
        mutex_unlock(&hm->buckets[idx].lock);
        return false;
    }
    kevue_dyna_foreach(&hm->buckets[idx], entry_ptr)
    {
        Entry *entry = *entry_ptr;
        if (entry->hash == hash && entry->key_len == key_len && memcmp(entry->data, key, key_len) == 0) {
            kevue_buffer_write(buf, entry->data + entry->key_len, entry->val_len);
            mutex_unlock(&hm->buckets[idx].lock);
            return true;
        }
    }
    mutex_unlock(&hm->buckets[idx].lock);
    return false;
}

bool kevue_hm_del(HashMap *hm, const void *key, size_t key_len)
{
    if (hm == NULL || hm->ma == NULL || key_len == 0) return false;
    mutex_lock(&hm->resize_lock);
    if (hm->bucket_count > HASHMAP_BUCKET_INITIAL_COUNT) {
        if ((double)atomic_load(&hm->slots_taken) / (double)hm->bucket_count < HASHMAP_MIN_LOAD) {
            kevue__hm_resize(hm, max(HASHMAP_BUCKET_INITIAL_COUNT, hm->bucket_count / HASHMAP_RESIZE_FACTOR));
        }
    }
    uint64_t hash = rapidhash(key, key_len);
    size_t idx = hash % hm->bucket_count;
    mutex_lock(&hm->buckets[idx].lock);
    mutex_unlock(&hm->resize_lock);
    if (hm->buckets[idx].ptr == NULL) {
        mutex_unlock(&hm->buckets[idx].lock);
        return false;
    }
    kevue_dyna_foreach(&hm->buckets[idx], entry_ptr)
    {
        Entry *entry = *entry_ptr;
        if (entry->hash == hash && entry->key_len == key_len && memcmp(entry->data, key, key_len) == 0) {
            ptrdiff_t eidx = entry_ptr - hm->buckets[idx].ptr;
            hm->ma->free(*entry_ptr, hm->ma->ctx);
            kevue_dyna_remove(&hm->buckets[idx], (size_t)eidx);
            atomic_fetch_sub(&hm->slots_taken, 1);
            mutex_unlock(&hm->buckets[idx].lock);
            return true;
        }
    }
    mutex_unlock(&hm->buckets[idx].lock);
    return false;
}

static void kevue__hm_resize(HashMap *hm, size_t new_size)
{
    print_debug("HashMap %s %zu -> %zu", new_size > hm->bucket_count ? "grows" : "shrinks", hm->bucket_count, new_size);
    Bucket *new_buckets = hm->ma->malloc(new_size * sizeof(Bucket), hm->ma->ctx);
    if (new_buckets == NULL) {
        return;
    }
    for (size_t bucket = 0; bucket < new_size; bucket++) {
        new_buckets[bucket].ptr = NULL;
    }
    for (size_t bucket = 0; bucket < hm->bucket_count; bucket++) {
        mutex_lock(&hm->buckets[bucket].lock);
    }
    for (size_t bucket = 0; bucket < hm->bucket_count; bucket++) {
        if (hm->buckets[bucket].ptr == NULL) continue;
        kevue_dyna_foreach(&hm->buckets[bucket], entry_ptr)
        {
            Entry *entry = *entry_ptr;
            size_t idx = entry->hash % new_size;
            if (new_buckets[idx].ptr == NULL) {
                kevue_dyna_init(&new_buckets[idx], HASHMAP_BUCKET_ENTRY_INITIAL_COUNT, hm->ma);
            }
            kevue_dyna_append(&new_buckets[idx], entry);
        }
    }
    size_t old_size = hm->bucket_count;
    hm->bucket_count = new_size;
    Bucket *old_buckets = hm->buckets;
    hm->buckets = new_buckets;
    for (size_t bucket = 0; bucket < old_size; bucket++) {
        mutex_unlock(&old_buckets[bucket].lock);
        if (old_buckets[bucket].ptr == NULL) continue;
        kevue_dyna_deinit(&old_buckets[bucket]);
    }
    hm->ma->free(old_buckets, hm->ma->ctx);
}
