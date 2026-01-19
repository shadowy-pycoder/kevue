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
// clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_hashmap.c -o ./bin/kevue-bench-hashmap -DUSE_TCMALLOC -ltcmalloc
#include "../src/buffer.c"
#include "../src/common.c"
#include "../src/threaded_hashmap.c"

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#ifdef USE_TCMALLOC
#include "../src/tcmalloc_allocator.c"
#endif
#ifdef USE_JEMALLOC
#include "../src/jemalloc_allocator.c"
#endif

#define NUM_ENTRIES (1024 * 1024 * 10UL)

int main(void)
{
    KevueAllocator *ma;
#if defined(USE_TCMALLOC)
    ma = &kevue_tcmalloc_allocator;
#elif defined(USE_JEMALLOC)
    ma = &kevue_jemalloc_allocator;
#else
    ma = &kevue_default_allocator;
#endif
    HashMap *hm = kevue_hm_threaded_create(ma);
    printf("Inserting %zu items...\n", NUM_ENTRIES);
    uint64_t start = nsec_now();
    bool     op_failed = false;
    for (size_t i = 0; i < NUM_ENTRIES; i++) {
        char key[64] = {};
        char val[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        int  val_len = snprintf(val, sizeof(val), "World%zu", i);
        if (!kevue__hm_threaded_put(hm, key, (size_t)key_len, val, (size_t)val_len)) {
            op_failed = true;
            break;
        }
    }
    uint64_t finish = nsec_now();
    if (op_failed) {
        kevue__hm_threaded_destroy(hm);
        exit(EXIT_FAILURE);
    }
    uint64_t elapsed_ns = finish - start;
    double   elapsed_sec = (double)elapsed_ns * 1e-9;
    double   req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Inserting %zu items takes: %.9fs (%.2f op/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    printf("Getting %zu items...\n", NUM_ENTRIES);
    op_failed = false;
    start = nsec_now();
    Buffer *buf = kevue_buffer_create(BUF_SIZE, ma);
    for (size_t i = 0; i < NUM_ENTRIES; i++) {
        char key[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        if (!kevue__hm_threaded_get(hm, key, (size_t)key_len, buf)) {
            op_failed = true;
            break;
        }
    }
    finish = nsec_now();
    if (op_failed) {
        kevue__hm_threaded_destroy(hm);
        kevue_buffer_destroy(buf);
        exit(EXIT_FAILURE);
    }
    elapsed_ns = finish - start;
    elapsed_sec = (double)elapsed_ns * 1e-9;
    req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Getting %zu items takes: %.9fs (%.2f op/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    printf("Fetching %zu items...\n", NUM_ENTRIES);
    kevue_buffer_reset(buf);
    start = nsec_now();
    if (!kevue__hm_threaded_items(hm, buf)) {
        kevue__hm_threaded_destroy(hm);
        kevue_buffer_destroy(buf);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu items takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Fetching %zu keys...\n", NUM_ENTRIES);
    kevue_buffer_reset(buf);
    start = nsec_now();
    if (!kevue__hm_threaded_keys(hm, buf)) {
        kevue__hm_threaded_destroy(hm);
        kevue_buffer_destroy(buf);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu keys takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Fetching %zu values...\n", NUM_ENTRIES);
    kevue_buffer_reset(buf);
    start = nsec_now();
    if (!kevue__hm_threaded_values(hm, buf)) {
        kevue__hm_threaded_destroy(hm);
        kevue_buffer_destroy(buf);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu values takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Counting %zu entries...\n", NUM_ENTRIES);
    start = nsec_now();
    kevue__hm_threaded_len(hm);
    finish = nsec_now();
    printf("Counting %zu entries takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Deleting %zu items...\n", NUM_ENTRIES);
    op_failed = false;
    start = nsec_now();
    for (size_t i = 0; i < NUM_ENTRIES; i++) {
        char key[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        if (!kevue__hm_threaded_del(hm, key, (size_t)key_len)) {
            op_failed = true;
            break;
        }
    }
    finish = nsec_now();
    if (op_failed) {
        kevue__hm_threaded_destroy(hm);
        kevue_buffer_destroy(buf);
        exit(EXIT_FAILURE);
    }
    elapsed_ns = finish - start;
    elapsed_sec = (double)elapsed_ns * 1e-9;
    req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Deleting %zu items takes: %.9fs (%.2f op/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    kevue__hm_threaded_destroy(hm);
    kevue_buffer_destroy(buf);
    return 0;
}
