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
// clang -O3 -flto -march=native -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_TCMALLOC -ltcmalloc
#include "../src/buffer.c"
#include "../src/client.c"
#include "../src/common.c"
#include "../src/protocol.c"

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#if defined(USE_TCMALLOC)
#include "../src/tcmalloc_allocator.c"
#elif defined(USE_JEMALLOC)
#include "../src/jemalloc_allocator.c"
#endif

#define NUM_ENTRIES (1024 * 1024 * 10UL)

// https://github.com/svaarala/duktape/blob/master/misc/splitmix64.c
static inline u64 splitmix64(u64 *state)
{
    u64 z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

int main(void)
{
    KevueClientConfig conf = { 0 };
    KevueClient      *kc = kevue_client_create(&conf);
    if (kc == NULL) exit(EXIT_FAILURE);
    KevueAllocator *ma = kevue_allocator();
    KevueResponse  *resp = (KevueResponse *)ma->malloc(sizeof(*resp), ma->ctx);
    if (!kevue_client_hello(kc, resp)) {
        printf("%s\n", kevue_error_code_to_string[resp->err_code]);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    printf("Inserting %zu items...\n", NUM_ENTRIES);
    u64  start = nsec_now();
    bool op_failed = false;
    u64  rng = 1;
    u64  val_rng = 1;
    for (u64 i = 0; i < NUM_ENTRIES; i++) {
        u64 key = splitmix64(&rng);
        u64 val = splitmix64(&val_rng);
        if (!kevue_client_set(kc, resp, &key, 8, &val, 8)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            op_failed = true;
            break;
        }
    }
    u64 finish = nsec_now();
    if (op_failed) {
        kevue_buffer_destroy(resp->val);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    u64 elapsed_ns = finish - start;
    f64 elapsed_sec = (f64)elapsed_ns * 1e-9;
    f64 req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Inserting %zu items takes: %.9fs (%.2f req/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    printf("Getting %zu items...\n", NUM_ENTRIES);
    op_failed = false;
    rng = 1;
    start = nsec_now();
    for (u64 i = 0; i < NUM_ENTRIES; i++) {
        u64 key = splitmix64(&rng);
        if (!kevue_client_get(kc, resp, &key, 8)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            op_failed = true;
            break;
        }
    }
    finish = nsec_now();
    if (op_failed) {
        kevue_buffer_destroy(resp->val);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    elapsed_ns = finish - start;
    elapsed_sec = (f64)elapsed_ns * 1e-9;
    req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Getting %zu items takes: %.9fs (%.2f req/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    printf("Fetching %zu items...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_items(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu items takes: %.9fs\n", NUM_ENTRIES, (f64)(finish - start) * 1e-9);
    printf("Fetching %zu keys...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_keys(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu keys takes: %.9fs\n", NUM_ENTRIES, (f64)(finish - start) * 1e-9);
    printf("Fetching %zu values...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_values(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu values takes: %.9fs\n", NUM_ENTRIES, (f64)(finish - start) * 1e-9);
    printf("Counting %zu entries...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_count(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Counting %zu entries takes: %.9fs\n", NUM_ENTRIES, (f64)(finish - start) * 1e-9);
    printf("Deleting %zu items...\n", NUM_ENTRIES);
    op_failed = false;
    rng = 1;
    start = nsec_now();
    for (u64 i = 0; i < NUM_ENTRIES; i++) {
        u64 key = splitmix64(&rng);
        if (!kevue_client_del(kc, resp, &key, 8)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            op_failed = true;
            break;
        }
    }
    finish = nsec_now();
    if (op_failed) {
        kevue_buffer_destroy(resp->val);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    elapsed_ns = finish - start;
    elapsed_sec = (f64)elapsed_ns * 1e-9;
    req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Deleting %zu items takes: %.9fs (%.2f req/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    kevue_buffer_destroy(resp->val);
    ma->free(resp, ma->ctx);
    kevue_client_destroy(kc);
    return 0;
}
