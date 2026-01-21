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
// clang -O3 -flto -Iinclude -Ilib ./src/allocator.c ./benchmarks/bench_server.c -o ./bin/kevue-bench-server -DUSE_TCMALLOC -ltcmalloc
#include "../src/buffer.c"
#include "../src/client.c"
#include "../src/common.c"
#include "../src/protocol.c"

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#if defined(USE_TCMALLOC)
#include <tcmalloc_allocator.h>
#elif defined(USE_JEMALLOC)
#include <jemalloc_allocator.h>
#endif

#define NUM_ENTRIES (1024 * 1024 * 10UL)

int main(void)
{
    KevueClientConfig conf = { 0 };
    KevueClient      *kc = kevue_client_create(&conf);
    if (kc == NULL) exit(EXIT_FAILURE);
    KevueResponse *resp = (KevueResponse *)conf.ma->malloc(sizeof(*resp), conf.ma->ctx);
    if (!kevue_client_hello(kc, resp)) {
        printf("%s\n", kevue_error_code_to_string[resp->err_code]);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    printf("Inserting %zu items...\n", NUM_ENTRIES);
    uint64_t start = nsec_now();
    bool     op_failed = false;
    for (size_t i = 0; i < NUM_ENTRIES; i++) {
        char key[64] = {};
        char val[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        int  val_len = snprintf(val, sizeof(val), "World%zu", i);
        if (!kevue_client_set(kc, resp, key, (uint16_t)key_len, val, (uint16_t)val_len)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            op_failed = true;
            break;
        }
    }
    uint64_t finish = nsec_now();
    if (op_failed) {
        kevue_buffer_destroy(resp->val);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    uint64_t elapsed_ns = finish - start;
    double   elapsed_sec = (double)elapsed_ns * 1e-9;
    double   req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Inserting %zu items takes: %.9fs (%.2f req/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    printf("Getting %zu items...\n", NUM_ENTRIES);
    op_failed = false;
    start = nsec_now();
    for (size_t i = 0; i < NUM_ENTRIES; i++) {
        char key[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        if (!kevue_client_get(kc, resp, key, (uint16_t)key_len)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            op_failed = true;
            break;
        }
    }
    finish = nsec_now();
    if (op_failed) {
        kevue_buffer_destroy(resp->val);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    elapsed_ns = finish - start;
    elapsed_sec = (double)elapsed_ns * 1e-9;
    req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Getting %zu items takes: %.9fs (%.2f req/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    printf("Fetching %zu items...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_items(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu items takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Fetching %zu keys...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_keys(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu keys takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Fetching %zu values...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_values(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Fetching %zu values takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Counting %zu entries...\n", NUM_ENTRIES);
    start = nsec_now();
    if (!kevue_client_count(kc, resp)) {
        kevue_buffer_destroy(resp->val);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    finish = nsec_now();
    printf("Counting %zu entries takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
    printf("Deleting %zu items...\n", NUM_ENTRIES);
    op_failed = false;
    start = nsec_now();
    for (size_t i = 0; i < NUM_ENTRIES; i++) {
        char key[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        if (!kevue_client_del(kc, resp, key, (uint16_t)key_len)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            op_failed = true;
            break;
        }
    }
    finish = nsec_now();
    if (op_failed) {
        kevue_buffer_destroy(resp->val);
        conf.ma->free(resp, conf.ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    elapsed_ns = finish - start;
    elapsed_sec = (double)elapsed_ns * 1e-9;
    req_sec = NUM_ENTRIES / elapsed_sec;
    printf("Deleting %zu items takes: %.9fs (%.2f req/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
    kevue_buffer_destroy(resp->val);
    conf.ma->free(resp, conf.ma->ctx);
    kevue_client_destroy(kc);
    return 0;
}
