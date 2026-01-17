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

// clang -g3 -Iinclude -Ilib ./src/allocator.c ./tests/test_fill_server.c -o ./bin/kevue-test-fill-server -DDEBUG
#include "../src/buffer.c"
#include "../src/client.c"
#include "../src/common.c"
#include "../src/protocol.c"

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
    KevueClient *kc = kevue_client_create(HOST, PORT, ma);
    if (kc == NULL) exit(EXIT_FAILURE);
    KevueResponse *resp = (KevueResponse *)ma->malloc(sizeof(KevueResponse), ma->ctx);
    if (!kevue_client_hello(kc, resp)) {
        printf("%s\n", kevue_error_code_to_string(resp->err_code));
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    uint64_t start = nsec_now();
    bool     op_failed = false;
    for (size_t i = 0; i < NUM_ENTRIES; i++) {
        if (i % 100000 == 0) printf("Added (%zu/%zu) key-value pairs\n", i, NUM_ENTRIES);
        char key[64] = {};
        char val[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        int  val_len = snprintf(val, sizeof(val), "World%zu", i);
        if (!kevue_client_set(kc, resp, key, (uint16_t)key_len, val, (uint16_t)val_len)) {
            printf("%s\n", kevue_error_code_to_string(resp->err_code));
            op_failed = true;
            break;
        }
    }
    if (!op_failed) {
        uint64_t finish = nsec_now();
        uint64_t elapsed_ns = finish - start;
        double   elapsed_sec = (double)elapsed_ns * 1e-9;
        double   req_sec = NUM_ENTRIES / elapsed_sec;
        printf("Inserting %zu items takes: %.9fs (%.2f req/sec)\n", NUM_ENTRIES, elapsed_sec, req_sec);
        start = nsec_now();
        kevue_client_items(kc, resp);
        finish = nsec_now();
        if (resp->err_code == KEVUE_ERR_OK) {
            printf("Fetching %zu items takes: %.9fs\n", NUM_ENTRIES, (double)(finish - start) * 1e-9);
        } else {
            printf("Fething items failed: %s\n", kevue_error_code_to_string(resp->err_code));
        }
    }
    kevue_buffer_destroy(resp->val);
    ma->free(resp, ma->ctx);
    kevue_client_destroy(kc);
}
