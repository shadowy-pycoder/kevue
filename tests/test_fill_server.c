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

// clang -g3 -Iinclude -Ilib ./tests/test_fill_server.c -o ./bin/kevue-test-fill-server -DDEBUG
#include "../src/buffer.c"
#include "../src/client.c"
#include "../src/common.c"
#include "../src/protocol.c"
#include "tests_common.h"

#define NUM_ENTRIES (1024 * 1024 * 10UL)

int main(void)
{
    KevueClientConfig conf = { 0 };
#if defined(USE_ARENA)
    KevueAllocator  arena_ma = kevue_allocator_from_arena_sizes(KEVUE_ARENA_RESERVE_SIZE_DEFAULT, KEVUE_ARENA_COMMIT_SIZE_DEFAULT);
    KevueAllocator *ma = &arena_ma;
#else
    KevueAllocator *ma = kevue_allocator();
#endif
    KevueClient *kc = kevue_client_create(ma, &conf);
    if (kc == NULL) exit(EXIT_FAILURE);
    KevueResponse *resp = (KevueResponse *)kc->ma->malloc(sizeof(KevueResponse), kevue_alignof(KevueResponse), kc->ma->ctx);
    if (!kevue_client_hello(kc, resp)) {
        printf("%s\n", kevue_error_code_to_string[resp->err_code]);
        kc->ma->free(resp, kc->ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    for (u64 i = 0; i < NUM_ENTRIES; i++) {
        if (i % 100000 == 0) printf("Added (%zu/%zu) key-value pairs\n", i, NUM_ENTRIES);
        char key[64] = {};
        char val[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        int  val_len = snprintf(val, sizeof(val), "World%zu", i);
        if (!kevue_client_set(kc, resp, key, (u16)key_len, val, (u16)val_len)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            break;
        }
    }
    kevue_buffer_destroy(resp->val);
    kc->ma->free(resp, kc->ma->ctx);
    kevue_client_destroy(kc);
}
