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

// clang -g3 -Iinclude -Ilib ./src/allocator.c ./tests/test_get_request.c -o ./bin/kevue-test-get-request -DDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../src/buffer.c"
#include "../src/client.c"
#include "../src/common.c"
#include "../src/protocol.c"
#include "protocol.h"

#if defined(USE_TCMALLOC) && defined(USE_JEMALLOC)
#error "You can define only one memory allocator at a time"
#endif
#if defined(USE_TCMALLOC)
#include "../src/tcmalloc_allocator.c"
#elif defined(USE_JEMALLOC)
#include "../src/jemalloc_allocator.c"
#endif

#define NUM_REQUESTS 32

int main(void)
{
    KevueClientConfig conf = { 0 };
    KevueClient      *kc = kevue_client_create(&conf);
    if (kc == NULL) exit(EXIT_FAILURE);
    KevueAllocator *ma = kevue_allocator();
    KevueResponse  *resp = (KevueResponse *)ma->malloc(sizeof(KevueResponse), ma->ctx);
    memset(resp, 0, sizeof(*resp));
    if (!kevue_client_hello(kc, resp)) {
        printf("%s\n", kevue_error_code_to_string[resp->err_code]);
        ma->free(resp, ma->ctx);
        kevue_client_destroy(kc);
        exit(EXIT_FAILURE);
    }
    for (u64 i = 0; i < NUM_REQUESTS; i++) {
        printf("OK Request (%zu/%d) PASSED\r", i + 1, NUM_REQUESTS);
        fflush(stdout);
        char key[64] = {};
        char val[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i);
        int  val_len = snprintf(val, sizeof(val), "World%zu", i);
        if (!kevue_client_set(kc, resp, key, (u16)key_len, val, (u16)val_len)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            ma->free(resp, ma->ctx);
            kevue_client_destroy(kc);
            exit(EXIT_FAILURE);
        }
        if (!kevue_client_get(kc, resp, key, (u16)key_len)) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
            ma->free(resp, ma->ctx);
            kevue_client_destroy(kc);
            exit(EXIT_FAILURE);
        }
        assert(resp->err_code == KEVUE_ERR_OK);
        usleep(1000 * 20);
    }
    printf("\n");
    for (u64 i = 0; i < NUM_REQUESTS; i++) {
        printf("NOT_FOUND Request (%zu/%d) PASSED\r", i + 1, NUM_REQUESTS);
        fflush(stdout);
        char key[64] = {};
        int  key_len = snprintf(key, sizeof(key), "Hello%zu", i + NUM_REQUESTS);
        kevue_client_get(kc, resp, key, (u16)key_len);
        if (resp->err_code != KEVUE_ERR_NOT_FOUND) {
            printf("%s\n", kevue_error_code_to_string[resp->err_code]);
        }
        assert(resp->err_code == KEVUE_ERR_NOT_FOUND);
        usleep(1000 * 20);
    }
    printf("\n");
    kevue_buffer_destroy(resp->val);
    ma->free(resp, ma->ctx);
    kevue_client_destroy(kc);
}
