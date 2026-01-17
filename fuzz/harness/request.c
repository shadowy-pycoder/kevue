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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <allocator.h>
#include <buffer.h>
#include <protocol.h>

__AFL_FUZZ_INIT();

#define CAPACITY 64

static inline void buffer_init(Buffer *buf, int capacity)
{
    memset(buf, 0, sizeof(*buf));
    KevueAllocator *ma = &kevue_default_allocator;
    buf->ptr = ma->malloc(capacity, ma->ctx);
    memset(buf->ptr, 0, capacity);
    buf->ma = ma;
}

static inline void buffer_deinit(Buffer *buf)
{
    buf->ma->free(buf->ptr, buf->ma->ctx);
}

int main(void)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    unsigned char *fuzz_buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000)) {
        size_t       len = __AFL_FUZZ_TESTCASE_LEN;
        Buffer       in_buf = { 0 };
        Buffer       out_buf = { 0 };
        KevueRequest req = { 0 };
        buffer_init(&in_buf, len);
        buffer_init(&out_buf, CAPACITY);
        memcpy(in_buf.ptr, fuzz_buf, len);
        KevueErr err = kevue_request_deserialize(&req, &in_buf);
        (void)err;
        kevue_request_serialize(&req, &out_buf);
        buffer_deinit(&in_buf);
        buffer_deinit(&out_buf);
    }
    return 0;
}
