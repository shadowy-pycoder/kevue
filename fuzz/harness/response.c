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
#include <unistd.h>

#include <allocator.h>
#include <buffer.h>
#include <common.h>
#include <protocol.h>

__AFL_FUZZ_INIT();

int main(void)

{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *fuzz_buf = __AFL_FUZZ_TESTCASE_BUF;

    Buffer *in_buf = kevue_buffer_create(1024, &kevue_default_allocator);
    Buffer *out_buf = kevue_buffer_create(1024, &kevue_default_allocator);
    while (__AFL_LOOP(1000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        KevueResponse resp = { 0 };
        kevue_buffer_grow(in_buf, len);
        kevue_buffer_write(in_buf, fuzz_buf, len);
        KevueErr err = kevue_response_deserialize(&resp, in_buf);
        UNUSED(err);
        kevue_response_serialize(&resp, out_buf);
        kevue_buffer_reset(in_buf);
        kevue_buffer_reset(out_buf);
    }
}
