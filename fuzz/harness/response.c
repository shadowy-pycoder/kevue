#include <stdint.h>
#include <unistd.h>

#include <allocator.h>
#include <buffer.h>
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
        kevue_request_serialize(&resp, out_buf);
        kevue_buffer_reset(in_buf);
        kevue_buffer_reset(out_buf);
    }
}
