// clang -Iinclude -Ilib ./tests/test_request_deserialize.c -o ./bin/kevue-test-request-deserialize -DDEBUG
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/allocator.c"
#include "../src/buffer.c"
#include "../src/common.c"
#include "../src/protocol.c"

uint8_t data[] = {
    0x22, // magic byte
    0x00, 0x00, 0x00, 0x0f, // total length
    0x03, // command length
    'G', 'E', 'T', // command
    0x00, 0x04, // key length
    't', 'e', 's', 't' // key
};

uint8_t malformed_data[] = {
    0x22, // magic byte
    0x00, 0x00, 0x00, 0x0f, // total length
    0x03, // command length
    'G', 'E', 'T', // command
    0x00, 0xff, // key length malformed
    't', 'e', 's', 't' // key
};

uint8_t garbage[] = {
    0x00, 0x04, 0x45, 0x00, 0x00, 0x54, 0x00, 0x22,
    0x00, 0x00, 0x00, 0x10, 0x04, 0x50, 0x49, 0x00,
    0x00, 0x02, 0x00, 0x40, 0x00, 0x73, 0x00, 0x03,
    0x53, 0x45, 0x54, 0x00, 0x00
};

int main()
{
    KevueRequest req = { 0 };
    Buffer *buf = kevue_buffer_create(64, &kevue_default_allocator);
    assert(buf != NULL);
    kevue_buffer_write(buf, data, sizeof(data));
    KevueErr err = kevue_request_deserialize(&req, buf);
    assert(err == KEVUE_ERR_OK);
    kevue_request_print(&req);
    printf("\n");

    kevue_buffer_reset(buf);
    memset(&req, 0, sizeof(req));
    kevue_buffer_write(buf, malformed_data, sizeof(malformed_data));
    err = kevue_request_deserialize(&req, buf);
    printf("%s\n", kevue_error_code_to_string(err));
    printf("\n");
    assert(err == KEVUE_ERR_LEN_INVALID);

    kevue_buffer_reset(buf);
    memset(&req, 0, sizeof(req));
    kevue_buffer_write(buf, garbage, sizeof(garbage));
    err = kevue_request_deserialize(&req, buf);
    printf("%s\n", kevue_error_code_to_string(err));
    printf("\n");
    assert(err == KEVUE_ERR_MAGIC_BYTE_INVALID);

    kevue_buffer_reset(buf);
    memset(&req, 0, sizeof(req));
    for (size_t i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        kevue_buffer_append(buf, &data[i], sizeof(data[0]));
        err = kevue_request_deserialize(&req, buf);
        if (err == KEVUE_ERR_INCOMPLETE_READ) continue;
        if (err != KEVUE_ERR_OK) exit(EXIT_FAILURE);
        if (err == KEVUE_ERR_OK) {
            kevue_request_print(&req);
            exit(EXIT_SUCCESS);
        }
    }
    exit(EXIT_FAILURE);
}
