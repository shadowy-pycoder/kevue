/*
 * Copyright 2025 shadowy-pycoder
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
/*
 * Protocol structure (Request):
 *  Magic byte 0x22 (sum of ascii codes of "kevue" word modulo 255)
 *  Total length including magic byte and this field -> uint32
 *  Length of the command (GET/SET/DELETE) - 1 byte
 *  Command (GET/SET/DELETE) case insensitive
 *  Depends on the command GET/DELETE -> key -> uint16 length [key]
 *  SET -> key, value -> uint16 length [key] uint16 length [value]
 *  Use ntohs/htons for uint16 length conversion
 *
 * Protocol structure (Response):
 *  Magic byte 0x22 (sum of ascii codes of "kevue" word modulo 255)
 *  Total length including magic byte and this field -> uint32
 *  Error byte uint8
 *  Length of the reply uint16 (0 if no value)
 *  Reply: actual value (case sensitive)
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <allocator.h>
#include <buffer.h>

#define KEVUE_MAGIC_BYTE          "\x22"
#define KEVUE_MAGIC_BYTE_SIZE     1
#define KEVUE_MESSAGE_HEADER_SIZE (KEVUE_MAGIC_BYTE_SIZE + 4)
#define KEVUE_MESSAGE_MAX_LEN     UINT32_MAX

#define COMMAND_LIST \
    X(HELLO)         \
    X(GET)           \
    X(SET)           \
    X(DELETE)

typedef enum KevueCommand {
#define X(name) name,
    COMMAND_LIST
#undef X
} KevueCommand;

#define ERROR_CODE_LIST                                      \
    X(KEVUE_ERR_OK, "OK")                                    \
    X(KEVUE_ERR_INCOMPLETE_READ, "Reading was not complete") \
    X(KEVUE_ERR_MAGIC_BYTE_INVALID, "Magic byte is invalid") \
    X(KEVUE_ERR_UNKNOWN_COMMAND, "Unknown command")          \
    X(KEVUE_ERR_LEN_INVALID, "Length is invalid")            \
    X(KEVUE_ERR_NOT_FOUND, "Not found")                      \
    X(KEVUE_ERR_READ_FAILED, "Failed reading message")       \
    X(KEVUE_ERR_EOF, "Peer closed connection")               \
    X(KEVUE_ERR_HANDSHAKE, "Handshake failed")

typedef enum KevueErr {
#define X(name, str) name,
    ERROR_CODE_LIST
#undef X
} KevueErr;

typedef struct KevueRequest {
    uint32_t total_len;
    uint8_t cmd_len;
    KevueCommand cmd;
    uint16_t key_len;
    char *key;
    uint16_t val_len;
    char *val;
} KevueRequest;

typedef struct KevueResponse {
    uint32_t total_len;
    KevueErr err_code;
    uint16_t val_len;
    Buffer *val;
    KevueAllocator *ma;
} KevueResponse;

KevueErr kevue_read_message_length(int sock, Buffer *buf, uint32_t *total_len);
KevueErr kevue_deserialize_request(KevueRequest *req, Buffer *buf);
void kevue_serialize_request(KevueRequest *req, Buffer *buf);
KevueErr kevue_deserialize_response(KevueResponse *resp, Buffer *buf);
void kevue_destroy_response(KevueResponse *resp);
void kevue_serialize_response(KevueResponse *resp, Buffer *buf);
void kevue_print_request(KevueRequest *req);
void kevue_print_response(KevueResponse *resp);
char *kevue_command_to_string(KevueCommand cmd);
char *kevue_error_to_string(KevueErr e);
bool kevue_compare_command(char *data, uint8_t len, KevueCommand cmd);
