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
 *  Length of the reply uint16
 *  Reply: OK,ERROR,NULL (case insensitive) actual value (case sensitive)
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <buffer.h>

#define KEVUE_MAGIC_BYTE "\x22"
#define KEVUE_MAGIC_SIZE 1

#define COMMAND_LIST \
    X(GET)           \
    X(SET)           \
    X(DELETE)

typedef enum KevueCommand {
#define X(name) name,
    COMMAND_LIST
#undef X
} KevueCommand;

#define ERROR_CODE_LIST                                \
    X(ERR_OK, "OK")                                    \
    X(ERR_BUFFER_TO_SMALL, "Buffer too small")         \
    X(ERR_MAGIC_BYTE_INVALID, "Magic byte is invalid") \
    X(ERR_UNKNOWN_COMMAND, "Unknown command")          \
    X(ERR_LEN_INVALID, "Length is invalid")

typedef enum ParseErr {
#define X(name, str) name,
    ERROR_CODE_LIST
#undef X
} ParseErr;

typedef struct KevueRequest {
    uint32_t total_len;
    uint8_t command_len;
    KevueCommand command;
    uint16_t key_len;
    char *key;
    uint16_t val_len;
    char *val;
} KevueRequest;

ParseErr kevue_deserialize_request(KevueRequest *req, Buffer *buf);
void kevue_print_request(KevueRequest *req);
const char *kevue_command_to_string(KevueCommand cmd);
const char *kevue_error_to_string(ParseErr e);
