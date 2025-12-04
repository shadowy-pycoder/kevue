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
#include "buffer.h"
#include <assert.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <common.h>
#include <protocol.h>

static bool compare_command(char *data, uint8_t len, KevueCommand cmd);

bool compare_command(char *data, uint8_t len, KevueCommand cmd)
{
    const char *cmd_name = kevue_command_to_string(cmd);
    return strlen(cmd_name) == len && memcmp(data, cmd_name, len) == 0;
}

const char *kevue_command_to_string(KevueCommand c)
{
    switch (c) {
#define X(name) \
    case name:  \
        return #name;
        COMMAND_LIST
#undef X
    }
    return "Unknown";
}

const char *kevue_error_to_string(ParseErr e)
{
    switch (e) {
#define X(name, str) \
    case name:       \
        return str;
        ERROR_CODE_LIST
#undef X
    }
    return "Unknown";
}

ParseErr kevue_deserialize_request(KevueRequest *req, Buffer *buf)
{
    assert(buf->offset == 0);
    assert(buf->size >= KEVUE_MAGIC_SIZE);
    if (memcmp(buf->ptr, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_SIZE) != 0) return ERR_MAGIC_BYTE_INVALID;
    buf->offset = KEVUE_MAGIC_SIZE;
    if (buf->size < buf->offset + sizeof(uint32_t)) return ERR_BUFFER_TO_SMALL;
    memcpy(&req->total_len, buf->ptr + buf->offset, sizeof(uint32_t));
    req->total_len = ntohl(req->total_len);
    if (req->total_len > buf->size) return ERR_BUFFER_TO_SMALL;
    buf->offset += sizeof(uint32_t);
    if (buf->offset > buf->size) return ERR_LEN_INVALID;
    memcpy(&req->command_len, buf->ptr + buf->offset, sizeof(uint8_t));
    buf->offset += sizeof(uint8_t);
    if (buf->offset > buf->size) return ERR_LEN_INVALID;
    to_upper(buf->ptr + buf->offset, req->command_len);
    if (compare_command(buf->ptr + buf->offset, req->command_len, GET)) {
        req->command = GET;
    } else if (compare_command(buf->ptr + buf->offset, req->command_len, SET)) {
        req->command = SET;
    } else if (compare_command(buf->ptr + buf->offset, req->command_len, DELETE)) {
        req->command = DELETE;
    } else {
        return ERR_UNKNOWN_COMMAND;
    }
    buf->offset += req->command_len;
    if (buf->offset > buf->size) return ERR_LEN_INVALID;
    memcpy(&req->key_len, buf->ptr + buf->offset, sizeof(uint16_t));
    req->key_len = ntohs(req->key_len);
    buf->offset += sizeof(uint16_t);
    if (buf->offset > buf->size) return ERR_LEN_INVALID;
    req->key = buf->ptr + buf->offset;
    buf->offset += req->key_len;
    if (buf->offset > buf->size) return ERR_LEN_INVALID;
    switch (req->command) {
    case SET:
        memcpy(&req->val_len, buf->ptr + buf->offset, sizeof(uint16_t));
        req->val_len = ntohs(req->val_len);
        buf->offset += sizeof(uint16_t);
        if (buf->offset > buf->size) return ERR_LEN_INVALID;
        req->val = buf->ptr + buf->offset;
        buf->offset += req->val_len;
        if (buf->offset > buf->size) return ERR_LEN_INVALID;
        break;
    default:
        req->val_len = 0;
        req->val = NULL;
    }
    return ERR_OK;
}

void kevue_print_request(KevueRequest *req)
{
    printf("Total Length: %d\n", req->total_len);
    printf("Command Length: %d\n", req->command_len);
    printf("Command: %*s\n", req->command_len, kevue_command_to_string(req->command));
    printf("Key Length: %d\n", req->key_len);
    printf("Key: %*s\n", req->key_len, req->key);
    if (req->val_len > 0) {
        printf("Value Length: %d\n", req->val_len);
        printf("Value: %*s\n", req->val_len, req->val);
    }
}
