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
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <buffer.h>
#include <common.h>
#include <protocol.h>

static bool kevue__compare_command(char *data, uint8_t len, KevueCommand cmd);

bool kevue__compare_command(char *data, uint8_t len, KevueCommand cmd)
{
    const char *cmd_name = kevue_command_to_string(cmd);
    return strlen(cmd_name) == len && memcmp(data, cmd_name, len) == 0;
}

char *kevue_command_to_string(KevueCommand c)
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

char *kevue_error_to_string(KevueErr e)
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

KevueMessageHeader kevue_read_message_header(int sock, Buffer *buf)
{
    KevueMessageHeader h = { 0 };
    while (buf->size < KEVUE_MESSAGE_HEADER_SIZE) {
        int nr = read(sock, buf->ptr + buf->size, KEVUE_MESSAGE_HEADER_SIZE - buf->size);
        if (nr < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                h.err_code = KEVUE_ERR_INCOMPLETE_READ;
                return h;
            }
            if (errno == EINTR)
                continue;
            h.err_code = KEVUE_ERR_READ_FAILED;
            return h;
        } else if (nr == 0) {
            h.err_code = KEVUE_ERR_EOF;
            return h;
        } else {
            buf->size += nr;
#ifdef DEBUG
            printf("DEBUG: Read %d bytes \n", nr);
#endif
        }
    }
    assert(buf->offset == 0);
    if (memcmp(buf->ptr, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_BYTE_SIZE) != 0) {
        h.err_code = KEVUE_ERR_MAGIC_BYTE_INVALID;
        return h;
    }
    buf->offset = KEVUE_MAGIC_BYTE_SIZE;
    memcpy(&h.total_len, buf->ptr + buf->offset, sizeof(uint32_t));
    h.total_len = ntohl(h.total_len);
    h.err_code = KEVUE_ERR_OK;
    buf->offset += sizeof(uint32_t);
    return h;
}

KevueErr kevue_deserialize_request(KevueRequest *req, Buffer *buf)
{
    assert(buf->offset == KEVUE_MESSAGE_HEADER_SIZE);
    assert(req->total_len == buf->size);
    memcpy(&req->cmd_len, buf->ptr + buf->offset, sizeof(uint8_t));
    buf->offset += sizeof(uint8_t);
    to_upper(buf->ptr + buf->offset, req->cmd_len);
    if (kevue__compare_command(buf->ptr + buf->offset, req->cmd_len, GET)) {
        req->cmd = GET;
    } else if (kevue__compare_command(buf->ptr + buf->offset, req->cmd_len, SET)) {
        req->cmd = SET;
    } else if (kevue__compare_command(buf->ptr + buf->offset, req->cmd_len, DELETE)) {
        req->cmd = DELETE;
    } else {
        return KEVUE_ERR_UNKNOWN_COMMAND;
    }
    buf->offset += req->cmd_len;
    memcpy(&req->key_len, buf->ptr + buf->offset, sizeof(uint16_t));
    req->key_len = ntohs(req->key_len);
    buf->offset += sizeof(uint16_t);
    req->key = buf->ptr + buf->offset;
    buf->offset += req->key_len;
    if (buf->offset > req->total_len) return KEVUE_ERR_LEN_INVALID;
    req->val_len = 0;
    req->val = NULL;
    if (req->cmd == SET) {
        memcpy(&req->val_len, buf->ptr + buf->offset, sizeof(uint16_t));
        req->val_len = ntohs(req->val_len);
        buf->offset += sizeof(uint16_t);
        req->val = buf->ptr + buf->offset;
        buf->offset += req->val_len;
        if (buf->offset > req->total_len) return KEVUE_ERR_LEN_INVALID;
    }
    return KEVUE_ERR_OK;
}

void kevue_print_request(KevueRequest *req)
{
    printf("Total Length: %d\n", req->total_len);
    printf("Command Length: %d\n", req->cmd_len);
    printf("Command: %*s\n", req->cmd_len, kevue_command_to_string(req->cmd));
    printf("Key Length: %d\n", req->key_len);
    printf("Key: %.*s\n", req->key_len, req->key);
    if (req->val_len > 0) {
        printf("Value Length: %d\n", req->val_len);
        printf("Value: %.*s\n", req->val_len, req->val);
    }
}

void kevue_serialize_request(KevueRequest *req, Buffer *buf)
{
    assert(req->cmd_len > 0);
    assert(req->key_len > 0);
    req->total_len = KEVUE_MAGIC_BYTE_SIZE + sizeof(req->total_len) + sizeof(req->cmd_len) + req->cmd_len + sizeof(req->key_len) + req->key_len;
    if (req->cmd == SET) {
        assert(req->val_len > 0);
        req->total_len += sizeof(req->val_len) + req->val_len;
    }
    if (buf->capacity < req->total_len) kevue_buffer_grow(buf, req->total_len - buf->capacity);
    kevue_buffer_append(buf, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_BYTE_SIZE);
    uint32_t tl = htonl(req->total_len);
    kevue_buffer_append(buf, &tl, sizeof(req->total_len));
    kevue_buffer_append(buf, &req->cmd_len, sizeof(req->cmd_len));
    kevue_buffer_append(buf, kevue_command_to_string(req->cmd), req->cmd_len);
    uint16_t kl = htons(req->key_len);
    kevue_buffer_append(buf, &kl, sizeof(req->key_len));
    kevue_buffer_append(buf, req->key, req->key_len);
    if (req->cmd == SET) {
        uint16_t vl = htons(req->val_len);
        kevue_buffer_append(buf, &vl, sizeof(req->val_len));
        kevue_buffer_append(buf, req->val, req->val_len);
    }
}

KevueErr kevue_deserialize_response(KevueResponse *resp, Buffer *buf)
{
    assert(buf->offset == KEVUE_MESSAGE_HEADER_SIZE);
    assert(resp->total_len == buf->size);
    memcpy(&resp->err_code, buf->ptr + buf->offset, sizeof(uint8_t));
    buf->offset += sizeof(uint8_t);
    memcpy(&resp->val_len, buf->ptr + buf->offset, sizeof(uint16_t));
    resp->val_len = ntohs(resp->val_len);
    buf->offset += sizeof(uint16_t);
    if (resp->err_code != KEVUE_ERR_OK) {
        resp->val_len = 0;
        return KEVUE_ERR_OK;
    }
    if (resp->val_len > 0) {
        resp->val = (char *)malloc(resp->val_len);
        memcpy(resp->val, buf->ptr + buf->offset, resp->val_len);
        buf->offset += resp->val_len;
        if (buf->offset > resp->total_len) return KEVUE_ERR_LEN_INVALID;
    }
    return KEVUE_ERR_OK;
}

void kevue_destroy_response(KevueResponse *resp)
{
    if (resp->val_len > 0) free(resp->val);
    free(resp);
}

void kevue_serialize_response(KevueResponse *resp, Buffer *buf)
{
    resp->total_len = KEVUE_MAGIC_BYTE_SIZE + sizeof(resp->total_len) + sizeof(uint8_t) + sizeof(resp->val_len);
    if (resp->err_code != KEVUE_ERR_OK) resp->val_len = 0;
    if (resp->val_len > 0) {
        resp->total_len += resp->val_len;
    }
    if (buf->capacity < resp->total_len) kevue_buffer_grow(buf, resp->total_len - buf->capacity);
    kevue_buffer_append(buf, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_BYTE_SIZE);
    uint32_t tl = htonl(resp->total_len);
    kevue_buffer_append(buf, &tl, sizeof(resp->total_len));
    uint8_t ec = resp->err_code;
    kevue_buffer_append(buf, &ec, sizeof(uint8_t));
    uint16_t vl = htons(resp->val_len);
    kevue_buffer_append(buf, &vl, sizeof(resp->val_len));
    if (resp->val_len > 0) {
        kevue_buffer_append(buf, resp->val, resp->val_len);
    }
}

void kevue_print_response(KevueResponse *resp)
{
    printf("Total Length: %d\n", resp->total_len);
    printf("Error Code: %d\n", resp->err_code);
    printf("Error Description: %s\n", kevue_error_to_string(resp->err_code));
    if (resp->val_len > 0) {
        printf("Value Length: %d\n", resp->val_len);
        printf("Value: %.*s\n", resp->val_len, resp->val);
    }
}
