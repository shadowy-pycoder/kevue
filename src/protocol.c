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
/**
 * @file protocol.c
 * @brief kevue protocol implementation.
 */
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#include <allocator.h>
#include <buffer.h>
#include <common.h>
#include <protocol.h>

typedef struct KevueCommandPDispatchesult {
    KevueCommand cmd;
    KevueErr     err;
} KevueCommandDispatchResult;

static KevueCommandDispatchResult kevue__command_dispatch(uint8_t cmd_len, Buffer *buf);
static bool kevue__command_should_contain_request_payload(KevueCommand cmd);

bool kevue_command_compare(const char *data, uint8_t len, KevueCommand cmd)
{
    if (!kevue_command_valid(cmd)) return false;
    return kevue_command_length[cmd] == len && strncasecmp(data, kevue_command_to_string[cmd], len) == 0;
}

bool kevue_command_valid(KevueCommand cmd)
{
    return cmd >= 0 && cmd < KEVUE_CMD_MAX;
}

#define X(name) sizeof(#name) - 1,
const uint8_t kevue_command_length[] = {
    COMMAND_LIST
};
#undef X

#define X(name) #name,
const char *kevue_command_to_string[] = {
    COMMAND_LIST
};
#undef X

static KevueCommandDispatchResult kevue__command_dispatch(uint8_t cmd_len, Buffer *buf)
{
    KevueCommandDispatchResult dr = { 0 };
    dr.err = KEVUE_ERR_OK;
    switch (cmd_len) {
    case 3:
        if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, GET)) {
            dr.cmd = GET;
        } else if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, SET)) {
            dr.cmd = SET;
        } else if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, DEL)) {
            dr.cmd = DEL;
        } else {
            dr.err = KEVUE_ERR_UNKNOWN_COMMAND;
        }
        break;
    case 4:
        if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, PING)) {
            dr.cmd = PING;
        } else if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, KEYS)) {
            dr.cmd = KEYS;
        } else {
            dr.err = KEVUE_ERR_UNKNOWN_COMMAND;
        }
        break;
    case 5:
        if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, HELLO)) {
            dr.cmd = HELLO;
        } else if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, COUNT)) {
            dr.cmd = COUNT;
        } else if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, ITEMS)) {
            dr.cmd = ITEMS;
        } else {
            dr.err = KEVUE_ERR_UNKNOWN_COMMAND;
        }
        break;
    case 6:
        if (kevue_command_compare((char *)buf->ptr + buf->offset, cmd_len, VALUES)) {
            dr.cmd = VALUES;
        } else {
            dr.err = KEVUE_ERR_UNKNOWN_COMMAND;
        }
        break;
    default:
        dr.err = KEVUE_ERR_UNKNOWN_COMMAND;
    }
    return dr;
}

static bool kevue__command_should_contain_request_payload(KevueCommand cmd)
{
    switch (cmd) {
    case GET:
    case SET:
    case DEL:
        return true;
    case HELLO:
    case PING:
    case COUNT:
    case ITEMS:
    case KEYS:
    case VALUES:
    case KEVUE_CMD_MAX:
    default:
        return false;
    }
}

bool kevue_error_code_valid(KevueErr e)
{
    return e >= 0 && e < KEVUE_ERR_MAX;
}

#define X(name, str) str,
const char *kevue_error_code_to_string[] = {
    ERROR_CODE_LIST
};
#undef X

KevueErr kevue_request_deserialize(KevueRequest *req, Buffer *buf)
{
    // magic byte
    if (buf->size < KEVUE_MESSAGE_HEADER_SIZE) return KEVUE_ERR_INCOMPLETE_READ;
    if (memcmp(buf->ptr, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_BYTE_SIZE) != 0) {
        return KEVUE_ERR_MAGIC_BYTE_INVALID;
    }
    buf->offset = KEVUE_MAGIC_BYTE_SIZE;

    // total length
    uint32_t tl;
    memcpy(&tl, buf->ptr + buf->offset, sizeof(tl));
    req->total_len = be32toh(tl);
    if (req->total_len > buf->size) return KEVUE_ERR_INCOMPLETE_READ;
    buf->offset += sizeof(req->total_len);

    // cmd length
    if (buf->offset + sizeof(req->cmd_len) > req->total_len || buf->offset + sizeof(req->cmd_len) > buf->size) return KEVUE_ERR_LEN_INVALID;
    memcpy(&req->cmd_len, buf->ptr + buf->offset, sizeof(req->cmd_len));
    buf->offset += sizeof(req->cmd_len);

    // parse command
    if (buf->offset + req->cmd_len > req->total_len || buf->offset + req->cmd_len > buf->size) return KEVUE_ERR_LEN_INVALID;
    KevueCommandDispatchResult dr = kevue__command_dispatch(req->cmd_len, buf);
    if (dr.err == KEVUE_ERR_UNKNOWN_COMMAND) return KEVUE_ERR_UNKNOWN_COMMAND;
    req->cmd = dr.cmd;
    buf->offset += req->cmd_len;

    // parse key length
    if (buf->offset + sizeof(req->key_len) > req->total_len || buf->offset + sizeof(req->key_len) > buf->size) return KEVUE_ERR_LEN_INVALID;
    memcpy(&req->key_len, buf->ptr + buf->offset, sizeof(req->key_len));
    req->key_len = be16toh(req->key_len);
    buf->offset += sizeof(req->key_len);
    if (req->key_len == 0) {
        if (!kevue__command_should_contain_request_payload(req->cmd)) return KEVUE_ERR_OK;
        return KEVUE_ERR_LEN_INVALID;
    }

    if (req->key_len > 0) {
        // parse key
        if (buf->offset + req->key_len > req->total_len || buf->offset + req->key_len > buf->size) return KEVUE_ERR_LEN_INVALID;
        req->key = buf->ptr + buf->offset;
        buf->offset += req->key_len;

        req->val_len = 0;
        req->val = NULL;
        if (req->cmd == SET) {
            // parse value length
            if (buf->offset + sizeof(req->val_len) > req->total_len || buf->offset + sizeof(req->val_len) > buf->size) return KEVUE_ERR_LEN_INVALID;
            memcpy(&req->val_len, buf->ptr + buf->offset, sizeof(req->val_len));
            req->val_len = be16toh(req->val_len);
            buf->offset += sizeof(req->val_len);

            // parse value
            if (buf->offset + req->val_len > req->total_len || buf->offset + req->val_len > buf->size) return KEVUE_ERR_LEN_INVALID;
            req->val = buf->ptr + buf->offset;
            buf->offset += req->val_len;
        }
    }
    return KEVUE_ERR_OK;
}

KevueErr kevue_request_serialize(KevueRequest *req, Buffer *buf)
{
    if (req->cmd_len == 0) return KEVUE_ERR_LEN_INVALID;
    if (!kevue_command_valid(req->cmd)) return KEVUE_ERR_UNKNOWN_COMMAND;
    if (req->cmd_len != kevue_command_length[req->cmd]) return KEVUE_ERR_LEN_INVALID;
    if (req->key_len == 0 && kevue__command_should_contain_request_payload(req->cmd)) return KEVUE_ERR_PAYLOAD_INVALID;
    req->total_len = KEVUE_MAGIC_BYTE_SIZE + sizeof(req->total_len) + sizeof(req->cmd_len) + req->cmd_len * sizeof(char);
    req->total_len += (uint32_t)sizeof(req->key_len) + req->key_len * (uint32_t)sizeof(*req->key);
    if (req->cmd == SET) {
        if (req->val_len == 0) return KEVUE_ERR_LEN_INVALID;
        req->total_len += (uint32_t)sizeof(req->val_len) + req->val_len * (uint32_t)sizeof(*req->val);
    }
    kevue_buffer_grow(buf, req->total_len);
    kevue_buffer_append(buf, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_BYTE_SIZE);
    uint32_t tl = htobe32(req->total_len);
    kevue_buffer_append(buf, &tl, sizeof(req->total_len));
    kevue_buffer_append(buf, &req->cmd_len, sizeof(req->cmd_len));
    kevue_buffer_append(buf, kevue_command_to_string[req->cmd], req->cmd_len);
    uint16_t kl = htobe16(req->key_len);
    kevue_buffer_append(buf, &kl, sizeof(req->key_len));
    if (req->key_len > 0) {
        if (req->key == NULL) return KEVUE_ERR_PAYLOAD_INVALID;
        kevue_buffer_append(buf, req->key, req->key_len);
    }
    if (req->val_len > 0) {
        uint16_t vl = htobe16(req->val_len);
        kevue_buffer_append(buf, &vl, sizeof(req->val_len));
        if (req->val == NULL) return KEVUE_ERR_PAYLOAD_INVALID;
        kevue_buffer_append(buf, req->val, req->val_len);
    }
    return KEVUE_ERR_OK;
}

void kevue_request_print(KevueRequest *req)
{
    fputs("Request: \n", stdout);
    fprintf(stdout, "\tTotal Length: %u\n", req->total_len);
    fprintf(stdout, "\tCommand Length: %u\n", req->cmd_len);
    fprintf(stdout, "\tCommand: %s\n", kevue_command_to_string[req->cmd]);
    fprintf(stdout, "\tKey Length: %u\n", req->key_len);
    if (req->key_len > 0) {
        fputs("\tKey: ", stdout);
        fwrite(req->key, sizeof(*req->key), req->key_len, stdout);
        fputc('\n', stdout);
    }
    if (req->val_len > 0) {
        fprintf(stdout, "\tValue Length: %u\n", req->val_len);
        fputs("\tValue: ", stdout);
        fwrite(req->val, sizeof(*req->val), req->val_len, stdout);
        fputc('\n', stdout);
    }
    fflush(stdout);
}

KevueErr kevue_response_deserialize(KevueResponse *resp, Buffer *buf)
{
    // magic byte
    if (buf->size < KEVUE_MESSAGE_HEADER_SIZE) return KEVUE_ERR_INCOMPLETE_READ;
    if (memcmp(buf->ptr, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_BYTE_SIZE) != 0) {
        return KEVUE_ERR_MAGIC_BYTE_INVALID;
    }
    buf->offset = KEVUE_MAGIC_BYTE_SIZE;

    // total length
    uint64_t tl;
    memcpy(&tl, buf->ptr + buf->offset, sizeof(tl));
    resp->total_len = be64toh(tl);
    if (resp->total_len > buf->size) return KEVUE_ERR_INCOMPLETE_READ;
    buf->offset += sizeof(resp->total_len);

    // cmd length
    if (buf->offset + sizeof(resp->cmd_len) > resp->total_len || buf->offset + sizeof(resp->cmd_len) > buf->size) return KEVUE_ERR_LEN_INVALID;
    memcpy(&resp->cmd_len, buf->ptr + buf->offset, sizeof(resp->cmd_len));
    buf->offset += sizeof(resp->cmd_len);

    // parse command
    if (buf->offset + resp->cmd_len > resp->total_len || buf->offset + resp->cmd_len > buf->size) return KEVUE_ERR_LEN_INVALID;
    KevueCommandDispatchResult dr = kevue__command_dispatch(resp->cmd_len, buf);
    if (dr.err == KEVUE_ERR_UNKNOWN_COMMAND) return KEVUE_ERR_UNKNOWN_COMMAND;
    resp->cmd = dr.cmd;
    buf->offset += resp->cmd_len;

    // parse error code
    if (buf->offset + sizeof(uint8_t) > resp->total_len || buf->offset + sizeof(uint8_t) > buf->size) return KEVUE_ERR_LEN_INVALID;
    resp->err_code = (KevueErr)buf->ptr[buf->offset];
    if (!kevue_error_code_valid(resp->err_code)) return KEVUE_ERR_PAYLOAD_INVALID;
    if (resp->err_code != KEVUE_ERR_OK) {
        if (resp->val_len != 0) return KEVUE_ERR_LEN_INVALID;
        return resp->err_code;
    }
    buf->offset += sizeof(uint8_t);

    // parse value length
    if (buf->offset + sizeof(resp->val_len) > resp->total_len || buf->offset + sizeof(resp->val_len) > buf->size) return KEVUE_ERR_LEN_INVALID;
    memcpy(&resp->val_len, buf->ptr + buf->offset, sizeof(resp->val_len));
    resp->val_len = be64toh(resp->val_len);
    buf->offset += sizeof(resp->val_len);

    // parse value
    if (resp->val_len > 0) {
        if (buf->offset + resp->val_len > resp->total_len || buf->offset + resp->val_len > buf->size) return KEVUE_ERR_LEN_INVALID;
        if (resp->val == NULL) resp->val = kevue_buffer_create(resp->val_len * 2, buf->ma);
        // NOTE: add fatal error for situations like oom
        if (resp->val == NULL) return KEVUE_ERR_OPERATION;
        if (resp->cmd == COUNT) {
            uint64_t v;
            size_t   v_size = sizeof(v);
            if (buf->offset + v_size > resp->total_len || buf->offset + v_size > buf->size) return KEVUE_ERR_LEN_INVALID;
            memcpy(&v, buf->ptr + buf->offset, v_size);
            v = be64toh(v);
            kevue_buffer_write(resp->val, &v, v_size);
            kevue_buffer_append(resp->val, buf->ptr + buf->offset + v_size, resp->val_len - v_size);
        } else if (resp->cmd == ITEMS || resp->cmd == KEYS || resp->cmd == VALUES) {
            uint64_t v;
            size_t   v_size = sizeof(v);
            kevue_buffer_reset(resp->val);
            while (buf->offset < buf->size) { // TODO: check this condition for robustness
                // parse len to host endianness
                if (buf->offset + v_size > resp->total_len || buf->offset + v_size > buf->size) return KEVUE_ERR_LEN_INVALID;
                memcpy(&v, buf->ptr + buf->offset, v_size);
                v = be64toh(v);
                kevue_buffer_append(resp->val, &v, v_size);
                buf->offset += v_size;

                // append value as is
                if (buf->offset + v > resp->total_len || buf->offset + v > buf->size) return KEVUE_ERR_LEN_INVALID;
                kevue_buffer_append(resp->val, buf->ptr + buf->offset, v);
                buf->offset += v;
            }
        } else {
            kevue_buffer_write(resp->val, buf->ptr + buf->offset, resp->val_len);
        }
        buf->offset += resp->val_len;
    }
    return KEVUE_ERR_OK;
}

KevueErr kevue_response_serialize(KevueResponse *resp, Buffer *buf)
{
    if (resp->cmd_len == 0) return KEVUE_ERR_LEN_INVALID;
    if (!kevue_command_valid(resp->cmd)) return KEVUE_ERR_UNKNOWN_COMMAND;
    if (resp->cmd_len != kevue_command_length[resp->cmd]) return KEVUE_ERR_LEN_INVALID;
    if (!kevue_error_code_valid(resp->err_code)) return KEVUE_ERR_PAYLOAD_INVALID;
    if (resp->err_code != KEVUE_ERR_OK && resp->val_len > 0) return KEVUE_ERR_LEN_INVALID;
    resp->total_len = KEVUE_MAGIC_BYTE_SIZE + sizeof(resp->total_len) + sizeof(resp->cmd_len) + resp->cmd_len * sizeof(char);
    resp->total_len += sizeof(uint8_t) + sizeof(resp->val_len);
    if (resp->val_len > 0) {
        if (resp->val == NULL) return KEVUE_ERR_PAYLOAD_INVALID;
        resp->total_len += resp->val_len * sizeof(*resp->val->ptr);
    }
    kevue_buffer_grow(buf, resp->total_len);
    kevue_buffer_append(buf, KEVUE_MAGIC_BYTE, KEVUE_MAGIC_BYTE_SIZE);
    uint64_t tl = htobe64(resp->total_len);
    kevue_buffer_append(buf, &tl, sizeof(resp->total_len));
    kevue_buffer_append(buf, &resp->cmd_len, sizeof(resp->cmd_len));
    kevue_buffer_append(buf, kevue_command_to_string[resp->cmd], resp->cmd_len);
    uint8_t ec = (uint8_t)resp->err_code;
    kevue_buffer_append(buf, &ec, sizeof(uint8_t));
    uint64_t vl = htobe64(resp->val_len);
    kevue_buffer_append(buf, &vl, sizeof(resp->val_len));
    if (resp->val_len > 0) {
        if (resp->cmd == COUNT) {
            uint64_t v;
            size_t   v_size = sizeof(v);
            if (resp->val_len < v_size || resp->val->size < v_size) return KEVUE_ERR_LEN_INVALID;
            memcpy(&v, resp->val->ptr, v_size);
            v = htobe64(v);
            kevue_buffer_append(buf, &v, v_size);
            kevue_buffer_append(buf, resp->val->ptr + v_size, resp->val_len - v_size);
        } else if (resp->cmd == ITEMS || resp->cmd == KEYS || resp->cmd == VALUES) {
            uint64_t v, saved_v;
            size_t   v_size = sizeof(v);
            resp->val->offset = 0;
            while (resp->val->offset < resp->val_len) {
                if (resp->val->offset + v_size > resp->total_len) return KEVUE_ERR_LEN_INVALID;
                memcpy(&v, resp->val->ptr + resp->val->offset, v_size);
                saved_v = v;
                v = htobe64(v);
                kevue_buffer_append(buf, &v, v_size);
                resp->val->offset += v_size;

                if (resp->val->offset + saved_v > resp->total_len) return KEVUE_ERR_LEN_INVALID;
                kevue_buffer_append(buf, resp->val->ptr + resp->val->offset, saved_v);
                resp->val->offset += saved_v;
            }
        } else {
            kevue_buffer_append(buf, resp->val->ptr, resp->val_len);
        }
    }
    return KEVUE_ERR_OK;
}

void kevue_response_print(KevueResponse *resp)
{
    fputs("Response: \n", stdout);
    fprintf(stdout, "\tTotal Length: %lu\n", resp->total_len);
    fprintf(stdout, "\tCommand Length: %u\n", resp->cmd_len);
    fprintf(stdout, "\tCommand: %s\n", kevue_command_to_string[resp->cmd]);
    fprintf(stdout, "\tError Code: %u\n", resp->err_code);
    fprintf(stdout, "\tError Description: %s\n", kevue_error_code_to_string[resp->err_code]);
    if (resp->val_len > 0) {
        fprintf(stdout, "\tValue Length: %lu\n", resp->val_len);
        fputs("\tValue: ", stdout);
        kevue_buffer_print_hex(resp->val);
    }
    fflush(stdout);
}
