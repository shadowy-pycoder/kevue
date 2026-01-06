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
 * @file protocol.h
 * @brief kevue protocol API.
 *
 * Protocol structure (Request):<br>
 *  Magic byte 0x22 (sum of ascii codes of "kevue" word modulo 255)<br>
 *  Total length including magic byte and this field -> uint32<br>
 *  Length of the command (GET/SET/DEL) - 1 byte<br>
 *  Command (GET/SET/DEL) case insensitive<br>
 *  Depends on the command GET/DEL -> key -> uint16 length [key]<br>
 *  SET -> key, value -> uint16 length [key] uint16 length [value]<br>
 *  Use ntohs/htons for uint16 length conversion<br>
 *
 * Protocol structure (Response):<br>
 *  Magic byte 0x22 (sum of ascii codes of "kevue" word modulo 255)<br>
 *  Total length including magic byte and this field -> uint32<br>
 *  Error byte uint8<br>
 *  Length of the reply uint16 (0 if no value)<br>
 *  Reply: actual value (case sensitive)<br>
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
    X(DEL)           \
    X(PING)

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
    X(KEVUE_ERR_WRITE_FAILED, "Failed writing message")      \
    X(KEVUE_ERR_READ_TIMEOUT, "Timed out reading message")   \
    X(KEVUE_ERR_WRITE_TIMEOUT, "Timed out writing message")  \
    X(KEVUE_ERR_EOF, "Peer closed connection")               \
    X(KEVUE_ERR_HANDSHAKE, "Handshake failed")               \
    X(KEVUE_ERR_OPERATION, "Operation failed")

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
    const uint8_t *key;
    uint16_t val_len;
    const uint8_t *val;
} KevueRequest;

typedef struct KevueResponse {
    uint32_t total_len;
    KevueErr err_code;
    uint16_t val_len;
    Buffer *val;
} KevueResponse;

/**
 * @brief Reads the total message length from the socket into the buffer.
 *
 * This function reads enough bytes from @p sock to determine the full
 * message length and appends them to @p buf. The decoded length is stored
 * in @p total_len.
 *
 * @param sock       Connected socket file descriptor.
 * @param buf        Buffer used to accumulate incoming data.
 * @param total_len  Output pointer receiving the total message length.
 *
 * @return KEVUE_ERR_OK on success, or an error code on failure.
 */
KevueErr kevue_message_read_length(int sock, Buffer *buf, uint32_t *total_len);

/**
 * @brief Deserializes a request from a buffer.
 *
 * Parses request fields from @p buf and populates @p req.
 * The buffer read position is advanced accordingly.
 *
 * @param req  Request structure to populate.
 * @param buf  Buffer containing serialized request data.
 *
 * @return KEVUE_ERR_OK on success, or an error code on malformed input.
 */
KevueErr kevue_request_deserialize(KevueRequest *req, Buffer *buf);

/**
 * @brief Serializes a request into a buffer.
 *
 * Encodes the contents of @p req and appends the serialized representation
 * to @p buf.
 *
 * @param req  Request to serialize.
 * @param buf  Destination buffer.
 */
void kevue_request_serialize(KevueRequest *req, Buffer *buf);

/**
 * @brief Prints a human-readable representation of a request.
 *
 * @param req  Request to print.
 */
void kevue_request_print(KevueRequest *req);

/**
 * @brief Deserializes a response from a buffer.
 *
 * Parses response fields from @p buf and populates @p resp.
 * The buffer read position is advanced accordingly.
 *
 * @param resp  Response structure to populate.
 * @param buf   Buffer containing serialized response data.
 *
 * @return KEVUE_ERR_OK on success, or an error code on malformed input.
 */
KevueErr kevue_response_deserialize(KevueResponse *resp, Buffer *buf);

/**
 * @brief Serializes a response into a buffer.
 *
 * Encodes the contents of @p resp and appends the serialized representation
 * to @p buf.
 *
 * @param resp  Response to serialize.
 * @param buf   Destination buffer.
 */
void kevue_response_serialize(KevueResponse *resp, Buffer *buf);

/**
 * @brief Prints a human-readable representation of a response.
 *
 * Intended for debugging and logging purposes.
 *
 * @param resp  Response to print.
 */
void kevue_response_print(KevueResponse *resp);

/**
 * @brief Converts a command enum value to its string representation.
 *
 * @param cmd  Command value.
 *
 * @return Pointer to a static string representing the command.
 */
char *kevue_command_to_string(KevueCommand cmd);

/**
 * @brief Compares raw command data with a command enum.
 *
 * Checks whether the byte sequence in @p data matches the textual
 * representation of @p cmd.
 *
 * @param data  Pointer to command data.
 * @param len   Length of @p data in bytes.
 * @param cmd   Command to compare against.
 *
 * @return true if the command matches, false otherwise.
 */
bool kevue_command_compare(const char *data, uint8_t len, KevueCommand cmd);

/**
 * @brief Converts an error code to its string representation.
 *
 * @param e  Error code.
 *
 * @return Pointer to a static string describing the error.
 */
char *kevue_error_to_string(KevueErr e);
