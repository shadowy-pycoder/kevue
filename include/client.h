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
 * @file client.h
 * @brief kevue client API.
 */
#pragma once

#include <netinet/in.h>
#include <stdint.h>

#include <allocator.h>
#include <protocol.h>

typedef struct KevueClient KevueClient;

typedef struct KevueClientConfig {
    char           *host; // defaults to KEVUE_HOST
    char           *port; // defaults to KEVUE_PORT
    char           *unix_path; // defaults to KEVUE_UNIX_SOCK_PATH
    int             read_timeout; // defaults to READ_TIMEOUT
    int             write_timeout; // defaults to WRITE_TIMEOUT
    KevueAllocator *ma; // defaults to kevue_default_allocator
} KevueClientConfig;

/**
 * @brief Creates a new kevue client instance.
 *
 * @param conf  Client config
 *
 * @return Pointer to a newly created client, or NULL on failure.
 */
KevueClient *kevue_client_create(KevueClientConfig *conf);

/**
 * @brief Destroys a kevue client instance.
 *
 * Closes any open connections and releases all associated resources.
 *
 * @param kc  Client instance to destroy.
 */
void kevue_client_destroy(KevueClient *kc);

/**
 * @brief Performs the client-server handshake.
 *
 * Sends a HELLO command to the server and validates the response.
 * This function is typically called immediately after establishing
 * a connection.
 *
 * @param kc    Client instance.
 * @param resp  Response structure to populate.
 *
 * @return true if the handshake succeeds, false on failure.
 *
 * @note On failure, @p resp->err_code is set to KEVUE_ERR_HANDSHAKE.
 * @note This command is used to verify protocol compatibility
 *       between client and server.
 */
bool kevue_client_hello(KevueClient *kc, KevueResponse *resp);

/**
 * @brief Retrieves the value associated with a key.
 *
 * Sends a GET request for @p key and stores the server response in @p resp.
 *
 * @param kc       Client instance.
 * @param resp     Response structure to populate.
 * @param key      Pointer to key data.
 * @param key_len  Length of @p key in bytes.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_get(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len);

/**
 * @brief Sets the value for a key.
 *
 * Sends a SET request with the specified key and value.
 * The server response is stored in @p resp.
 *
 * @param kc        Client instance.
 * @param resp      Response structure to populate.
 * @param key       Pointer to key data.
 * @param key_len   Length of @p key in bytes.
 * @param val       Pointer to value data.
 * @param val_len   Length of @p val in bytes.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_set(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len, const void *val, uint16_t val_len);

/**
 * @brief Deletes a key.
 *
 * Sends a DEL request for the specified key.
 * The server response is stored in @p resp.
 *
 * @param kc       Client instance.
 * @param resp     Response structure to populate.
 * @param key      Pointer to key data.
 * @param key_len  Length of @p key in bytes.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_del(KevueClient *kc, KevueResponse *resp, const void *key, uint16_t key_len);

/**
 * @brief Sends a ping request to the server.
 *
 * Used to check server availability and connection health.
 *
 * @param kc    Client instance.
 * @param resp  Response structure to populate.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_ping(KevueClient *kc, KevueResponse *resp);

/**
 * @brief Sends a ping request with an attached message.
 *
 * The provided message is echoed by the server according
 * to the protocol. The response is stored in @p resp.
 *
 * @param kc            Client instance.
 * @param resp          Response structure to populate.
 * @param message       Pointer to message data.
 * @param message_len   Length of @p message in bytes.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_ping_with_message(KevueClient *kc, KevueResponse *resp, const void *message, uint16_t message_len);

/**
 * @brief Retrieves the number of entries.
 *
 * Sends a COUNT command to the server and stores the response
 * in @p resp.
 *
 * @param kc    Client instance.
 * @param resp  Response structure to populate.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_count(KevueClient *kc, KevueResponse *resp);

/**
 * @brief Retrieves all stored items.
 *
 * Sends an ITEMS command to the server and stores the response
 * in @p resp.
 *
 * @param kc    Client instance.
 * @param resp  Response structure to populate.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note The response payload contains a serialized list of key-value pairs.
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_items(KevueClient *kc, KevueResponse *resp);

/**
 * @brief Retrieves all keys.
 *
 * Sends a KEYS command to the server and stores the response
 * in @p resp.
 *
 * @param kc    Client instance.
 * @param resp  Response structure to populate.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note The response payload contains a serialized list of keys.
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_keys(KevueClient *kc, KevueResponse *resp);

/**
 * @brief Retrieves all values.
 *
 * Sends a VALUES command to the server and stores the response
 * in @p resp.
 *
 * @param kc    Client instance.
 * @param resp  Response structure to populate.
 *
 * @return true on successful request execution, false on failure.
 *
 * @note The response payload contains a serialized list of values.
 * @note In case of false result, caller may want to check @p resp error code for failure reason.
 */
bool kevue_client_values(KevueClient *kc, KevueResponse *resp);
