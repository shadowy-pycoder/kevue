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

/**
 * @brief Creates a new kevue client instance.
 *
 * Establishes a connection to the server identified by @p host and @p port.
 * Memory is allocated using the provided allocator.
 *
 * @param host  Server hostname or IP address.
 * @param port  Server port as a string.
 * @param ma    Allocator used for client resources.
 *
 * @return Pointer to a newly created client, or NULL on failure.
 *
 * @note if @p ma is NULL default allocator is used
 */
KevueClient *kevue_client_create(const char *host, const char *port, KevueAllocator *ma);

/**
 * @brief Destroys a kevue client instance.
 *
 * Closes any open connections and releases all associated resources.
 *
 * @param kc  Client instance to destroy.
 */
void kevue_client_destroy(KevueClient *kc);

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
