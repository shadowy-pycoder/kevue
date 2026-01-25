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
 * @file server.h
 * @brief kevue server API.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

#include <allocator.h>
#include <common.h>
#include <hashmap.h>

#define MAX_CONNECTIONS 4092
#define SEND_BUF_SIZE   (1024 * 1024 * 2)
#define RECV_BUF_SIZE   (1024 * 1024 * 2)

/**
 * @struct KevueServer
 * @brief kevue server instance.
 *
 * Holds server configuration, worker threads, and shared state.
 */
typedef struct KevueServer KevueServer;

typedef struct KevueServerConfig {
    char           *host; // defaults to KEVUE_HOST
    char           *port; // defaults to KEVUE_PORT
    char           *unix_path; // defaults to KEVUE_UNIX_SOCK_PATH
    int             workers; // defaults to KEVUE_SERVER_WORKERS
    size_t          recv_buf_size; // defaults to RECV_BUF_SIZE
    size_t          send_buf_size; // defaults to SEND_BUF_SIZE
    KevueAllocator *ma; // defaults to kevue_default_allocator
} KevueServerConfig;

/**
 * @brief Creates a new kevue server instance.
 *
 * Initializes server state but does not start worker threads.
 *
 * @param conf  Server config
 *
 * @return Pointer to a newly created server, or NULL on failure.
 */
KevueServer *kevue_server_create(KevueServerConfig *conf);

/**
 * @brief Starts the kevue server.
 *
 * Creates worker threads and begins accepting client connections.
 *
 * @param ks  Server instance.
 */
void kevue_server_start(KevueServer *ks);

/**
 * @brief Destroys a kevue server instance.
 *
 * Stops all worker threads, closes open file descriptors,
 * and releases associated resources.
 *
 * @param ks  Server instance to destroy.
 */
void kevue_server_destroy(KevueServer *ks);
