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
#pragma once
#include <pthread.h>
#include <stdint.h>

#define MAX_CONNECTIONS 4092
#define SERVER_WORKERS  1
#define EPOLL_TIMEOUT   (30 * 1000)
#define SND_BUF_SIZE    (1024 * 1024 * 2)
#define RECV_BUF_SIZE   (1024 * 1024 * 2)

typedef struct KevueServer {
    const char *host;
    uint16_t port;
    int fds[SERVER_WORKERS];
    pthread_t threads[SERVER_WORKERS];
    int efd;
} KevueServer;

typedef struct Address Address;
typedef struct Socket Socket;
typedef struct KevueConnection KevueConnection;

KevueServer *kevue_server_create(char *host, uint16_t port);
void kevue_server_start(KevueServer *ks);
void kevue_server_destroy(KevueServer *ks);
