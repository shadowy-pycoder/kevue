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

#include <netinet/in.h>
#include <stdint.h>

#include <allocator.h>
#include <protocol.h>

typedef struct KevueClient KevueClient;

KevueClient *kevue_client_create(char *host, char *port, KevueAllocator *ma);
void kevue_client_destroy(KevueClient *kc);
bool kevue_client_get(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len);
bool kevue_client_set(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len, char *val, uint16_t val_len);
bool kevue_client_del(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len);
bool kevue_client_ping(KevueClient *kc, KevueResponse *resp);
bool kevue_client_ping_with_message(KevueClient *kc, KevueResponse *resp, char *message, uint16_t message_len);
