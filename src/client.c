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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <buffer.h>
#include <client.h>
#include <common.h>
#include <protocol.h>

static void usage(void);
static int kevue_create_client_sock();

struct KevueClient {
    int fd;
    struct sockaddr_in server_addr;
    Buffer *rbuf;
    Buffer *wbuf;
};

int kevue_create_client_sock()
{
    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0) {
        printf("ERROR: Creating socket failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int enable = 1;
    if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&enable, sizeof(enable)) < 0) {
        printf("ERROR: Setting TCP_NODELAY option for client failed: %s\n", strerror(errno));
        close(client_sock);
        return false;
    }
    return client_sock;
}

KevueClient *kevue_client_create(char *host, uint16_t port)
{
    KevueClient *kc = (KevueClient *)malloc(sizeof(KevueClient));
    struct sockaddr_in server_addr = { 0 };
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) < 0) {
        printf("ERROR: %s is not valid IP address\n", host);
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    kc->server_addr = server_addr;
    kc->fd = kevue_create_client_sock();
    kc->rbuf = kevue_buffer_create(BUF_SIZE);
    kc->wbuf = kevue_buffer_create(BUF_SIZE);
    if (connect(kc->fd, (struct sockaddr *)&kc->server_addr, sizeof(kc->server_addr)) < 0) {
        printf("ERROR: connecting to %s:%d failed: %s\n", host, port, strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("INFO: connected to %s:%d\n", host, port);
    return kc;
}

void kevue_client_destroy(KevueClient *kc)
{
    close(kc->fd);
    kevue_buffer_destroy(kc->rbuf);
    kevue_buffer_destroy(kc->wbuf);
    free(kc);
    kc = NULL;
}

void usage(void)
{
    printf("Usage: kevue-client <host> <port>\n");
}

void kevue_client_get(KevueClient *kc, KevueResponse *resp, char *key, uint16_t key_len)
{
    KevueRequest req = { 0 };
    req.cmd_len = 3;
    req.cmd = GET;
    req.key_len = key_len;
    req.key = key;
    kevue_serialize_request(&req, kc->wbuf);
    int nw = write(kc->fd, kc->wbuf->ptr + kc->wbuf->offset, kc->wbuf->size - kc->wbuf->offset);
    int nr = read(kc->fd, kc->rbuf->ptr + kc->rbuf->size, kc->rbuf->capacity - kc->rbuf->size);
    for (int i = 0; i < nr; i++) printf("%02x ", kc->rbuf->ptr[i]);
    kc->rbuf->size = nr;
    printf("\n");
    KevueErr err = kevue_deserialize_response(resp, kc->rbuf);
    printf("%s\n", kevue_error_to_string(err));
    if (err == ERR_OK) kevue_print_response(resp);
}

int main(int argc, char **argv)
{
    char *host;
    int port;
    if (argc == 3) {
        host = argv[1];
        port = atoi(argv[2]);
        if (port < 0 || port > 65535) {
            usage();
        }
    } else if (argc > 1) {
        usage();
        exit(EXIT_FAILURE);
    } else {
        host = HOST;
        port = PORT;
    }
    KevueClient *kc = kevue_client_create(host, port);
    KevueResponse *resp = (KevueResponse *)malloc(sizeof(KevueResponse));
    kevue_client_get(kc, resp, "random", 6);
    kevue_destroy_response(resp);
    kevue_client_destroy(kc);
}
