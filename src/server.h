/*
 * MIT License
 *
 * Copyright (c) 2019 Maarten Hoeben
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#ifndef SERVER_H
#define SERVER_H

#include "harray.h"
#include "hserv.h"
#include "hws.h"

#define SERVER_FLAG_SECURE                  0x01
#define SERVER_FLAG_EXIT                    0x02
#define SERVER_FLAG_VERBOSE                 0x04

#define SERVER_DEFAULT_FLAGS                0x00
#define SERVER_DEFAULT_PORT                 8080
#define SERVER_DEFAULT_INDEX_FILE           "index.html"
#define SERVER_DEFAULT_CERTIFICATE_FILE     "cert.pem"
#define SERVER_DEFAULT_PRIVATE_KEY_FILE     "key.pem"

typedef struct server_s
{
    /*
     * Configuration
     */
    char const* exec;

    int flags;

    char const* bind;
    int port;

    char const* filepath;
    char const* index_file;
    FILE* logfile;
    harray_t response_fields;

    char const* certificate_file;
    char const* private_key_file;

    char const* websocket_subprotocol;

    /*
     * State
     */
    int request_nr;
    hserv_t* hserv;
    hws_t* hws;

    hserv_event_t hws_event;

    hws_socket_t* socket;
} server_t;

void server_create(server_t* server);
void server_destroy(server_t* server);
int server_start(server_t* server);
int server_stop(server_t* server);

#endif /* SERVER_H */

