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
 */
#include "websocket.h"
#include "hbuffer.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#undef HWS_SOCKET_USER_STORAGE
#define HWS_SOCKET_USER_STORAGE 128
#define HWS_IMPL
#include "hws.h"

/*
 * Implementation
 */

#define WEBSOCKET_BUFFER_SIZE   65536

typedef struct state_s
{
    hws_opcode_t receive_opcode;
    hbuffer_t receive_buffer;

    hbuffer_t send_buffer;
    hserv_event_t stdin_event;
} state_t;

void state_free(server_t* server, state_t* state)
{
    hserv_event_remove(server->hserv, &state->stdin_event);

    hbuffer_free(&state->send_buffer);
    hbuffer_free(&state->receive_buffer);
}

static int on_stdin(hserv_t* hserv, struct epoll_event* event)
{
    server_t* server = hserv_get_user_data(hserv);
    state_t* state = ((hserv_event_t*)event->data.ptr)->user_data;
    hws_opcode_t opcode;

    state->send_buffer.size = fread(
        state->send_buffer.data, 1, state->send_buffer.capacity, stdin);

    if (0 != ferror(stdin)) {
        fprintf(stderr, "%s: Failed to read from stdin (%s)\n", server->exec, strerror(errno));
        return -1;
    }

    if (0 == feof(stdin)) { 
        opcode = HWS_CLOSE;
    }
    else {
        // TODO make configurable.
        opcode = HWS_BINARY;
    }

    if (-1 == hws_socket_send(server->hws, server->socket, opcode,
            state->send_buffer.data, state->send_buffer.size, 1)) {
        fprintf(stderr, "%s: Failed to send WebSocket frame (%s)\n", server->exec, strerror(errno));
        return -1;
    }

    hserv_event_modify(server->hserv, &state->stdin_event, 0);
    return 0;
}

static int on_receive_header(hws_t* hws, hws_socket_t* socket,
    hws_opcode_t opcode, size_t size, int flags)
{
    server_t* server = hws_get_user_data(hws);
    state_t* state = hws_socket_get_user_data(socket);

    (void)flags;

    switch (opcode) {
    case HWS_TEXT:
    case HWS_BINARY:
    case HWS_CLOSE:
        break;

    default:
        fprintf(stderr, "%s: Unsupported upcode %d\n", server->exec, opcode);
        return -1;
    }

    state->receive_opcode = opcode;
    hbuffer_resize(&state->receive_buffer, size);
    return 0;
}

static int on_received(hws_t* hws, hws_socket_t* socket,
    void* buffer, size_t size)
{
    server_t* server = hws_get_user_data(hws);
    state_t* state = hws_socket_get_user_data(socket);

    switch (state->receive_opcode) {
    case HWS_TEXT:
    case HWS_BINARY:
        if (size != fwrite(buffer, 1, size, stdout)) {
            fprintf(stderr, "%s: failed to write to stdout (%s)\n", server->exec, strerror(errno));
            return -1;
        }
        break;

    case HWS_CLOSE:
        server_stop(server);
        break;

    default:
        break;
    }

    return 0;
}

static int on_sent(hws_t* hws, hws_socket_t* socket,
    void const* buffer, size_t size)
{
    server_t* server = hws_get_user_data(hws);
    state_t* state = hws_socket_get_user_data(socket);
    (void)buffer;
    (void)size;

    return hserv_event_modify(server->hserv, &state->stdin_event, EPOLLIN);
}

static void on_closed(hws_t* hws, hws_socket_t* socket, int error)
{
    server_t* server = hws_get_user_data(hws);
    state_t* state = hws_socket_get_user_data(socket);
    (void)error;

    state_free(server, state);

    server_stop(server);
}

/*
 * Public
 */
hserv_status_code_t websocket_is_upgrade(
    hserv_session_t const* session, char const* subprotocol)
{
    char const* fields = hserv_request_get_header_fields(session);
    char const* value;

    if (0 != strcmp("GET", hserv_request_get_method(session))) {
        return HSERV_SC_NOT_FOUND;
    }

    if (NULL != hserv_header_field_find(fields, "Connection", &value)
     && 1 != hserv_header_field_value_contains(value, "Upgrade", ",")) {
        return HSERV_SC_NOT_FOUND;
    }

    if (NULL != hserv_header_field_find(fields, "Upgrade", &value)
     && 0 != strcmp("websocket", value)) {
        return HSERV_SC_NOT_FOUND;
    }

    if (0 != hserv_request_get_content_length(session)) {
        return HSERV_SC_BAD_REQUEST;
    }

    if (NULL == hserv_header_field_find(fields, "Sec-WebSocket-Version", &value)
     || 0 != strcmp("13", value)) {
        return HSERV_SC_BAD_REQUEST;
    }

    if (NULL == hserv_header_field_find(fields, "Sec-WebSocket-Key", &value)) {
        return HSERV_SC_BAD_REQUEST;
    }

    if (NULL == hserv_header_field_find(fields, "Sec-WebSocket-Protocol", &value)
     || 0 != strcasecmp(subprotocol, value)) {
        return HSERV_SC_NOT_FOUND;
    }
    
    return HSERV_SC_SWITCHING_PROTOCOLS;
}

int websocket_respond(hserv_t* hserv, hserv_session_t* session,
    harray_t const* response_fields, char const* subprotocol)
{
    harray_t fields = HARRAY_INIT(response_fields->sizeof_type);

    /* Copy response header fields. */
    if (-1 == harray_copy(&fields, response_fields)) {
        goto internal_server_error;
    }

    /* Get the Sec-WebSocket-Key from the request header. */
    char const* key = NULL;
    hserv_header_field_find(hserv_request_get_header_fields(session),
        "Sec-WebSocket-Key", &key);
    assert(NULL != key);

    /* Create a Sec-WebSocket-Accept value from the key. */
    char* accept = hws_generate_sec_websocket_accept(key, strlen(key));
    if (NULL == accept) {
        goto internal_server_error;
    }

    /* Add WebSocket upgrade response fields. */
    if (-1 == harray_push_back(&fields, "Connection")
     || -1 == harray_push_back(&fields, "upgrade")
     || -1 == harray_push_back(&fields, "Upgrade")
     || -1 == harray_push_back(&fields, "websocket")
     || -1 == harray_push_back(&fields, "Sec-WebSocket-Accept")
     || -1 == harray_push_back(&fields, accept)
     || -1 == harray_push_back(&fields, "Sec-WebSocket-Protocol")
     || -1 == harray_push_back(&fields, subprotocol)
    ) {
        goto internal_server_error;
    }

    /* Respond. */
    if (-1 == hserv_respond(hserv, session, HSERV_SC_SWITCHING_PROTOCOLS, NULL,
            fields.data, 0, NULL)) {
        goto internal_server_error;
    }

    free(accept);
    harray_free(&fields);
    return 0;

internal_server_error:
    free(accept);
    harray_free(&fields);
    return -1;
}

int websocket_upgrade(server_t* server, hserv_session_t* session)
{
    /* Get SSL structure and file-descriptor from upgraded session. */
#ifdef HSERV_HAVE_OPENSSL
    SSL* ssl = hserv_session_get_ssl(session);
#endif
    int fd = hserv_session_upgraded(server->hserv, session);
    assert(fd >= 0);

    hws_socket_callbacks_t callbacks;
    callbacks.interrupt = NULL;
    callbacks.receive_header = on_receive_header;
    callbacks.received = on_received;
    callbacks.sent = on_sent;
    callbacks.closed = on_closed;
#ifdef HWS_HAVE_OPENSSL
    server->socket = hws_socket_create(server->hws, fd, ssl, &callbacks);
#else
    server->socket = hws_socket_create(server->hws, fd, &callbacks);
#endif
    if (NULL == server->socket) {
        return -1;
    }

    assert(HWS_SOCKET_USER_STORAGE >= sizeof(state_t));
    state_t* state = hws_socket_get_user_data(server->socket);

    state->stdin_event.fd = -1;
    state->stdin_event.callback = on_stdin;
    state->stdin_event.user_data = server;

    if (-1 == hserv_event_add(server->hserv, &state->stdin_event, EPOLLIN)) { 
        fprintf(stderr, "%s: Failed to add event for stdin (%s)\n", server->exec, strerror(errno));
        goto cleanup;
    }

    hbuffer_init(&state->receive_buffer);
    if (-1 == hbuffer_reserve(&state->receive_buffer, WEBSOCKET_BUFFER_SIZE)) { 
        fprintf(stderr, "%s: Failed to allocate WebSocket receive buffer (%s)\n", server->exec, strerror(errno));
        goto cleanup;
    }

    hbuffer_init(&state->send_buffer);
    if (-1 == hbuffer_reserve(&state->send_buffer, WEBSOCKET_BUFFER_SIZE)) { 
        fprintf(stderr, "%s: Failed to allocate WebSocket send buffer (%s)\n", server->exec, strerror(errno));
        goto cleanup;
    }

    return 0;

cleanup:
    state_free(server, state);
    return -1;
}

