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
#include "server.h"
#include "hbuffer.h"
#include "hfs.h"
#include "utility.h"
#include "websocket.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#pragma GCC diagnostic ignored "-Wstrict-overflow"

#define HSERV_HEADER_FIELD_DATE
#define HSERV_HEADER_FIELD_SERVER   "HServ"

#undef HSERV_SESSION_USER_STORAGE
#define HSERV_SESSION_USER_STORAGE 128
#define HSERV_IMPL
#include "hserv.h"

/*
 * Implementation
 */
#define TRANSACTION_BUFFER_SIZE     65536

typedef struct transaction_s
{
    int nr;

    hbuffer_t buffer;

    method_t method;
    char* filepath;
    char* trailer;

    FILE* request_file;

    int status_code;
    FILE* response_file;
    size_t response_length;
    size_t response_offset;
} transaction_t;

static int transaction_init(server_t const* server, hserv_session_t const* session, int nr)
{
    transaction_t* t = hserv_session_get_user_data(session);
    t->nr = nr;

    t->method = get_method(hserv_request_get_method(session));
    switch (t->method) {
    case METHOD_INVALID:
        t->status_code = HSERV_SC_BAD_REQUEST;
        return 0;
    case METHOD_GET:
    case METHOD_HEAD:
    case METHOD_POST:
    case METHOD_PUT:
    case METHOD_DELETE:
        break;
    default:
        t->status_code = HSERV_SC_METHOD_NOT_ALLOWED;
        return 0;
    }

    char const* target = hserv_request_get_target(session);

    /* Get path and trailer from target. */
    /* TODO fix for # fragment. */
    char const* ptr = strchr(target, '?');
    if (NULL != ptr) {
        /* Copy trailer. */
        t->trailer = strdup(ptr + 1);
        if (NULL == t->trailer) {
            return -1;
        }
    }
    else {
        /* No trailer found. */
        ptr = target + strlen(target);
    }

    /* Requesting root directory? */
    if (1 == ptr - target) {
        /* Replace target with index-file. */
        assert('/' == target[0]);

        /* Malloc memory for "/<index-file>\0" */
        size_t length = strlen(server->index_file) + 2;
        t->filepath = (char*)malloc(length);
        if (NULL != t->filepath) {
            snprintf(t->filepath, length, "/%s", server->index_file);
        }
    }
    else {
        /* Copy filepath. */
        t->filepath = strndup(target, ptr - target);
    }
    if (NULL == t->filepath) {
        return -1;
    }

    /* Canonicalize filepath. */
    if (-1 == hfs_canonicalize_path(t->filepath)) {
        /* Not a valid filepath. */
        free(t->filepath);
        t->filepath = NULL;
        t->status_code = HSERV_SC_FORBIDDEN;
    }
    else {
        t->status_code = HSERV_SC_OK;
    }

    return 0;
}

static void transaction_free(hserv_t* hserv, hserv_session_t const* session)
{
    server_t* server = hserv_get_user_data(hserv);
    transaction_t* t = hserv_session_get_user_data(session);

    /* Free buffers. */
    hbuffer_free(&t->buffer);
    free(t->filepath);
    free(t->trailer);

    /* Close request file, if opened and not stdout. */
    if (NULL != t->request_file
     && stdout != t->request_file) {
        fclose(t->request_file);
    }

    /* Close response file, if opened and not stdin. */
    if (NULL != t->response_file
     && stdin != t->response_file) {
        fclose(t->response_file);
    }

    memset(t, 0, sizeof(*t));

    /* Exit server after request? */
    if (0 != (SERVER_FLAG_EXIT & server->flags)) {
        server_stop(server);
    }
}

static FILE* open_target(server_t* server, transaction_t* t, char const* mode, size_t* content_length, char const** content_type)
{
    /* Transaction still ok? */
    if (HSERV_SC_OK != t->status_code) {
        return NULL;
    }

    char const* filename = NULL;

    assert(strlen(t->filepath) >= 1);
    assert('/' == t->filepath[0]);

    /* Read or write to directory or file? */
    if (1 == is_dir(server->filepath)) {
        /* Combine server's directory and filepath. */
        VERIFY(-1 != hbuffer_printf(&t->buffer, "%s%s",
            server->filepath, t->filepath));

        /* Write? Create directories. */
        if ('w' == *mode || 'a' == *mode) {
            /* Strip filename from file path. */
            char* path = hfs_strip_filename((char*)t->buffer.data);

            /* Create directories recusively. */
            if (-1 == hfs_mkdir_recursive(path, 0755)) {
                fprintf(stderr, "%s: Failed to create path '%s' (%s)\n",
                    server->exec, path, strerror(errno));

                t->status_code = HSERV_SC_UNPROCESSABLE_ENTITY;
                return NULL;
            }
            /* Restore file path. */
            path[strlen(path)] = '/';
        }
        filename = (char const*)t->buffer.data;
    }
    /* Filepaths match? */
    else if (0 == strcmp(server->filepath, t->filepath + 1)) {
        /* Open transaction's filepath. */
        filename = t->filepath + 1;
    }
    else {
        /* Filepath is not found. */
        t->status_code = HSERV_SC_NOT_FOUND;
        return NULL;
    }

    /* Open file. */
    FILE* file = fopen(filename, mode);
    if (NULL == file) {
        switch (errno) {
        case ENOENT:
            t->status_code = HSERV_SC_NOT_FOUND;
            break;
        case EACCES:
            t->status_code = HSERV_SC_FORBIDDEN;
            break;
        case EISDIR:
            t->status_code = HSERV_SC_UNPROCESSABLE_ENTITY;
            break;
        /* TODO etc...*/
        default:
            t->status_code = HSERV_SC_INTERNAL_SERVER_ERROR;
            break;
        }
        return NULL;
    }

    struct stat st;
    if (-1 == fstat(fileno(file), &st)) {
        t->status_code = HSERV_SC_INTERNAL_SERVER_ERROR;
        fclose(file);
        return NULL;
    }
    if (!(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) {
        t->status_code = HSERV_SC_UNPROCESSABLE_ENTITY;
        fclose(file);
        return NULL;
    }

    /* Get file's content-length? */
    if (NULL != content_length) {
        *content_length = st.st_size;

        /* Get file's content-type */
        if (NULL != content_type) {
            *content_type = guess_content_type(filename, file, st.st_size);
            if (NULL == *content_type) {
                /* File was readable, but content-type could not be guessed? */
                t->status_code = HSERV_SC_INTERNAL_SERVER_ERROR;
                fclose(file);
                return NULL;
            }
        }
    }

    return file;
}

static int respond_with_error(hserv_t* hserv, hserv_session_t* session,
    hserv_status_code_t status_code)
{
    char const* headers []= {
        "Connection", "close",
        NULL
    };
    return hserv_respond(hserv, session, status_code, NULL, headers, 0, NULL);
}

int respond_on_content(hserv_t* hserv,
    hserv_session_t* session, void const* buffer, size_t size, size_t more)
{
    (void)buffer;

    transaction_t* t = hserv_session_get_user_data(session);

    /* Update progress... */
    t->response_offset += size;
    assert(t->response_offset <= t->response_length);

    /* Finished responsing with all content? */
    if (0 == more) {
        assert(t->response_offset == t->response_length
                 || HSERV_CHUNKED == t->response_length);
        return 0;
    }

    /* File error? */
    if (ferror(t->response_file) > 0) {
        return -1;
    }

    /* End of file? */
    if (feof(t->response_file) > 0) {
        goto terminate_chunked;
    }

    assert(t->buffer.capacity >= TRANSACTION_BUFFER_SIZE);
    size = t->buffer.capacity < TRANSACTION_BUFFER_SIZE
            ? t->buffer.capacity : TRANSACTION_BUFFER_SIZE;

    /* Read buffer worth of data. */
    ssize_t r = fread(t->buffer.data, 1, size, t->response_file);
    if (-1 == r) {
        return -1;
    }
    else if (0 == r) {
        goto terminate_chunked;
    }

    /* Send bytes read and check on callback for error or EOF. */
    hserv_response_send(hserv, session, t->buffer.data, r, respond_on_content);
    return 0;

terminate_chunked:
    /* Terminate stdin chunked response. */
    assert(HSERV_CHUNKED == t->response_length);
    hserv_response_send(hserv, session, NULL, 0, NULL);
    return 0;
}

static int respond(hserv_t* hserv, hserv_session_t* session)
{
    server_t* server = hserv_get_user_data(hserv);
    transaction_t* t = hserv_session_get_user_data(session);

    /* Respond with error? */
    if (t->status_code >= 300) {
        return respond_with_error(hserv, session, t->status_code);
    }

    /* Reserve transaction buffer. */
    if (-1 == hbuffer_reserve(&t->buffer, TRANSACTION_BUFFER_SIZE)) {
        return -1;
    }
    t->buffer.size = 0;

    char const* content_type = NULL;
    harray_t fields = HARRAY_INIT(server->response_fields.sizeof_type);

    /* Open file for reading? */
    if (HSERV_SC_OK == t->status_code
     && (METHOD_GET == t->method || METHOD_HEAD == t->method)) {
        /* Write to a file on the file-system? */
        if (NULL != server->filepath) {
            /* Write request to transaction's target. */
            t->response_file = open_target(server, t, "r",
                &t->response_length, &content_type);
        }
        else {
            /* Write request data to stdin. */
            t->response_file = stdin;
            t->response_length = HSERV_CHUNKED;
        }
    }
    /* Switching protocol to WebSocket? */
    else if (HSERV_SC_SWITCHING_PROTOCOLS == t->status_code) {
        /* Handle WebSocket upgrade response. */
        if (-1 == websocket_respond(hserv, session,
                &server->response_fields, server->websocket_subprotocol)) {
            goto internal_server_error;
        }

        return 0;
    }

    /* Copy response header fields. */
    if (-1 == harray_copy(&fields, &server->response_fields)) {
        goto internal_server_error;
    }

    /* Guess content-type? */
    if (NULL == find_header_field(&fields, "Content-Type")
      && NULL != content_type) {
        char const* name = "Content-Type";
        if (-1 == harray_push_back(&fields, &name)
         || -1 == harray_push_back(&fields, &content_type)) {
            goto internal_server_error;
        }
    }

    /* User wants transfer-encoding chunked? */
    ssize_t index = has_header_field_value(&fields,
        "Transfer-Encoding", "chunked", ",");
    if (index >= 0) {
        /* Erase header field. Note that this assumes that the user never */
        /* uses a transfer-encoding other than chunked. */
        harray_erase(&fields, index);
        harray_erase(&fields, index);

        t->response_length = HSERV_CHUNKED;
    }

    static const void* null = NULL;

    /* NULL terminate header fields array. */
    if (-1 == harray_push_back(&fields, &null)) {
        goto internal_server_error;
    }

    /* Respond. */
    if (-1 == hserv_respond(hserv, session, t->status_code, NULL, fields.data,
            t->response_length, NULL)) {
        goto internal_server_error;
    }

    if (METHOD_GET == t->method
     && -1 == respond_on_content(hserv, session, NULL, 0,
            t->response_length)) {
        goto internal_server_error;
    }

    harray_free(&fields);
    return 0;

internal_server_error:
    harray_free(&fields);
    return respond_with_error(hserv, session, HSERV_SC_INTERNAL_SERVER_ERROR);
}

static int request_on_content(hserv_t* hserv,
    hserv_session_t* session, void* buffer, size_t size, size_t more)
{
    transaction_t* t = hserv_session_get_user_data(session);

    /* Write request content? */
    if (NULL != t->request_file
      && size != fwrite(buffer, 1, size, t->request_file)) {
        return -1;
    }

    /* All content received? */
    if (0 == more) {
        /* Close request file, if opened and not stdout. */
        if (NULL != t->request_file
         && stdout != t->request_file) {
            fclose(t->request_file);
            t->request_file = NULL;
        }

        return respond(hserv, session);
    }

    /* Receive remaining content. */
    if (-1 == hserv_request_receive(hserv, session,
            t->buffer.data, t->buffer.capacity, request_on_content)) {
        return -1;
    }

    return 0;
}

static int request_on_start(
    hserv_t* hserv, hserv_session_t* session)
{
    server_t* server = hserv_get_user_data(hserv);

    /* Initialize request structure, stored as session data. */
    if (-1 == transaction_init(server, session, ++server->request_nr)) {
        return -1;
    }

    transaction_t* t = hserv_session_get_user_data(session);

    /* Open file for writing? */
    if (HSERV_SC_OK == t->status_code
     && (METHOD_POST == t->method || METHOD_PUT == t->method)) {
        /* Write to a file on the file-system? */
        if (NULL != server->filepath) {
            /* Write request to transaction's target. */
            t->request_file = open_target(server, t, "w", NULL, NULL);
        }
        else {
            /* Write request data to stdout. */
            t->request_file = stdout;
        }
    }

    fprintf(
        stdout != t->request_file ? stdout : stderr,
        "#%4d: %s %s %s %s\n",
        t->nr,
        get_date_and_time(),
        hserv_request_get_method(session),
        hserv_request_get_target(session),
        hserv_request_get_version(session)
    );

    /* Write headers? */
    if (0 != (SERVER_FLAG_VERBOSE & server->flags)
     && NULL != t->request_file) {
        fprintf(t->request_file, "%s %s %s\n",
            hserv_request_get_method(session),
            hserv_request_get_target(session),
            hserv_request_get_version(session)
        );

        char const* it = hserv_request_get_header_fields(session);
        do {
            char const* name;
            char const* value;

            it = hserv_header_fields_iterate(it, &name, &value);
            if (NULL == it) {
                break;
            }

            fprintf(t->request_file, "%s: %s\n", name, value);
        }
        while (1);
    }

    /* Check websocket upgrade. */
    if (HSERV_SC_OK == t->status_code
     && NULL != server->websocket_subprotocol) {
        t->status_code = websocket_is_upgrade(
            session, server->websocket_subprotocol);
    }

    if (hserv_request_get_content_length(session) > 0) {
        /* Reserve space in the request buffer to progressively */
        /* receive the content. */
        if (-1 == hbuffer_reserve(&t->buffer, TRANSACTION_BUFFER_SIZE)) {
            return -1;
        }
        t->buffer.size = 0;

        /* Receive content. */
        if (-1 == hserv_request_receive(hserv, session,
            t->buffer.data, t->buffer.capacity,
            request_on_content)) {
            return -1;
        }

        return 0;
    }

    return respond(hserv, session);
}

static void request_on_end(
    hserv_t* hserv, hserv_session_t* session, int failed)
{
    server_t* server = hserv_get_user_data(hserv);
    (void)failed;

    int stop = 0 != (SERVER_FLAG_EXIT & server->flags);

    if (NULL != server->websocket_subprotocol) {
        stop = -1 == websocket_upgrade(server, session);
    }

    transaction_free(hserv, session);

    if (0 != stop) {
        server_stop(server);
    }
}

static int on_hws_event(hserv_t* hserv, struct epoll_event* event)
{
    server_t* server = hserv_get_user_data(hserv);
    (void)event;

    return hws_poll(server->hws);
}

/*
 * Public
 */
void server_create(server_t* server)
{
    assert(HSERV_SESSION_USER_STORAGE >= sizeof(transaction_t));

    memset(server, 0, sizeof(*server));
    server->flags = SERVER_DEFAULT_FLAGS;
    server->port = SERVER_DEFAULT_PORT;
    server->index_file = SERVER_DEFAULT_INDEX_FILE;
    harray_init(&server->response_fields, sizeof(char const*));
    server->certificate_file = SERVER_DEFAULT_CERTIFICATE_FILE;
    server->private_key_file = SERVER_DEFAULT_PRIVATE_KEY_FILE;
}

void server_destroy(server_t* server)
{
    harray_free(&server->response_fields);
    if (NULL != server->logfile) {
        fclose(server->logfile);
    }

    if (NULL != server->hws) {
        hserv_event_remove(server->hserv, &server->hws_event);
        hws_destroy(server->hws);
    }

    if (NULL != server->hserv) {
        hserv_destroy(server->hserv);
    }
}

int server_start(server_t* server)
{
    hserv_config_t config;
    hserv_init(&config, request_on_start, request_on_end);

    if (-1 == hserv_init_binding_ipv4(&config, server->port, server->bind)) {
        fprintf(stderr, "%s: Invalid binding ip address '%s'\n",
            server->exec, server->bind);
        return -1;
    }

    if (0 != (server->flags & SERVER_FLAG_SECURE)) {
        config.secure = 1;
        config.certificate_file = server->certificate_file;
        config.private_key_file = server->private_key_file;
    }

    config.user_data = server;

    server->hserv = hserv_create(&config);
    if (NULL == server->hserv) {
        fprintf(stderr, "%s: Failed to create HTTP server\n", server->exec);
        return -1;
    }

    if (NULL != server->websocket_subprotocol) {
        server->hws = hws_create(server);
        if (NULL == server->hws) {
            fprintf(stderr, "%s: Failed to create WebSocket server\n",
                server->exec);
            return -1;
        }

        server->hws_event.fd = hws_get_fd(server->hws);
        server->hws_event.callback = on_hws_event;
        assert(server->hws_event.fd >= 0);

        if (-1 == hserv_event_add(server->hserv, &server->hws_event, EPOLLIN)) {
            fprintf(stderr,
                "%s: Failed to add WebSocket server to HTTP server (%s)\n",
                server->exec, strerror(errno)
            );
            return -1;
        }
    }

    hserv_start(server->hserv);
    return 0;
}

int server_stop(server_t* server)
{
    return hserv_stop(server->hserv);
}

