/*
 * MIT License
 *
 * Copyright (c) 2019 Maarten Hoeben
 * Copyright (c) 2017 @jinqiangshou, CTrabant
 * Copyright (c) 2013 Tom Cumming
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
 * SHA1 code based on: https://github.com/CTrabant/teeny-sha1,
 *                     https://github.com/jinqiangshou/EncryptionLibrary.
 *
 * Base64 code based on: https://github.com/tomcumming/base64.
 */
#ifdef __cplusplus
extern "C"
{
#endif

#ifndef HWS_H
#define HWS_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#ifdef HWS_HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef HWS_MAX_ERROR_STRING
#define HWS_MAX_ERROR_STRING        80
#endif

#ifndef HWS_SOCKET_USER_STORAGE
#define HWS_SOCKET_USER_STORAGE     0
#endif

#ifdef HWS_VISIBILITY_STATIC
#define HWS_VISIBILITY static
#else
#define HWS_VISIBILITY extern
#endif

typedef enum hws_state_e
{
    HWS_STATE_CONNECTING,
    HWS_STATE_OPEN,
    HWS_STATE_CLOSING,
    HWS_STATE_CLOSED
} hws_state_t;

/*
 * RFC 6455 5.2 opcodes.
 */
typedef enum hws_opcode_e
{
    HWS_OPCODE_CONTINUATION = 0,
    HWS_OPCODE_TEXT = 1,
    HWS_OPCODE_BINARY = 2,
    HWS_OPCODE_CLOSE = 8,
    HWS_OPCODE_PING = 9,
    HWS_OPCODE_PONG = 10
} hws_opcode_t;

typedef struct hws_config_s
{
    void* user_data;

    char error_string[HWS_MAX_ERROR_STRING];
} hws_config_t;

typedef struct hws_s hws_t;
typedef struct hws_socket_s hws_socket_t;

typedef struct hws_socket_connect_config_s
{
    struct sockaddr address __attribute__ ((aligned (4)));
    char const* target;
    char const* host;
    char const* protocols;
    char const* header_fields;

    int(*response)(hws_t* hws, hws_socket_t* socket,
        int status_code, char const* fields);
} hws_socket_connect_config_t;

typedef struct hws_socket_callbacks_s
{
    int(*interrupt)(hws_t* hws, hws_socket_t* socket);
    int(*frame_header)(hws_t* hws, hws_socket_t* socket,
        hws_opcode_t opcode, size_t size, int final);
    int(*frame_received)(hws_t* hws, hws_socket_t* socket,
        void* buffer, size_t size);
    int(*frame_sent)(hws_t* hws, hws_socket_t* socket,
        void const* buffer, size_t size);
    void(*closed)(hws_t* hws, hws_socket_t* socket, int clean);
} hws_socket_callbacks_t;

/*
 * Creates an hws instance. Returns a ready to poll hws instance upon
 * success and NULL upon failure.
 */
HWS_VISIBILITY hws_t* hws_create(hws_config_t* config);

/*
 * Destroys an hws instance, releasing all its resources. Active websocket
 * connections are closed and destroyed.
 *
 * Note that the instance shall not be running. Use hws_stop() to stop a
 * running instance.
 */
HWS_VISIBILITY void hws_destroy(hws_t* hws);

/*
 * Gets the hws instance's epoll facilities` file descriptor.
 */
HWS_VISIBILITY int hws_get_fd(hws_t* hws);

/*
 * Gets the hws instance's error string.
 */
HWS_VISIBILITY char const* hws_get_error_string(hws_t* hws);

/*
 * Gets the hws instance's user data.
 */
HWS_VISIBILITY void* hws_get_user_data(hws_t* hws);

/*
 * Starts the hws instance. A running instance only returns on an instance
 * error, or when stopped by a call to hws_stop().
 *
 * Returns 0 for success, -1 on failure.
 *
 * See hws_poll() and hws_socket_interrupt() for information on thread-safety.
 */
HWS_VISIBILITY int hws_start(hws_t* hws);

/*
 * Stops a running hws instance.
 */
HWS_VISIBILITY int hws_stop(hws_t* hws);

/*
 * Polls an hws instance.
 *
 * This can be used to integrate the instance in a user's main loop.
 *
 * Returns 1 when an event was handled, 0 when no event was handled and
 * -1 on failure.
 *
 * Hws is not thread-safe. Hws's functions shall only be called from
 * hws callbacks or when it is guaranteed that no other thread is currently
 * in one of hws's functions. The only exception is hws_socket_interrupt().
 * This function may be called from any thread context at any time.
 */
HWS_VISIBILITY int hws_poll(hws_t* hws);

/*
 * Creates an hws websocket and connects to an HTTP(S) server to upgrade to
 * a WebSocket client connection.
 *
 * Returns an hws socket instance on success and NULL on failure.
 */
HWS_VISIBILITY hws_socket_t* hws_socket_connect(hws_t* hws,
    hws_socket_connect_config_t const* config,
    hws_socket_callbacks_t const* callbacks);
    
/*
 * Creates an hws websocket for given file descriptor and secure socket.
 * Typically, a websocket is negotiated between an HTTP server and HTTP
 * client via the upgrade mechanism. After the server's response is sent
 * or received, the file descriptor and its secure socket are ready to be
 * passed to hws.
 *
 * Returns an hws socket instance on success and NULL on failure.
 */
#ifdef HWS_HAVE_OPENSSL
HWS_VISIBILITY hws_socket_t* hws_socket_create(hws_t* hws, int fd, SSL* ssl,
    hws_socket_callbacks_t const* callbacks);
#else
HWS_VISIBILITY hws_socket_t* hws_socket_create(hws_t* hws, int fd,
    hws_socket_callbacks_t const* callbacks);
#endif

/*
 * Destroys an hws websocket. 
 */
HWS_VISIBILITY void hws_socket_destroy(hws_t* hws, hws_socket_t* socket);

/*
 * Sets the socket's user data.
 *
 * When hws is compiled with HWS_SOCKET_USER_STORAGE > 0, the socket's
 * user pointer is pre-initialized with a pointer to a buffer of the configured
 * size. If user storage is configured, passing NULL restores the pointer
 * to this buffer.
 */
HWS_VISIBILITY void hws_socket_set_user_data(
    hws_socket_t* socket, void* user_data);

/*
 * Gets the socket's user data.
 *
 * When hws is compiled with HWS_SOCKET_USER_STORAGE > 0, the socket's
 * user pointer is pre-initialized with a pointer to a buffer of the configured
 * size.
 *
 * Returns a pointer to the configured user data or user storage buffer.
 */
HWS_VISIBILITY void* hws_socket_get_user_data(hws_socket_t* socket);

/*
 * Gets the socket's state.
 */
HWS_VISIBILITY hws_state_t hws_socket_get_state(hws_socket_t* socket);

/*
 * Gets the socket's peer socket address.
 */
HWS_VISIBILITY int hws_socket_get_peer(
    hws_socket_t* socket, struct sockaddr *peer_addr, socklen_t* length);

/*
 * Sets the socket's nodelay option.
 */
HWS_VISIBILITY int hws_socket_set_nodelay(hws_socket_t* socket, int enable);

/*
 * Instructs the socket to callback from the socket's thread context.
 *
 * Hws is not thread-safe. Hws's functions shall only be called from
 * hws callbacks or when it is guaranteed that no other thread is currently
 * in one of hws's functions. The only exception is hws_socket_interrupt().
 * This function may be called from any thread context at any time. This can
 * be used to restart receiving and sending frames from any thread. Upon
 * calling hws_socket_interrupt() from another thread, hws calls back the
 * socket's configured interrupt callback at the earliest possible time.
 */
HWS_VISIBILITY int hws_socket_interrupt(hws_socket_t* socket);

/*
 * Disables the socket receiving frames.
 */
HWS_VISIBILITY void hws_socket_receive_disable(hws_socket_t* socket);

/*
 * Enables the socket receiving frames.
 */
HWS_VISIBILITY void hws_socket_receive_enable(hws_socket_t* socket);

/*
 * Instructs hws to receive frame data to the provided buffer of given capacity.
 * This function shall be called after hws called the message_header() callback.
 * The buffer's capacity shall be at least the size of the frame as indicated
 * by the callback's size argument. Upon complete reception of the frame, hws
 * calls the receive() callback with the filled buffer.
 *
 * Returns 0 on success, -1 on failure.
 */
HWS_VISIBILITY int hws_socket_receive(hws_t* hws, hws_socket_t* socket,
    void* buffer, size_t capacity);

/*
 * Instructs hws to send a frame. Upon completion, hws calls the sent()
 * callback. The user shall not call hws_socket_send() before the previous
 * frame has been sent. (Maintaining a send queue is the user's responsibility.)
 * The buffer shall remain valid and unchanged until the frame has beent sent.
 *
 * Returns 0 on success, -1 on failure.
 */
HWS_VISIBILITY int hws_socket_send(hws_t* hws, hws_socket_t* socket,
    hws_opcode_t opcode, void const* buffer, size_t size, int final);

/*
 * Same as hws_socket_send(), but for masked frames. Hws modifies the buffer
 * to mask the frame.
 */
HWS_VISIBILITY int hws_socket_send_masked(hws_t* hws, hws_socket_t* socket,
    hws_opcode_t opcode, void* buffer, size_t size, int final);


/*
 * Get the socket's error string.
 */
HWS_VISIBILITY char const* hws_socket_get_error_string(hws_socket_t* socket);

/*
 * Set the socket's error string.
 */
HWS_VISIBILITY void hws_socket_set_error_string(hws_socket_t* socket,
    char const* format, ...);

/*
 * This function generates a 160 bitSHA1 hash from the passed data.
 * The digest argument shall point to a buffer of at least 20 bytes.
 */
HWS_VISIBILITY void hws_sha1(
    uint8_t *digest, void const *data, size_t size);

/*
 * Determines the length of a base64 encoded string for data of given size.
 */
HWS_VISIBILITY size_t hws_base64_encode_get_length(size_t size);

/*
 * Base64 encodes data of given size. The base64 pointer shall point to a
 * buffer of a capacity as determined by hws_base64_encode_get_length(size).
 */
HWS_VISIBILITY size_t hws_base64_encode(
    char* base64, void const *data, size_t size);

/*
 * Determines the size of the buffer required for decoding a base64 encoded
 * string of given length.
 */
HWS_VISIBILITY size_t hws_base64_decode_get_size(size_t length);

/*
 * Base64 decodes strings of given length. The data pointer shall point to a
 * buffer of a capacity as determined by hws_base64_decode_get_size(length).
 */
HWS_VISIBILITY ssize_t hws_base64_decode(
    void* data, char const* base64, size_t length);

/*
 * Generates a Sec-WebSocket-Key value.
 */
HWS_VISIBILITY char* hws_generate_sec_websocket_key();

/*
 * Generates a Sec-WebSocket-Accept value for given Sec-WebSocket-Key value.
 */
HWS_VISIBILITY char* hws_generate_sec_websocket_accept(
    char const* key, size_t length);

#endif /* HWS_*/

#ifdef HWS_IMPL

#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#ifdef HWS_VISIBILITY_STATIC
#define HWS_VISIBILITY_IMPL static
#else
#define HWS_VISIBILITY_IMPL
#endif

/*
 * Implementation
 */
typedef struct hws_list_s
{
    struct hws_list_s* next;
    struct hws_list_s* prev;
} hws_list_t;

typedef struct hws_list_s hws_list_element_t;
typedef struct hws_list_s hws_list_iterator_t;

static void hws_list_init(hws_list_t* list)
{
    list->next = list;
    list->prev = list;
}

static hws_list_iterator_t* hws_list_begin(hws_list_t* list)
{
    return list->next;
}

static hws_list_iterator_t* hws_list_end(hws_list_t* list)
{
    return list;
}

static void hws_list_insert(hws_list_iterator_t* before, hws_list_element_t* element)
{
    element->next = before;
    element->prev = before->prev;

    before->prev->next = element;
    before->prev = element;
}

static void hws_list_erase(hws_list_iterator_t* element)
{
    element->prev->next = element->next;
    element->next->prev = element->prev;

    element->prev = element;
    element->next = element;
}

static inline void hws_list_push_back(
    hws_list_t* list, hws_list_element_t* element)
{
    hws_list_insert(hws_list_end(list), element);
}

typedef int(*hws_event_callback_t)(hws_t* hws, struct epoll_event* event);

#define HWS_MAX(a, b) ((a) > (b) ? (a) : (b))

typedef struct hws_event_s
{
    int fd;
    hws_event_callback_t callback;
    void* user_data;
} hws_event_t;

#define HWS_BIT_FIN    0x80 /* WebSocket FIN bit. */
#define HWS_BIT_MASK   0x80 /* WebSocket MASK bit. */

struct hws_socket_s
{
    hws_list_element_t element;

    hws_event_t interrupt;
    hws_event_t socket;
#ifdef HWS_HAVE_OPENSSL
    SSL* ssl;
#endif

#define HWS_RECEIVE_HEADER  0x01
#define HWS_RECEIVE_PAYLOAD 0x02
#define HWS_RECEIVE_MASK    0x03
#define HWS_CLOSED_BY_PEER  0x04

#define HWS_SEND_HEADER     0x10
#define HWS_SEND_PAYLOAD    0x20
#define HWS_SEND_MASK       0x30
#define HWS_CLOSED_BY_USER  0x40

    hws_socket_callbacks_t callbacks;

    hws_state_t state;
    uint8_t flags;

    uint8_t receive_disable;
    uint8_t receive_header[14];
    uint8_t receive_header_length;
    size_t receive_size;
    uint8_t* receive_buffer;
    size_t receive_progress;

    uint8_t send_header[14];
    uint8_t send_header_length;
    uint8_t const* send_buffer;
    size_t send_size;
    size_t send_progress;

    char error_string[HWS_MAX(HWS_MAX_ERROR_STRING, 1)];

    void* user_data;
#if HWS_SOCKET_USER_STORAGE > 0
    char user_storage[HWS_SOCKET_USER_STORAGE];
#endif
};

struct hws_s
{
    int stop;
    int epoll_fd;
    hws_event_t timer;

#ifdef HWS_HAVE_OPENSSL
    SSL_CTX* ssl_context;
#endif

    hws_list_t sockets;

    char error_string[HWS_MAX(HWS_MAX_ERROR_STRING, 1)];

    void* user_data;
};

#if (HWS_MAX_ERROR_STRING > 0)

static char const* hws_strerror(char* error_string)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"

#if (_POSIX_C_SOURCE >= 200112L) && ! _GNU_SOURCE
    if (0 != strerror_r(errno, error_string, HWS_MAX_ERROR_STRING)) {
#else
    if (NULL == strerror_r(errno, error_string, HWS_MAX_ERROR_STRING)) {
#endif
        snprintf(error_string, HWS_MAX_ERROR_STRING, "%d", errno);
    }
    return error_string;
#pragma GCC diagnostic pop
}

static char const* hws_set_error_string(char* error_string, char const* string)
{
    char errno_string[HWS_MAX_ERROR_STRING];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    /* Concat formatted string with parenthesized errno string. */ 
    snprintf(error_string, HWS_MAX_ERROR_STRING,
        "%s (%s)", string, hws_strerror(errno_string));
#pragma GCC diagnostic pop

    return error_string;
}

#else

static char const* hws_set_error_string(char* error_string, char const* string)
{
    (void)error_string;
    (void)string;
    return "";
}

#endif // (0 != HWS_MAX_ERROR_STRING)

static int hws_event_add(
    hws_t* hws, hws_socket_t* socket, hws_event_t* event, uint32_t events)
{
    struct epoll_event epoll_event;
    epoll_event.events = events;
    epoll_event.data.ptr = event;

    if (-1 == epoll_ctl(hws->epoll_fd,
            EPOLL_CTL_ADD, event->fd, &epoll_event)) {
        hws_set_error_string(
            NULL != socket ? socket->error_string : hws->error_string,
            "epoll_ctl(...EPOLL_CTL_ADD...) failed"
        );
        return -1;
    }

    return 0;
}

static int hws_event_modify(hws_t* hws, hws_socket_t* socket)
{
    struct epoll_event epoll_event;
    epoll_event.events = 0;
    epoll_event.data.ptr = &socket->socket;

    if (0 != (HWS_RECEIVE_MASK & socket->flags)) {
        epoll_event.events |= EPOLLIN;
    }
    if (0 != (HWS_SEND_MASK & socket->flags)) {
        epoll_event.events |= EPOLLOUT;
    }

    if (-1 == epoll_ctl(hws->epoll_fd,
            EPOLL_CTL_MOD, socket->socket.fd, &epoll_event)) {
        hws_set_error_string(socket->error_string,
            "epoll_ctl(...EPOLL_CTL_MOD...) failed");
    }

    return 0;
}

#ifdef HWS_HAVE_OPENSSL
static int hws_event_modify_ssl(
    hws_t* hws, hws_socket_t* socket, int result)
{
    struct epoll_event epoll_event;

    result = SSL_get_error(socket->ssl, result);
    switch (result) {
    case SSL_ERROR_WANT_READ:   epoll_event.events = EPOLLIN; break;
    case SSL_ERROR_WANT_WRITE:  epoll_event.events = EPOLLOUT; break;
    /* Not sure how SSL socket closure can be detected. */
    case SSL_ERROR_ZERO_RETURN: return -2;
    default:
        // TODO get SSL's error info.
        hws_socket_set_error_string(socket, "An SSL error occurred");
        return -1;
    }
    epoll_event.data.ptr = &socket->socket;

    if (-1 == epoll_ctl(hws->epoll_fd,
            EPOLL_CTL_MOD, socket->socket.fd, &epoll_event)) {
        hws_set_error_string(socket->error_string,
            "epoll_ctl(...EPOLL_CTL_MOD...) failed");
        return -1;
    }

    return 0;
}
#endif

static void hws_event_remove(hws_t* hws, hws_event_t* event)
{
    if (-1 == event->fd) {
        return;
    }

    (void)epoll_ctl(hws->epoll_fd, EPOLL_CTL_DEL, event->fd, NULL);
    close(event->fd);
}

static void* hws_event_user_data(struct epoll_event* epoll_event)
{
    return ((hws_event_t*)epoll_event->data.ptr)->user_data;
}

static int hws_timer_create(hws_t* hws, hws_event_t* event, char* error_string)
{
    /* Create timer. */
    event->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (-1 == event->fd) {
        hws_set_error_string(error_string, "timerfd_create() failed");
        goto error;
    }

    /* Add to epoll facility. */
    if (-1 == hws_event_add(hws, NULL, event, EPOLLIN)) {
        goto error;
    }
    return 0;

error:
    hws_event_remove(hws, event);
    return -1;
}

static int hws_timer_set(hws_event_t const* event,
    time_t value_sec, long value_nsec,
    time_t interval_sec, long interval_nsec,
    char* error_string)
{
    struct itimerspec spec;
    spec.it_value.tv_sec = value_sec;
    spec.it_value.tv_nsec = value_nsec;
    spec.it_interval.tv_sec = interval_sec;
    spec.it_interval.tv_nsec = interval_nsec;

    if (-1 == timerfd_settime(event->fd, 0, &spec, NULL)) {
        hws_set_error_string(error_string, "timerfd_settime() failed");
        return -1;
    }

    return 0;
}

static int64_t hws_timer_read(hws_event_t const* event)
{
    uint64_t expired;
    ssize_t bytes = read(event->fd, &expired, sizeof(expired));
    return bytes == sizeof(expired) ? (int64_t)expired : (int64_t)-1;
}

static ssize_t hws_recv(hws_t* hws, hws_socket_t* socket,
    void* buffer, size_t size)
{
    /* Returns the number of bytes that can be read, which may be 0 in case */
    /* SSL wants to renegotiate. Errors are returned signalled as -1, while */
    /* socket closure is signalled as -2. */
    ssize_t r;

#ifdef HWS_HAVE_OPENSSL
    if (NULL != socket->ssl) {
        size_t bytes;

        r = SSL_read_ex(socket->ssl, buffer, size, &bytes);
        if (r <= 0) {
            /* Returns 0 for success, -1 for failure, -2 for closure. */
            return hws_event_modify_ssl(hws, socket, r);
        }

        return bytes;
    }
#else
    (void)hws;
#endif
    /* Returns > 0 for success, -1 for failure and 0 for closure. */
    r = recv(socket->socket.fd, buffer, size, 0);
    switch (r) { 
    case -1:
        /* Trying to receive while nothing available? */
#if EAGAIN != EWOULDBLOCK
        if (EAGAIN == errno || EWOULDBLOCK == errno) {
#else
        if (EAGAIN == errno) {
#endif
            return 0;
        }

        hws_set_error_string(socket->error_string, "recv() failed");
        return -1;  /* An error occurred. */
    case 0:
        return -2;  /* Socket closed. (See comment on SSL why -2.) */
    default:
        return r;   /* Received 'r' bytes. */
    }
}

static ssize_t hws_send(hws_t* hws, hws_socket_t* socket,
    void const* buffer, size_t size)
{
    ssize_t r;

#ifdef HWS_HAVE_OPENSSL
    if (NULL != socket->ssl) {
        size_t bytes;
        r = SSL_write_ex(socket->ssl, buffer, size, &bytes);
        if (r <= 0) {
            r = hws_event_modify_ssl(hws, socket, r);
            if (r < 0) {
                // TODO get SSL's error info.
                hws_socket_set_error_string(socket, "SSL_write_ex() failed");
                return -1;
            }

            return 0;
        }

        return bytes;
    }
#else
    (void)hws;
#endif
    r = send(socket->socket.fd, buffer, size, 0);
    if (-1 == r) {
        hws_set_error_string(socket->error_string, "send() failed");
        return -1;
    }

    return r;
}

static int hws_socket_send_update_close_state(
    hws_socket_t* socket, hws_opcode_t opcode)
{
    /* Update state when being passed a close frame. */
    if (HWS_OPCODE_CLOSE == opcode) {
        if (socket->state < HWS_STATE_CLOSING) {
            /* User initiated close sequence. */
            socket->state = HWS_STATE_CLOSING;
            socket->flags |= HWS_CLOSED_BY_USER;
            return 0;
        }
        else if (socket->state == HWS_STATE_CLOSING
              && HWS_CLOSED_BY_PEER == (HWS_CLOSED_BY_PEER & socket->flags)) {
            /* User initiated close sequence. */
            socket->state = HWS_STATE_CLOSED;
            /* Disable receiving. */
            hws_socket_receive_disable(socket);
            return 1;
        }
        else {
            /* Non-compliant close sequence. */
            assert(0);

            hws_socket_set_error_string(socket, "Non-compliant close sequence");
            return -1;
        }
    }

    return 0;
}

static void hws_mask(uint8_t* data, size_t size, uint8_t const* mask)
{
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= mask[i & 3];
    }
}

static int hws_socket_on_interrupt(hws_t* hws, struct epoll_event* event)
{
    assert(event->events & EPOLLIN);
    hws_socket_t* socket = (hws_socket_t*)hws_event_user_data(event);

    /* Read timer interrupt. */
    (void)hws_timer_read(&socket->interrupt);

    /* Callback. */
    return socket->callbacks.interrupt(hws, socket);
}

static int hws_socket_on_event(hws_t* hws, struct epoll_event* epoll_event)
{
    hws_socket_t* socket = (hws_socket_t*)hws_event_user_data(epoll_event);
    ssize_t bytes;
    int closed_clean = 0;

    /* Cleanup socket if peer closed the socket. */
    if (0 != (EPOLLHUP & epoll_event->events)) {
        goto closed;
    }

    if (0 != (EPOLLIN & epoll_event->events)
     && 0 != (HWS_RECEIVE_HEADER & socket->flags)) {
        /* Progressively receive header. */
        bytes = hws_recv(hws, socket,
            socket->receive_header + socket->receive_progress,
            socket->receive_header_length - socket->receive_progress);
        switch (bytes) {
        case -2: goto closed;
        case -1: return -1;
        case  0: return  0; /* Would block or SSL renegotiates. */
        default:
            break;
        }

        /* Update progress. */
        socket->receive_progress += bytes;
        /* Enough received? */
        if (socket->receive_progress < socket->receive_header_length) {
            goto send;
        }

        uint8_t const* ptr = socket->receive_header;

        /* Determine header size. */
        if (126 == (0x7f & ptr[1])) {
            socket->receive_header_length = 2 + 2;
        }
        else if (127 == (0x7f & ptr[1])) {
            socket->receive_header_length = 2 + 8;
        }
        else {
            socket->receive_header_length = 2;
        }
        if (0 != (HWS_BIT_MASK & ptr[1])) {
            socket->receive_header_length += 4;
        }
        if (socket->receive_progress < socket->receive_header_length) {
            goto send;
        }

        /* Header received, reset progress. */
        socket->flags &= ~HWS_RECEIVE_HEADER;
        socket->receive_progress = 0;

        /* Deserialize header fields. */
        hws_opcode_t const opcode = (hws_opcode_t)(ptr[0] & 0xf);
        int const final = 0 != (HWS_BIT_FIN & ptr[0]);

        /* Determine frame size. */
        if ((ptr[1] & 0x7f) < 126) {
            socket->receive_size = ptr[1] & 0x7f;
        }
        else if ((ptr[1] & 0x7f) == 126) {
            socket->receive_size = (((size_t)ptr[2]) << 8)
                                 | (((size_t)ptr[3]) << 0);
        }
        else if ((ptr[1] & 0x7f) == 127) {
            socket->receive_size = (((size_t)ptr[6]) << 24)
                                 | (((size_t)ptr[7]) << 16)
                                 | (((size_t)ptr[8]) <<  8)
                                 | (((size_t)ptr[9]) <<  0);
        }

        /* Update state when receiving a close frame. */
        if (HWS_OPCODE_CLOSE == opcode) {
            if (socket->state < HWS_STATE_CLOSING) {
                /* Peer initiated close sequence. */
                socket->state = HWS_STATE_CLOSING;
                socket->flags |= HWS_CLOSED_BY_PEER;
            }
            else if (socket->state == HWS_STATE_CLOSING
                  && HWS_CLOSED_BY_USER == (HWS_CLOSED_BY_USER & socket->flags)) {
                /* End of close sequence. */
                closed_clean = 1;
                goto closed;
            }
            else {
                /* Non-compliant close sequence. */
                assert(0);

                hws_socket_set_error_string(socket,
                    "Non-compliant close sequence");
                return -1;
            }
        }

        /* Callback. */
        if (socket->callbacks.frame_header(hws, socket,
            opcode, socket->receive_size, final) < 0) {
            return -1;
        }

        /* Payload? */
        if (socket->receive_size > 0) {
            /* User provided a receive buffer? */
            if (NULL == socket->receive_buffer) {
                /* Disable receiving. */
                assert(0 == (HWS_RECEIVE_PAYLOAD & socket->flags));
                if (-1 == hws_event_modify(hws, socket)) {
                    return -1;
                }

                goto send;
            }
        }
        else {
            /* Callback. */
            if (socket->callbacks.frame_received(hws, socket,
                socket->receive_buffer, socket->receive_size) < 0) {
            }

            /* Reset initial receive header size. */
            socket->receive_header_length = 2;

            /* Receiving disabled? */
            if (0 != socket->receive_disable) {
                /* Disable receiving until re-enabled. */
                if (-1 == hws_event_modify(hws, socket)) {
                    return -1;
                }
            }
            else {
                /* Receive next header. */
                socket->flags |= HWS_RECEIVE_HEADER;
            }
            goto send;
        }
    }

    if (0 != (EPOLLIN & epoll_event->events)
     && 0 != (HWS_RECEIVE_PAYLOAD & socket->flags)) {
        /* Progressively receive payload. */
        bytes = hws_recv(hws, socket,
            socket->receive_buffer + socket->receive_progress,
            socket->receive_size - socket->receive_progress);
        switch (bytes) {
        case -2: goto closed;
        case -1: return -1;
        case  0: return  0; /* Would block or SSL renegotiates. */
        default:
            break;
        }

        /* Update progress. */
        socket->receive_progress += bytes;

        /* Payload received? */
        if (socket->receive_progress < socket->receive_size) {
            goto send;
        }

        /* Payload received, reset progress. */
        socket->flags &= ~HWS_RECEIVE_PAYLOAD;
        socket->receive_progress = 0;

        /* Masked? */
        if (0 != (HWS_BIT_MASK & socket->receive_header[1])) {
            hws_mask(socket->receive_buffer, socket->receive_size,
                socket->receive_header + socket->receive_header_length - 4);
        }

        /* Callback. */
        if (socket->callbacks.frame_received(hws, socket,
            socket->receive_buffer, socket->receive_size) < 0) {
        }

        /* Reset header and buffer. */
        socket->receive_header_length = 2;
        socket->receive_buffer = NULL;
        socket->receive_size = 0;

        /* Receiving disabled? */
        if (0 != socket->receive_disable) {
            /* Disable receiving until re-enabled. */
            if (-1 == hws_event_modify(hws, socket)) {
                return -1;
            }
        }
        else {
            /* Receive next header. */
            socket->flags |= HWS_RECEIVE_HEADER;
        }
    }

send:
    if (0 != (EPOLLOUT & epoll_event->events)
     && 0 != (HWS_SEND_HEADER & socket->flags)) {
        /* Progressively send header. */
        bytes = hws_send(hws, socket,
            socket->send_header + socket->send_progress,
            socket->send_header_length - socket->send_progress);
        if (bytes < 0) {
            return -1;
        }
        /* Update progress. */
        socket->send_progress += bytes;
        /* Header sent? */
        if (socket->send_progress < socket->send_header_length) {
            return 0;
        }

        /* Header sent, reset progress. */
        socket->flags &= ~HWS_SEND_HEADER;
        socket->send_progress = 0;

        /* Payload? */
        if (socket->send_size > 0) {
            socket->flags |=  HWS_SEND_PAYLOAD;
        }
        else {
            /* Disable send event. */
            hws_event_modify(hws, socket);

            /* Callback send has been completed. */
            if (socket->callbacks.frame_sent(hws, socket,
                    socket->send_buffer, socket->send_size) < 0) {
                return -1;
            }

            /* Closed? */
            if (HWS_STATE_CLOSED == socket->state) {
                closed_clean = 1;
                goto closed;
            }
        }
    }

    if (0 != (EPOLLOUT & epoll_event->events)
     && 0 != (HWS_SEND_PAYLOAD & socket->flags)) {
        /* Progressively send payload. */
        bytes = hws_send(hws, socket,
            socket->send_buffer + socket->send_progress,
            socket->send_size - socket->send_progress);
        if (bytes < 0) {
            return -1;
        }
        /* Update progress. */
        socket->send_progress += bytes;
        /* Header sent? */
        if (socket->send_progress < socket->send_size) {
            return 0;
        }

        /* Payload sent, reset progress. */
        socket->flags &= ~HWS_SEND_PAYLOAD;
        socket->send_progress = 0;
        socket->send_buffer = NULL;
        socket->send_size = 0;

        /* Disable send event. */
        hws_event_modify(hws, socket);

        /* Callback send has been completed. */
        if (socket->callbacks.frame_sent(hws, socket,
            socket->send_buffer, socket->send_size) < 0) {
            return -1;
        }

        /* Closed? */
        if (HWS_STATE_CLOSED == socket->state) {
            closed_clean = 1;
            goto closed;
        }
    }

    return 0;

closed:
    socket->state = HWS_STATE_CLOSED;
    socket->callbacks.closed(hws, socket, closed_clean);
    hws_socket_destroy(hws, socket);
    return 0;
}

static int hws_socket_on_maintenance(hws_socket_t* socket)
{
    /* TODO. */
    (void)socket;
    return 0;
}

static int hws_on_timer(hws_t* hws, struct epoll_event* event)
{
    assert(event->events & EPOLLIN);
    (void)event;

    (void)hws_timer_read(&hws->timer);

    /* Call socket's timer handling function. */
    hws_list_iterator_t* it = hws_list_begin(&hws->sockets);
    while (hws_list_end(&hws->sockets) != it) {
        hws_socket_t* socket = (hws_socket_t*)it;
        int r = hws_socket_on_maintenance(socket);

        /* Get next socket before destroying socket. */
        it = it->next;

        if (r < 0) {
            socket->state = HWS_STATE_CLOSED;
            socket->callbacks.closed(hws, socket, 0);
            hws_socket_destroy(hws, socket);
        }
    }

    return 0;
}

static int hws_run(hws_t* hws, int timeout)
{
    struct epoll_event event;

    do {
        /* Wait for event. */
        int r = epoll_wait(hws->epoll_fd, &event, 1, timeout);
        if (r <= 0) {
            if (-1 == r) {
                hws_set_error_string(hws->error_string, "epoll_wait() failed");
                return -1;
            }
            break;
        }

        /* Stopping? */
        if (0 != hws->stop) {
            break;
        }

        hws_event_t const* e = (hws_event_t*)event.data.ptr;

        /* Callback. */
        if (-1 == e->callback(hws, &event)) {
            /* Check timer fd callback returned an error. */
            if (e->fd == hws->timer.fd) {
                return -1;
            }
            else {
                /* Socket returned an error, notify user and destroy socket. */
                hws_socket_t* socket =
                    (hws_socket_t*)hws_event_user_data(&event);
                socket->state = HWS_STATE_CLOSED;
                socket->callbacks.closed(hws, socket, 0);
                hws_socket_destroy(hws, socket);
            }
        }
    }
    while (1);

    return 0;
}

static inline uint32_t hsha1_rol(uint32_t word, uint32_t shift)
{
    return (word << shift)
         | (word >> (32 - shift));
}

static char const hws_base64_encode_table[65]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline uint8_t* hws_base64_encode_start(uint8_t* dst, uint8_t const *src)
{
    uint8_t t;
    *dst++ = hws_base64_encode_table[(src[0] & 0xfc) >> 2];

    t  = (src[0] & 0x03) << 4;
    t |= (src[1] & 0xf0) >> 4;
    *dst++ = hws_base64_encode_table[t];

    return dst;
}

static uint8_t hws_base64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return ((uint8_t)c) - 'A' + 0;
    }
    if (c >= 'a' && c <= 'z') {
        return ((uint8_t)c) - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return ((uint8_t)c) - '0' + 52;
    }

    return '+' == c ? 62 : 63;
}

static uint8_t* hws_base64_decode2(uint8_t *dst, uint8_t const* src)
{
    *dst  = (hws_base64_decode_char(src[0])       ) << 2;
    *dst |= (hws_base64_decode_char(src[1]) & 0x30) >> 4;
    return ++dst;
}

static uint8_t* hws_base64_decode3(uint8_t *dst, uint8_t const* src)
{
    dst = hws_base64_decode2(dst, src);

    *dst  = (hws_base64_decode_char(src[1]) & 0x0f) << 4;
    *dst |= (hws_base64_decode_char(src[2]) & 0x3c) >> 2;
    return ++dst;
}

static uint8_t* hws_base64_decode4(uint8_t *dst, uint8_t const* src)
{
    dst = hws_base64_decode3(dst, src);

    *dst  = (hws_base64_decode_char(src[2]) & 0x03) << 6;
    *dst |= (hws_base64_decode_char(src[3])       );
    return ++dst;
}

/*
 * Public
 */
HWS_VISIBILITY_IMPL hws_t* hws_create(hws_config_t* config)
{
    hws_t* hws = (hws_t*)calloc(1, sizeof(hws_t));
    if (NULL == hws) {
        snprintf(config->error_string, HWS_MAX_ERROR_STRING, "calloc() failed");
        goto error;
    }

    hws->epoll_fd = -1;

    hws->timer.fd = -1;
    hws->timer.callback = hws_on_timer;
    hws->user_data = hws;

    hws_list_init(&hws->sockets);

    hws->user_data = config->user_data;

    /* Create epoll facility. */
    hws->epoll_fd = epoll_create1(0);
    if (-1 == hws->epoll_fd) {
        hws_set_error_string(config->error_string, "epoll_create1() failed");
        goto error;
    }

    /* Create a 1 second maintenance timer. */
    if (-1 == hws_timer_create(hws, &hws->timer, config->error_string)
     || -1 == hws_timer_set(&hws->timer, 1, 0, 1, 0, config->error_string)) {
        goto error;
    }

    return hws;

error:
    hws_destroy(hws);
    return NULL;
}

HWS_VISIBILITY_IMPL void hws_destroy(hws_t* hws)
{
    if (NULL == hws) {
        return;
    }

    /* Destroy all active sockets. */
    hws_list_iterator_t* it = hws_list_begin(&hws->sockets);
    while (hws_list_end(&hws->sockets) != it) {
        /* Get pointer to socket. */
        hws_socket_t* socket = (hws_socket_t*)it;

        /* Get next iterator before the socket (which contains the link) */
        /* is destroyed. */
        it = it->next;

        /* Destroy socket. */
        hws_socket_destroy(hws, socket);
    }

#ifdef HWS_HAVE_OPENSSL
    if (NULL != hws->ssl_context) {
        SSL_CTX_free(hws->ssl_context);
    }
#endif
    if (-1 != hws->timer.fd) {
        close(hws->timer.fd);
    }
    if (-1 != hws->epoll_fd) {
        close(hws->epoll_fd);
    }
    free(hws);
}

HWS_VISIBILITY_IMPL int hws_get_fd(hws_t* hws)
{
    return NULL != hws ? hws->epoll_fd : -1;
}

HWS_VISIBILITY_IMPL char const* hws_get_error_string(hws_t* hws)
{
    assert(NULL != hws);
    return hws->error_string;
}

HWS_VISIBILITY_IMPL void* hws_get_user_data(hws_t* hws)
{
    assert(NULL != hws);
    return hws->user_data;
}

HWS_VISIBILITY_IMPL int hws_start(hws_t* hws)
{
    assert(NULL != hws);
    hws->stop = 0;
    return hws_run(hws, -1);
}

HWS_VISIBILITY_IMPL int hws_stop(hws_t* hws)
{
    assert(NULL != hws);
    hws->stop = 1;

    /* Modify timer to immediately fire and exit epoll_wait. */
    return hws_timer_set(&hws->timer, 0, 1, 1, 0, hws->error_string);
}

HWS_VISIBILITY_IMPL int hws_poll(hws_t* hws)
{
    assert(NULL != hws);
    return hws_run(hws, 0);
}

HWS_VISIBILITY hws_socket_t* hws_socket_connect(hws_t* hws,
    hws_socket_connect_config_t const* config,
    hws_socket_callbacks_t const* callbacks)
{
    assert(NULL != hws);
    assert(NULL != config);
    assert(NULL != callbacks);
    
    hws_socket_t* sock = NULL;
    int fd = -1;
#ifdef HWS_HAVE_OPENSSL
    SSL* ssl = NULL;
#endif

    /* Create a stream socket for address' family. */
    fd = socket(config->address.sa_family, SOCK_STREAM, 0);
    if (-1 == fd) {
        return NULL;
    }

#ifdef HWS_HAVE_OPENSSL
    /* Create SSL context, if not created. */
    if (NULL == hws->ssl_context) {
        // TODO
    }

    /* Create an SSL structure. */
    ssl = SSL_new(hws->ssl_context);
    if (NULL == ssl) {
        goto error;
    }

    /* Create a socket structure for fd, ssl and callbacks. */
    sock = hws_socket_create(hws, fd, ssl, callbacks);
#else

    /* Create a socket structure for fd, ssl and callbacks. */
    sock = hws_socket_create(hws, fd, callbacks);
#endif
    if (NULL == sock) {
        goto error;
    }

    /* Reset variables now owned by socket. */
    fd = -1;
#ifdef HWS_HAVE_OPENSSL
    ssl = NULL;
#endif

    /* Override state. */
    sock->state = HWS_STATE_CONNECTING;

    /* Determine socket address length. */
    socklen_t length;
    switch (config->address.sa_family) {
    case AF_INET:   length = sizeof(struct sockaddr_in); break;
    case AF_INET6:  length = sizeof(struct sockaddr_in6); break;
    default:
        /* Unsupported address family. */
        goto error;
    }

    /* Connect, expect EINPROGRESS error. */
    if (-1 == connect(sock->socket.fd, &config->address, length)
     && EINPROGRESS != errno) {
        goto error;
    }

    /* TODO complete connect handshake and HTTP. */
    return sock;

error:
    hws_socket_destroy(hws, sock);

    if (NULL != ssl) {
        SSL_free(ssl);
    }
    if (-1 != fd) {
        close(fd);
    }
    return NULL;
}

#ifdef HWS_HAVE_OPENSSL
HWS_VISIBILITY_IMPL hws_socket_t* hws_socket_create(hws_t* hws, int fd,
    SSL* ssl, hws_socket_callbacks_t const* callbacks)
#else
HWS_VISIBILITY_IMPL hws_socket_t* hws_socket_create(hws_t* hws, int fd,
    hws_socket_callbacks_t const* callbacks)
#endif
{
    assert(NULL != hws);
    assert(fd >= 0);
    assert(NULL != callbacks);

    hws_socket_t* socket = (hws_socket_t*)calloc(1, sizeof(hws_socket_t));
    if (NULL == socket) {
        snprintf(hws->error_string, HWS_MAX_ERROR_STRING, "calloc() failed");
        goto error;
    }

    socket->interrupt.fd = -1;
    socket->interrupt.callback = hws_socket_on_interrupt;
    socket->interrupt.user_data = socket;

    socket->socket.fd = fd;
    socket->socket.callback = hws_socket_on_event;
    socket->socket.user_data = socket;

#ifdef HWS_HAVE_OPENSSL
    socket->ssl = ssl;
#endif

    socket->callbacks = *callbacks;

    socket->state = HWS_STATE_OPEN;
    socket->flags = HWS_RECEIVE_HEADER;
    socket->receive_header_length = 2;

#if HWS_SOCKET_USER_STORAGE > 0
    socket->user_data = socket->user_storage;
#endif

    int flags;

    /* Make socket non-blocking. */
    if ( -1 == (flags = fcntl(fd, F_GETFL, 0))
      || -1 == fcntl(fd, F_SETFL, flags|O_NONBLOCK)) {
        hws_set_error_string(hws->error_string,
            "fcntl(...O_NONBLOCK...) failed");
        goto error;
    }

    /* Create interrupt timer. */
    if (-1 == hws_timer_create(hws, &socket->interrupt, hws->error_string)) {
        goto error;
    }

    /* Add socket to epoll facility. */
    if (-1 == hws_event_add(hws, socket, &socket->socket, EPOLLIN)) {
        goto error;
    }

    /* Add socket to socket list. */
    hws_list_push_back(&hws->sockets, &socket->element);
    return socket;

error:
    hws_socket_destroy(hws, socket);
    return NULL;
}

HWS_VISIBILITY_IMPL void hws_socket_destroy(hws_t* hws, hws_socket_t* socket)
{
    if (NULL == socket) {
        return;
    }

    hws_list_erase(&socket->element);
    hws_event_remove(hws, &socket->socket);
    hws_event_remove(hws, &socket->interrupt);

#ifdef HWS_HAVE_OPENSSL
    SSL_free(socket->ssl);
#endif
    if (-1 != socket->socket.fd) {
        close(socket->socket.fd);
    }
    if (-1 != socket->interrupt.fd) {
        close(socket->interrupt.fd);
    }

    free(socket);
}

HWS_VISIBILITY_IMPL void hws_socket_set_user_data(hws_socket_t* socket,
    void* user_data)
{
    assert(NULL != socket);
#if HWS_SOCKET_USER_STORAGE > 0
    if (NULL == user_data) {
        socket->user_data = &socket->user_storage;
        return;
    }
#endif
    socket->user_data = user_data;
}

HWS_VISIBILITY_IMPL void* hws_socket_get_user_data(hws_socket_t* socket)
{
    assert(NULL != socket);
    return socket->user_data;
}

HWS_VISIBILITY_IMPL hws_state_t hws_socket_get_state(hws_socket_t* socket)
{
    assert(NULL != socket);
    return socket->state;
}

HWS_VISIBILITY_IMPL int hws_socket_get_peer(
    hws_socket_t* socket, struct sockaddr *peer_address, socklen_t* length)
{
    assert(NULL != socket);

    if (-1 == getpeername(socket->socket.fd,
            (struct sockaddr*)peer_address, length)) {
        hws_set_error_string(socket->error_string, "getpeername() failed");
        return -1;
    }

    return 0;
}

HWS_VISIBILITY_IMPL int hws_socket_set_nodelay(hws_socket_t* socket, int enable)
{
    assert(NULL != socket);

    if (-1 == setsockopt(socket->socket.fd,
            IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable))) {
        hws_set_error_string(socket->error_string, "setsockopt() failed");
        return -1;
    }

    return 0;
}

HWS_VISIBILITY_IMPL int hws_socket_interrupt(hws_socket_t* socket)
{
    return hws_timer_set(&socket->interrupt, 0, 1, 0, 0, socket->error_string);
}

HWS_VISIBILITY_IMPL void hws_socket_receive_disable(hws_socket_t* socket)
{
    socket->receive_disable = 1;
}

HWS_VISIBILITY_IMPL void hws_socket_receive_enable(hws_socket_t* socket)
{
    socket->receive_disable = 0;
}

HWS_VISIBILITY_IMPL int hws_socket_receive(hws_t* hws, hws_socket_t* socket,
    void* buffer, size_t capacity)
{
    assert(NULL != hws);
    assert(NULL != socket);
    assert(NULL != buffer);
    assert(0 == (socket->flags & HWS_RECEIVE_MASK));
    assert(NULL == socket->receive_buffer);

    if (capacity < socket->receive_size) {
        return -1;
    }

    socket->receive_buffer = (uint8_t*)buffer;

    socket->flags |= HWS_RECEIVE_PAYLOAD;
    return hws_event_modify(hws, socket);
}

HWS_VISIBILITY_IMPL int hws_socket_send(hws_t* hws, hws_socket_t* socket,
    hws_opcode_t opcode, void const* buffer, size_t size, int final)
{
    assert(NULL != hws);
    assert(NULL != socket);
    assert(0 == (socket->flags & HWS_SEND_MASK));
    assert(NULL == socket->send_buffer);
    assert(0 == size || buffer != NULL);

    if (-1 == hws_socket_send_update_close_state(socket, opcode)) {
        return -1;
    }

    /* Force final bit on all control frames. RFC6455 5.4 says that control */
    /* frames themselves MUST NOT be fragmented. Hence, FIN is always set. */
    if (opcode >= HWS_OPCODE_CLOSE) {
        final = 1;
    }

    uint8_t* ptr = socket->send_header;

    ptr[0]  = 0 != (0 != final) ? HWS_BIT_FIN : 0x00;
    ptr[0] |= (uint8_t)opcode;
    ptr[1]  = 0x00;

    if (size < 126) {
        ptr[1] |= (uint8_t)size;
        ptr += 2;
    }
    else if (size < 65536) {
        ptr[1] |= 126;
        ptr[2] = (uint8_t)(size >> 8);
        ptr[3] = (uint8_t)(size >> 0);
        ptr += 4;
    }
    else {
        ptr[1] |= 127;

#if UINTPTR_MAX == 0xffffffffffffffff
        assert(size <= 0xffffffff);
#endif
        ptr[2] = 0;
        ptr[3] = 0;
        ptr[4] = 0;
        ptr[5] = 0;
        ptr[6] = (uint8_t)(size >> 24);
        ptr[7] = (uint8_t)(size >> 16);
        ptr[8] = (uint8_t)(size >>  8);
        ptr[9] = (uint8_t)(size >>  0);
        ptr += 10;
    }

    socket->send_header_length = ptr - socket->send_header;
    socket->send_buffer = (uint8_t const*)buffer;
    socket->send_size = size;

    socket->flags |= HWS_SEND_HEADER;
    return hws_event_modify(hws, socket);
}

HWS_VISIBILITY_IMPL int hws_socket_send_masked(hws_t* hws, hws_socket_t* socket,
    hws_opcode_t opcode, void* buffer, size_t size, int final)
{
    assert(NULL != hws);
    assert(NULL != socket);
    assert(0 == (socket->flags & HWS_SEND_MASK));
    assert(NULL == socket->send_buffer);
    assert(0 == size || buffer != NULL);

    if (-1 == hws_socket_send_update_close_state(socket, opcode)) {
        return -1;
    }

    /* Force final bit on all control frames. RFC6455 5.4 says that control */
    /* frames themselves MUST NOT be fragmented. Hence, FIN is always set. */
    if (opcode >= HWS_OPCODE_CLOSE) {
        final = 1;
    }

    uint8_t* ptr = socket->receive_header;

    ptr[0]  = 0 != (0 != final) ? HWS_BIT_FIN : 0x00;
    ptr[0] |= (uint8_t)opcode;
    ptr[1]  = HWS_BIT_MASK;

    if (size < 126) {
        ptr[1] |= (uint8_t)size;
        ptr += 2;
    }
    else if (size < 65536) {
        ptr[1] |= 126;
        ptr[2] = (uint8_t)(size >> 8);
        ptr[3] = (uint8_t)(size >> 0);
        ptr += 4;
    }
    else {
        ptr[1] |= 127;

#if UINTPTR_MAX == 0xffffffffffffffff
        assert(size <= 0xffffffff);
#endif
        ptr[2] = 0;
        ptr[3] = 0;
        ptr[4] = 0;
        ptr[5] = 0;
        ptr[6] = (uint8_t)(size >> 24);
        ptr[7] = (uint8_t)(size >> 16);
        ptr[8] = (uint8_t)(size >>  8);
        ptr[9] = (uint8_t)(size >>  0);
        ptr += 10;
    }

    /* Create mask key. */
    ptr[0] = (uint8_t)random();
    ptr[1] = (uint8_t)random();
    ptr[2] = (uint8_t)random();
    ptr[3] = (uint8_t)random();

    /* Mask data in place. */
    hws_mask((uint8_t*)buffer, size, ptr);
    ptr += 4;

    socket->send_header_length = ptr - socket->send_header;
    socket->send_buffer = (uint8_t const*)buffer;
    socket->send_size = size;

    socket->flags |= HWS_SEND_HEADER;
    return hws_event_modify(hws, socket);
}

HWS_VISIBILITY_IMPL char const* hws_socket_get_error_string(
    hws_socket_t* socket)
{
    assert(NULL != socket);
    return socket->error_string;
}

HWS_VISIBILITY_IMPL void hws_socket_set_error_string(hws_socket_t* socket,
    char const* format, ...)
{
    assert(NULL != socket);

    va_list ap;
    va_start(ap, format);
    vsnprintf(socket->error_string, HWS_MAX_ERROR_STRING, format, ap);
    va_end(ap);
}

HWS_VISIBILITY_IMPL void hws_sha1(uint8_t *digest,
    void const *data, size_t size)
{
    assert(NULL != digest);
    assert(NULL != data);

    uint8_t const* ptr = (uint8_t const*)data;
    size_t const iterations = ((size + 8) >> 6) + 1;
    size_t i, j;
    uint32_t words[80], a, b, c, d, e, f, k, t;
    size_t index;
    uint8_t trailer[128] = { 0 };
    uint32_t hash[5] =
        { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

    /* Pad and add data size, all big endian. */
    index = 64 * iterations - size;
    trailer[0] = 0x80;
    trailer[index - 8] = (uint8_t)((size << 3) >> 56 & 0xFF);
    trailer[index - 7] = (uint8_t)((size << 3) >> 48 & 0xFF);
    trailer[index - 6] = (uint8_t)((size << 3) >> 40 & 0xFF);
    trailer[index - 5] = (uint8_t)((size << 3) >> 32 & 0xFF);
    trailer[index - 4] = (uint8_t)((size << 3) >> 24 & 0xFF);
    trailer[index - 3] = (uint8_t)((size << 3) >> 16 & 0xFF);
    trailer[index - 2] = (uint8_t)((size << 3) >> 8 & 0xFF);
    trailer[index - 1] = (uint8_t)((size << 3) >> 0 & 0xFF);

    for (i = 0, index = 0; i < iterations; i++) {
        memset(words, 0, sizeof(words));

        /* Break 512-bit blocks into 16 32-bit, big endian words. */
        for (j = 0; j <= 15; j++) {
            int count = 24;
            while (index < size && count >= 0) {
                words[j] += (((uint32_t)ptr[index]) << count);
                ++index;
                count -= 8;
            }
// TODO investigate.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-overflow"
            /* Fill out W with padding as needed */
            while (count >= 0)
            {
                words[j] += (((uint32_t)trailer[index - size]) << count);
                ++index;
                count -= 8;
            }
#pragma GCC diagnostic pop
        }

        /* Extend 16 32 bit words into 80 32 bit words. */
        for (j = 16; j <= 31; ++j) {
            words[j] = hsha1_rol((words[j -  3]
                                ^ words[j -  8]
                                ^ words[j - 14]
                                ^ words[j - 16]), 1);
        }
        for (j = 32; j <= 79; ++j) {
            words[j] = hsha1_rol((words[j -  6]
                                ^ words[j - 16]
                                ^ words[j - 28]
                                ^ words[j - 32]), 2);
        }

        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];

        for (j = 0; j <= 79; j++) {
            if (j < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5a827999;
            }
            else if (j < 40) {
                assert(j >= 20);
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            }
            else if (j < 60) {
                assert(j >= 40);
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            }
            else {
                assert(j >= 60);
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }
            t = hsha1_rol(a, 5) + f + e + k + words[j];
            e = d;
            d = c;
            c = hsha1_rol(b, 30);
            b = a;
            a = t;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
    }

    for (i = 0; i < 5; ++i) {
        digest[(i << 2) + 0] = (uint8_t)(hash[i] >> 24);
        digest[(i << 2) + 1] = (uint8_t)(hash[i] >> 16);
        digest[(i << 2) + 2] = (uint8_t)(hash[i] >>  8);
        digest[(i << 2) + 3] = (uint8_t)(hash[i] >>  0);
    }
}

HWS_VISIBILITY_IMPL size_t hws_base64_encode_get_length(size_t size)
{
    return ((size + 2) / 3) << 2;
}


HWS_VISIBILITY_IMPL size_t hws_base64_encode(char* base64,
    void const *data, size_t size)
{
    uint8_t const* src = (uint8_t const*)data;
    uint8_t* dst = (uint8_t*)base64;

    while (size >= 3) {
        /* 1st and 2nd chars. */
        dst = hws_base64_encode_start(dst, src);

        /* 3rd char. */
        *dst  = (src[1] & 0x0f) << 2;
        *dst |= (src[2] & 0xc0) >> 6;
        *dst  = hws_base64_encode_table[*dst];
        ++dst;

        /* 4th char. */
        *dst++ = hws_base64_encode_table[src[2] & 0x3f];

        src += 3;
        size -= 3;
    }

    switch (size) {
    case 2:
     {
        /* 1st and 2nd chars + padding. */
         dst   = hws_base64_encode_start(dst, src);
        *dst++ = hws_base64_encode_table[(src[1] & 0x0f) << 2];
        *dst++ = '=';
        break;
     }
    case 1:
        /* 1st and 2nd chars + padding. */
        *dst++ = hws_base64_encode_table[(src[0] & 0xfc) >> 2];
        *dst++ = hws_base64_encode_table[(src[0] & 0x03) << 4];
        *dst++ = '=';
        *dst++ = '=';
        break;

    default:
        break;
    }

    return ((char*)dst) - base64;
}

HWS_VISIBILITY_IMPL size_t hws_base64_decode_get_size(size_t length)
{
    return (3 * (length >> 2)) + 2;
}

HWS_VISIBILITY_IMPL ssize_t hws_base64_decode(void* data,
    char const* base64, size_t length)
{
    uint8_t const* src = (uint8_t const*)base64;
    uint8_t* dst = (uint8_t*)data;

    if (0 == length) {
        return 0;
    }

    while (length >= 5) {
        dst = hws_base64_decode4(dst, src);
        src += 4;
        length -= 4;
    }

    switch (length) {
    case 4:
        if ('=' != src[3]) {
            dst = hws_base64_decode4(dst, src);
        }
        else if ('=' != src[2]) {
            dst = hws_base64_decode3(dst, src);
        }
        else {
            dst = hws_base64_decode2(dst, src);
        }
        break;

    case 3:
        dst = hws_base64_decode3(dst, src);
        break;

    case 2:
        break;

    default:
        assert(0);
        return -1;
    }

    return dst - (uint8_t*)data;
}

HWS_VISIBILITY_IMPL char* hws_generate_sec_websocket_key()
{
    uint8_t data[16];
    char* base64;
    size_t length;

    /* Generate random key. */
    for (size_t i = 0; i < sizeof(data); ++i) {
        data[i] = random();
    }

    /* Get base64 encoded length. */
    length = hws_base64_encode_get_length(sizeof(data));

    /* Allocate buffer for base64 encoded version. */
    base64 = (char*)malloc(length + 1);
    if (NULL == base64) {
        return NULL;
    }

    /* Return base64 encoded, 0 terminated key. */
    length = hws_base64_encode(base64, data, sizeof(data));
    assert(24 == length);
    base64[length] = 0;
    return base64;
}

HWS_VISIBILITY_IMPL char* hws_generate_sec_websocket_accept(
    char const* key, size_t length)
{
    static char const* uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char* base64;

    /* Test length of key string. */
    if (24 != length) {
        return NULL;
    }

    /* Concatenate key and RFC 6455 uuid. */
    char buffer[24 + 36];
    assert(length + strlen(uuid) == sizeof(buffer));
    memcpy(buffer, key, length);
    memcpy(buffer + length, uuid, 36);

    /* SHA1 hash combination. */
    uint32_t hash[5];
    hws_sha1((uint8_t*)hash, buffer, sizeof(buffer));

    /* Get base64 encoded length of hash. */
    length = hws_base64_encode_get_length(sizeof(hash));

    /* Allocate buffer for base64 encoded version. */
    base64 = (char*)malloc(length + 1);
    if (NULL == base64) {
        return NULL;
    }

    /* Return base64 encoded, 0 terminated key. */
    length = hws_base64_encode(base64, hash, sizeof(hash));
    base64[length] = 0;
    return base64;
}

#endif /* HWS_IMPL */

#ifdef HWS_IMPL_TEST

#include "htest.h"

/* https://www.di-mgt.com.au/sha_testvectors.html */
struct hws_test_sha1_vector_s
{
    char const* data;
    char const* digest;
};
static struct hws_test_sha1_vector_s hws_test_sha1_vectors[] =
{
    { "",
        "da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709" },
    { "abc",
        "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1" },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "a49b2446 a02c645b f419f995 b6709125 3a04a259" },
    { NULL, NULL }
};

/* https://www.rfc-editor.org/rfc/rfc4648#page-12 */
struct hws_test_base64_vector_s
{
    char const* data;
    char const* base64;
};
static struct hws_test_base64_vector_s hws_test_base64_vectors[] =
{
    { "",       "" },
    { "f",      "Zg==" },
    { "fo",     "Zm8=" },
    { "foo",    "Zm9v" },
    { "foob",   "Zm9vYg==" },
    { "fooba",  "Zm9vYmE=" },
    { "foobar", "Zm9vYmFy" },
    { NULL, NULL }
};

HTEST_CASE(hws_sha1)
{
    uint8_t digest[20];
    char hex[45];

    for (int i = 0; NULL != hws_test_sha1_vectors[i].data; ++i) {
        hws_sha1(digest, hws_test_sha1_vectors[i].data,
            strlen(hws_test_sha1_vectors[i].data));
        snprintf(hex, sizeof(hex),
            "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
            digest[ 0], digest[ 1], digest[ 2], digest[ 3],
            digest[ 4], digest[ 5], digest[ 6], digest[ 7],
            digest[ 8], digest[ 9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15],
            digest[16], digest[17], digest[18], digest[19]
        );
        HTEST_STRING(hws_test_sha1_vectors[i].digest, ==, hex);
    }
}

HTEST_CASE(hws_base64)
{
    char base64[9];
    uint8_t data[6];
    size_t length;

    for (size_t i = 0; i < 64; ++i) {
        HTEST_INT(hws_base64_decode_char(hws_base64_encode_table[i]), ==, i);
    }

    for (int i = 0; NULL != hws_test_base64_vectors[i].data; ++i) {
        char const* dat = hws_test_base64_vectors[i].data;
        char const* b64 = hws_test_base64_vectors[i].base64;

        HTEST_SIZE(strlen(b64), ==, hws_base64_encode_get_length(strlen(dat)));
        HTEST_SIZE(strlen(dat), <, hws_base64_decode_get_size(strlen(b64)));

        length = hws_base64_encode(base64, dat, strlen(dat));
        HTEST_SIZE(strlen(b64), ==, length);
        HTEST_INT(0, ==, memcmp(b64, base64, length));

        length = hws_base64_decode(data, base64, length);
        HTEST_SIZE(strlen(dat), ==, length);
        HTEST_INT(0, ==, memcmp(dat, data, length));
    }

    char const* sec_websocket_key = "dGhlIHNhbXBsZSBub25jZQ==";
    char* sec_websocket_accept = hws_generate_sec_websocket_accept(
        sec_websocket_key, strlen(sec_websocket_key));
    if (0 != strcmp("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", sec_websocket_accept)) {
        free(sec_websocket_accept);
        HTEST_ERROR("hws_generate_sec_websocket_accept");
    }
    free(sec_websocket_accept);
}

htest_suite_t hws_test_suite =
{
    HTEST_CASE_REF(hws_sha1),
    HTEST_CASE_REF(hws_base64),
    NULL
};

#endif /* HWS_IMPL_TEST */

#ifdef __cplusplus
}
#endif

