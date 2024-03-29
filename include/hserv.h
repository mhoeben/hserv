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
#ifdef __cplusplus
extern "C"
{
#endif

#ifndef HSERV_H
#define HSERV_H

#include <limits.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#ifdef HSERV_HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef HSERV_VISIBILITY_STATIC
#define HSERV_VISIBILITY static
#else
#define HSERV_VISIBILITY extern
#endif

#define HSERV_SOCKOPT_REUSEADDR             0x01
#define HSERV_SOCKOPT_REUSEPORT             0x02

#ifndef HSERV_CONFIG_SOCKOPTS
#define HSERV_CONFIG_SOCKOPTS               0x00
#endif

#ifndef HSERV_CONFIG_SERVER_CLOEXEC
#define HSERV_CONFIG_SERVER_CLOEXEC         1
#endif

#ifndef HSERV_CONFIG_SESSION_CLOEXEC
#define HSERV_CONFIG_SESSION_CLOEXEC        1
#endif

#ifndef HSERV_CONFIG_BINDING_FAMILY
#define HSERV_CONFIG_BINDING_FAMILY         AF_INET
#endif

#ifndef HSERV_CONFIG_BINDING_PORT
#define HSERV_CONFIG_BINDING_PORT           8080
#endif

#ifndef HSERV_CONFIG_BACKLOG
#define HSERV_CONFIG_BACKLOG                8
#endif

#ifndef HSERV_MAX_ERROR_STRING
#define HSERV_MAX_ERROR_STRING              80
#endif

#ifndef HSERV_MAX_DATE_LENGTH
#define HSERV_MAX_DATE_LENGTH               40
#endif

#ifndef HSERV_MAX_VERSION_LENGTH
#define HSERV_MAX_VERSION_LENGTH            9
#endif

#ifndef HSERV_MAX_HEADERS_LENGTH
#define HSERV_MAX_HEADERS_LENGTH            8192
#endif

#ifndef HSERV_SESSION_REQUEST_TIMEOUT
#define HSERV_SESSION_REQUEST_TIMEOUT       30
#endif

#ifndef HSERV_SESSION_RESPONSE_TIMEOUT
#define HSERV_SESSION_RESPONSE_TIMEOUT      30
#endif

#ifndef HSERV_SESSION_KEEP_ALIVE_TIMEOUT
#define HSERV_SESSION_KEEP_ALIVE_TIMEOUT    120
#endif

#ifndef HSERV_SESSION_USER_STORAGE
#define HSERV_SESSION_USER_STORAGE          0
#endif

#ifndef HSERV_HEADER_FIELD_DATE
/* Define HSERV_HEADER_FIELD_DATE to add a Date field to responses. */
#endif

#ifndef HSERV_HEADER_FIELD_SERVER
/* Define HSERV_HEADER_FIELD_SERVER to add a Server field to responses. */
#endif

typedef enum hserv_status_code_e
{
    HSERV_SC_CONTINUE = 100,
    HSERV_SC_SWITCHING_PROTOCOLS = 101,
    HSERV_SC_EARLY_HINTS = 103,

    HSERV_SC_OK = 200,
    HSERV_SC_CREATED = 201,
    HSERV_SC_ACCEPTED = 202,
    HSERV_SC_NON_AUTHORITATIVE_INFORMATION = 203,
    HSERV_SC_NO_CONTENT = 204,
    HSERV_SC_RESET_CONTENT = 205,
    HSERV_SC_PARTIAL_CONTENT = 206,

    HSERV_SC_MULTIPLE_CHOICES = 300,
    HSERV_SC_MOVED_PERMANENTLY = 301,
    HSERV_SC_FOUND = 302,
    HSERV_SC_SEE_OTHER = 303,
    HSERV_SC_NOT_MODIFIED = 304,
    HSERV_SC_TEMPORARY_REDIRECT = 307,
    HSERV_SC_PERMANENT_REDIRECT = 308,

    HSERV_SC_BAD_REQUEST = 400,
    HSERV_SC_UNAUTHORIZED = 401,
    HSERV_SC_PAYMENT_REQUIRED = 402,
    HSERV_SC_FORBIDDEN = 403,
    HSERV_SC_NOT_FOUND = 404,
    HSERV_SC_METHOD_NOT_ALLOWED = 405,
    HSERV_SC_NOT_ACCEPTABLE = 406,
    HSERV_SC_PROXY_AUTHENTICATION_REQUIRED = 407,
    HSERV_SC_REQUEST_TIMEOUT = 408,
    HSERV_SC_CONFLICT = 409,
    HSERV_SC_GONE = 410,
    HSERV_SC_LENGTH_REQUIRED = 411,
    HSERV_SC_PRECONDITION_FAILED = 412,
    HSERV_SC_PAYLOAD_TOO_LARGE = 413,
    HSERV_SC_URI_TOO_LONG = 414,
    HSERV_SC_UNSUPPORTED_MEDIA_TYPE = 415,
    HSERV_SC_RANGE_NOT_SATISFIABLE = 416,
    HSERV_SC_EXPECTATION_FAILED = 417,
    HSERV_SC_IM_A_TEAPOT = 418,
    HSERV_SC_UNPROCESSABLE_ENTITY = 422,
    HSERV_SC_TOO_EARLY = 425,
    HSERV_SC_UPGRADE_REQUIRED = 426,
    HSERV_SC_PRECONDITION_REQUIRED = 428,
    HSERV_SC_TOO_MANY_REQUESTS = 429,
    HSERV_SC_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    HSERV_SC_UNAVAILABLE_FOR_LEGAL_REASONS = 451,

    HSERV_SC_INTERNAL_SERVER_ERROR = 500,
    HSERV_SC_NOT_IMPLEMENTED = 501,
    HSERV_SC_BAD_GATEWAY = 502,
    HSERV_SC_SERVICE_UNAVAILABLE = 503,
    HSERV_SC_GATEWAY_TIMEOUT = 504,
    HSERV_SC_HTTP_VERSION_NOT_SUPPORTED = 505,
    HSERV_SC_VARIANT_ALSO_NEGOTIATES = 506,
    HSERV_SC_INSUFFICIENT_STORAGE = 507,
    HSERV_SC_LOOP_DETECTED = 508,
    HSERV_SC_NOT_EXTENDED = 510,
    HSERV_SC_NETWORK_AUTHENTICATION_REQUIRED = 511
} hserv_status_code_t;

typedef struct hserv_s hserv_t;

#define HSERV_CHUNKED   SSIZE_MAX

typedef struct hserv_session_s hserv_session_t;

typedef int(*hserv_event_callback_t)(
    hserv_t* hserv, struct epoll_event* event);

typedef int (*hserv_accept_callback_t)(
    hserv_t* hserv, hserv_session_t* session);

typedef int(*hserv_transaction_start_callback_t)(
    hserv_t* hserv, hserv_session_t* session);

typedef int(*hserv_request_content_callback_t)(hserv_t* hserv,
    hserv_session_t* session, void* buffer, size_t size, size_t more);

typedef int(*hserv_response_content_callback_t)(hserv_t* hserv,
    hserv_session_t* session, void const* buffer, size_t size, size_t more);

typedef void(*hserv_transaction_end_callback_t)(
    hserv_t* hserv, hserv_session_t* session, int failed);

typedef int(*hserv_session_interrupt_callback_t)(
    hserv_t* hserv, hserv_session_t* session);

typedef struct hserv_config_s
{
    uint32_t                    sockopts;
    struct sockaddr             binding __attribute__ ((aligned (4)));
    int                         backlog;
    hserv_accept_callback_t     accept_callback;
    hserv_transaction_start_callback_t  transaction_start_callback;
    hserv_transaction_end_callback_t    transaction_end_callback;
#ifdef HSERV_HAVE_OPENSSL
    char const*                 certificate_file;
    char const*                 private_key_file;
#endif
    void*                       user_data;

    char                        error_string[HSERV_MAX_ERROR_STRING];
} hserv_config_t;

typedef struct hserv_event_s
{
    int fd;
    hserv_event_callback_t callback;
    void* user_data;
} hserv_event_t;

/*
 * Initializes an hserv config structure with defaults and the transaction
 * start and end callbacks.
 */
HSERV_VISIBILITY void hserv_init(hserv_config_t* config,
    hserv_transaction_start_callback_t transaction_start_callback,
    hserv_transaction_end_callback_t transaction_end_callback);

/*
 * Initializes the config's binding structure with a IPv4 port and address.
 */
HSERV_VISIBILITY int hserv_init_binding_ipv4(hserv_config_t* config,
    uint16_t port, char const* address);

/*
 * Creates an hserv instance with given config. Returns a ready to poll hserv
 * instance upon success and NULL upon failure.
 */
HSERV_VISIBILITY hserv_t* hserv_create(hserv_config_t* config);

/*
 * Destroys an hserv instance, releasing all its resources. Pending sessions
 * are destroyed.
 *
 * Note that the server shall not be running. Use hserv_stop() to stop a
 * running instance.
 */
HSERV_VISIBILITY void hserv_destroy(hserv_t* hserv);

/*
 * Gets hserv's epoll facilities` file descriptor.
 */
HSERV_VISIBILITY int hserv_get_fd(hserv_t* hserv);

#ifdef HSERV_HAVE_OPENSSL
/*
 * Gets the SSL context for user configuration.
 */
HSERV_VISIBILITY SSL_CTX* hserv_get_ssl_context(hserv_t* hserv);
#endif

/*
 * Gets the hserv instance's error string.
 */
HSERV_VISIBILITY char const* hserv_get_error_string(hserv_t* hserv);

/*
 * Adds file-descriptor event to hserv's epoll facility.
 */
HSERV_VISIBILITY int hserv_event_add(hserv_t* hserv,
    hserv_event_t* event, uint32_t events);

/*
 * Modifies file-descriptor's events.
 */
HSERV_VISIBILITY int hserv_event_modify(hserv_t* hserv,
    hserv_event_t* event, uint32_t events);

/*
 * Removes a file-descriptor event from hserv's epoll facility.
 */
HSERV_VISIBILITY void hserv_event_remove(hserv_t* hserv,
    hserv_event_t const* event);

/*
 * Gets the hserv instance's user data.
 */
HSERV_VISIBILITY void* hserv_get_user_data(hserv_t* hserv);

/*
 * Starts the hserv instance. A running instance only returns on an instance
 * error, or when stopped by a call to hserv_stop().
 *
 * Returns 0 for success, -1 on failure.
 *
 * See hserv_poll() and hserv_session_interrupt() for information on
 * thread-safety.
 */
HSERV_VISIBILITY int hserv_start(hserv_t* hserv);

/*
 * Stops a running hserv instance.
 */
HSERV_VISIBILITY int hserv_stop(hserv_t* hserv);

/*
 * Polls an hserv instance.
 *
 * This can be used to integrate the instance in a user's main loop.
 *
 * Returns 1 when an event was handled, 0 when no event was handled and
 * -1 on failure.
 *
 * Hserv is not thread-safe. Hserv's functions shall only be called from
 * hserv callbacks or when it is guaranteed that no other thread is currently
 * in one of hserv's functions. The only exception is hserv_session_interrupt().
 * This function may be called from any thread context at any time.
 */
HSERV_VISIBILITY int hserv_poll(hserv_t* hserv);

/*
 * Get a reason string for given status code.
 */
HSERV_VISIBILITY char const* hserv_get_reason_string(
    hserv_status_code_t status_code);

/*
 * Parses HTTP header fields. The header string shall not include a start-line
 * and shall include the terminating \r\n. An example of such a string is
 *
 * Date: Sat Nov 13 13:11:00 CET 1971\r\n
 * Server: hserv-1.0\r\n
 * \r\n
 *
 * The function modifies the buffer by zero terminating the header's field
 * names and values. The resulting modified buffer can be passed to
 * hserv_header_iterate() and hserv_header_find() to iterate or find
 * header.
 *
 * Returns the number of fields, or -1 when the fields are invalid.
 */
HSERV_VISIBILITY int hserv_header_fields_parse(char* fields, size_t length);

/*
 * Iterates an HTTP header string. The it value shall be initially called
 * with a pointer to a buffer containing parsed HTTP header. Parsed HTTP
 * header can be obtained by calling hserv_request_get_header_fields() on a
 * request or by parsing a user buffer using hserv_header_parse(). Upon return
 * name and value point to the iterated header's field name and value. Call
 * hserv_header_iterate() with the result of the previous call until the
 * function returns NULL to iterate through all fields.
 *
 * Returns an iterator to the next field or NULL if no more fields are
 * available.
 */
HSERV_VISIBILITY char const* hserv_header_fields_iterate(
    char const* it, char const** name, char const** value);

/*
 * Iterate HTTP header with given field name. The iteration process is the
 * same as for hserv_header_iterate(), but the function only returns those
 * fields that case insensitively match the name argument.
 *
 * Returns an iterator to the next field or NULL if no more fields are
 * available.
 */
HSERV_VISIBILITY char const* hserv_header_field_find(
    char const* it, char const *name, char const** value);

/*
 * Tests whether the field value contains the given value, potentially separated
 * from other values by given delim.
 */
HSERV_VISIBILITY int hserv_header_field_value_contains(
    char const* field_value, char const *value, char const* delim);

/*
 * Iterates the HTTP header fields to find a field with given name and
 * that contains the given value, either as the field's value or in a list
 * separated by delim.
 */
HSERV_VISIBILITY int hserv_header_field_contains(
    const char* it, char const* name, char const* value, char const* delim);

/*
 * Copies parsed header to the provided buffer. The iterator argument is
 * a pointed to a buffer containing parsed HTTP header. The function copies
 * the available fields to the provided buffer in such a way that the
 * new buffer can also be iterated.
 *
 * This may be useful to copy request header so they can be iterated after
 * they are invalidated by the response header.
 *
 * Returns the number of bytes in the buffer or -1 if the buffer was not large
 * enough.
 */
HSERV_VISIBILITY ssize_t hserv_header_fields_copy(
    char const* it, char* buffer, size_t size);

/*
 * Returns the request's method.
 *
 * Note that the request's method is only valid for the duration of the
 * request callback.
 */
HSERV_VISIBILITY char const* hserv_request_get_method(
    hserv_session_t const* session);

/*
 * Returns the request's target.
 *
 * Note that the request's target is only valid for the duration of the
 * request callback.
 */
HSERV_VISIBILITY char const* hserv_request_get_target(
    hserv_session_t const* session);

/*
 * Return's the request's version, e.g. HTTP/1.1.
 *
 * Note that the request's version is only valid for the duration of the
 * request callback.
 */
HSERV_VISIBILITY char const* hserv_request_get_version(
    hserv_session_t const* session);

/*
 * Return's an iterator the request's header fields.
 *
 * Note that the request's header is only valid for the duration of the
 * request. Calling hserv_respond() invalidates the request header. Calling
 * this function during the response yields NULL. Copy the header using
 * hserv_header_fields_copy() if the request's header need to be available
 * after a response is generated.
 *
 * Returns an header iterator to be used with hserv_header_fields_iterate(),
 * hserv_header_field_find(), hserv_header_field_contains()
 * or hserv_header_fields_copy().
 */
HSERV_VISIBILITY char const* hserv_request_get_header_fields(
    hserv_session_t const* session);

/*
 * Return's the request's content-length. If the returned value equals
 * HSERV_CHUNKED, the request uses chunked transfer-encoding.
 */
HSERV_VISIBILITY size_t hserv_request_get_content_length(
    hserv_session_t const* session);

/*
 * Instructs hserv to receive content to the provided buffer of given capacity.
 * The provided callback is called when either the buffer has reached
 * capacity or the request's content is fully read. The more argument of the
 * callback can be used to detect the latter.
 *
 * This function shall be called when the user is ready to receive content.
 * This may be from the start-request callback or any time later.
 *
 * The buffer shall remain available until the callback is called.
 *
 * New calls to hserv_request_receive() must be made from either the callback or
 * any user context until all content has been received. hserv_request_receive()
 * shall not be called when another read is pending.
 *
 * The request may time out if hserv_request_receive() is not called within
 * HSERV_SESSION_REQUEST_TIMEOUT seconds. Calling hserv_request_receive() resets
 * this timeout.
 *
 * Note that in the case of chunked transfer-encoding, the amount of data
 * received has no relation to the chunks. The buffer is filled until
 * capacity and may contain several whole chunks or parts of chunks, etc...
 *
 * Returns 0 on success, -1 on failure.
 */
HSERV_VISIBILITY int hserv_request_receive(hserv_t* hserv,
    hserv_session_t* session, void* buffer, size_t capacity,
    hserv_request_content_callback_t callback);

/*
 * Reponds to the passed request with given status code, reason and fields.
 * If reason is NULL, hserv picks the status code related reason from a table.
 * The fields array shall be a NULL terminated array of name and value pairs.
 *
 * Hserv automatically generates for each response the following fields:
 *
 * - Date
 * - Server
 * - Content-Length (content dependent)
 * - Transfer-Encoding (content dependent)
 * - Connection (optional)
 *
 * With the exception of the Connection field, these fields shall not be used
 * in the user fields. Hserv may override the Connection field if necessary.
 * Other user fields may be added as desired.
 *
 * The user shall specify the response's content-length. If the
 * content_length argument equals HSERV_CHUNKED, hserv will use chunked
 * transfer encoding.
 *
 * If the content_length argument is not 0, the user shall either provide the
 * content as a pointer to a buffer of specified size by means of the content
 * argument, or the user shall use the hserv_response_send() function to
 * progressively write the content.
 *
 * If the content_length argument equals 0, the content argument is ignored
 * and the user shall not call hserv_response_send().
 *
 * After all content is transmitted (if any), hserv will call the
 * request-end callback.
 *
 * Returns 0 on success, -1 on failure.
 */
HSERV_VISIBILITY int hserv_respond(hserv_t* hserv,
    hserv_session_t* session, hserv_status_code_t status_code,
    char const* reason, char const* const fields[],
    size_t content_length, void const* content);

/*
 * Instruct hserv to send the data in the provided buffer of given size
 * as the response's content, up to the content-length specified by
 * the hserv_respond() function. If the buffer is exhausted before the
 * specified amount of content is sent, the callback is called with the more
 * argument set to the amount that still needs to be sent. The user shall take
 * care to not provide more data than specified in the content_length argument
 * of hserv_respond(). If a content-length amount of data has been sent,
 * the callback is called with the more argument set to 0.
 *
 * This function shall be called when the user is ready to send content.
 * This may be right after hserv_respond() is called or any later moment.
 *
 * The buffer shall remain available until the callback is called.
 *
 * New calls to hserv_response_send() must be made from either the callback or
 * any user context until all content has been sent. hserv_response_send()
 * shall not be called when another send is pending.
 *
 * The response may time out if hserv_response_send() is not called within
 * HSERV_SESSION_RESPONSE_TIMEOUT seconds. Calling hserv_response_send() resets
 * this timeout.
 *
 * Note that in the case of chunked transfer-encoding, the buffers are sent
 * as chunks. Send buffer == NULL and size == 0 to terminate sending chunks.
 */
HSERV_VISIBILITY int hserv_response_send(hserv_t* hserv,
    hserv_session_t* session, void const* buffer, size_t size,
    hserv_response_content_callback_t callback);

#ifdef HSERV_HAVE_OPENSSL
/*
 * Gets the session's SSL structure.
 */
HSERV_VISIBILITY SSL* hserv_session_get_ssl(hserv_session_t const* session);

/*
 * Sets the session's SSL structure.
 *
 * This function shall be called from the accept callback to override the
 * SSL connection structure with a fully initialized custom structure. The
 * session adopts ownership without increasing the reference count.
 */
HSERV_VISIBILITY int hserv_session_set_ssl(hserv_session_t* session, SSL* ssl);
#endif

/*
 * Gets the session's peer socket address.
 */
HSERV_VISIBILITY int hserv_session_get_peer(
    hserv_session_t* session, struct sockaddr *peer_addr, socklen_t* length);

/*
 * Sets the session's interrupt callback.
 *
 * See hserv_session_interrupt() for a discussion how the interrupt facility
 * is used.
 */
HSERV_VISIBILITY void hserv_session_set_interrupt_callback(
    hserv_session_t* session, hserv_session_interrupt_callback_t callback);

/*
 * Instructs the session to callback from the session's thread context.
 *
 * Hserv is not thread-safe. Hserv's functions shall only be called from
 * hserv callbacks or when it is guaranteed that no other thread is currently
 * in one of hserv's functions. The only exception is hserv_session_interrupt().
 * This function may be called from any thread context at any time. This can
 * be used to restart content streaming from any thread. Upon calling
 * hserv_session_interrupt() from another thread, hserv calls back the
 * session's configured interrupt callback at the earliest possible time.
 */
HSERV_VISIBILITY int hserv_session_interrupt(hserv_session_t* session);

/*
 * Gets the session's error string.
 */
HSERV_VISIBILITY char const* hserv_session_get_error_string(
    hserv_session_t* session);

/*
 * Sets the session's error string.
 */
HSERV_VISIBILITY void hserv_session_set_error_string(
    hserv_session_t* session, char const* format, ...);

/*
 * Sets the sessions's user data.
 *
 * When hserv is compiled with HSERV_SESSION_USER_STORAGE > 0, the session's
 * user pointer is pre-initialized with a pointer to a buffer of the configured
 * size. If user storage is configured, passing NULL restores the pointer
 * to this buffer.
 */
HSERV_VISIBILITY void hserv_session_set_user_data(
    hserv_session_t* session, void* user_data);

/*
 * Gets the session's user data.
 *
 * When hserv is compiled with HSERV_SESSION_USER_STORAGE > 0, the session's
 * user pointer is pre-initialized with a pointer to a buffer of the configured
 * size.
 *
 * Returns a pointer to the configured user data or user storage buffer.
 */
HSERV_VISIBILITY void* hserv_session_get_user_data(
    hserv_session_t const* session);

/*
 * Used to remove the session after it upgraded. The function removes the
 * session from the server, frees its state and returns the socket's
 * file descriptor. The associated SSL structure may be obtained by calling
 * hserv_session_get_ssl() prior to calling hserv_session_upgraded().
 *
 * After the upgrade the file descriptor (and SSL structure) are the
 * responsibility of the user.
 */
HSERV_VISIBILITY int hserv_session_upgraded(
    hserv_t* hserv, hserv_session_t* session);

#endif /* HSERV_H */

#ifdef HSERV_IMPL

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HSERV_VISIBILITY_STATIC
#define HSERV_VISIBILITY_IMPL static
#else
#define HSERV_VISIBILITY_IMPL
#endif

/*
 * Implementation
 */
typedef struct hserv_list_s
{
    struct hserv_list_s* next;
    struct hserv_list_s* prev;
} hserv_list_t;

typedef struct hserv_list_s hserv_list_element_t;
typedef struct hserv_list_s hserv_list_iterator_t;

static void hserv_list_init(hserv_list_t* list)
{
    list->next = list;
    list->prev = list;
}

static hserv_list_iterator_t* hserv_list_begin(hserv_list_t* list)
{
    return list->next;
}

static hserv_list_iterator_t* hserv_list_end(hserv_list_t* list)
{
    return list;
}

static void hserv_list_insert(hserv_list_iterator_t* before,
    hserv_list_element_t* element)
{
    element->next = before;
    element->prev = before->prev;

    before->prev->next = element;
    before->prev = element;
}

static void hserv_list_erase(hserv_list_iterator_t* it)
{
    it->prev->next = it->next;
    it->next->prev = it->prev;

    it->prev = it;
    it->next = it;
}

static inline void hserv_list_push_back(
    hserv_list_t* list, hserv_list_element_t* element)
{
    hserv_list_insert(hserv_list_end(list), element);
}

#define HSERV_MAX(a, b) ((a) > (b) ? (a) : (b))

struct hserv_session_s
{
    hserv_list_element_t element;

    int timeout;

    char const* request_method;
    char const* request_target;
    char request_version[HSERV_MAX_VERSION_LENGTH];
    char const* request_fields;
    size_t content_length;

    hserv_event_t interrupt;
    hserv_session_interrupt_callback_t interrupt_callback;

    hserv_request_content_callback_t request_content_callback;
    hserv_response_content_callback_t response_content_callback;

    struct sockaddr peer;
    hserv_event_t socket;
#ifdef HSERV_HAVE_OPENSSL
    SSL* ssl;
#endif

#define HSERV_FLAGS_CHUNK_FIRST     0x01
#define HSERV_FLAGS_CHUNK_LAST      0x02
#define HSERV_FLAGS_CHUNK_MASK      0x03
#define HSERV_FLAGS_HEAD_REQUEST    0x04

    int8_t flags;
    int8_t responding;
    int8_t close;
    int8_t callback_request_end;

    size_t progress;

    char header_buffer[HSERV_MAX_HEADERS_LENGTH];
    size_t header_length;

    size_t buffer_capacity;
    size_t buffer_size;
    char* buffer;

    char error_string[HSERV_MAX(HSERV_MAX_ERROR_STRING, 1)];

    void* user_data;
#if HSERV_SESSION_USER_STORAGE > 0
    char user_storage[HSERV_SESSION_USER_STORAGE];
#endif
};

static int hserv_request_on_header(hserv_t* hserv,
    struct epoll_event* epoll_event);
static int hserv_request_on_content_length(hserv_t* hserv,
    struct epoll_event* epoll_event);
static int hserv_request_on_chunked_header(hserv_t* hserv,
    struct epoll_event* epoll_event);
static int hserv_request_on_chunked(hserv_t* hserv,
    struct epoll_event* epoll_event);
static int hserv_request_on_chunked_trailer(hserv_t* hserv,
    struct epoll_event* epoll_event);

static int hserv_response_on_header(hserv_t* hserv,
    struct epoll_event* epoll_event);
static int hserv_response_on_content_length(hserv_t* hserv,
    struct epoll_event* epoll_event);
static int hserv_response_on_chunked_header_trailer(hserv_t* hserv,
    struct epoll_event* epoll_event);
static int hserv_response_on_chunked(hserv_t* hserv,
    struct epoll_event* epoll_event);

static void hserv_session_destroy(hserv_t* hserv, hserv_session_t* session);

struct hserv_s
{
    hserv_config_t config;

    int stop;
    int epoll_fd;
    hserv_event_t server;
    hserv_event_t timer;

#ifdef HSERV_HAVE_OPENSSL
    SSL_CTX* ssl_context;
#endif

    char date[HSERV_MAX_DATE_LENGTH];

    hserv_list_t sessions;

    char error_string[HSERV_MAX(HSERV_MAX_ERROR_STRING, 1)];

    void* user_data;
};

static const char* hserv_reasons[] =
{
    "Continue", "Switching Protocols", "", "Early Hints", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",

    "OK", "Created", "Accepted", "Non Authorative Information", "No Content", "Reset Content", "Partial Content", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",

    "Multiple Choices", "Moved Permanantly", "Found", "See Other", "Not Modified", "", "", "Temporary Redirect", "Permanent Redirect", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",

    "Bad Request", "Unauthorized", "Payment Required", "Forbidden", "Not Found", "Method Not Allowed", "Not Acceptable", "Proxy Authentication Required", "Request Timeout", "Conflict",
    "Gone", "Length Required", "Precondition Failed", "Payload Too Large", "URI Too Long", "Unsupported Media Type", "Range Not Satisfiable", "Expectation Failed", "I'm a teapot", "",
    "", "", "Unprocessable Entity", "", "", "Too Early", "Upgrade Required", "", "Precondition Required", "Too Many Requests",
    "", "Request Header Fields Too Large", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "Unavailable For Legal Reasons", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",

    "Internal Server Error", "Not Implemented", "Bad Gateway", "Service Unavailable", "Gateway Timeout", "HTTP Version Not Supported", "Variant Also Negotiates", "Insufficient Storage", "Loop Detected", "",
    "Not Extended", "Network Authentication Required", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", ""
};

#if (HSERV_MAX_ERROR_STRING > 0)

static char const* hserv_strerror(char* error_string)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"

#if (_POSIX_C_SOURCE >= 200112L) && ! _GNU_SOURCE
    if (0 != strerror_r(errno, error_string, HSERV_MAX_ERROR_STRING)) {
#else
    if (NULL == strerror_r(errno, error_string, HSERV_MAX_ERROR_STRING)) {
#endif
        snprintf(error_string, HSERV_MAX_ERROR_STRING, "%d", errno);
    }
    return error_string;
#pragma GCC diagnostic pop
}

static char const* hserv_set_error_string(char* error_string, char const* string)
{
    char errno_string[HSERV_MAX_ERROR_STRING];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    /* Concat formatted string with parenthesized errno string. */ 
    snprintf(error_string, HSERV_MAX_ERROR_STRING,
        "%s (%s)", string, hserv_strerror(errno_string));
#pragma GCC diagnostic pop

    return error_string;
}

#else

static char const* hserv_set_error_string(char* error_string, char const* string)
{
    (void)error_string;
    (void)string;
    return "";
}

#endif // (0 != HSERV_MAX_ERROR_STRING)

static int hserv_session_event_modify(
    hserv_t* hserv, hserv_session_t* session, uint32_t events)
{
    struct epoll_event epoll_event;
    epoll_event.events = events;
    epoll_event.data.ptr = &session->socket;

    if (-1 == epoll_ctl(hserv->epoll_fd,
            EPOLL_CTL_MOD, session->socket.fd, &epoll_event)) {
        hserv_set_error_string(session->error_string,
            "epoll_ctl(...EPOLLCTL_MOD...) failed");
        return -1;
    }

    return 0;
}

#ifdef HSERV_HAVE_OPENSSL
static int hserv_session_event_modify_ssl(
    hserv_t* hserv, hserv_session_t* session, int result)
{
    struct epoll_event epoll_event;

    result = SSL_get_error(session->ssl, result);
    switch (result) {
    case SSL_ERROR_WANT_READ:   epoll_event.events = EPOLLIN|EPOLLRDHUP; break;
    case SSL_ERROR_WANT_WRITE:  epoll_event.events = EPOLLOUT|EPOLLRDHUP; break;
    case SSL_ERROR_ZERO_RETURN: return -2;
    default:
        // TODO get SSL's error info.
        hserv_set_error_string(session->error_string, "An SSL error occurred");
        return -1;
    }
    epoll_event.data.ptr = &session->socket;

    if (-1 == epoll_ctl(hserv->epoll_fd,
            EPOLL_CTL_MOD, session->socket.fd, &epoll_event)) {
        hserv_set_error_string(session->error_string,
            "epoll_ctl(...EPOLL_CTL_MOD...) failed");
        return -1;
    }

    return 0;
}
#endif

static void* hserv_event_user_data(struct epoll_event* epoll_event)
{
    return ((hserv_event_t*)epoll_event->data.ptr)->user_data;
}

static int hserv_set_nonblock(int fd, char* error_string)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))
     || -1 == fcntl(fd, F_SETFL, flags|O_NONBLOCK)) {
        hserv_set_error_string(error_string, "fcntl(...O_NONBLOCK...) failed");
        return -1;
    }

    return 0;
}

static ssize_t hserv_socket_recv(hserv_t* hserv, hserv_session_t* session,
    void* buffer, size_t size, int flags)
{
    /* Returns the number of bytes that can be read, which may be 0 in case */
    /* SSL wants to renegotiate. Errors are returned signalled as -1, while */
    /* socket closure is signalled as -2. */
    ssize_t r;

#ifdef HSERV_HAVE_OPENSSL
    if (NULL != session->ssl) {
        size_t bytes;

        if (MSG_PEEK == flags) {
            r = SSL_peek_ex(session->ssl, buffer, size, &bytes);
        }
        else {
            r = SSL_read_ex(session->ssl, buffer, size, &bytes);
        }
        if (r <= 0) {
            /* Returns 0 for success, -1 for failure, -2 for closure. */
            return hserv_session_event_modify_ssl(hserv, session, r);
        }

        return bytes;
    }
#else
    (void)hserv;
#endif
    r = recv(session->socket.fd, buffer, size, flags);
    switch (r) {
    case -1:
        hserv_set_error_string(session->error_string, "recv() failed");
        return -1;  /* An error occurred. */
    case 0:
        return -2;  /* Socket closed. (See comment on SSL why -2.) */
    default:
        return r;
    }
}

static ssize_t hserv_socket_send(hserv_t* hserv, hserv_session_t* session,
    void const* buffer, size_t size)
{
    ssize_t r;

#ifdef HSERV_HAVE_OPENSSL
    if (NULL != session->ssl) {
        size_t bytes;
        r = SSL_write_ex(session->ssl, buffer, size, &bytes);
        if (r <= 0) {
            r = hserv_session_event_modify_ssl(hserv, session, r);
            if (r < 0) {
                // TODO get SSL's error info.
                hserv_session_set_error_string(session,
                    "SSL_write_ex() failed");
                return -1;
            }

            return 0;
        }

        return bytes;
    }
#else
    (void)hserv;
#endif
    r = send(session->socket.fd, buffer, size, 0);
    if (-1 == r) {
        hserv_set_error_string(session->error_string, "send() failed");
        return -1;
    }

    return r;
}

static int hserv_timer_create(
    hserv_t* hserv, hserv_event_t* event, char *error_string)
{
    /* Create timer. */
    event->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (-1 == event->fd) {
        hserv_set_error_string(error_string, "timerfd_create() failed");
        goto error;
    }

    /* Add to epoll facility. */
    if (-1 == hserv_event_add(hserv, event, EPOLLIN)) {
        goto error;
    }
    return 0;

error:
    hserv_event_remove(hserv, event);
    return -1;
}

static int hserv_timer_set(hserv_event_t const* event,
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
        hserv_set_error_string(error_string, "timerfd_settime failed");
        return -1;
    }

    return 0;
}

static int64_t hserv_timer_read(hserv_event_t const* event)
{
    uint64_t expired;
    ssize_t bytes = read(event->fd, &expired, sizeof(expired));
    return bytes == sizeof(expired) ? (int64_t)expired : (int64_t)-1;
}

static int hserv_session_on_interrupt(hserv_t* hserv, struct epoll_event* event)
{
    assert(event->events & EPOLLIN);
    hserv_session_t* session = (hserv_session_t*)hserv_event_user_data(event);

    /* Read timer interrupt. */
    (void)hserv_timer_read(&session->interrupt);

    /* Callback set? */
    if (NULL == session->interrupt_callback) {
        return 0;
    }

    /* Callback. */
    return session->interrupt_callback(hserv, session);
}

static char* hserv_header_parse_start_line(
    char* ptr, char* end, char const* tokens[3])
{
    char* start = ptr;

    /* Find end of header and 0-terminate. */
    ptr = (char*)memchr(ptr, '\r', end - ptr);
    *ptr = 0;

    /* Check \n follows \r. */
    if (ptr + 1 >= end || ptr[1] != '\n') {
        return NULL;
    }

    /* Store pointer to start of header. */
    char* hdr = ptr + 2;

    /* Tokenize first token. */
    tokens[0] = strtok_r(start, " \t", &ptr);
    if (NULL == tokens[0]) {
        return NULL;
    }

    /* Tokenize second token. */
    tokens[1] = strtok_r(ptr, " \t", &ptr);
    if (NULL == tokens[1]) {
        return NULL;
    }

    /* Tokenize third token. */
    tokens[2] = ptr + strspn(ptr, " \t");
    return hdr;
}

static void hserv_header_format_status_line(hserv_session_t* session,
    char const* version, hserv_status_code_t status_code, char const* reason)
{
    if (NULL == reason) {
        assert(((int)status_code) >= 100 && ((int)status_code) < 599);
        reason = hserv_reasons[status_code - 100];
    }

    int length = sprintf(session->header_buffer, "%s %d %s\r\n",
        version, status_code, reason);
    assert(length > 0);

    session->header_length = length;
}

static int hserv_header_field_append(hserv_session_t* session,
    char const* name, char const* value)
{
    /* Determine length of "field-name: field-value\r\n". */
    ssize_t length = strlen(name) + 2 + strlen(value) + 2;

    /* Check it fits in the remaining space in the session's header buffer. */
    if (session->header_length + length
            > sizeof(session->header_buffer) - 2) {
        return -1;
    }

    /* Append by formatting. */
    length = sprintf(session->header_buffer + session->header_length,
        "%s: %s\r\n", name, value);
    if (length < 0) {
        hserv_session_set_error_string(session,
            "Failed to append header field");
        return -1;
    }

    session->header_length += length;
    return 0;
}

static char* hserv_header_value_trim(char* value)
{
    char* end = value + strlen(value);

    while ((' ' == *value || '\t' == *value) && end != value) {
        ++value;
    }
    while ((' ' == *end || '\t' == *end) && end > value) {
        --value;
    }

    *end = 0;
    return value;
}

static int hserv_header_fields_terminate(hserv_session_t* session)
{
    /* Check \r\n fits in the remaining space in the session's */
    /* headers buffer. */
    if (session->header_length + 2 > sizeof(session->header_buffer)) {
        hserv_session_set_error_string(session,
            "Failed to terminate header fields");
        return -1;
    }

    /* Append \r\n. */
    session->header_buffer[session->header_length + 0] = '\r';
    session->header_buffer[session->header_length + 1] = '\n';
    session->header_length += 2;
    return 0;
}

static int hserv_request_content_callback(hserv_t* hserv,
    hserv_session_t* session, void* buffer, size_t buffer_size, size_t more)
{
    hserv_request_content_callback_t callback =
        session->request_content_callback;

    /* Reset receive process. */
    session->request_content_callback = NULL;
    session->buffer_capacity = 0;
    session->buffer_size = 0;
    session->buffer = NULL;

    /* Callback with content received so far. */
    return callback(hserv, session, buffer, buffer_size, more);
}

static int hserv_response_content_callback(hserv_t* hserv, hserv_session_t* session,
    void const* buffer, size_t buffer_size, size_t more)
{
    hserv_response_content_callback_t callback =
        session->response_content_callback;

    /* Reset send process. */
    session->response_content_callback = NULL;
    session->buffer_size = 0;
    session->buffer = NULL;

    /* Callback with content send so far. */
    return NULL != callback
        ? callback(hserv, session, buffer, buffer_size, more)
        : 0;
}

static int hserv_session_next_request(hserv_t* hserv, hserv_session_t* session)
{
    /* Callback end of request. */
    if (session->callback_request_end) {
        hserv->config.transaction_end_callback(hserv, session, 0);
        /* Prevent calling it again from hserv_session_destroy(). */
        session->callback_request_end = 0;
    }

    /* Close session? */
    if (!!session->close) {
        hserv_session_destroy(hserv, session);
        return 0;
    }

    /* Reset timeout. */
    session->timeout = HSERV_SESSION_KEEP_ALIVE_TIMEOUT;

    /* Setup session structure to receive next request. */
    session->request_method = NULL;
    session->request_target = NULL;
    session->request_version[0] = 0;
    session->request_fields = NULL;

    session->request_content_callback = NULL;
    session->response_content_callback = NULL;

    session->socket.callback = hserv_request_on_header;

    session->flags = HSERV_FLAGS_CHUNK_FIRST;
    session->close = 0;
    session->callback_request_end = 0;
    session->responding = 0;

    session->progress = 0;
    session->header_length = 0;
    session->buffer_capacity = 0;
    session->buffer_size = 0;
    session->buffer = NULL;

    if (-1 == hserv_session_event_modify(hserv, session, EPOLLIN|EPOLLRDHUP)) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    return 0;
}

static int hserv_respond_error(hserv_t* hserv, hserv_session_t* session,
    hserv_status_code_t status_code, int close)
{
    assert(NULL != session);
    session->close |= !!close;
    return hserv_respond(hserv, session, status_code, NULL, NULL, 0, NULL);
}

static int hserv_request_receive_headers(hserv_t* hserv,
    struct epoll_event* epoll_event, size_t sentinel, char** end)
{
    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Destroy session if the socket is in error state (EPOLLERR|EPOLLHUP) */
    /* or the  peer closed the socket (EPOLLRDHUP). There is no use in */
    /* receiving a request when the response cannot be sent. */
    /* Cleanup session if peer closed the socket. */
    if (0 != ((EPOLLERR|EPOLLHUP|EPOLLRDHUP) & epoll_event->events)) {
        hserv_session_destroy(hserv, session);
        return 0;
    }

    ssize_t remaining =
        sizeof(session->header_buffer) - session->header_length;

    /* Check headers are not exceeding available space. */
    if (remaining <= 0) {
        hserv_respond_error(hserv, session,
            HSERV_SC_REQUEST_HEADER_FIELDS_TOO_LARGE, 1);
        return 0;
    }

    /* Reset timeout. */
    session->timeout = HSERV_SESSION_REQUEST_TIMEOUT;

    /* Peek at header bytes. */
    ssize_t bytes = hserv_socket_recv(hserv, session,
        session->header_buffer + session->header_length, remaining, MSG_PEEK);
    if (bytes < 0) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    int complete = 0;

    /* Look for header terminator \r\n[\r\n] by progressive looking for */
    /* \r and then looking for \n]\r\n] if enough data is in the buffer. */
    char* ptr = &session->header_buffer[session->progress];
         *end = &session->header_buffer[session->header_length + bytes];
    if (4 == sentinel) {
        while (ptr < *end - 3) {
            if ('\r' == ptr[0] && '\n' == ptr[1]
             && '\r' == ptr[2] && '\n' == ptr[3]) {
                *end = ptr + 4;
                complete = 1;
                break;
            }

            ++ptr;
        }
    }
    else {
        assert(2 == sentinel);
        while (ptr < *end - 1) {
            if ('\r' == ptr[0] && '\n' == ptr[1]) {
                *end = ptr + 2;
                complete = 1;
                break;
            }

            ++ptr;
        }
    }

    /* Calculate remaining bytes of header. */
    remaining = *end - (session->header_buffer + session->header_length);

    /* Receive remainder. */
    bytes = hserv_socket_recv(hserv, session,
        session->header_buffer + session->header_length, remaining, 0);
    if (bytes < remaining) {
        if (bytes < 0) {
            hserv_session_destroy(hserv, session);
            return -1;
        }
        session->header_length += bytes;
        return 0;
    }

    session->header_length += bytes;
    session->progress = session->header_length;
    return complete;
}

static int hserv_request_receive_content(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Reset timeout. */
    session->timeout = HSERV_SESSION_REQUEST_TIMEOUT;

    /* Determine how many content bytes still need to be received. */
    assert(session->progress < session->content_length);
    size_t remaining = session->content_length - session->progress;

    /* Determine how many bytes can be received. */
    assert(session->buffer_size < session->buffer_capacity);
    assert(session->buffer_size < remaining);
    ssize_t bytes = session->buffer_capacity < remaining
                  ? session->buffer_capacity : remaining;
           bytes -= session->buffer_size;

    /* Receive content. */
    bytes = hserv_socket_recv(hserv, session,
        session->buffer + session->buffer_size, bytes, 0);
    if (bytes < 0) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    /* Update and check progress. */
    session->buffer_size += bytes;
    session->progress += bytes;
    if (session->buffer_size < session->buffer_capacity
     && session->progress < session->content_length) {
        /* Wait for more bytes. */
        return 0;
    }

    return 1;
}

static int hserv_response_send_content(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Reset timeout. */
    session->timeout = HSERV_SESSION_RESPONSE_TIMEOUT;

    assert(session->buffer_size <= session->content_length);
    assert(session->progress < session->buffer_size);
    assert(0 == session->buffer_capacity);
    assert(NULL != session->buffer);

    /* Send content. */
    ssize_t bytes = hserv_socket_send(hserv, session,
        session->buffer + session->progress,
        session->buffer_size - session->progress);
    if (-1 == bytes) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    /* Update progress. */
    session->progress += bytes;

    /* More to send? */
    if (session->progress < session->buffer_size) {
        return 0;
    }

    /* Reset progress. */
    session->progress = 0;
    return 1;
}


#ifdef HSERV_HAVE_OPENSSL
static int hserv_request_on_ssl_accept(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    int r = SSL_accept(session->ssl);
    if (-1 == r) {
        if (-1 == hserv_session_event_modify_ssl(hserv, session, r)) {
            hserv_session_destroy(hserv, session);
            return -1;
        }
    }
    else if (0 == r) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    /* Start receiving the request headers. */
    session->socket.callback = hserv_request_on_header;
    hserv_session_event_modify(hserv, session, EPOLLIN);
    return 0;
}
#endif

static int hserv_request_on_header(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    char* end;

    /* Receive headers terminated by \r\n\r\n. */
    int r = hserv_request_receive_headers(hserv, epoll_event, 4, &end);
    if (r <= 0) {
        return r;
    }

    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    char const* start_line[3];

    /* Parse request line. */
    char* ptr = hserv_header_parse_start_line(
        session->header_buffer, end, start_line);
    if (NULL == ptr) {
        /* Bad request. */
        hserv_respond_error(hserv, session, HSERV_SC_BAD_REQUEST, 1);
        return 0;
    }

    /* Parse request headers. */
    if (-1 == hserv_header_fields_parse(ptr, end - ptr)) {
        /* Bad request. */
        hserv_respond_error(hserv, session, HSERV_SC_BAD_REQUEST, 1);
        return 0;
    }

    /* Default connection behavior. */
    session->close = 0 == strcmp(session->request_version, "HTTP/1.0") ? 1 : 0;

    /* Determine content-length. */
    char const* it;
    char const* name;
    char const* value;
    ssize_t content_length = -1;

    /* Iterate headers to find out more about the request. */
    it = ptr; do {
        it = hserv_header_fields_iterate(it, &name, &value);
        if (NULL == it) {
            break;
        }

        if (0 == strcasecmp("connection", name)
            && 0 == strcasecmp("close", value)) {
            session->close = 1;
        }
        else if (0 == strcasecmp("keep-alive", name)) {
            /* TODO parse keep-alive session properties. */
            session->close = 0;
        }
        else if (0 == strcasecmp("transfer-encoding", name)) {
            if (0 == strcmp("chunked", value)) {
                /*
                 * RFC 9112 6.3
                 *
                 * 3. If a message is received with both a Transfer-Encoding
                 * and a Content-Length header field, the Transfer-Encoding
                 * overrides the Content-Length. Such a message might indicate
                 * an attempt to perform request smuggling (Section 11.2) or
                 * response splitting (Section 11.1) and ought to be handled as
                 * an error. An intermediary that chooses to forward the message
                 * MUST first remove the received Content-Length field and
                 * process the Transfer- Encoding (as described below) prior to
                 * forwarding the message downstream.
                 */
                if (-1 != content_length) {
                    /* Bad request. */
                    hserv_respond_error(
                        hserv, session, HSERV_SC_BAD_REQUEST, 1);
                    return 0;
                }

                /*
                 * RFC 9112 6.3
                 *
                 * 4. If a Transfer-Encoding header field is present and the
                 * chunked transfer coding (Section 7.1) is the final encoding,
                 * the message body length is determined by reading and decoding
                 * the chunked data until the transfer coding indicates the data
                 * is complete.
                 */
                content_length = HSERV_CHUNKED;
            }
            else {
                /* Hserv only support chunked transfer encoding. Any other */
                /* transfer encoding is rejected with a bad request response. */
                hserv_respond_error(hserv, session, HSERV_SC_BAD_REQUEST, 1);
                return 0;
            }
        }
        else if (0 == strcasecmp("content-length", name)) {
            /* See RFC 9112 6.3 #3, also referenced in the transfer-encoding */
            /* clause above. */
            if (HSERV_CHUNKED == content_length) {
                /* Bad request. */
                hserv_respond_error(hserv, session, HSERV_SC_BAD_REQUEST, 1);
                return 0;
            }

            /*
             * RFC 9112 6.3
             *
             * 5. If a message is received without Transfer-Encoding and with
             * either multiple Content-Length header fields having differing
             * field-values or a single Content-Length header field having an
             * invalid value, then the message framing is invalid and the
             * recipient MUST treat it as an unrecoverable error. If this is a
             * request message, the server MUST respond with a 400 (Bad Request)
             * status code and then close the connection. If this is a response
             * message received by a proxy, the proxy MUST close the connection
             * to the server, discard the received response, and send a 502
             * (Bad Gateway) response to the client. If this is a response
             * message received by a user agent, the user agent MUST close the
             * connection to the server and discard the received response.
             */
            size_t const length = strtoul(value, &end, 10);
            if ( 0 != *end
              || (content_length >= 0 && content_length != (ssize_t)length)
            ) {
                /* Bad request. */
                hserv_respond_error(hserv, session, HSERV_SC_BAD_REQUEST, 1);
                return 0;
            }

            content_length = length;
        }
    }
    while(1);

    /*
     * RFC 9112 6.3
     *
     * 7. If this is a request message and none of the above are true, then
     *    the message body length is zero (no message body is present).
     */
    if (-1 == content_length) {
        session->content_length = content_length = 0;
    }
    else {
        session->content_length = content_length;
    }

    /* Reset progress. */
    session->progress = 0;

    /* Set request's start-line properties. */
    session->request_method = start_line[0];
    session->request_target = start_line[1];
    strncpy(session->request_version, start_line[2],
        sizeof(session->request_version) - 1);
    session->request_version[sizeof(session->request_version) - 1] = 0;
    session->request_fields = ptr;

    /* Remember when it is a HEAD request. */
    if (0 == strcmp("HEAD", session->request_method)) {
        session->flags |= HSERV_FLAGS_HEAD_REQUEST;
    }

    /* Callback request. */
    if (hserv->config.transaction_start_callback(hserv, session) < 0) {
        /* Internal server error. */
        hserv_respond_error(hserv, session, HSERV_SC_INTERNAL_SERVER_ERROR, 1);
        return 0;
    }

    /* Reset request. */
    session->request_method = NULL;
    session->request_target = NULL;
    session->request_fields = NULL;

    /* Called request start callback. Arm calling end request callback */
    /* to allow user to cleanup if for some reason the request or */
    /* response fails. */
    session->callback_request_end = 1;

    /* Does request have content? */
    if (content_length > 0) {
        /* Setup for content-length or chunked transfer-encoded content. */
        if (content_length < HSERV_CHUNKED) {
            session->socket.callback = hserv_request_on_content_length;

            /* Suspend if user has not provided a buffer. */
            if (NULL == session->buffer || 0 == session->buffer_capacity) {
                hserv_session_event_modify(hserv, session, 0);
            }
        }
        else {
            /* Continue receiving to receive the chunked header. */
            session->socket.callback = hserv_request_on_chunked_header;
            session->header_length = 0;
        }
    }
    else {
        if (0 == session->responding) {
            /* Suspend if user has not responded. */
            hserv_session_event_modify(hserv, session, 0);
        }
    }

    return 0;
}

static int hserv_request_on_content_length(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    /* Receive content. */
    int r = hserv_request_receive_content(hserv, epoll_event);
    if (r <= 0) {
        return r;
    }

    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Calculate remaining content to receive. */
    assert(session->progress <= session->content_length);
    size_t more = session->content_length - session->progress;

    /* Callback with content received so far. */
    if (hserv_request_content_callback(hserv,
            session, session->buffer, session->buffer_size, more) < 0) {
        /* Internal server error. */
        hserv_respond_error(hserv, session, HSERV_SC_INTERNAL_SERVER_ERROR, 1);
        return 0;
    }

    /* More content to receive? */
    if (more > 0) {
        /* Suspend if user has not provided a buffer. */
        if (NULL == session->buffer || 0 == session->buffer_size) {
            hserv_session_event_modify(hserv, session, 0);
        }
    }
    else {
        /* Suspend if user has not responded. */
        if (0 == session->responding) {
            hserv_session_event_modify(hserv, session, 0);
        }
    }

    return 0;
}

static int hserv_request_on_chunked_header(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    char* end;

    /* Receive headers terminated by \r\n\r\n. */
    int r = hserv_request_receive_headers(hserv, epoll_event, 2, &end);
    if (r <= 0) {
        return r;
    }

    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Zero terminate and parse chunk length. */
    end[-2] = 0;
    session->content_length = strtoul(session->header_buffer, &end, 16);
    if (0 != *end) {
        /* Bad request. */
        hserv_respond_error(hserv, session, HSERV_SC_BAD_REQUEST, 1);
        return 0;
    }

    /* Reset progress. */
    session->progress = 0;

    /* Callback with content recevied and next chunk length, unless it is */
    /* the last chunk. The callback will then be after receiving the trailer. */
    if (session->content_length > 0
     && hserv_request_content_callback(hserv, session,
        session->buffer, session->buffer_size, session->content_length) < 0) {
        /* Internal server error. */
        hserv_respond_error(hserv, session, HSERV_SC_INTERNAL_SERVER_ERROR, 1);
        return 0;
    }

    /* Receive chunked content or a trailer? */
    if (session->content_length > 0) {
        session->socket.callback = hserv_request_on_chunked;
    }
    else {
        session->socket.callback = hserv_request_on_chunked_trailer;
    }
    return 0;
}

static int hserv_request_on_chunked(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    /* Receive content. */
    int r = hserv_request_receive_content(hserv, epoll_event);
    if (r <= 0) {
        return r;
    }

    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Calculate remaining chunk to receive. */
    assert(session->progress <= session->content_length);
    size_t more = session->content_length - session->progress;

    /* If more data must be recevied before the chunks end, the user provided */
    /* a buffer that is not large enough to receive the complete chunk. */
    if (more > 0) {
        /* Callback with content received so far. */
        if (hserv_request_content_callback(hserv,
                session, session->buffer, session->buffer_size, more) < 0) {
            /* Internal server error. */
            hserv_respond_error(hserv, session,
                HSERV_SC_INTERNAL_SERVER_ERROR, 1);
            return 0;
        }

        /* Suspend if user has not provided a buffer. */
        if (NULL == session->buffer || 0 == session->buffer_size) {
            hserv_session_event_modify(hserv, session, 0);
        }
    }
    else {
        /* Complete chunk has been received. Receive trailer and receive next */
        /* chunk header. Callback with received data will be done when the */
        /* next chunk length is known. */
        session->socket.callback = hserv_request_on_chunked_trailer;
        session->progress = 0;
        session->header_length = 0;
    }

    return 0;
}

static int hserv_request_on_chunked_trailer(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* This function either receives the \r\n trailer of a chunk or the */
    /* trailer after the last chunk. In the latter case, the code either */
    /* needs to receive \r\n or (field_line)*\r\n. In any case 2 octets */
    /* can be received first. */
    if (session->progress < 2) {
        ssize_t bytes = 2 - session->progress;

        /* Receive \r\n or start of trailer. */
        bytes = hserv_socket_recv(hserv, session,
            session->header_buffer, bytes, 0);
        if (bytes < 0) {
            hserv_session_destroy(hserv, session);
            return -1;
        }

        /* Update and check progress. */
        session->progress += bytes;
        if (session->progress < 2) {
            return 0;
        }
    }

    /* Did the previous chunk contain content? */
    if (session->content_length > 0) {
        /* Receive next chunk header. */
        session->socket.callback = hserv_request_on_chunked_header;
        session->progress = 0;
        session->header_length = 0;
        return 0;
    }


    /* Is there a chunk trailer? */
    if ('\r' != session->header_buffer[0]
     && '\n' != session->header_buffer[1]) {
        /* Continue to receive trailers terminated by \r\n\r\n. */
        char* end;
        int r = hserv_request_receive_headers(hserv, epoll_event, 4, &end);
        if (r <= 0) {
            return r;
        }

        /* Parse request trailers. */
        if (-1 == hserv_header_fields_parse(
                session->header_buffer, session->header_length)) {
            /* Bad request. */
            hserv_respond_error(hserv, session, HSERV_SC_BAD_REQUEST, 1);
            return 0;
        }

        /* Set request's trailers. */
        session->request_fields = session->header_buffer;
    }

    if (hserv_request_content_callback(hserv, session,
        session->buffer, session->buffer_size, session->content_length) < 0) {
        /* Internal server error. */
        hserv_respond_error(hserv, session, HSERV_SC_INTERNAL_SERVER_ERROR, 1);
        return 0;
    }

    /* Reset progress. */
    session->progress = 0;

    /* Suspend if user has not responded. */
    if (0 == session->responding) {
        hserv_session_event_modify(hserv, session, 0);
    }

    return 0;
}

static int hserv_response_on_header(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Reset timeout. */
    session->timeout = HSERV_SESSION_RESPONSE_TIMEOUT;

    assert(session->progress < session->header_length);

    /* Send header. */
    ssize_t bytes = hserv_socket_send(hserv, session,
        session->header_buffer + session->progress,
        session->header_length - session->progress);
    if (-1 == bytes) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    /* Update progress. */
    session->progress += bytes;

    /* More to send? */
    if (session->progress < session->header_length) {
        return 0;
    }

    /* Reset progress. */
    session->progress = 0;
    session->header_length = 0;

    /* No content to send? */
    if (0 == session->content_length
     || 0 != (HSERV_FLAGS_HEAD_REQUEST & session->flags)) {
        return hserv_session_next_request(hserv, session);
    }

    /* Setup for content-length or chunked transfer-encoded content. */
    if (session->content_length < HSERV_CHUNKED) {
        session->socket.callback = hserv_response_on_content_length;
    }
    else {
        session->socket.callback = hserv_response_on_chunked_header_trailer;
    }

    /* Suspend if user has not provided content, unless the last chunk flag */
    /* is set. */
    if ((NULL == session->buffer || 0 == session->buffer_size)
     && (0 == (HSERV_FLAGS_CHUNK_LAST & session->flags))) {
        hserv_session_event_modify(hserv, session, 0);
    }

    return 0;
}

static int hserv_response_on_content_length(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    int r = hserv_response_send_content(hserv, epoll_event);
    if (r <= 0) {
        return r;
    }

    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Update total progress. */
    session->content_length -= session->buffer_size;

    /* More content to send? */
    size_t more = session->content_length;

    /* Callback with content send so far. */
    if (hserv_response_content_callback(hserv, session,
            session->buffer, session->buffer_size, more) < 0) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    /* More content to send? */
    if (more > 0) {
        /* Suspend if user has not provided a buffer. */
        if (NULL == session->buffer || 0 == session->buffer_size) {
            hserv_session_event_modify(hserv, session, 0);
        }

        return 0;
    }

    /* All content has been sent, prepare for next request. */
    return hserv_session_next_request(hserv, session);
}

static int hserv_response_on_chunked_header_trailer(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Reset timeout. */
    session->timeout = HSERV_SESSION_RESPONSE_TIMEOUT;

    /* Format header and (optionally) trailer? */
    if (0 == session->header_length) {
        /* After the first header, the headers buffer includes the trailer */
        /* of the previous chunk as well as the header of the current. */
        /* Last chunks also contain the trailer following the last chunk. */
        int r;
        switch (HSERV_FLAGS_CHUNK_MASK & session->flags) {
        case HSERV_FLAGS_CHUNK_FIRST:
            r = sprintf(session->header_buffer, "%zx\r\n",
                            session->buffer_size);
            break;
        default:
            r = sprintf(session->header_buffer, "\r\n%zx\r\n",
                            session->buffer_size);
            break;
        case HSERV_FLAGS_CHUNK_LAST:
            r = sprintf(session->header_buffer, "\r\n%zx\r\n\r\n",
                            session->buffer_size);
            break;
        case HSERV_FLAGS_CHUNK_FIRST|HSERV_FLAGS_CHUNK_LAST:
            r = sprintf(session->header_buffer, "%zx\r\n\r\n",
                            session->buffer_size);
            break;
        }
        assert(r > 0);

        session->flags &= ~HSERV_FLAGS_CHUNK_FIRST;
        session->header_length = r;
    }

    /* Send header. */
    ssize_t bytes = hserv_socket_send(hserv, session,
        session->header_buffer + session->progress,
        session->header_length - session->progress);
    if (-1 == bytes) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    /* Update progress. */
    session->progress += bytes;

    /* More to send? */
    if (session->progress < session->header_length) {
        return 0;
    }

    /* Reset progress. */
    session->progress = 0;
    session->header_length = 0;

    /* Last chunk? */
    if (0 != (HSERV_FLAGS_CHUNK_LAST & session->flags)) {
        return hserv_session_next_request(hserv, session);
    }
    else {
        session->socket.callback = hserv_response_on_chunked;
    }

    return 0;
}

static int hserv_response_on_chunked(hserv_t* hserv,
    struct epoll_event* epoll_event)
{
    int r = hserv_response_send_content(hserv, epoll_event);
    if (r <= 0) {
        return r;
    }

    hserv_session_t* session =
        (hserv_session_t*)hserv_event_user_data(epoll_event);

    /* Callback for next chunk. */
    if (hserv_response_content_callback(hserv, session,
        session->buffer, session->buffer_size, HSERV_CHUNKED) < 0) {
        hserv_session_destroy(hserv, session);
        return -1;
    }

    /* Suspend if user has not provided a buffer. */
    if ((NULL == session->buffer || 0 == session->buffer_size)
     && (0 == (HSERV_FLAGS_CHUNK_LAST & session->flags))) {
        hserv_session_event_modify(hserv, session, 0);
    }

    /* hserv_response_on_chunked_header_trailer combines sending trailer */
    /* and header. */
    session->socket.callback = hserv_response_on_chunked_header_trailer;
    return 0;
}

static int hserv_session_on_maintenance(hserv_session_t* session)
{
// TODO investigate.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-overflow"
    /* Destroy session on timeout. */
    --session->timeout;
    return session->timeout >= 0 ? 0 : -1;
#pragma GCC diagnostic pop
}

static hserv_session_t* hserv_session_create(hserv_t* hserv,
    int fd, struct sockaddr const* sockaddr, socklen_t socklen)
{
    hserv_session_t* session =
        (hserv_session_t*)calloc(1, sizeof(hserv_session_t));
    if (NULL == session) {
        goto error;
    }

    session->interrupt.fd = -1;
    session->interrupt.callback = hserv_session_on_interrupt;
    session->interrupt.user_data = session;

    memcpy(&session->peer, sockaddr, socklen);

    session->socket.fd = fd;
    session->socket.callback = hserv_request_on_header;
    session->socket.user_data = session;

#if HSERV_SESSION_USER_STORAGE > 0
    session->user_data = session->user_storage;
#endif

    /* Create interrupt timer. */
    if (-1 == hserv_timer_create(
            hserv, &session->interrupt, hserv->error_string)) {
        goto error;
    }

    /* Make socket non blocking. */
    if (-1 == hserv_set_nonblock(session->socket.fd, hserv->error_string)) {
        goto error;
    }

    /* Add socket to epoll facility. */
    if (-1 == hserv_event_add(hserv, &session->socket, EPOLLIN)) {
        goto error;
    }

    /* Setup session for next request. */
    if (-1 == hserv_session_next_request(hserv, session)) {
        goto error;
    }

#ifdef HSERV_HAVE_OPENSSL
    if (NULL != hserv->ssl_context) {
        /* Create an SSL structure. */
        session->ssl = SSL_new(hserv->ssl_context);
        if (NULL == session->ssl) {
            goto error;
        }
        SSL_set_fd(session->ssl, fd);

        /* Override request callback to first negotiate the SSL connection. */
        session->socket.callback = hserv_request_on_ssl_accept;
    }
#endif

    /* Add session to session list. */
    hserv_list_push_back(&hserv->sessions, &session->element);
    return session;

error:
    hserv_session_destroy(hserv, session);
    return NULL;
}

static void hserv_session_destroy(hserv_t* hserv, hserv_session_t* session)
{
    if (NULL == session) {
        return;
    }

    if (session->callback_request_end) {
        hserv->config.transaction_end_callback(hserv, session, 1);
    }

    hserv_list_erase(&session->element);
    hserv_event_remove(hserv, &session->socket);
    hserv_event_remove(hserv, &session->interrupt);

#ifdef HSERV_HAVE_OPENSSL
    SSL_free(session->ssl);
#endif
    if (-1 != session->socket.fd) {
        close(session->socket.fd);
    }
    if (-1 != session->interrupt.fd) {
        close(session->interrupt.fd);
    }

    free(session);
}

static int hserv_session_accept(hserv_t* hserv, struct epoll_event* event)
{
    assert(event->events & EPOLLIN);
    (void)event;

    struct sockaddr sockaddr;
    socklen_t socklen = sizeof(sockaddr);

    int fd = accept(hserv->server.fd, &sockaddr, &socklen);
    if (-1 == fd) {
        hserv_set_error_string(hserv->error_string, "accept() failed");
        return -1;
    }

#if (0 != HSERV_CONFIG_SESSION_CLOEXEC)
    // Set the close-on-exec flag for the session socket.
    if (-1 == fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        hserv_set_error_string(hserv->error_string,
            "fcntl(...FD_CLOEXEC...) failed");
        close(fd);
        return -1;
    }
#endif

    hserv_session_t* session =
        hserv_session_create(hserv, fd, &sockaddr, socklen);
    if (NULL == session) {
        close(fd);
        return -1;
    }

    if (NULL != hserv->config.accept_callback) {
        if (hserv->config.accept_callback(hserv, session) < 0) {
            hserv_session_destroy(hserv, session);
        }
    }

    return 0;
}

static void hserv_update_date(hserv_t* hserv)
{
    time_t rawtime;
    struct tm * timeinfo;

    time(&rawtime);
    timeinfo = gmtime(&rawtime);

    strftime(hserv->date, sizeof(hserv->date), "%a, %d %b %Y %T GMT", timeinfo);
}

static int hserv_on_timer(hserv_t* hserv, struct epoll_event* event)
{
    assert(event->events & EPOLLIN);
    (void)event;

    (void)hserv_timer_read(&hserv->timer);

    /* Call session's timer handling function. */
    hserv_list_iterator_t* it = hserv_list_begin(&hserv->sessions);
    while (hserv_list_end(&hserv->sessions) != it) {
        hserv_session_t* session = (hserv_session_t*)it;
        int r = hserv_session_on_maintenance(session);

        /* Get next session before destroying session. */
        it = it->next;

        if (r < 0) {
            hserv_session_destroy(hserv, session);
        }
    }

    /* Update current time. */
    hserv_update_date(hserv);
    return 0;
}

static int hserv_run(hserv_t* hserv, int timeout)
{
    struct epoll_event event;

    do {
        /* Wait for event. */
        int r = epoll_wait(hserv->epoll_fd, &event, 1, timeout);
        if (r <= 0) {
            if (-1 == r) {
                hserv_set_error_string(hserv->error_string,
                    "epoll_wait() failed");
                return -1;
            }
            break;
        }

        hserv_event_t const* e = (hserv_event_t*)event.data.ptr;
        int const fd = e->fd;

        /* Callback. */
        if (-1 == e->callback(hserv, &event)) {
            /* Check server or timer fd callback returned an error. */
            if (fd == hserv->server.fd || fd == hserv->timer.fd) {
                /* Exit when either callback returned an error. */
                return -1;
            }
        }
    }
    while (0 == hserv->stop);

    return 0;
}

/*
 * Public
 */
HSERV_VISIBILITY_IMPL void hserv_init(hserv_config_t* config,
    hserv_transaction_start_callback_t transaction_start_callback,
    hserv_transaction_end_callback_t transaction_end_callback)
{
    assert(NULL != config);
    assert(NULL != transaction_start_callback);
    assert(NULL != transaction_end_callback);

    memset(config, 0, sizeof(*config));

    config->sockopts = HSERV_CONFIG_SOCKOPTS;
    config->backlog = HSERV_CONFIG_BACKLOG;

    config->binding.sa_family = HSERV_CONFIG_BINDING_FAMILY;
#if (HSERV_CONFIG_BINDING_FAMILY == AF_INET)
    struct sockaddr_in* sa = (struct sockaddr_in*)&config->binding;
    sa->sin_port = htons(HSERV_CONFIG_BINDING_PORT);
#elif (HSERV_CONFIG_BINDING_FAMILY == AF_INET6)
    struct sockaddr_in6* sa = (struct sockaddr_in6*)&config->binding;
    sa->sin6_port = htons(HSERV_CONFIG_BIND_PORT);
#else
    #error "unsupported socket family"
#endif
    config->transaction_start_callback = transaction_start_callback;
    config->transaction_end_callback = transaction_end_callback;
}

HSERV_VISIBILITY_IMPL int hserv_init_binding_ipv4(hserv_config_t* config,
    uint16_t port, char const* address)
{
    struct sockaddr_in* sa = (struct sockaddr_in*)&config->binding;
    sa->sin_port = htons(port);
    if (NULL != address) {
        if (inet_pton(AF_INET, address, &sa->sin_addr) <= 0) {
            hserv_set_error_string(config->error_string, "inet_pton() failed");
            return -1;
        }
    }

    return 0;
}

HSERV_VISIBILITY_IMPL hserv_t* hserv_create(hserv_config_t* config)
{
    assert(NULL != config);

    int const flags = 1;
    socklen_t socklen;

    hserv_t* hserv = (hserv_t*)calloc(1, sizeof(hserv_t));
    if (NULL == hserv) {
        snprintf(config->error_string, HSERV_MAX_ERROR_STRING,
            "calloc() failed");
        goto error;
    }

    /* Construct struct. */
    hserv->config = *config;
    hserv->epoll_fd = -1;

    hserv->server.fd = -1;
    hserv->server.callback = hserv_session_accept;
    hserv->server.user_data = hserv;

    hserv->timer.fd = -1;
    hserv->timer.callback = hserv_on_timer;
    hserv->timer.user_data = hserv;

    hserv_list_init(&hserv->sessions);

    /* Create epoll facility. */
    hserv->epoll_fd = epoll_create1(0);
    if (-1 == hserv->epoll_fd) {
        hserv_set_error_string(config->error_string, "epoll_create1() failed");
        goto error;
    }

#ifdef HSERV_HAVE_OPENSSL
    if (NULL != hserv->config.certificate_file
     && NULL != hserv->config.private_key_file) {
        hserv->ssl_context = SSL_CTX_new(TLS_server_method());
        if (NULL == hserv->ssl_context) {
            snprintf(config->error_string, HSERV_MAX_ERROR_STRING,
                "SSL_CTX_new() failed");
            goto error;
        }

        if (NULL != hserv->config.certificate_file
         && 1 != SSL_CTX_use_certificate_file(hserv->ssl_context,
                hserv->config.certificate_file, SSL_FILETYPE_PEM)) {
            snprintf(config->error_string, HSERV_MAX_ERROR_STRING,
                "SSL_CTX_use_certificate_file() failed");
            goto error;
        }
        if (NULL != hserv->config.private_key_file
         && 1 != SSL_CTX_use_PrivateKey_file(hserv->ssl_context,
                hserv->config.private_key_file, SSL_FILETYPE_PEM)) {
            snprintf(config->error_string, HSERV_MAX_ERROR_STRING,
                "SSL_CTX_use_PrivateKey_file() failed");
            goto error;
        }
    }
#endif

    /* Create server socket. */
    hserv->server.fd = socket(
        hserv->config.binding.sa_family, SOCK_STREAM, 0);
    if (-1 == hserv->server.fd) {
        hserv_set_error_string(config->error_string, "socket() failed");
        goto error;
    }

#if (0 != HSERV_CONFIG_SERVER_CLOEXEC)
    // Set the close-on-exec flag for the server socket.
    if (-1 == fcntl(hserv->server.fd, F_SETFD, FD_CLOEXEC)) {
        hserv_set_error_string(config->error_string,
            "fcntl(...FD_CLOEXEC...) failed");
        goto error;
    }
#endif

    /* Make socket non-blocking. */
    if (-1 == hserv_set_nonblock(hserv->server.fd, config->error_string)) {
        goto error;
    }

    /* Set socket REUSEADDR option. */
    if (0 != (HSERV_SOCKOPT_REUSEADDR & config->sockopts)
     && -1 == setsockopt(hserv->server.fd, SOL_SOCKET, SO_REUSEADDR,
            &flags, sizeof(flags))) {
        hserv_set_error_string(config->error_string,
            "setsockopt(...SO_REUSEADDR...) failed");
        goto error;
    }

    /* Set socket REUSEPORT option. */
    if (0 != (HSERV_SOCKOPT_REUSEPORT & config->sockopts)
     && -1 == setsockopt(hserv->server.fd, SOL_SOCKET, SO_REUSEPORT,
            &flags, sizeof(flags))) {
        hserv_set_error_string(config->error_string,
            "setsockopt(...SO_REUSEPORT...) failed");
        goto error;
    }

    switch (hserv->config.binding.sa_family) {
    case AF_INET: socklen = sizeof(struct sockaddr_in); break;
    case AF_INET6: socklen = sizeof(struct sockaddr_in6); break;
    default:
        snprintf(config->error_string, HSERV_MAX_ERROR_STRING,
            "Invalid or unsupported address family");
        goto error;
    }
    if (-1 == bind(hserv->server.fd, &hserv->config.binding, socklen)) {
        hserv_set_error_string(config->error_string, "bind() failed");
        goto error;
    }

    /* Listen...*/
    if (-1 == listen(hserv->server.fd, config->backlog)) {
        hserv_set_error_string(config->error_string, "listen() failed");
        goto error;
    }

    /* ...and add to epoll facility. */
    if (-1 == hserv_event_add(hserv, &hserv->server, EPOLLIN)) {
        hserv_set_error_string(config->error_string, "epoll_ctl() failed");
        goto error;
    }

    /* Create a 1 second maintenance timer. */
    if (-1 == hserv_timer_create(hserv, &hserv->timer, config->error_string)
     || -1 == hserv_timer_set(&hserv->timer, 1, 0, 1, 0, config->error_string)) {
        goto error;
    }

    /* Update date. */
    hserv_update_date(hserv);
    return hserv;

error:
    hserv_destroy(hserv);
    return NULL;
}

HSERV_VISIBILITY_IMPL void hserv_destroy(hserv_t* hserv)
{
    if (NULL == hserv) {
        return;
    }

    /* Destroy all active sessions. */
    hserv_list_iterator_t* it = hserv_list_begin(&hserv->sessions);
    while (hserv_list_end(&hserv->sessions) != it) {
        hserv_session_t* session = (hserv_session_t*)it;
        it = it->next;

        hserv_session_destroy(hserv, session);
    }

    /* Close and free server resources. */
#ifdef HSERV_HAVE_OPENSSL
    if (NULL != hserv->ssl_context) {
        SSL_CTX_free(hserv->ssl_context);
    }
#endif
    if (hserv->timer.fd >= 0) {
        close(hserv->timer.fd);
    }
    if (hserv->server.fd >= 0) {
        close(hserv->server.fd);
    }
    if (-1 != hserv->epoll_fd) {
        close(hserv->epoll_fd);
    }
    free(hserv);
}

HSERV_VISIBILITY_IMPL int hserv_get_fd(hserv_t* hserv)
{
    return NULL != hserv ? hserv->epoll_fd : -1;
}

#ifdef HSERV_HAVE_OPENSSL
HSERV_VISIBILITY_IMPL SSL_CTX* hserv_get_ssl_context(hserv_t* hserv)
{
    assert(NULL != hserv);
    return hserv->ssl_context;
}
#endif

HSERV_VISIBILITY_IMPL char const* hserv_get_error_string(hserv_t* hserv)
{
    assert(NULL != hserv);
    return hserv->error_string;
}

HSERV_VISIBILITY_IMPL int hserv_event_add(hserv_t* hserv,
    hserv_event_t* event, uint32_t events)
{
    assert(NULL != hserv);
    assert(NULL != event);

    struct epoll_event epoll_event;
    epoll_event.events = events;
    epoll_event.data.ptr = event;

    if (-1 == epoll_ctl(
            hserv->epoll_fd, EPOLL_CTL_ADD, event->fd, &epoll_event)) {
        hserv_set_error_string(hserv->error_string,
            "epoll_ctl(...EPOLL_CTL_ADD...) failed");
        return -1;
    }

    return 0;
}

HSERV_VISIBILITY_IMPL int hserv_event_modify(hserv_t* hserv,
    hserv_event_t* event, uint32_t events)
{
    assert(NULL != hserv);
    assert(NULL != event);

    struct epoll_event epoll_event;
    epoll_event.events = events;
    epoll_event.data.ptr = event;

    if (-1 == epoll_ctl(
            hserv->epoll_fd, EPOLL_CTL_MOD, event->fd, &epoll_event)) {
        hserv_set_error_string(hserv->error_string,
            "epoll_ctl(...EPOLL_CTL_MOD...) failed");
        return -1;
    }

    return 0;
}

HSERV_VISIBILITY_IMPL void hserv_event_remove(hserv_t* hserv,
    hserv_event_t const* event)
{
    assert(NULL != hserv);
    assert(NULL != event);

    if (-1 == event->fd) {
        return;
    }

    (void)epoll_ctl(hserv->epoll_fd, EPOLL_CTL_DEL, event->fd, NULL);
}

HSERV_VISIBILITY_IMPL void* hserv_get_user_data(hserv_t* hserv)
{
    assert(NULL != hserv);
    return hserv->config.user_data;
}

HSERV_VISIBILITY_IMPL int hserv_start(hserv_t* hserv)
{
    assert(NULL != hserv);
    hserv->stop = 0;
    return hserv_run(hserv, -1);
}

HSERV_VISIBILITY_IMPL int hserv_stop(hserv_t* hserv)
{
    assert(NULL != hserv);
    hserv->stop = 1;

    /* Modify timer to immediately fire and exit epoll_wait. */
    return hserv_timer_set(&hserv->timer, 0, 1, 1, 0, hserv->error_string);
}

HSERV_VISIBILITY_IMPL int hserv_poll(hserv_t* hserv)
{
    assert(NULL != hserv);
    return hserv_run(hserv, 0);
}

HSERV_VISIBILITY_IMPL char const* hserv_get_reason_string(
    hserv_status_code_t status_code)
{
    assert(((int)status_code) >= 100 && ((int)status_code) < 599);
    return hserv_reasons[status_code - 100];
}

HSERV_VISIBILITY_IMPL int hserv_header_fields_parse(char* fields, size_t length)
{
    int count = 0;

    char* ptr = fields;
    char* end = fields + length;

    assert(end - ptr >= 4);
    assert('\r' == end[-4] && '\n' == end[-3]
        && '\r' == end[-2] && '\n' == end[-1]);

    /* Trim trailing \r\n. */
    end -= 2;

    /* Double zero terminate in place of terminating \r\n. */
    end[0] = 0;
    end[1] = 0;

    while (ptr < end) {
        /* Store pointer to start. */
        char* start = ptr;

        /* Find end of field-line. */
        ptr = (char*)memchr(ptr, '\r', end - ptr);

        /* Check \n follows \r. */
        if (ptr + 1 >= end || ptr[1] != '\n') {
            return -1;
        }

        /* Zero terminate at \n. */
        ptr[1] = 0;

        /* Store ptr to next field. */
        char* next = ptr + 2;

        /*
         * RFC 9112 5.
         *
         * Field-line syntax is:
         *
         * field-line   = field-name ":" OWS field-value OWS
         */

        /* Tokenize field-name and 0-terminate. */
        if (NULL == strtok_r(start, ":", &ptr)) {
            return -1;
        }

        /* Skip OWS. */
        ptr += strspn(ptr, " \t");

        /* Store start of field value. */
        start = ptr;

        /* Field value not empty? */
        if (*start != '\r') {
            /* Go to end of field-line and reverse trim OWS + \r. */
            ptr = start + strlen(start) - 1;
            while (ptr > start) {
                if (NULL == strchr(" \t\r", *ptr)) {
                    break;
                }
                --ptr;
            }
            ptr[1] = 0;
        }
        else {
            /* Terminate empty field value. */
            *start = 0;
        }

        /* Update header count. */
        ++count;

        /* Next header. */
        ptr = next;
    }

    return count;
}

HSERV_VISIBILITY_IMPL char const* hserv_header_fields_iterate(
    char const* it, char const** name, char const** value)
{
    assert(NULL != name);
    assert(NULL != value);

    /* End of it? */
    if (NULL == it || 0 == it[0]) {
        return NULL;
    }

    /* Field name. */
    *name = it;

    /* Skip field name and OWS. */
    it += strlen(it) + 1;
    it += strspn(it, " \t");

    /* Field value. */
    *value = it;

    /* Skip field value, OWS, \r plus zero termination. */
    it += strlen(it) + 1;
    it += strspn(it, " \t\r") + 1;
    return it;
}

HSERV_VISIBILITY_IMPL char const* hserv_header_field_find(
    char const* it, char const *name, char const** value)
{
    assert(NULL != name);
    assert(NULL != value);

    char const* current;

    do {
        it = hserv_header_fields_iterate(it, &current, value);
        if (NULL == it) {
            return NULL;
        }

        if (0 == strcasecmp(name, current)) {
            return it;
        }
    }
    while (1);
}

HSERV_VISIBILITY_IMPL int hserv_header_field_value_contains(
    char const* field_value, char const *value, char const* delim)
{
    if (NULL != delim) {
        char* string = strdup(field_value);
        char* start = string;
        char* save;
        char* candidate;

        if (NULL == string) {
            return -1;
        }

        do {
            candidate = strtok_r(start, delim, &save);
            if (NULL == candidate) {
                free(string);
                break;
            }

            candidate = hserv_header_value_trim(candidate);
            if (0 == strcasecmp(candidate, value)) {
                free(string);
                return 1;
            }

            start = NULL;
        }
        while (1);
    }
    else {
        if (0 == strcasecmp(field_value, value)) {
            return 1;
        }
    }

    return 0;
}

HSERV_VISIBILITY_IMPL int hserv_header_field_contains(
    const char* it, char const* name, char const* value, char const* delim)
{
    assert(NULL != it);
    assert(NULL != name);
    assert(NULL != value);

    char const* found;

    do {
        it = hserv_header_field_find(it, name, &found);
        if (NULL == it) {
            return 0;
        }

        switch (hserv_header_field_value_contains(found, value, delim)) {
        case 1:
            return 1;
        case 0:
            break;
        default:
            return -1;
        }
    }
    while (1);
}

HSERV_VISIBILITY_IMPL ssize_t hserv_header_fields_copy(
    char const* it, char* buffer, size_t size)
{
    assert(NULL != buffer);
    assert(0 != size);

    char const* name;
    char const* value;
    size_t name_length, value_length;
    ssize_t result = 0;

    do {
        it = hserv_header_fields_iterate(it, &name, &value);
        if (NULL == it) {
            assert(size > 0);
            *buffer = 0;
            return result + 1;
        }

        name_length = strlen(name) + 1;
        value_length = strlen(value) + 1;

        if (name_length + value_length > size - 1) {
            return -1;
        }

        memcpy(buffer, name, name_length);
        buffer += name_length;

        memcpy(buffer, value, value_length);
        buffer += value_length;

        *buffer++ = 0;

        size -= name_length + value_length + 1;
        result += name_length + value_length + 1;
    } while(1);
}

HSERV_VISIBILITY_IMPL char const* hserv_request_get_method(
    hserv_session_t const* session)
{
    return session->request_method;
}

HSERV_VISIBILITY_IMPL char const* hserv_request_get_target(
    hserv_session_t const* session)
{
    return session->request_target;
}

HSERV_VISIBILITY_IMPL char const* hserv_request_get_version(
    hserv_session_t const* session)
{
    return session->request_version;
}

HSERV_VISIBILITY_IMPL char const* hserv_request_get_header_fields(
    hserv_session_t const* session)
{
    return session->request_fields;
}

HSERV_VISIBILITY_IMPL size_t hserv_request_get_content_length(
    hserv_session_t const* session)
{
    return session->content_length;
}

HSERV_VISIBILITY_IMPL int hserv_request_receive(hserv_t* hserv,
    hserv_session_t* session, void* buffer, size_t capacity,
    hserv_request_content_callback_t callback)
{
    assert(NULL != hserv);
    assert(NULL != session);
    assert(NULL != buffer);
    assert(capacity > 0);
    assert(NULL != callback);

    assert(NULL == session->request_content_callback);
    session->request_content_callback = callback;

    assert(NULL == session->buffer);
    session->buffer_capacity = capacity;
    session->buffer_size = 0;
    session->buffer = (char*)buffer;

    /* Resume receiving. */
    if (-1 == hserv_session_event_modify(hserv, session, EPOLLIN)) {
        session->request_content_callback = NULL;
        session->buffer = NULL;
        session->buffer_capacity = 0;
        return -1;
    }

    return 0;
}

HSERV_VISIBILITY_IMPL int hserv_respond(
    hserv_t* hserv, hserv_session_t* session,
    hserv_status_code_t status_code, char const* reason,
    char const* const fields[], size_t content_length, void const* content)
{
    assert(NULL != hserv);
    assert(NULL != session);
    assert(((int)status_code) >= 100 && ((int)status_code) < 599);
    assert(NULL == content
        || (content_length > 0 && content_length < HSERV_CHUNKED));

    assert(0 == session->responding);

    /* Reset request validity. */
    session->request_method = NULL;
    session->request_target = NULL;
    session->request_fields = NULL;

    /* Format start-line and add mandatory headers. */
    hserv_header_format_status_line(
        session, session->request_version, status_code, reason);
    if (0
#ifdef HSERV_HEADER_FIELD_DATE
     || -1 == hserv_header_field_append(session, "Date", hserv->date)
#endif
#ifdef HSERV_HEADER_FIELD_SERVER
     || -1 == hserv_header_field_append(session, "Server", HSERV_HEADER_FIELD_SERVER)
#endif
    ) {
        return -1;
    }

    if (NULL != fields) {
        while (NULL != *fields) {
#ifdef HSERV_HEADER_FIELD_DATE
            assert(0 != strcasecmp(fields[0], "date"));
#endif
#ifdef HSERV_HEADER_FIELD_SERVER
            assert(0 != strcasecmp(fields[0], "server"));
#endif
            assert(0 != strcasecmp(fields[0], "content-length"));
            assert(0 != strcasecmp(fields[0], "transfer-encoding"));

            if (0 == strcasecmp(fields[0], "connection")) {
                /* Skip connection header if session is to be closed or */
                /* mark session to be closed if so specified and skip. */
                if (1 == session->close
                 || 0 == strcasecmp(fields[1], "close")) {
                    session->close = 1;
                    fields += 2;
                    continue;
                }
            }

            if (-1 == hserv_header_field_append(
                        session, fields[0], fields[1])) {
                return -1;
            }

            fields += 2;
        }
    }

    if (HSERV_CHUNKED == content_length) {
        if (-1 == hserv_header_field_append(
                session, "Transfer-Encoding", "chunked")) {
            return -1;
        }
    } /* else below */
    /*
     * RFC 9112 6.3.
     *
     * Any response to a HEAD request and any response with a 1xx
     * (Informational), 204 (No Content), or 304 (Not Modified) status code is
     * always terminated by the first empty line after the header fields,
     * regardless of the header fields present in the message, and thus cannot
     * contain a message body or trailer section.
     */
    else if ((status_code < 100 || status_code > 199)
     && HSERV_SC_NO_CONTENT != status_code
     && HSERV_SC_NOT_MODIFIED != status_code) {
        char value[20]; /* Max uint64_t string representation length. */
        sprintf(value, "%zu", content_length);
        if (-1 == hserv_header_field_append(session, "Content-Length", value)) {
            return -1;
        }
    }

    /* Add connection header if the session is to be closed. */
    if (1 == session->close) {
        if (-1 == hserv_header_field_append(session, "Connection", "close")) {
            return -1;
        }
    }

    /* Terminate header. */
    if (-1 == hserv_header_fields_terminate(session)) {
        return -1;
    }

    /* Setup response. */
    session->timeout = HSERV_SESSION_RESPONSE_TIMEOUT;
    session->content_length = content_length;
    session->responding = 1;
    session->progress = 0;
    if (NULL != content) {
        session->buffer_size = content_length;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
        session->buffer = (char*)content;
#pragma GCC diagnostic pop
    }

    /* Modify socket events to start sending response. */
    session->socket.callback = hserv_response_on_header;
    return hserv_session_event_modify(hserv, session, EPOLLOUT);
}

HSERV_VISIBILITY_IMPL int hserv_response_send(hserv_t* hserv,
    hserv_session_t* session, void const* buffer, size_t size,
    hserv_response_content_callback_t callback)
{
    assert(NULL != hserv);
    assert(NULL != session);

    assert(1 == session->responding);
    assert(!(HSERV_FLAGS_CHUNK_LAST & session->flags));
    assert(NULL == session->buffer);
    assert(size <= session->content_length);
    assert(0 != session->content_length);

    /* Check whether it is the last chunk. */
    if (HSERV_CHUNKED == session->content_length && 0 == size) {
        session->flags |= HSERV_FLAGS_CHUNK_LAST;
    }

    /* Ignore extraneous content. */
    if (size > session->content_length) {
        size = session->content_length;
    }

    session->response_content_callback = callback;
    session->progress = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    session->buffer = (char*)buffer;
#pragma GCC diagnostic pop
    session->buffer_size = size;

    /* Modify socket events to start sending response content. */
    /* Note that the socket's callback is already setup at this point. */
    return hserv_session_event_modify(hserv, session, EPOLLOUT);
}

#ifdef HSERV_HAVE_OPENSSL
HSERV_VISIBILITY_IMPL SSL* hserv_session_get_ssl(
    hserv_session_t const* session)
{
    assert(NULL != session);
    return session->ssl;
}

HSERV_VISIBILITY_IMPL int hserv_session_set_ssl(
    hserv_session_t* session, SSL* ssl)
{
    assert(NULL != session);
    assert(NULL != ssl);

    /* Free current SSL connection object. */
    SSL_free(session->ssl);

    /* Set session's SSL connection object. */
    session->ssl = ssl;
    return 1 == SSL_set_fd(session->ssl, session->socket.fd) ? 0 : -1;
}
#endif

HSERV_VISIBILITY_IMPL int hserv_session_get_peer(
    hserv_session_t* session, struct sockaddr *peer_address, socklen_t* length)
{
    assert(NULL != session);
    return getpeername(session->socket.fd,
        (struct sockaddr*)peer_address, length);
}

HSERV_VISIBILITY_IMPL void hserv_session_set_interrupt_callback(
    hserv_session_t* session, hserv_session_interrupt_callback_t callback)
{
    assert(NULL != session);
    session->interrupt_callback = callback;
}

HSERV_VISIBILITY_IMPL int hserv_session_interrupt(hserv_session_t* session)
{
    assert(NULL != session);
    return hserv_timer_set(
        &session->interrupt, 0, 1, 0, 0, session->error_string);
}

HSERV_VISIBILITY_IMPL char const* hserv_session_get_error_string(
    hserv_session_t* session)
{
    assert(NULL != session);
    return session->error_string;
}

HSERV_VISIBILITY_IMPL void hserv_session_set_error_string(
    hserv_session_t* session, char const *format, ...)
{
    assert(NULL != session);

    va_list ap;
    va_start(ap, format);
    vsnprintf(session->error_string, HSERV_MAX_ERROR_STRING, format, ap);
    va_end(ap);
}

HSERV_VISIBILITY_IMPL void hserv_session_set_user_data(
    hserv_session_t* session, void* user_data)
{
    assert(NULL != session);
#if HSERV_SESSION_USER_STORAGE > 0
    if (NULL == user_data) {
        session->user_data = &session->user_storage;
        return;
    }
#endif
    session->user_data = user_data;
}

HSERV_VISIBILITY void* hserv_session_get_user_data(
    hserv_session_t const* session)
{
    assert(NULL != session);
    return session->user_data;
}

HSERV_VISIBILITY int hserv_session_upgraded(
    hserv_t* hserv, hserv_session_t* session)
{
    int fd = session->socket.fd;

    /* Remove file-descriptor from epoll facility. */
    (void)epoll_ctl(hserv->epoll_fd, EPOLL_CTL_DEL, fd, NULL);

    /* File-descriptor and ssl are now the user's responsibility. */
    session->socket.fd = -1;
#ifdef HSERV_HAVE_OPENSSL
    session->ssl = NULL;
#endif
    session->close = 1;
    session->callback_request_end = 0;
    return fd;
}

#endif /* HSERV_IMPL */

#ifdef HSERV_IMPL_TEST

#include "htest.h"

HTEST_CASE(hserv_header_fields)
{
    char fields[64];
    strcpy(fields, "foo: bar\r\nbar:  baz   \r\nbaz:\r\nfoo:1\r\n\r\n");

    HTEST_INT(hserv_header_fields_parse(fields, strlen(fields)), >, 0);

    char const* name;
    char const* value;
    char const* it;

    HTEST_POINTER(NULL, !=, (it = hserv_header_fields_iterate(fields, &name, &value)));
    HTEST_INT(0, ==, strcmp("foo", name));
    HTEST_INT(0, ==, strcmp("bar", value));

    HTEST_POINTER(NULL, !=, (it = hserv_header_fields_iterate(it, &name, &value)));
    HTEST_INT(0, ==, strcmp("bar", name));
    HTEST_INT(0, ==, strcmp("baz", value));

    HTEST_POINTER(NULL, !=, (it = hserv_header_fields_iterate(it, &name, &value)));
    HTEST_INT(0, ==, strcmp("baz", name));
    HTEST_INT(0, ==, strcmp("", value));

    HTEST_POINTER(NULL, !=, (it = hserv_header_fields_iterate(it, &name, &value)));
    HTEST_INT(0, ==, strcmp("foo", name));
    HTEST_INT(0, ==, strcmp("1", value));

    HTEST_POINTER(NULL, ==, hserv_header_fields_iterate(it, &name, &value));

    HTEST_POINTER(NULL, !=, (it = hserv_header_field_find(fields, "foo", &value)));
    HTEST_INT(0, ==, strcmp("bar", value));
    HTEST_POINTER(NULL, !=, (it = hserv_header_field_find(it, "foo", &value)));
    HTEST_INT(0, ==, strcmp("1", value));
    HTEST_POINTER(NULL, ==, (it = hserv_header_field_find(it, "foo", &value)));

    HTEST_POINTER(NULL, !=, (it = hserv_header_field_find(fields, "bar", &value)));
    HTEST_INT(0, ==, strcmp("baz", value));
    HTEST_POINTER(NULL, ==, (it = hserv_header_field_find(it, "bar", &value)));

    HTEST_POINTER(NULL, !=, (it = hserv_header_field_find(fields, "baz", &value)));
    HTEST_INT(0, ==, strcmp("", value));
    HTEST_POINTER(NULL, ==, (it = hserv_header_field_find(it, "baz", &value)));
}

htest_suite_t hserv_test_suite =
{
    HTEST_CASE_REF(hserv_header_fields),
    NULL
};

#endif /* HSERV_IMPL_TEST */

#ifdef __cplusplus
}
#endif

