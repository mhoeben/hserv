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
#include "server.h"
#include "hbuffer.h"
#include "utility.h"
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static hbuffer_t server_filepath = HBUFFER_INIT;
static hbuffer_t server_response_fields = HBUFFER_INIT;

static server_t server;

static void usage()
{
    fprintf(stderr, "usage: hserv [options] [<directory-or-file>]\n");
    fprintf(stderr, "  -b <ip-address>   bind to interface with specified address.\n");
    fprintf(stderr, "  -c <cert-file>    SSL certificate file. (Default: '%s'.)\n", SERVER_DEFAULT_CERTIFICATE_FILE);
    fprintf(stderr, "  -h                this help text.\n");
    fprintf(stderr, "  -H <name:value>   response name:value header field. (May be used multiple times.)\n");
    fprintf(stderr, "  -i <index-file>   file to serve when the request target is '/'. (Default: '%s'.)\n", SERVER_DEFAULT_INDEX_FILE);
    fprintf(stderr, "  -k <key-file>     SSL private key file. (Default: '%s'.)\n", SERVER_DEFAULT_PRIVATE_KEY_FILE);
    fprintf(stderr, "  -l [<logfile>]    log request/response URLs and headers, optionally to file.\n");
    fprintf(stderr, "  -p <port>         sets the port. (Default: %d.)\n", SERVER_DEFAULT_PORT);
    fprintf(stderr, "  -s                secure HTTP.\n");
    fprintf(stderr, "  -v                verbose logging.\n");
    fprintf(stderr, "  -w <subprotocol>  accept websocket a connection for given <subprotocol>.\n");
    fprintf(stderr, "  -x                exit after first transaction. (Default when no <directory-or_file> is specified.)\n");
}

char const* strip_slash(hbuffer_t* buffer, char const* path)
{
    /* Server appends the request's target, which should always start with a */
    /* slash. Hence, a path's trailing slash should be stripped. Handle the */
    /* "" case by substituting the string with ".". Note that "." and "/"  */
    /* do not require any specific handling. */

    size_t length = strlen(path);

    /* "" is converted to '.'. */
    if (0 == length) {
        VERIFY(-1 != hbuffer_assign(buffer, ".", 2));
        return (char const*)buffer->data;
    }

    /* Strip trailing slash. */
    if ('/' == path[length - 1]) {
        VERIFY(-1 != hbuffer_strncpy(buffer, path, length - 1));
        return (char const*)buffer->data;
    }

    /* Path can be used as is. */
    return path;
}

void on_sigint(int signal)
{
    (void)signal;
    (void)server_stop(&server);
}

void cleanup()
{
    server_destroy(&server);
    hbuffer_free(&server_filepath);
    hbuffer_free(&server_response_fields);
    utility_cleanup();
}

int main(int argc, char* argv[])
{
    VERIFY(-1 != utility_init());

    server_create(&server);
    server.exec = argv[0];

    do {
        int opt = getopt(argc, argv, ":b:c:hH:i:k:l:p:svw:x");
        if (-1 == opt) {
            break;
        }

        switch (opt) {
        case 'b':
            server.bind = optarg;
            break;

        case 'c':
            server.certificate_file = optarg;
            break;

        case 'h':
            cleanup();
            usage();
            return EXIT_SUCCESS;

        case 'H':
            {
                char const zero = 0;
                char const* ptr = strchr(optarg, ':');
                if (NULL == ptr) {
                    fprintf(stderr, "%s: Invalid header format '%s' (no colon).\n", server.exec, optarg);
                    cleanup();
                    return EXIT_FAILURE;
                }

                VERIFY(-1 != hbuffer_append(&server_response_fields, optarg, (ptr - optarg))
                    && -1 != hbuffer_append(&server_response_fields, &zero, 1));

                do { ++ptr; } while (isspace(*ptr));

                VERIFY(-1 != hbuffer_append(&server_response_fields, ptr, strlen(ptr))
                    && -1 != hbuffer_append(&server_response_fields, &zero, 1));
            }
            break;

        case 'i':
            server.index_file = optarg;
            break;

        case 'k':
            server.private_key_file = optarg;
            break;

        case 'l':
            if (NULL != server.logfile) {
                fprintf(stderr, "%s: Log file already specified.\n", server.exec);
                cleanup();
                return EXIT_FAILURE;
            }

            server.logfile = fopen(optarg, "a");
            if (NULL == server.logfile) {
                fprintf(stderr, "%s: Failed to open logfile '%s' (%s)", server.exec, optarg, strerror(errno));
                cleanup();
                return EXIT_FAILURE;
            }
            break;

        case 'p':
            server.port = atoi(optarg);
            if (server.port <= 0 || server.port >= 65536) {
                fprintf(stderr, "%s: Invalid server port '%s'.\n", server.exec, optarg);
                cleanup();
                return EXIT_FAILURE;
            }
            break;

        case 's':
#if defined(HSERV_HAVE_OPENSSL)
            server.flags |= SERVER_FLAG_SECURE;
            break;
#else
            fprintf(stderr, "%s: Compiled without OpenGGL support, secure HTTP not supported.\n", server.exec);
            cleanup();
            return EXIT_FAILURE;
#endif

        case 'v':
            server.flags |= SERVER_FLAG_VERBOSE;
            break;

        case 'w':
            server.websocket_subprotocol = optarg;
            break;

        case 'x':
            server.flags |= SERVER_FLAG_EXIT;
            break;

        case ':':
            fprintf(stderr, "%s: Missing argument for option '%s'.\n", server.exec, argv[optind - 1]);
            cleanup();
            return EXIT_FAILURE;

        default:
            fprintf(stderr, "%s: Invalid option '%s'.\n", server.exec, argv[optind - 1]);
            cleanup();
            return EXIT_FAILURE;
        }
    }
    while (1);

    argv += optind;
    argc -= optind;

    if (argc > 1) {
        fprintf(stderr, "%s: Multiple files or directories specified.\n", server.exec);
        cleanup();
        return EXIT_FAILURE;
    }
    else if (1 == argc) {
        if (NULL != server.websocket_subprotocol) {
            fprintf(stderr, "%s: Not reading from stdin/out for a WebSocket.\n", server.exec);
            cleanup();
            return EXIT_FAILURE;
        }

        /* Set server's filepath. */
        server.filepath = strip_slash(&server_filepath, argv[0]);

        /* Check if filepath is a regular file or link. */
        if (is_reg(server.filepath)) {
            if (0 != strcmp(SERVER_DEFAULT_INDEX_FILE, server.index_file)) {
                fprintf(stderr, "%s: Warning, overriding specified index file to '%s'.\n", server.exec, server.filepath);
            }

            /* Index file equals the served file. */
            server.index_file = server.filepath;
        }
    }
    else {
        /* Exit after first request when no file or directory has been specified. */
        server.flags |= SERVER_FLAG_EXIT;
    }

    if (0 != (SERVER_FLAG_SECURE & server.flags)) {
        if (0 != access(server.certificate_file, R_OK) || 1 != is_reg(server.certificate_file)) {
            fprintf(stderr, "%s: Cannot read SSL certificate file '%s' (%s).\n", server.exec, server.certificate_file, strerror(errno));
            cleanup();
            return EXIT_FAILURE;
        }

        if (0 != access(server.private_key_file, R_OK) || 1 != is_reg(server.private_key_file)) {
            fprintf(stderr, "%s: Cannot read SSL private-key file '%s' (%s).\n", server.exec, server.private_key_file, strerror(errno));
            cleanup();
            return EXIT_FAILURE;
        }
    }

    /* Add additional response headers. */
    char const* ptr = (char const*)server_response_fields.data;
    char const* end = (char const*)ptr + server_response_fields.size;

    while (NULL != ptr && ptr < end) {
        VERIFY(-1 != harray_push_back(&server.response_fields, &ptr));
        ptr += strlen(ptr) + 1;

        VERIFY(-1 != harray_push_back(&server.response_fields, &ptr));
        ptr += strlen(ptr) + 1;
    }

    struct sigaction sig_action = { 0 };
    struct sigaction sig_restore = { 0 };

    sig_action.sa_handler = on_sigint;

    if (-1 == sigaction(SIGINT, &sig_action, &sig_restore)) {
        fprintf(stderr, "%s: Failed to install signal handler.\n", server.exec);
        cleanup();
        return EXIT_FAILURE;
    }

    server_start(&server);

    cleanup();
    return EXIT_SUCCESS;
}

