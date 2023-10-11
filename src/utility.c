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
#include "utility.h"

#define HARRAY_IMPL
#include "harray.h"

#define HBUFFER_IMPL
#include "hbuffer.h"

#define HFS_IMPL
#include "hfs.h"

#define HHASH_MAP_IMPL
#include "hhash_map.h"

#include "hserv.h"

#include <string.h>
#include <time.h>

/*
 * Implementation
 */
static method_t method_get = METHOD_GET;
static method_t method_head = METHOD_HEAD;
static method_t method_post = METHOD_POST;
static method_t method_put = METHOD_PUT;
static method_t method_delete = METHOD_DELETE;
static method_t method_connect = METHOD_CONNECT;
static method_t method_options = METHOD_OPTIONS;
static method_t method_trace = METHOD_TRACE;
static method_t method_patch = METHOD_PATCH;
static hhash_map_t method_table;

static hhash_map_t ext_table;

/*
 * Public
 */
int utility_init()
{
    if (hhash_map_init(&method_table, 16) < 0) {
        return -1;
    }

    if (
        hhash_map_insert(&method_table, "GET", 3, &method_get) < 0
     || hhash_map_insert(&method_table, "HEAD", 4, &method_head) < 0
     || hhash_map_insert(&method_table, "POST", 4, &method_post) < 0
     || hhash_map_insert(&method_table, "PUT", 3, &method_put) < 0
     || hhash_map_insert(&method_table, "DELETE",  6, &method_delete) < 0
     || hhash_map_insert(&method_table, "CONNECT",  7, &method_connect) < 0
     || hhash_map_insert(&method_table, "OPTIONS",  7, &method_options) < 0
     || hhash_map_insert(&method_table, "TRACE",  5, &method_trace) < 0
     || hhash_map_insert(&method_table, "PATCH",  5, &method_patch) < 0
    ) {
        return -1;
    }

    if (hhash_map_init(&ext_table, 32) < 0) {
        return -1;
    }

    if (
        hhash_map_insert(&ext_table, "txt",  3, "text/plain") < 0
     || hhash_map_insert(&ext_table, "css",  3, "text/css") < 0
     || hhash_map_insert(&ext_table, "htm",  3, "text/html") < 0
     || hhash_map_insert(&ext_table, "html", 4, "text/html") < 0
     || hhash_map_insert(&ext_table, "js",   2, "text/javascript") < 0
     || hhash_map_insert(&ext_table, "xml",  3, "text/xml") < 0
     || hhash_map_insert(&ext_table, "json", 4, "application/json") < 0
     || hhash_map_insert(&ext_table, "png",  3, "image/png") < 0
     || hhash_map_insert(&ext_table, "jpg",  3, "image/jpeg") < 0
     || hhash_map_insert(&ext_table, "jpeg", 4, "image/jpeg") < 0
     || hhash_map_insert(&ext_table, "webp", 4, "image/webp") < 0
     || hhash_map_insert(&ext_table, "gif",  3, "image/gif") < 0
     || hhash_map_insert(&ext_table, "bmp",  3, "image/bmp") < 0
    ) {
        return -1;
    }

    return 0;
}

void utility_cleanup()
{
    hhash_map_free(&ext_table);
    hhash_map_free(&method_table);
}

#if !(defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L)

char* strndup(char const* string, size_t n)
{
    assert(NULL != string);

    size_t length = strlen(string);
    if (length > n) {
        length = n;
    }

    char* dup = malloc(length + 1);
    if (NULL == dup) {
        return NULL;
    }

    memcpy(dup, string, length);
    dup[length] = 0;
    return dup;
}

#endif

int is_dir(char const* filepath)
{
    struct stat st;

    if (-1 == stat(filepath, &st)) {
        return ENOENT == errno ? 0 :-1;
    }

    return !!S_ISDIR(st.st_mode);
}

int is_reg(char const* filepath)
{
    struct stat st;

    if (-1 == stat(filepath, &st)) {
        return ENOENT == errno ? 0 :-1;
    }

    return !!S_ISREG(st.st_mode);
}

method_t get_method(char const* method)
{
    method_t const* m = hhash_map_find(&method_table, method, strlen(method));
    return NULL != m ? *m : METHOD_INVALID;
}

char const* find_header_field(harray_t const* fields, char const* name)
{
    for (size_t i = 0; i < fields->size; i += 2) {
        if (0 == strcasecmp(((char const**)fields->data)[i], name)) {
            return ((char const**)fields->data)[i + 1];
        }
    }

    return NULL;
}

ssize_t has_header_field_value(harray_t const* fields, char const* name,
    char const* value, char const* delim)
{
    for (size_t i = 0; i < fields->size; i += 2) {
        if (0 == strcasecmp(((char const**)fields->data)[i], name)) {
            switch (hserv_header_field_value_contains(
                ((char const**)fields->data)[i + 1], value, delim)) {
            case 1:
                return i;
            case 0:
                break;
            default:
                return -1;
            }
        }
    }

    return -1;
}

char const* guess_content_type(char const* filepath, FILE* file, size_t size)
{
    char const* slash = strrchr(filepath, '/');
    char const* ext = strrchr(filepath, '.');

    /* Lookup extension. Note that '.' belongs to a path component when it */
    /* occurs before a slash. */
    if (NULL != ext && ext > slash) {
        char const* content_type = hhash_map_find(&ext_table, ext + 1, strlen(ext + 1));
        if (NULL != content_type) {
            return content_type;
        }
    }

    /* Read file's header bytes, restore file pointer. */
    char header[8];
    ssize_t r = fread(header, 1, 8, file);
    if (r == -1) {
        return NULL;
    }

    /* Return file to start and clear any errors. */
    VERIFY(-1 != fseek(file, 0, SEEK_SET));
    if (r < 8) {
        return "application/octet-stream";
    }

    if (fread(header, 8, 1, file) < 1
     || -1 == fseek(file, 0, SEEK_SET)) {
        return NULL;
    }

#pragma push_macro("MATCHES")
#define MATCHES(signature, length) \
    (size >= length && 0 == memcmp(header, signature, length))

    /* Look at data to make an educated guess. */
    if (MATCHES("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 8)) {
        return "image/png";
    }
    if (MATCHES("RIFF", 4) || MATCHES("WEBP", 4)) {
        return "image/webp";
    }
    if (MATCHES("\xFF\xD8\xFF", 3)) {
        return "image/jpeg";
    }
    if (MATCHES("GIF87a", 6) || MATCHES("GIF89a", 6)) {
        return "image/gif";
    }
    if (MATCHES("BM", 2)) {
        return "image/bmp";
    }
    if (size >= 8 && 0 == memcmp(header + 4, "\x66\x74\x79\x70", 4)) {
        return "video/mp4";
    }

#pragma pop_macro("MATCHES")

    return "application/octet-stream";
}

char const* get_date_and_time()
{
    static char string[64];
    time_t rawtime;
    struct tm* timeinfo;

    time(&rawtime);
    timeinfo = gmtime(&rawtime);
    strftime(string, sizeof(string), "%a, %d %b %Y %T GMT", timeinfo);

    return string;
}

