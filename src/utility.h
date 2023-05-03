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
#ifndef UTILITY_H
#define UTILITY_H

#include "harray.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define ASSERT(expr)    assert(expr)

#ifndef NDEBUG
#define VERIFY(expr)    assert(expr)
#else
#define VERIFY(expr)    do { (void)(expr); } while (0)
#endif

int utility_init();
void utility_cleanup();

#if !(defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L)
char* strndup(char const* string, size_t n);
#endif

int is_dir(char const* filepath);
int is_reg(char const* filepath);

typedef enum method_e
{
    METHOD_INVALID,

    METHOD_GET,
    METHOD_HEAD,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE,
    METHOD_CONNECT,
    METHOD_OPTIONS,
    METHOD_TRACE,
    METHOD_PATCH
} method_t;

method_t get_method(char const* method);
char const* find_header_field(harray_t const* fields, char const* name);
ssize_t has_header_field_value(harray_t const* fields, char const* name,
    char const* value, char const* delim);
char const* guess_content_type(char const* filepath, FILE* file, size_t size);
char const* get_date_and_time();

#endif /* UTILITY_H */

