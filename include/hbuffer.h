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
#ifdef __cplusplus
extern "C"
{
#endif

#ifndef HBUFFER_H
#define HBUFFER_H

#include <stdint.h>
#include <stdlib.h>

#ifdef HBUFFER_VISIBILITY_STATIC
#define HBUFFER_VISIBILITY static
#else
#define HBUFFER_VISIBILITY extern
#endif

typedef struct hbuffer_s
{
    size_t capacity;    /* Never modify directly. */
    size_t size;        /* Shall be <= capacity. */
    void* data;         /* Never modify directly. */
} hbuffer_t;

#define HBUFFER_INIT { 0 }

HBUFFER_VISIBILITY void hbuffer_init(hbuffer_t* buffer);
HBUFFER_VISIBILITY void hbuffer_free(hbuffer_t* buffer);

HBUFFER_VISIBILITY int hbuffer_copy(hbuffer_t* dst, hbuffer_t const* src);
HBUFFER_VISIBILITY void hbuffer_move(hbuffer_t* dst, hbuffer_t* src);

HBUFFER_VISIBILITY void hbuffer_clear(hbuffer_t* buffer);
HBUFFER_VISIBILITY int hbuffer_shrink(hbuffer_t* buffer);
HBUFFER_VISIBILITY int hbuffer_reserve(hbuffer_t* buffer, size_t capacity);
HBUFFER_VISIBILITY int hbuffer_resize(hbuffer_t* buffer, size_t size);
HBUFFER_VISIBILITY int hbuffer_assign(hbuffer_t* buffer, void const* data, size_t size);
HBUFFER_VISIBILITY int hbuffer_append(hbuffer_t* buffer, void const* data, size_t size);
HBUFFER_VISIBILITY int hbuffer_insert(hbuffer_t* buffer, size_t offset, void const* data, size_t size);
HBUFFER_VISIBILITY void hbuffer_erase(hbuffer_t* buffer, size_t offset, size_t size);

HBUFFER_VISIBILITY int hbuffer_strcpy(hbuffer_t* buffer, char const* string);
HBUFFER_VISIBILITY int hbuffer_strncpy(hbuffer_t* buffer, char const* string, size_t max);
HBUFFER_VISIBILITY int hbuffer_printf(hbuffer_t* buffer, char const* format, ...);
HBUFFER_VISIBILITY int hbuffer_appendf(hbuffer_t* buffer, char const* format, ...);

#endif /* HBUFFER_H */

#ifdef HBUFFER_IMPL

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * Implementation
 */
static void* hbuffer_realloc(hbuffer_t* buffer, size_t capacity, int shrink)
{
    if (0 == shrink && capacity <= buffer->capacity) {
        return buffer->data;
    }

    void* data = realloc(buffer->data, capacity);
    if (NULL == data) {
        return NULL;
    }

    buffer->data = data;
    buffer->capacity = capacity;
    if (buffer->capacity < buffer->size) {
        buffer->size = buffer->capacity;
    }
    return data;
}

int hbuffer_vappendf(hbuffer_t* buffer, char const* format, va_list ap)
{
    ssize_t length;

    va_list apl;
    va_copy(apl, ap);

    length = vsnprintf(((char*)buffer->data) + buffer->size,
        buffer->capacity - buffer->size, format, apl);
    if (length < 0) {
        return -1;
    }

    /* Take into account that vsnprintf also needs space for a 0 terminator, */
    /* but don't include the zero terminator in the size. */
    if (buffer->size + length + 1 < buffer->capacity) {
        buffer->size += length;
        return 0;
    }

    if (NULL == hbuffer_realloc(buffer, buffer->size + length + 1, 0)) {
        return -1;
    }

    length = vsnprintf(((char*)buffer->data) + buffer->size,
        buffer->capacity - buffer->size, format, ap);
    if (length < 0) {
        return -1;
    }

    buffer->size += length;
    return length;
}

/*
 * Public
 */
void hbuffer_init(hbuffer_t* buffer)
{
    memset(buffer, 0, sizeof(*buffer));
}

void hbuffer_free(hbuffer_t* buffer)
{
    if (NULL != buffer->data) {
        free(buffer->data);
    }
    memset(buffer, 0, sizeof(*buffer));
}

int hbuffer_copy(hbuffer_t* dst, hbuffer_t const* src)
{
    hbuffer_clear(dst);
    return hbuffer_append(dst, src->data, src->size);
}

void hbuffer_move(hbuffer_t* dst, hbuffer_t* src)
{
    hbuffer_free(dst);
    memcpy(dst, src, sizeof(*dst));
    memset(src, 0, sizeof(*src));
}

void hbuffer_clear(hbuffer_t* buffer)
{
    buffer->size = 0;
}

int hbuffer_shrink(hbuffer_t* buffer)
{
    assert(buffer->size <= buffer->capacity);

    if (NULL == buffer->data || 0 == buffer->size) {
        hbuffer_free(buffer);
        return 0;
    }

    if (NULL == hbuffer_realloc(buffer, buffer->size, 1)) {
        return -1;
    }

    return 0;
}

int hbuffer_reserve(hbuffer_t* buffer, size_t capacity)
{
    assert(buffer->size <= buffer->capacity);

    if (NULL == hbuffer_realloc(buffer, capacity, 0)) {
        return -1;
    }

    return 0;
}

int hbuffer_resize(hbuffer_t* buffer, size_t size)
{
    assert(buffer->size <= buffer->capacity);

    if (size > 0 && NULL == hbuffer_realloc(buffer, size, 0)) {
        return -1;
    }

    buffer->size = size;
    return 0;
}

int hbuffer_assign(hbuffer_t* buffer, void const* data, size_t size)
{
    buffer->size = 0;
    return hbuffer_append(buffer, data, size);
}

int hbuffer_append(hbuffer_t* buffer, void const* data, size_t size)
{
    return hbuffer_insert(buffer, buffer->size, data, size);
}

int hbuffer_insert(hbuffer_t* buffer, size_t offset, void const* data, size_t size)
{
    assert(offset <= buffer->size);
    assert(buffer->size <= buffer->capacity);

    if (0 == size) {
        return 0;
    }

    if (NULL == hbuffer_realloc(buffer, buffer->size + size, 0)) {
        return -1;
    }

    uint8_t* ptr = (uint8_t*)buffer->data;

    /* Move tail. Note that when inserting at the tail, this is a NOP. */
    memmove(ptr + offset + size, ptr + offset, buffer->size - offset);

    /* Insert can be used to insert space in the middle without copying data. */
    if (NULL != data) {
        memcpy(ptr + offset, data, size);
    }
    buffer->size += size;
    return 0;
}

void hbuffer_erase(hbuffer_t* buffer, size_t offset, size_t size)
{
    assert(offset + size <= buffer->size);
    assert(buffer->size <= buffer->capacity);

    uint8_t* ptr = (uint8_t*)buffer->data;

    memmove(ptr + offset, ptr + offset + size, buffer->size - (offset + size));
    buffer->size -= size;
}

int hbuffer_strcpy(hbuffer_t* buffer, char const* string)
{
    return hbuffer_assign(buffer, string, strlen(string) + 1);
}

int hbuffer_strncpy(hbuffer_t* buffer, char const* string, size_t max)
{
    size_t length = strnlen(string, max);

    if (NULL == hbuffer_realloc(buffer, length + 1, 0)) {
        return -1;
    }

    char* ptr = (char*)buffer->data;
    memcpy(ptr, string, length);
    ptr[length] = 0;
    return 0;
}

int hbuffer_printf(hbuffer_t* buffer, char const* format, ...)
{
    assert(NULL != format);

    va_list ap;
    int r;

    va_start(ap, format);
    hbuffer_clear(buffer);
    r = hbuffer_vappendf(buffer, format, ap);
    va_end(ap);

    return r;
}

int hbuffer_appendf(hbuffer_t* buffer, char const* format, ...)
{
    assert(NULL != format);

    va_list ap;
    int r;

    va_start(ap, format);
    r = hbuffer_vappendf(buffer, format, ap);
    va_end(ap);

    return r;
}

#endif /* HBUFFER_IMPL */

#ifdef HBUFFER_IMPL_TEST

#include "htest.h"

HTEST_CASE(hbuffer)
{
    hbuffer_t buffer;
    hbuffer_init(&buffer);

    HTEST_INT(0, ==, hbuffer_assign(&buffer, "bar", 3));
    HTEST_INT(0, ==, hbuffer_append(&buffer, "baz", 3));
    HTEST_INT(0, ==, hbuffer_insert(&buffer, 0, "foo", 3));
    HTEST_INT(9, ==, buffer.capacity);
    HTEST_INT(9, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foobarbaz", 9);

    hbuffer_erase(&buffer, 3, 3);
    HTEST_INT(9, ==, buffer.capacity);
    HTEST_INT(6, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foobaz", 6);

    hbuffer_shrink(&buffer);
    HTEST_INT(6, ==, buffer.capacity);
    HTEST_INT(6, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foobaz", 6);

    HTEST_INT(0, ==, hbuffer_insert(&buffer, 3, "bar", 3));
    HTEST_INT(9, ==, buffer.capacity);
    HTEST_INT(9, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foobarbaz", 9);

    hbuffer_erase(&buffer, 6, 3);
    HTEST_INT(9, ==, buffer.capacity);
    HTEST_INT(6, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foobar", 6);

    hbuffer_erase(&buffer, 0, 3);
    HTEST_INT(9, ==, buffer.capacity);
    HTEST_INT(3, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "bar", 3);

    hbuffer_strncpy(&buffer, "foo", 3);
    HTEST_INT(9, ==, buffer.capacity);
    HTEST_INT(3, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foo", 4);

    hbuffer_clear(&buffer);
    hbuffer_shrink(&buffer);
    HTEST_INT(0, ==, buffer.capacity);
    HTEST_INT(0, ==, buffer.size);
    HTEST_POINTER(NULL, ==, buffer.data);

    HTEST_INT(3, ==, hbuffer_printf(&buffer, "%s", "foo"));
    HTEST_INT(4, ==, buffer.capacity);
    HTEST_INT(3, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foo", 4);

    HTEST_INT(3, ==, hbuffer_appendf(&buffer, "%s", "bar"));
    HTEST_INT(7, ==, buffer.capacity);
    HTEST_INT(6, ==, buffer.size);
    HTEST_MEMORY(buffer.data, ==, "foobar", 7);

    hbuffer_free(&buffer);
}

htest_suite_t hbuffer_test_suite =
{
    HTEST_CASE_REF(hbuffer),
    NULL
};

#endif /* HBUFFER_IMPL_TEST */

#ifdef __cplusplus
}
#endif

