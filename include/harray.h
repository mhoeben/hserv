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

#ifndef HARRAY_H
#define HARRAY_H

#include <stdint.h>
#include <stdlib.h>

#ifdef HARRAY_VISIBILITY_STATIC
#define HARRAY_VISIBILITY static
#else
#define HARRAY_VISIBILITY extern
#endif

typedef struct harray_s
{
    size_t sizeof_type; /* Never modify directly. */
    size_t capacity;    /* Never modify directly. */
    size_t size;        /* Shall be <= capacity. */
    void* data;         /* Never modify directly. */
} harray_t;

#define HARRAY_INIT(sizeof_type) { sizeof_type, 0, 0, NULL }

HARRAY_VISIBILITY void harray_init(harray_t* array, size_t sizeof_type);
HARRAY_VISIBILITY void harray_free(harray_t* array);

HARRAY_VISIBILITY int harray_copy(harray_t* dst, harray_t const* src);
HARRAY_VISIBILITY void harray_move(harray_t* dst, harray_t* src);

HARRAY_VISIBILITY void* harray_at(harray_t* array, size_t index);

HARRAY_VISIBILITY void harray_clear(harray_t* array);
HARRAY_VISIBILITY int harray_shrink(harray_t* array);
HARRAY_VISIBILITY int harray_reserve(harray_t* array, size_t capacity);
HARRAY_VISIBILITY int harray_resize(harray_t* array, size_t size);
HARRAY_VISIBILITY int harray_push_back(harray_t* array, void const* value);
HARRAY_VISIBILITY void harray_pop_back(harray_t* array);
HARRAY_VISIBILITY int harray_insert(harray_t* array, size_t index, void const* value);
HARRAY_VISIBILITY void harray_erase(harray_t* array, size_t index);

#endif /* HARRAY_H */

#ifdef HARRAY_IMPL

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * Implementation
 */
static void* harray_realloc(harray_t* array, size_t capacity, int shrink)
{
    if (0 == shrink && capacity <= array->capacity) {
        return array->data;
    }

    void* data = realloc(array->data, array->sizeof_type * capacity);
    if (NULL == data) {
        return NULL;
    }

    array->data = data;
    array->capacity = capacity;
    if (array->capacity < array->size) {
        array->size = array->capacity;
    }
    return data;
}

/*
 * Public
 */
void harray_init(harray_t* array, size_t sizeof_type)
{
    memset(array, 0, sizeof(*array));
    array->sizeof_type = sizeof_type;
}

void harray_free(harray_t* array)
{
    if (NULL != array->data) {
        free(array->data);
    }
    memset(array, 0, sizeof(*array));
}

int harray_copy(harray_t* dst, harray_t const* src)
{
    assert(dst->sizeof_type == src->sizeof_type);

    harray_clear(dst);

    if (0 == src->size) {
        return 0;
    }

    if (NULL == harray_realloc(dst, src->size, 0)) {
        return -1;
    }

    dst->size = src->size;
    memcpy(dst->data, src->data, src->size * src->sizeof_type);
    return 0;
}

void harray_move(harray_t* dst, harray_t* src)
{
    assert(dst->sizeof_type == src->sizeof_type);

    harray_free(dst);
    memcpy(dst, src, sizeof(*dst));
    memset(src, 0, sizeof(*src));
}

void* harray_at(harray_t* array, size_t index)
{
    return ((uint8_t*)array->data) + (index * array->sizeof_type);
}

void harray_clear(harray_t* array)
{
    array->size = 0;
}

int harray_shrink(harray_t* array)
{
    assert(array->size <= array->capacity);

    if (NULL == array->data || 0 == array->size) {
        harray_free(array);
        return 0;
    }

    if (NULL == harray_realloc(array, array->size, 1)) {
        return -1;
    }

    return 0;
}

int harray_reserve(harray_t* array, size_t capacity)
{
    assert(array->size <= array->capacity);

    if (NULL == harray_realloc(array, capacity, 0)) {
        return -1;
    }

    return 0;
}

int harray_resize(harray_t* array, size_t size)
{
    assert(array->size <= array->capacity);

    if (size > 0 && NULL == harray_realloc(array, size, 0)) {
        return -1;
    }

    array->size = size;
    return 0;
}

int harray_push_back(harray_t* array, void const* value)
{
    return harray_insert(array, array->size, value);
}

void harray_pop_back(harray_t* array)
{
    --array->size;
}

int harray_insert(harray_t* array, size_t index, void const* value)
{
    assert(index <= array->size);
    assert(array->size <= array->capacity);

    if (NULL == harray_realloc(array, array->size + 1, 0)) {
        return -1;
    }

    uint8_t* ptr = (uint8_t*)array->data;
    index *= array->sizeof_type;

    /* Move tail. Note that when inserting at the tail, this is a NOP. */
    memmove(ptr + index + array->sizeof_type, ptr + index,
        (array->size * array->sizeof_type) - index);

    /* Insert can be used to insert space in the middle without copying data. */
    if (NULL != value) {
        memcpy(ptr + index, value, array->sizeof_type);
    }

    ++array->size;
    return 0;
}

void harray_erase(harray_t* array, size_t index)
{
    assert(index < array->size);
    assert(array->size <= array->capacity);

    uint8_t* ptr = (uint8_t*)array->data;
    index *= array->sizeof_type;

    memmove(ptr + index, ptr + index + array->sizeof_type,
        (array->size * array->sizeof_type) - (index + array->sizeof_type));
    --array->size;
}

#endif /* HARRAY_IMPL */

#ifdef HARRAY_IMPL_TEST

#include "htest.h"

HTEST_CASE(harray)
{
    typedef struct foo_s
    {
        char b;
        char a;
        char r;
    } foo_t;

    harray_t array;
    harray_init(&array, sizeof(foo_t));

    foo_t foo0 = { 'b', 'a', 'r' };
    foo_t foo1 = { 'b', 'a', 'z' };
    foo_t foo2 = { 'x', 'y', 'z' };

    HTEST_INT(0, ==, harray_push_back(&array, &foo0));
    HTEST_INT(0, ==, harray_push_back(&array, &foo1));
    HTEST_INT(0, ==, harray_push_back(&array, &foo2));
    HTEST_INT(3, ==, array.capacity);
    HTEST_INT(3, ==, array.size);

    HTEST_MEMORY(&foo0, ==, harray_at(&array, 0), sizeof(foo_t));
    HTEST_MEMORY(&foo1, ==, harray_at(&array, 1), sizeof(foo_t));
    HTEST_MEMORY(&foo2, ==, harray_at(&array, 2), sizeof(foo_t));

    harray_erase(&array, 1);
    HTEST_INT(3, ==, array.capacity);
    HTEST_INT(2, ==, array.size);

    HTEST_MEMORY(&foo0, ==, harray_at(&array, 0), sizeof(foo_t));
    HTEST_MEMORY(&foo2, ==, harray_at(&array, 1), sizeof(foo_t));

    HTEST_INT(0, ==, harray_insert(&array, 1, &foo1));
    HTEST_INT(3, ==, array.capacity);
    HTEST_INT(3, ==, array.size);

    HTEST_MEMORY(&foo0, ==, harray_at(&array, 0), sizeof(foo_t));
    HTEST_MEMORY(&foo1, ==, harray_at(&array, 1), sizeof(foo_t));
    HTEST_MEMORY(&foo2, ==, harray_at(&array, 2), sizeof(foo_t));

    harray_erase(&array, 0);
    HTEST_MEMORY(&foo1, ==, harray_at(&array, 0), sizeof(foo_t));
    HTEST_MEMORY(&foo2, ==, harray_at(&array, 1), sizeof(foo_t));

    HTEST_INT(0, ==, harray_insert(&array, 0, &foo0));
    HTEST_MEMORY(&foo0, ==, harray_at(&array, 0), sizeof(foo_t));
    HTEST_MEMORY(&foo1, ==, harray_at(&array, 1), sizeof(foo_t));
    HTEST_MEMORY(&foo2, ==, harray_at(&array, 2), sizeof(foo_t));

    harray_erase(&array, 2);
    HTEST_MEMORY(&foo0, ==, harray_at(&array, 0), sizeof(foo_t));
    HTEST_MEMORY(&foo1, ==, harray_at(&array, 1), sizeof(foo_t));

    harray_clear(&array);
    HTEST_INT(3, ==, array.capacity);
    HTEST_INT(0, ==, array.size);

    harray_free(&array);
}

htest_suite_t harray_test_suite =
{
    HTEST_CASE_REF(harray),
    NULL
};

#endif /* HARRAY_IMPL_TEST */

#ifdef __cplusplus
}
#endif

