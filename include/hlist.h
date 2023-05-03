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

#ifndef HLIST_H
#define HLIST_H

#include <stdlib.h>

typedef struct hlist_s
{
    struct hlist_s* next;
    struct hlist_s* prev;
} hlist_t;

typedef struct hlist_s hlist_element_t;
typedef struct hlist_s hlist_iterator_t;

#define HLIST_INIT(list) { &list, &list }

static inline void hlist_init(hlist_t* list)
{
    list->next = list;
    list->prev = list;
}

static inline hlist_iterator_t* hlist_begin(hlist_t* list)
{
    return list->next;
}

static inline hlist_iterator_t* hlist_end(hlist_t* list)
{
    return list;
}

static inline int hlist_iterate(hlist_t* list,
    int(*callback)(hlist_iterator_t*, void*), void* user_data)
{
    hlist_iterator_t* it = hlist_begin(list);
    hlist_iterator_t* current;

    while (it != hlist_end(list)) {
        current = it;
        it = it->next;

        if (callback(current, user_data) < 0) {
            return -1;
        }
    }

    return 0;
}

static inline int hlist_empty(hlist_t* list)
{
    return hlist_begin(list) == hlist_end(list);
}

static inline size_t hlist_size(hlist_t* list)
{
    size_t size = 0;
    hlist_iterator_t* it = hlist_begin(list);

    while (it != hlist_end(list)) {
        ++size;
        it = it->next;
    }

    return size;
}

static inline void hlist_insert(hlist_iterator_t* before, hlist_element_t* element)
{
    element->next = before;
    element->prev = before->prev;

    before->prev->next = element;
    before->prev = element;
}

static inline void hlist_erase(hlist_iterator_t* it)
{
    it->prev->next = it->next;
    it->next->prev = it->prev;

    it->prev = it;
    it->next = it;
}

static inline void hlist_push_front(hlist_t* list, hlist_element_t* element)
{
    hlist_insert(hlist_begin(list), element);
}

static inline void hlist_push_back(hlist_t* list, hlist_element_t* element)
{
    hlist_insert(hlist_end(list), element);
}

#endif /* HLIST_H */

#ifdef HLIST_IMPL_TEST

#include "htest.h"

HTEST_CASE(hlist)
{
    typedef struct element_s
    {
        hlist_element_t element;
        char const* name;
    } element_t;

    element_t foo = { { NULL }, "foo" };
    element_t bar = { { NULL }, "bar" };
    element_t baz = { { NULL }, "baz" };
    hlist_iterator_t* it;

    hlist_t list = HLIST_INIT(list);
    HTEST_INT(1, ==, hlist_empty(&list));

    hlist_push_back(&list, &foo.element);
    hlist_push_back(&list, &bar.element);
    hlist_push_back(&list, &baz.element);
    HTEST_INT(0, ==, hlist_empty(&list));
    HTEST_INT(3, ==, hlist_size(&list));

    it = hlist_begin(&list);
    HTEST_STRING("foo", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_STRING("bar", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_STRING("baz", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_POINTER(hlist_end(&list), ==, it);

    hlist_erase(&bar.element);
    HTEST_INT(2, ==, hlist_size(&list));

    it = hlist_begin(&list);
    HTEST_STRING("foo", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_STRING("baz", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_POINTER(hlist_end(&list), ==, it);

    hlist_erase(&foo.element);
    hlist_erase(&baz.element);
    HTEST_INT(1, ==, hlist_empty(&list));

    hlist_push_front(&list, &foo.element);
    hlist_push_front(&list, &bar.element);
    hlist_push_front(&list, &baz.element);

    it = hlist_begin(&list);
    HTEST_STRING("baz", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_STRING("bar", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_STRING("foo", ==, ((element_t*)it)->name);
    it = it->next;
    HTEST_POINTER(hlist_end(&list), ==, it);
}

htest_suite_t hlist_test_suite =
{
    HTEST_CASE_REF(hlist),
    NULL
};

#endif /* HLIST_IMPL_TEST */

#ifdef __cplusplus
}
#endif

