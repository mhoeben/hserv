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

#ifndef HFS_H
#define HFS_H

#include <stdint.h>
#include <stdlib.h>

#ifdef HFS_VISIBILITY_STATIC
#define HFS_VISIBILITY static
#else
#define HFS_VISIBILITY extern
#endif

HFS_VISIBILITY char const* hfs_strip_path(char const* filepath);

HFS_VISIBILITY char* hfs_strip_filename(char *filepath);

HFS_VISIBILITY int hfs_canonicalize_path(char* path);

HFS_VISIBILITY int hfs_mkdir_recursive(char const* path, mode_t mode);

#endif /* HFS_H */

#ifdef HFS_IMPL

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

char const* hfs_strip_path(char const* filepath)
{
    char const* slash = strrchr(filepath, '/');
    return NULL == slash ? filepath : slash + 1;
}

char* hfs_strip_filename(char *filepath)
{
    char* slash = strrchr(filepath, '/');
    if (NULL != slash) {
        *slash = 0;
    }
    else {
        *filepath = 0;
    }

    return filepath;
}

int hfs_canonicalize_path(char* path)
{
    assert(NULL != path);

    size_t length = strlen(path);

    /* Don't modify an empty path. */
    if (0 == length) {
        return 1;
    }

    /* Remember trailing character. */
    // char trailing_char = path[length - 1];

    /* Make a relative path. */
    char* start = '/' == *path ? path + 1 : path;
    char* end = start;

    int count = 0;

    /* Canonicalize path by applying "../" and filtering "./". Note that */
    /* this works from the assumption that a canonicalized path length never */
    /* exceeds the passed path length. */
    for (char* component = start, *temp; ; component = NULL) {
        /* Progressively tokenize path components in place. */
        component = strtok_r(component, "/", &temp);
        if (NULL == component) {
            break;
        }
        /* Should automatically handle empty components like "//". */
        assert(0 != component[0]);

        /* Handle "." and "..". */
        if ('.' == component[0]) {
            /* ".."? */
            if ('.' == component[1] && 0 == component[2]) {
                if (0 == count) {
                    /* Reject because path addresses above root. */
                    return -1;
                }
                /* Find last canonical path component. */
                end = strrchr(start, '/');
                if (NULL == end) {
                    end = start;
                }
                /* Pop path component by 0 terminating. */
                *end = 0;
                --count;
                continue;
            }
            /* "."? Ignore as a path component, unless it is at the start. */
            else if (0 == component[1]) {
                /* Ignore "." as a path component. */
                continue;
            }
        }

        length = strlen(component);

        /* Move path component to end of canonical path. */
        if (count > 0) {
            *end++ = '/';
        }
        memmove(end, component, length + 1);
        end += length;
        ++count;
    }

    /* Zero terminate. */
    *end = 0;
    return 0;
}

int hfs_mkdir_recursive(char const* path, mode_t mode)
{
    assert(NULL != path);

    char* temp = strdup(path);
    if (NULL == temp) {
        errno = ENOMEM;
        return -1;
    }
    char* ptr = temp;
    struct stat st;

    ptr += '/' == *ptr;

    while (NULL != ptr) {
        ptr = strchr(ptr, '/');
        if (NULL != ptr) {
            *ptr = 0;
        }

        if (-1 == stat(temp, &st)) {
            if (ENOENT != errno) {
                free(temp);
                return -1;
            }

            if (-1 == mkdir(temp, mode)) {
                free(temp);
                return -1;
            }
        }
        else if (!S_ISDIR(st.st_mode)) {
            free(temp);
            errno = ENOTDIR;
            return -1;
        }

        if (NULL != ptr) {
            *ptr++ = '/';
        }
    }

    free(temp);
    return 0;
}

#endif /* HFS_IMPL */

#ifdef HFS_IMPL_TEST

#include "htest.h"

static char hfs_test_buffer[256];

static char const* hfs_test_strip_filename(char const* filepath)
{
    memset(hfs_test_buffer, 0, sizeof(hfs_test_buffer));
    snprintf(hfs_test_buffer, sizeof(hfs_test_buffer), "%s", filepath);
    return hfs_strip_filename(hfs_test_buffer);
}

static char const* hfs_test_canonicalize_path(char const* path)
{
    memset(hfs_test_buffer, 0, sizeof(hfs_test_buffer));

    snprintf(hfs_test_buffer, sizeof(hfs_test_buffer), "%s", path);
    if (-1 == hfs_canonicalize_path(hfs_test_buffer)) {
        strcpy(hfs_test_buffer, "FAILED");
    }

    return hfs_test_buffer;
}

HTEST_CASE(hfs_strip_path)
{
    HTEST_STRING(hfs_strip_path("foo"), ==, "foo");
    HTEST_STRING(hfs_strip_path("bar/foo"), ==, "foo");
    HTEST_STRING(hfs_strip_path("/bar/foo"), ==, "foo");
    HTEST_STRING(hfs_strip_path("/bar/"), ==, "");
}

HTEST_CASE(hfs_strip_filename)
{
    HTEST_STRING(hfs_test_strip_filename("foo"), ==, "");
    HTEST_STRING(hfs_test_strip_filename("bar/foo"), ==, "bar");
    HTEST_STRING(hfs_test_strip_filename("/bar/foo"), ==, "/bar");
    HTEST_STRING(hfs_test_strip_filename("/bar/"), ==, "/bar");
}

HTEST_CASE(hfs_canonicalize_path)
{
    /* Tests from https://github.com/duanev/path-canon-c/blob/master/pathcanon.c */
    HTEST_STRING(hfs_test_canonicalize_path(""), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path("/"), ==, "/");
    HTEST_STRING(hfs_test_canonicalize_path("//"), ==, "/");
    HTEST_STRING(hfs_test_canonicalize_path("///"), ==, "/");
    HTEST_STRING(hfs_test_canonicalize_path("/foo"), ==, "/foo");
    HTEST_STRING(hfs_test_canonicalize_path("//foo"), ==, "/foo");
    HTEST_STRING(hfs_test_canonicalize_path("///foo"), ==, "/foo");
    HTEST_STRING(hfs_test_canonicalize_path("foo"), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("foo/"), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("foo//"), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("foo/bar"), ==, "foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo//bar"), ==, "foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo///bar"), ==, "foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo/./bar"), ==, "foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo/x/../bar"), ==, "foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path(".."), ==, "FAILED");
    HTEST_STRING(hfs_test_canonicalize_path("/.."), ==, "FAILED");
    HTEST_STRING(hfs_test_canonicalize_path("../bar"), ==, "FAILED");
    HTEST_STRING(hfs_test_canonicalize_path("/../bar"), ==, "FAILED");
    HTEST_STRING(hfs_test_canonicalize_path("//../bar"), ==, "FAILED");
    HTEST_STRING(hfs_test_canonicalize_path("./../bar"), ==, "FAILED");
    HTEST_STRING(hfs_test_canonicalize_path("./"), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path(".//"), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path(".///"), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path("./foo"), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("././foo"), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("./../foo"), ==, "FAILED");
    HTEST_STRING(hfs_test_canonicalize_path("foo/."), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("foo/./."), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/."), ==, "/foo");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/./."), ==, "/foo");
    HTEST_STRING(hfs_test_canonicalize_path("/./foo/."), ==, "/foo");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/././bar"), ==, "/foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo/../bar"), ==, "bar");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/../bar"), ==, "/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo/./../bar"), ==, "bar");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/./../bar"), ==, "/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo/xyz/../bar"), ==, "foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/xyz/../bar"), ==, "/foo/bar");
    HTEST_STRING(hfs_test_canonicalize_path("foo/xyz/../../bar"), ==, "bar");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/xyz/../../bar"), ==, "/bar");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/.."), ==, "/");
    HTEST_STRING(hfs_test_canonicalize_path("foo/.."), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path("foo/bar/.."), ==, "foo");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/bar/.."), ==, "/foo");
    HTEST_STRING(hfs_test_canonicalize_path("foo/bar/../.."), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/bar/../.."), ==, "/");
    HTEST_STRING(hfs_test_canonicalize_path("foo/bar/../../."), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/bar/../../."), ==, "/");
    HTEST_STRING(hfs_test_canonicalize_path("foo/bar/.././.."), ==, "");
    HTEST_STRING(hfs_test_canonicalize_path("/foo/bar/.././.."), ==, "/");
    HTEST_STRING(hfs_test_canonicalize_path("foo////..////z////"), ==, "z");
    HTEST_STRING(hfs_test_canonicalize_path("/////foo////..////z////"), ==, "/z");
    HTEST_STRING(hfs_test_canonicalize_path("d/./e/.././o/f/g/./h/../../.././n/././e/./i/.."), ==, "d/o/n/e");
}

static htest_suite_t hfs_test_suite =
{
    HTEST_CASE_REF(hfs_strip_path),
    HTEST_CASE_REF(hfs_strip_filename),
    HTEST_CASE_REF(hfs_canonicalize_path),
    NULL
};

#endif /* HFS_IMPL_TEST */

#ifdef __cplusplus
}
#endif

