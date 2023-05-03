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

#ifndef HTEST_H
#define HTEST_H

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HTEST_VISIBILITY_STATIC
#define HTEST_VISIBILITY static
#else
#define HTEST_VISIBILITY extern
#endif

void htest_print_hex(FILE* out, void const* data, size_t size);

HTEST_VISIBILITY void htest_print_error(FILE* out,
    char const* file, int line, char const* format, ...);

#define HTEST_ASSERT(type, stringify, a, op, b) \
    do { \
        type htest_a = (a); \
        type htest_b = (b); \
        if (!(htest_a op htest_b)) { \
            htest_print_error(stderr, __FILE__, __LINE__, \
                "assertion failed: %s %s %s (%s %s %s)", \
                #a, #op, #b, stringify(0, htest_a), #op, stringify(1, htest_b)); \
            return; \
        } \
    } \
    while (0)

HTEST_VISIBILITY char const* htest_stringify_char(int a_or_b, char value);
HTEST_VISIBILITY char const* htest_stringify_uchar(int a_or_b, unsigned char value);

HTEST_VISIBILITY char const* htest_stringify_short(int a_or_b, short value);
HTEST_VISIBILITY char const* htest_stringify_ushort(int a_or_b, unsigned short value);

HTEST_VISIBILITY char const* htest_stringify_int(int a_or_b, int value);
HTEST_VISIBILITY char const* htest_stringify_uint(int a_or_b, unsigned int value);

HTEST_VISIBILITY char const* htest_stringify_long(int a_or_b, long value);
HTEST_VISIBILITY char const* htest_stringify_ulong(int a_or_b, unsigned long value);

HTEST_VISIBILITY char const* htest_stringify_llong(int a_or_b, long long value);
HTEST_VISIBILITY char const* htest_stringify_ullong(int a_or_b, unsigned long long value);

HTEST_VISIBILITY char const* htest_stringify_float(int a_or_b, float value);
HTEST_VISIBILITY char const* htest_stringify_double(int a_or_b, double value);

HTEST_VISIBILITY char const* htest_stringify_int8(int a_or_b, int8_t value);
HTEST_VISIBILITY char const* htest_stringify_int16(int a_or_b, int16_t value);
HTEST_VISIBILITY char const* htest_stringify_int32(int a_or_b, int32_t value);
HTEST_VISIBILITY char const* htest_stringify_int64(int a_or_b, int64_t value);

HTEST_VISIBILITY char const* htest_stringify_uint8(int a_or_b, uint8_t value);
HTEST_VISIBILITY char const* htest_stringify_uint16(int a_or_b, uint16_t value);
HTEST_VISIBILITY char const* htest_stringify_uint32(int a_or_b, uint32_t value);
HTEST_VISIBILITY char const* htest_stringify_uint64(int a_or_b, uint64_t value);

HTEST_VISIBILITY char const* htest_stringify_size(int a_or_b, size_t value);
HTEST_VISIBILITY char const* htest_stringify_uintptr(int a_or_b, uintptr_t value);
HTEST_VISIBILITY char const* htest_stringify_pointer(int a_or_b, void const* value);

#define HTEST_CHAR(a, op, b) \
    HTEST_ASSERT(char, htest_stringify_char, a, op, b)
#define HTEST_UCHAR(a, op, b) \
    HTEST_ASSERT(unsigned char, htest_stringify_uchar, a, op, b)

#define HTEST_SHORT(a, op, b) \
    HTEST_ASSERT(short, htest_stringify_short, a, op, b)
#define HTEST_USHORT(a, op, b) \
    HTEST_ASSERT(unsigned short, htest_stringify_ushort, a, op, b)

#define HTEST_INT(a, op, b) \
    HTEST_ASSERT(int, htest_stringify_int, a, op, b)
#define HTEST_UINT(a, op, b) \
    HTEST_ASSERT(unsigned int, htest_stringify_uint, a, op, b)

#define HTEST_LONG(a, op, b) \
    HTEST_ASSERT(long, htest_stringify_long, a, op, b)
#define HTEST_ULONG(a, op, b) \
    HTEST_ASSERT(unsigned long, htest_stringify_ulong, a, op, b)

#define HTEST_LLONG(a, op, b) \
    HTEST_ASSERT(long long, htest_stringify_llong, a, op, b)
#define HTEST_ULLONG(a, op, b) \
    HTEST_ASSERT(unsigned long long, htest_stringify_ullong, a, op, b)

#define HTEST_FLOAT(a, op, b) \
    HTEST_ASSERT(float, htest_stringify_float, a, op, b)
#define HTEST_DOUBLE(a, op, b) \
    HTEST_ASSERT(double, htest_stringify_double, a, op, b)

#define HTEST_INT8(a, op, b) \
    HTEST_ASSERT(int8_t, htest_stringify_int8, a, op, b)
#define HTEST_INT16(a, op, b) \
    HTEST_ASSERT(int16_t, htest_stringify_int16, a, op, b)
#define HTEST_INT32(a, op, b) \
    HTEST_ASSERT(int32_t, htest_stringify_int32, a, op, b)
#define HTEST_INT64(a, op, b) \
    HTEST_ASSERT(int64_t, htest_stringify_int64, a, op, b)

#define HTEST_UINT8(a, op, b) \
    HTEST_ASSERT(uint8_t, htest_stringify_uint8, a, op, b)
#define HTEST_UINT16(a, op, b) \
    HTEST_ASSERT(uint16_t, htest_stringify_uint16, a, op, b)
#define HTEST_UINT32(a, op, b) \
    HTEST_ASSERT(uint32_t, htest_stringify_uint32, a, op, b)
#define HTEST_UINT64(a, op, b) \
    HTEST_ASSERT(uint64_t, htest_stringify_uint64, a, op, b)

#define HTEST_SIZE(a, op, b) \
    HTEST_ASSERT(size_t, htest_stringify_size, a, op, b)
#define HTEST_UINTPTR(a, op, b) \
    HTEST_ASSERT(uintptr_t , htest_stringify_uinptr, a, op, b)
#define HTEST_POINTER(a, op, b) \
    HTEST_ASSERT(void const*, htest_stringify_pointer, a, op, b)

#define HTEST_STRING(a, op, b) \
    do { \
        if (!(0 op strcmp((a), (b)))) { \
            htest_print_error(stderr, __FILE__, __LINE__, \
                "assertion failed: %s %s %s (\"%s\" %s \"%s\")", \
                #a, #op, #b, a, #op, b); \
            return; \
        } \
    } \
    while (0)

#define HTEST_MEMORY(a, op, b, size) \
    do { \
        uint8_t const* htest_a = (uint8_t const*)(a); \
        uint8_t const* htest_b = (uint8_t const*)(b); \
        if (NULL == htest_a) { \
            htest_print_error(stderr, __FILE__, __LINE__, \
                "assertion failed: %s != NULL", #a); \
        } \
        if (NULL == htest_b) { \
            htest_print_error(stderr, __FILE__, __LINE__, \
                "assertion failed: %s != NULL", #b); \
        } \
        for (size_t htest_i = 0; htest_i < size; ++htest_i) { \
            if (!(htest_a[htest_i] op htest_b[htest_i])) { \
                htest_print_error(stderr, __FILE__, __LINE__, \
                    "assertion failed: %s[%zu] %s %s[%zu] (%#02x %s %#02x)", \
                    #a, htest_i, #op, #b, htest_i, \
                    htest_a[htest_i], #op, htest_b[htest_i]); \
            } \
        } \
    } \
    while (0)

#define HTEST_TRUE(expr) \
    do { \
        int htest_a = !!(expr); \
        if (!htest_a) { \
            htest_print_error(stderr, __FILE__, __LINE__, \
                "assertion failed: true == %s" \
                    #expr); \
            return; \
        } \
    } \
    while (0)

#define HTEST_FALSE(expr) \
    do { \
        int htest_a = !(expr); \
        if (!htest_a) { \
            htest_print_error(stderr, __FILE__, __LINE__, \
                "assertion failed: false == %s" \
                    #expr); \
            return; \
        } \
    } \
    while (0)

#define HTEST_ERROR(string) \
    do { \
        htest_print_error(stderr, __FILE__, __LINE__, "error: %s", string); \
        return; \
    } \
    while (0)

typedef struct htest_case_s
{
    char const* name;
    void(*function)(void);
} htest_case_t;

typedef htest_case_t const* htest_suite_t[];

#define HTEST_CASE(name) \
    void htest_case_impl_##name(void); \
    htest_case_t const htest_case_##name = { #name, htest_case_impl_##name }; \
    void htest_case_impl_##name(void)

#define HTEST_CASE_REF(name) &htest_case_##name

HTEST_VISIBILITY int htest_main(int argc, char* argv[],
    htest_suite_t* suite[]);

#endif /* HTEST_H */

#ifdef HTEST_IMPL

/*
 * Implementation
 */
#include <inttypes.h>

#define HTEST_STRINGIFY_BUFFER_SIZE 40

char htest_string_a[HTEST_STRINGIFY_BUFFER_SIZE];
char htest_string_b[HTEST_STRINGIFY_BUFFER_SIZE];

static char const* htest_stringify(int a_or_b, char const* format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(0 == a_or_b ? htest_string_a : htest_string_b,
        HTEST_STRINGIFY_BUFFER_SIZE, format, ap);
    va_end(ap);
    return 0 == a_or_b ? htest_string_a : htest_string_b;
}

/*
 * Public
 */
void htest_print_hex(FILE* out, void const* data, size_t size)
{
    static char const* hex_digit = "0123456789abcdef";
    uint8_t const* ptr = (uint8_t const*)data;
    size_t i;
    size_t j;
    char buffer[128] = { 0 };
    char* ascii = buffer + 58;

    memset(buffer, ' ', 58 + 16);
    buffer[58 + 16] = '\0';
    buffer[58 + 17] = '\0';
    buffer[0] = '0';
    buffer[1] = '0';
    buffer[2] = '0';
    buffer[3] = '0';

    for (i = 0, j = 0; i < size; i++, j++) {
        if (j == 16) {
            fprintf(out, "%s\n", buffer);
            memset(buffer, ' ', 58 + 16);

            buffer[0] = hex_digit[(i >> 12) & 0xf];
            buffer[1] = hex_digit[(i >> 8) & 0xf];
            buffer[2] = hex_digit[(i >> 4) & 0xf];
            buffer[3] = hex_digit[(i >> 0) & 0xf];
            j = 0;
        }

        buffer[8 + (j * 3) + 0] = hex_digit[ptr[i] >> 4];
        buffer[8 + (j * 3) + 1] = hex_digit[ptr[i] & 0xf];
        ascii[j] = isprint(ptr[i]) ? ptr[i] : '.';
    }

    if (j != 0) {
        fprintf(out, "%s\n", buffer);
    }
}

void htest_print_error(FILE* out, char const* file, int line, char const* format, ...)
{
    fprintf(out, "%s:%d: ", file, line);

    va_list ap;
    va_start(ap, format);
    vfprintf(out, format, ap);
    va_end(ap);

    fputs("\n", out);
}

char const* htest_stringify_char(int a_or_b, char value)
{
    return htest_stringify(a_or_b, "'%c'(%d,%#02x)",
        isprint(value) ? value : '.', value, value);
}

char const* htest_stringify_uchar(int a_or_b, unsigned char value)
{
    return htest_stringify(a_or_b, "%#02x", value);
}

char const* htest_stringify_short(int a_or_b, short value)
{
    return htest_stringify(a_or_b, "%d", value);
}

char const* htest_stringify_ushort(int a_or_b, unsigned short value)
{
    return htest_stringify(a_or_b, "%u", value);
}

char const* htest_stringify_int(int a_or_b, int value)
{
    return htest_stringify(a_or_b, "%d", value);
}

char const* htest_stringify_uint(int a_or_b, unsigned int value)
{
    return htest_stringify(a_or_b, "%u", value);
}

char const* htest_stringify_long(int a_or_b, long value)
{
    return htest_stringify(a_or_b, "%ld", value);
}

char const* htest_stringify_ulong(int a_or_b, unsigned long value)
{
    return htest_stringify(a_or_b, "%lu", value);
}

char const* htest_stringify_llong(int a_or_b, long long value)
{
    return htest_stringify(a_or_b, "%lld", value);
}

char const* htest_stringify_ullong(int a_or_b, unsigned long long value)
{
    return htest_stringify(a_or_b, "%llu", value);
}

char const* htest_stringify_float(int a_or_b, float value)
{
    return htest_stringify(a_or_b, "%f", value);
}

char const* htest_stringify_double(int a_or_b, double value)
{
    return htest_stringify(a_or_b, "%lf", value);
}

char const* htest_stringify_int8(int a_or_b, int8_t value)
{
    return htest_stringify(a_or_b, "%" PRId8, value);
}

char const* htest_stringify_int16(int a_or_b, int16_t value)
{
    return htest_stringify(a_or_b, "%" PRId16, value);
}

char const* htest_stringify_int32(int a_or_b, int32_t value)
{
    return htest_stringify(a_or_b, "%" PRId32, value);
}

char const* htest_stringify_int64(int a_or_b, int64_t value)
{
    return htest_stringify(a_or_b, "%" PRId64, value);
}

char const* htest_stringify_uint8(int a_or_b, uint8_t value)
{
    return htest_stringify(a_or_b, "%" PRIu8, value);
}

char const* htest_stringify_uint16(int a_or_b, uint16_t value)
{
    return htest_stringify(a_or_b, "%" PRIu16, value);
}

char const* htest_stringify_uint32(int a_or_b, uint32_t value)
{
    return htest_stringify(a_or_b, "%" PRIu32, value);
}

char const* htest_stringify_uint64(int a_or_b, uint64_t value)
{
    return htest_stringify(a_or_b, "%" PRIu64, value);
}

char const* htest_stringify_size(int a_or_b, size_t value)
{
    return htest_stringify(a_or_b, "%zu", value);
}

char const* htest_stringify_uintptr(int a_or_b, uintptr_t value)
{
    return htest_stringify(a_or_b, "%" PRIxPTR, value);
}

char const* htest_stringify_pointer(int a_or_b, void const* value)
{
    return htest_stringify(a_or_b, "%p", value);
}

int htest_main(int argc, char* argv[], htest_suite_t* suites[])
{
    (void)argc;
    (void)argv;

    if (NULL == suites) {
        return 0;
    }

    for (size_t i = 0; NULL != suites[i]; ++i) {
        htest_suite_t* suite = suites[i];
        for (size_t j = 0; NULL != (*suite)[j]; ++j) {
            (*suite)[j]->function();
        }
    }

    return 0;
}

#endif /* HTEST_IMPL */

#ifdef __cplusplus
}
#endif

