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
#define HTEST_IMPL
#include "htest.h"

htest_suite_t* test_harray();
htest_suite_t* test_hbuffer();
htest_suite_t* test_hfs();
htest_suite_t* test_hhash_map();
htest_suite_t* test_hlist();
htest_suite_t* test_hserv();
htest_suite_t* test_hws();

int main(int argc, char* argv[])
{
    htest_suite_t* suites[] =
    {
        test_harray(),
        test_hbuffer(),
        test_hfs(),
        test_hhash_map(),
        test_hlist(),
        test_hserv(),
        test_hws(),
        NULL
    };

    return htest_main(argc, argv, suites);
}

