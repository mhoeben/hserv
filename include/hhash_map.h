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
 * Inspired by and code fragments from https://github.com/sheredom/hashmap.h
 */
#ifdef __cplusplus
extern "C"
{
#endif

#ifndef HHASH_MAP_H
#define HHASH_MAP_H

#include <stdint.h>
#include <stdlib.h>

#ifdef HHASH_MAP_VISIBILITY_STATIC
#define HHASH_MAP_VISIBILITY static
#else
#define HHASH_MAP_VISIBILITY extern
#endif

typedef struct hhash_map_s
{
    size_t capacity;
    size_t size;
    struct hhash_map_entry_s* entries;
} hhash_map_t;

typedef size_t hhash_map_iterator_t;

#define HHASH_MAP_INIT   { 0 }

#ifndef HHASH_MAP_MAX_ITERATIONS
#define HHASH_MAP_MAX_ITERATIONS   8
#endif

HHASH_MAP_VISIBILITY int hhash_map_init(hhash_map_t* map, size_t capacity);

HHASH_MAP_VISIBILITY void hhash_map_free(hhash_map_t* map);

HHASH_MAP_VISIBILITY int hhash_map_reserve(hhash_map_t* map, size_t capacity);

HHASH_MAP_VISIBILITY void hhash_map_clear(hhash_map_t* map);

HHASH_MAP_VISIBILITY int hhash_map_insert(hhash_map_t* map,
    void const* key, size_t key_length, void const* value);

HHASH_MAP_VISIBILITY void const* hhash_map_erase(hhash_map_t* map,
    void const* key, size_t key_length);

HHASH_MAP_VISIBILITY void const* hhash_map_find(hhash_map_t* map,
    void const* key, size_t key_length);

HHASH_MAP_VISIBILITY hhash_map_iterator_t hhash_map_begin(hhash_map_t* map);

HHASH_MAP_VISIBILITY hhash_map_iterator_t hhash_map_end(hhash_map_t* map);

HHASH_MAP_VISIBILITY hhash_map_iterator_t hhash_map_next(hhash_map_t* map,
    hhash_map_iterator_t it);

HHASH_MAP_VISIBILITY hhash_map_iterator_t hhash_map_find_iterator(hhash_map_t* map,
    void const* key, size_t key_length);

HHASH_MAP_VISIBILITY void const* hhash_map_get_key(hhash_map_t* map,
    hhash_map_iterator_t it);

HHASH_MAP_VISIBILITY size_t hhash_map_get_key_length(hhash_map_t* map,
    hhash_map_iterator_t it);

HHASH_MAP_VISIBILITY void const* hhash_map_get_value(hhash_map_t* map,
    hhash_map_iterator_t it);

#endif /* HHASH_MAP_H */

#ifdef HHASH_MAP_IMPL

#include <assert.h>
#include <string.h>

/*
 * Implementation
 */
#if (defined(_MSC_VER) && defined(__AVX__)) ||                                 \
    (!defined(_MSC_VER) && defined(__SSE4_2__))
#define HHASH_MAP_HAS_SSE42
#include <nmmintrin.h>
#endif

typedef struct hhash_map_entry_s
{
    uint8_t const* key;
    size_t key_length;
    void const* value;
} hhash_map_entry_t;

#ifndef NDEBUG
static int hhash_map_is_pow2(size_t capacity)
{
    return (capacity != 0) && ((capacity & (capacity - 1)) == 0);
}
#endif

static uint32_t hhash_map_get_crc32(uint8_t const* const key, size_t const length)
{
    size_t crc32 = 0;

#if defined(HHASH_MAP_HAS_SSE42)
    for (size_t i = 0; i < length; ++i) {
        crc32 = _mm_crc32_u8(crc32, s[i]);
    }
#else
    /* Using polynomial 0x11EDC6F41 to match SSE 4.2's crc function. */
    static uint32_t const table[] =
    {
        0x00000000U, 0xF26B8303U, 0xE13B70F7U, 0x1350F3F4U, 0xC79A971FU,
        0x35F1141CU, 0x26A1E7E8U, 0xD4CA64EBU, 0x8AD958CFU, 0x78B2DBCCU,
        0x6BE22838U, 0x9989AB3BU, 0x4D43CFD0U, 0xBF284CD3U, 0xAC78BF27U,
        0x5E133C24U, 0x105EC76FU, 0xE235446CU, 0xF165B798U, 0x030E349BU,
        0xD7C45070U, 0x25AFD373U, 0x36FF2087U, 0xC494A384U, 0x9A879FA0U,
        0x68EC1CA3U, 0x7BBCEF57U, 0x89D76C54U, 0x5D1D08BFU, 0xAF768BBCU,
        0xBC267848U, 0x4E4DFB4BU, 0x20BD8EDEU, 0xD2D60DDDU, 0xC186FE29U,
        0x33ED7D2AU, 0xE72719C1U, 0x154C9AC2U, 0x061C6936U, 0xF477EA35U,
        0xAA64D611U, 0x580F5512U, 0x4B5FA6E6U, 0xB93425E5U, 0x6DFE410EU,
        0x9F95C20DU, 0x8CC531F9U, 0x7EAEB2FAU, 0x30E349B1U, 0xC288CAB2U,
        0xD1D83946U, 0x23B3BA45U, 0xF779DEAEU, 0x05125DADU, 0x1642AE59U,
        0xE4292D5AU, 0xBA3A117EU, 0x4851927DU, 0x5B016189U, 0xA96AE28AU,
        0x7DA08661U, 0x8FCB0562U, 0x9C9BF696U, 0x6EF07595U, 0x417B1DBCU,
        0xB3109EBFU, 0xA0406D4BU, 0x522BEE48U, 0x86E18AA3U, 0x748A09A0U,
        0x67DAFA54U, 0x95B17957U, 0xCBA24573U, 0x39C9C670U, 0x2A993584U,
        0xD8F2B687U, 0x0C38D26CU, 0xFE53516FU, 0xED03A29BU, 0x1F682198U,
        0x5125DAD3U, 0xA34E59D0U, 0xB01EAA24U, 0x42752927U, 0x96BF4DCCU,
        0x64D4CECFU, 0x77843D3BU, 0x85EFBE38U, 0xDBFC821CU, 0x2997011FU,
        0x3AC7F2EBU, 0xC8AC71E8U, 0x1C661503U, 0xEE0D9600U, 0xFD5D65F4U,
        0x0F36E6F7U, 0x61C69362U, 0x93AD1061U, 0x80FDE395U, 0x72966096U,
        0xA65C047DU, 0x5437877EU, 0x4767748AU, 0xB50CF789U, 0xEB1FCBADU,
        0x197448AEU, 0x0A24BB5AU, 0xF84F3859U, 0x2C855CB2U, 0xDEEEDFB1U,
        0xCDBE2C45U, 0x3FD5AF46U, 0x7198540DU, 0x83F3D70EU, 0x90A324FAU,
        0x62C8A7F9U, 0xB602C312U, 0x44694011U, 0x5739B3E5U, 0xA55230E6U,
        0xFB410CC2U, 0x092A8FC1U, 0x1A7A7C35U, 0xE811FF36U, 0x3CDB9BDDU,
        0xCEB018DEU, 0xDDE0EB2AU, 0x2F8B6829U, 0x82F63B78U, 0x709DB87BU,
        0x63CD4B8FU, 0x91A6C88CU, 0x456CAC67U, 0xB7072F64U, 0xA457DC90U,
        0x563C5F93U, 0x082F63B7U, 0xFA44E0B4U, 0xE9141340U, 0x1B7F9043U,
        0xCFB5F4A8U, 0x3DDE77ABU, 0x2E8E845FU, 0xDCE5075CU, 0x92A8FC17U,
        0x60C37F14U, 0x73938CE0U, 0x81F80FE3U, 0x55326B08U, 0xA759E80BU,
        0xB4091BFFU, 0x466298FCU, 0x1871A4D8U, 0xEA1A27DBU, 0xF94AD42FU,
        0x0B21572CU, 0xDFEB33C7U, 0x2D80B0C4U, 0x3ED04330U, 0xCCBBC033U,
        0xA24BB5A6U, 0x502036A5U, 0x4370C551U, 0xB11B4652U, 0x65D122B9U,
        0x97BAA1BAU, 0x84EA524EU, 0x7681D14DU, 0x2892ED69U, 0xDAF96E6AU,
        0xC9A99D9EU, 0x3BC21E9DU, 0xEF087A76U, 0x1D63F975U, 0x0E330A81U,
        0xFC588982U, 0xB21572C9U, 0x407EF1CAU, 0x532E023EU, 0xA145813DU,
        0x758FE5D6U, 0x87E466D5U, 0x94B49521U, 0x66DF1622U, 0x38CC2A06U,
        0xCAA7A905U, 0xD9F75AF1U, 0x2B9CD9F2U, 0xFF56BD19U, 0x0D3D3E1AU,
        0x1E6DCDEEU, 0xEC064EEDU, 0xC38D26C4U, 0x31E6A5C7U, 0x22B65633U,
        0xD0DDD530U, 0x0417B1DBU, 0xF67C32D8U, 0xE52CC12CU, 0x1747422FU,
        0x49547E0BU, 0xBB3FFD08U, 0xA86F0EFCU, 0x5A048DFFU, 0x8ECEE914U,
        0x7CA56A17U, 0x6FF599E3U, 0x9D9E1AE0U, 0xD3D3E1ABU, 0x21B862A8U,
        0x32E8915CU, 0xC083125FU, 0x144976B4U, 0xE622F5B7U, 0xF5720643U,
        0x07198540U, 0x590AB964U, 0xAB613A67U, 0xB831C993U, 0x4A5A4A90U,
        0x9E902E7BU, 0x6CFBAD78U, 0x7FAB5E8CU, 0x8DC0DD8FU, 0xE330A81AU,
        0x115B2B19U, 0x020BD8EDU, 0xF0605BEEU, 0x24AA3F05U, 0xD6C1BC06U,
        0xC5914FF2U, 0x37FACCF1U, 0x69E9F0D5U, 0x9B8273D6U, 0x88D28022U,
        0x7AB90321U, 0xAE7367CAU, 0x5C18E4C9U, 0x4F48173DU, 0xBD23943EU,
        0xF36E6F75U, 0x0105EC76U, 0x12551F82U, 0xE03E9C81U, 0x34F4F86AU,
        0xC69F7B69U, 0xD5CF889DU, 0x27A40B9EU, 0x79B737BAU, 0x8BDCB4B9U,
        0x988C474DU, 0x6AE7C44EU, 0xBE2DA0A5U, 0x4C4623A6U, 0x5F16D052U,
        0xAD7D5351U
    };

    for (size_t i = 0; i < length; ++i) {
        crc32 = table[((uint8_t)crc32) ^ key[i]] ^ (crc32 >> 8);
    }
#endif
    return crc32;
}

static size_t hhash_map_get_iterator(hhash_map_t const* const map,
    uint8_t const* const key, size_t const key_length)
{
    uint32_t hash = hhash_map_get_crc32(key, key_length);

    /* Robert Jenkins' 32 bit mix Function. */
    hash += (hash << 12);
    hash ^= (hash >> 22);
    hash += (hash << 4);
    hash ^= (hash >> 9);
    hash += (hash << 10);
    hash ^= (hash >> 2);
    hash += (hash << 7);
    hash ^= (hash >> 12);

    /* Knuth's multiplicative method. */
    hash = (hash >> 3) * 2654435761;

    assert(hhash_map_is_pow2(map->capacity));
    return hash & (map->capacity - 1);
}

static int hhash_map_matches(hhash_map_entry_t const* const entry,
    uint8_t const* const key, size_t const key_length)
{
    return (entry->key_length == key_length)
        && (0 == memcmp(entry->key, key, key_length));
}

static int hhash_map_get_insertion_iterator(hhash_map_t const* const map,
    uint8_t const* const key, size_t const key_length, size_t* insertion_it)
{
    assert(NULL != insertion_it);

    /* Capacity available? */
    if (map->size == map->capacity) {
        return -1;
    }


    /* Get start iterator for given key. */
    size_t start = hhash_map_get_iterator(map, key, key_length);
    size_t used_entries = 0;
    size_t const max_iterations = map->capacity < HHASH_MAP_MAX_ITERATIONS
        ? map->capacity : HHASH_MAP_MAX_ITERATIONS;

    /* Check key is already in map. */
    for (size_t i = 0, it = start; i < max_iterations; ++i) {
        hhash_map_entry_t const* const entry = &map->entries[it];
        size_t const is_used = NULL != entry->key;

        used_entries += is_used;

        if (is_used && hhash_map_matches(entry, key, key_length)) {
            *insertion_it = it;
            return 1;
        }

        it = (it + 1) & (map->capacity - 1);
    }

    /* Check insertion is possible. */
    if (used_entries >= HHASH_MAP_MAX_ITERATIONS) {
        return -1;
    }

    /* Find unused entry. */
    for (size_t i = 0, it = start; i < max_iterations; ++i) {
        if (NULL == map->entries[it].key) {
            *insertion_it = it;
            return 0;
        }

        it = (it + 1) & (map->capacity - 1);
    }

    /* There should have been an unused entry...*/
    assert(0);
    return -1;
}

/*
 * Public
 */
int hhash_map_init(hhash_map_t* map, size_t capacity)
{
    assert(NULL != map);

    memset(map, 0, sizeof(hhash_map_t));

    // Reserve entries?
    if (capacity > 0) {
        if (hhash_map_reserve(map, capacity) < 0) {
            return -1;
        }
    }

    return 0;
}

void hhash_map_free(hhash_map_t* map)
{
    assert(NULL != map);

    if (NULL != map->entries) {
        free(map->entries);
    }
    memset(map, 0, sizeof(hhash_map_t));
}

int hhash_map_reserve(hhash_map_t* map, size_t capacity)
{
    assert(NULL != map);
    assert(hhash_map_is_pow2(capacity));

    // Check capacity.
    if (capacity <= map->capacity) {
        return 0;
    }

    /* Allocate a new entries array for given capacity. */
    hhash_map_entry_t* new_entries = calloc(capacity, sizeof(hhash_map_entry_t));
    if (NULL == new_entries) {
        return -1;
    }

    hhash_map_entry_t* const old_entries = map->entries;
    int r = 0;

    /* Rehash existing entries? */
    if (map->size > 0) {
        size_t const old_capacity = map->capacity;
        size_t const old_size = map->size;

        /* Assign new capacity and entries to map so insert function can be used. */
        map->capacity = capacity;
        map->size = 0;
        map->entries = new_entries;

        for (size_t i = 0; i < old_capacity; ++i) {
            hhash_map_entry_t const* const entry = &old_entries[i];

            /* Skip over unused entries. */
            if (NULL == entry->key) {
                continue;
            }

            /* Try to insert entry from old map into new entries array. */
            if (hhash_map_insert(map, entry->key, entry->key_length, entry->value) < 0) {
                /* Restore map, free new entries and return error. */
                map->capacity = old_capacity;
                map->size = old_size;
                map->entries = old_entries;
                free(new_entries);
                return -1;
            }
        }

        r = 1;
    }

    /* Free old entries array. */
    if (NULL != old_entries) {
        free(old_entries);
    }

    /* Update map's capacity and entries. */
    map->capacity = capacity;
    map->entries = new_entries;
    return r;
}

void hhash_map_clear(hhash_map_t* map)
{
    assert(NULL != map);

    map->size = 0;
    memset(map->entries, 0, sizeof(hhash_map_entry_t) * map->capacity);
}

int hhash_map_insert(hhash_map_t* map,
    void const* key, size_t key_length, void const* value)
{
    assert(NULL != map);
    assert(NULL != key && key_length > 0);

    if (0 == map->capacity) {
        /* Reserve capacity for a single entry. */
        if (hhash_map_reserve(map, 1) < 0) {
            return -1;
        }
    }

    size_t it;
    int r;

    /* Find insertion it. */
    do {
        /* Try to find an insertion iterator. */
        r = hhash_map_get_insertion_iterator(map, key, key_length, &it);
        if (r >= 0) {
            break;
        }

        /* Double capacity. */
        if (hhash_map_reserve(map, map->capacity * 2) < 0) {
            return -1;
        }
    }
    while (1);

    /* Insert entry if not already inserted... */
    if (r == 0) {
        map->entries[it].key = key;
        map->entries[it].key_length = key_length;
        map->entries[it].value = value;
        ++map->size;
    }

    return r;
}

void const* hhash_map_erase(hhash_map_t* map, void const* key, size_t key_length)
{
    size_t it = hhash_map_find_iterator(map, key, key_length);
    if (hhash_map_end(map) == it) {
        return NULL;
    }

    void const* value = map->entries[it].value;
    memset(&map->entries[it], 0, sizeof(hhash_map_entry_t));
    --map->size;
    return value;
}

void const* hhash_map_find(hhash_map_t* map, void const* key, size_t key_length)
{
    size_t it = hhash_map_find_iterator(map, key, key_length);
    return hhash_map_end(map) != it ? map->entries[it].value : NULL;
}

hhash_map_iterator_t hhash_map_begin(hhash_map_t* map)
{
    assert(NULL != map);

    hhash_map_iterator_t it;

    for (it = 0; it < map->capacity; ++it) {
        if (NULL != map->entries[it].key) {
            return it;
        }
    }

    return hhash_map_end(map);
}

hhash_map_iterator_t hhash_map_end(hhash_map_t* map)
{
    assert(NULL != map);
    (void)map;
    return (hhash_map_iterator_t)-1;
}

hhash_map_iterator_t hhash_map_next(hhash_map_t* map, hhash_map_iterator_t it)
{
    assert(NULL != map);
    assert(it < map->capacity);

    for (++it; it < map->capacity; ++it) {
        if (NULL != map->entries[it].key) {
            return it;
        }
    }

    return hhash_map_end(map);
}

hhash_map_iterator_t hhash_map_find_iterator(hhash_map_t* map,
    void const* key, size_t key_length)
{
    size_t it = hhash_map_get_iterator(map, key, key_length);

    /* Iterate at most the maximum length of a chain. */
    for (size_t i = 0; i < HHASH_MAP_MAX_ITERATIONS; ++i) {
        /* Entry at iterator hhash_map_matches key? */
        if (hhash_map_matches(&map->entries[it], key, key_length)) {
            return it;
        }

        it = (it + 1) & (map->capacity - 1);
    }

    return hhash_map_end(map);
}

void const* hhash_map_get_key(hhash_map_t* map, hhash_map_iterator_t it)
{
    assert(NULL != map);
    assert(it < map->capacity);
    assert(NULL != map->entries[it].key);
    return map->entries[it].key;
}

size_t hhash_map_get_key_length(hhash_map_t* map, hhash_map_iterator_t it)
{
    assert(NULL != map);
    assert(it < map->capacity);
    assert(NULL != map->entries[it].key);
    return map->entries[it].key_length;
}

void const* hhash_map_get_value(hhash_map_t* map, hhash_map_iterator_t it)
{
    assert(NULL != map);
    assert(it < map->capacity);
    assert(NULL != map->entries[it].key);
    return map->entries[it].value;
}

#endif /* HHASH_MAP_IMPL */

#ifdef HHASH_MAP_IMPL_TEST

#include "htest.h"

HTEST_CASE(hhash_map)
{
    hhash_map_t map;

    HTEST_INT(hhash_map_init(&map, 0), >=, 0);

    HTEST_INT(hhash_map_insert(&map, "foo", 3, "foo"), >=, 0);
    HTEST_INT(hhash_map_insert(&map, "bar", 3, "bar"), >=, 0);
    HTEST_INT(hhash_map_insert(&map, "baz", 3, "baz"), >=, 0);
    HTEST_INT(4, ==, map.capacity);
    HTEST_INT(3, ==, map.size);

    void const* value;

    value = hhash_map_find(&map, "foo", 3);
    HTEST_MEMORY(value, ==, "foo", 3);

    value = hhash_map_find(&map, "bar", 3);
    HTEST_MEMORY(value, ==, "bar", 3);

    value = hhash_map_find(&map, "baz", 3);
    HTEST_MEMORY(value, ==, "baz", 3);

    HTEST_INT(hhash_map_reserve(&map, 8), >=, 0);

    value = hhash_map_find(&map, "foo", 3);
    HTEST_MEMORY(value, ==, "foo", 3);

    value = hhash_map_find(&map, "bar", 3);
    HTEST_MEMORY(value, ==, "bar", 3);

    value = hhash_map_find(&map, "baz", 3);
    HTEST_MEMORY(value, ==, "baz", 3);
    HTEST_MEMORY(value, ==, "baz", 3);

    HTEST_POINTER(NULL, !=, hhash_map_erase(&map, "bar", 3));
    HTEST_POINTER(NULL, ==, hhash_map_find(&map, "bar", 3));

    for (hhash_map_iterator_t it = hhash_map_begin(&map);
        hhash_map_end(&map) != it;
        it = hhash_map_next(&map, it)) {

        HTEST_INT(3, ==, hhash_map_get_key_length(&map, it));
        HTEST_TRUE(
            (0 == memcmp("foo", hhash_map_get_key(&map, it), 3) || 0 == strcmp("foo", hhash_map_get_value(&map, it)))
         || (0 == memcmp("baz", hhash_map_get_key(&map, it), 3) || 0 == strcmp("baz", hhash_map_get_value(&map, it)))
        );
    }

    hhash_map_clear(&map);

    HTEST_SIZE(8, ==, map.capacity);
    HTEST_SIZE(0, ==, map.size);

    hhash_map_free(&map);
}

htest_suite_t hhash_map_test_suite =
{
    HTEST_CASE_REF(hhash_map),
    NULL
};

#endif /* HHASH_MAP_IMPL_TEST */

#ifdef __cplusplus
}
#endif

