// SPDX-License-Identifier: Apache-2.0
/* @desc: A longest-prefix-match library using DRI-24-8-basic
 * @author: Farbod Shahinfar
 * @date: Feburary, 2025
 * */
/* Make sure that eBPF program is compiled with `-D __BPF__` */
#pragma once
#include <linux/bpf.h>
#include <errno.h>
#include "stddef.h"
#include "compiler.h"
#include "bpf_arena_common.h"
#include "arena_mm.h"

typedef struct {
    __u32 prefixlen;
    __u32 data; // TODO: we only support IPv4
} __packed lpm_dri_key_t;

#define KEY_DATA_OFFSET (offsetof(_key_t, data))
#define KEY_SZ 4
#define MAX_VAL_SZ 128
/* how many entries each table has */
#define TBL24_COUNT (1 << 24)
#define TBL_LONG_CHUNK (1 << 8)
#define TBL_LONG_COUNT (1 << 14)

/* TODO: I don't like the naming system I've used for structs in this file.
 *       I should come up with something better :)
 * */

enum {
    NOT_SET = 0,
    IN_TBL_24 = 1,
    IN_TBL_LONG = 2,
};

/* This struct represents an entry in tbl-24 */
struct lpm_dri_entry {
    __u8 state;
    __u32 prefixlen; // what the prefixlen of the currently written data
    union {
        __u8 __arena *data;
        __u32 long_entry;
    };
} __packed;
typedef struct lpm_dri_entry __arena arena_lpm_dri_entry_t;

/* This struct represents an entry in tbl-8 */
struct lpm_dri_long_entry {
    __u8 valid;
    __u32 prefixlen;
    __u8 __arena *data;
};
typedef struct lpm_dri_long_entry __arena arena_lpm_dri_long_entry_t;

/* -(At the moment)- Previously, I've decided to have entries and their
 * allocated data next to each other. But it is possible to have a pool of
 * memories for data.
 *
 * -(I am not sure which design is better.)- This design is bad because we do
 * not have memory space for 2**24 values :)
 *
 * Let's implement the other one
 * */
struct lpm_dri {
    arena_lpm_dri_entry_t *tbl_24;
    __u32 tbl_24_sz; /* number of bytes */
    arena_lpm_dri_long_entry_t *tbl_long;
    __u32 tbl_long_sz; /* number of bytes */
    /* Number of 256 entry chunks of regions that we can alloc */
    __u32 tbl_long_free_chunks;
    __u32 tbl_long_alloc_chunks;
    /* ------------------------------------------------------- */
    __u32 value_size;
    mem_handle_t mem;
};
typedef struct lpm_dri __arena arena_lpm_dri_t;

#if defined(__BPF__)
#include <bpf/bpf_endian.h>
// enable using prefetching
#define PREFETCH 1
#include "honey/prefetching.h"

static __always_inline
void __arena *arena_lpm_dri_lookup_elem(arena_lpm_dri_t *dri, lpm_dri_key_t *key)
{
    cast_kern(dri);

    if (key->prefixlen != 32) {
        // TODO: I have not thought about what it means to query with range as
        // a key
        return NULL;
    }

    void __arena *data = NULL;
    __u32 K = bpf_ntohl(key->data);
    __u64 offset = K >> 8;
    arena_lpm_dri_entry_t *e = &dri->tbl_24[offset];
    if (e->state == NOT_SET) {
        return NULL;
    }

    if (e->state == IN_TBL_LONG) {
        __u32 base = e->long_entry;
        __u32 rel_off8 = K & 0xff;
        __u32 off = base + rel_off8;
        arena_lpm_dri_long_entry_t *e2 = &dri->tbl_long[off];
        data = e2->data;
        cast_kern(data)
        return data;
    }

    data = e->data
    cast_kern(data);
    return data;
}

static __always_inline
void __arena *arena_lpm_dri_lookup_elem_p1(arena_lpm_dri_t *dri, lpm_dri_key_t *key)
{
    cast_kern(dri);

    if (key->prefixlen != 32) {
        // TODO: I have not thought about what it means to query with range as
        // a key
        return NULL;
    }

    __u32 K = bpf_ntohl(key->data);
    __u64 offset = K >> 8;
    arena_lpm_dri_entry_t *e = &dri->tbl_24[offset];
    P((void *)e);
    return e;
}

static __always_inline
void __arena *arena_lpm_dri_lookup_elem_p2(arena_lpm_dri_t *dri, lpm_dri_key_t *key, arena_lpm_dri_entry_t *e)
{
    if (e->state == NOT_SET) {
        return NULL;
    }

    void __arena *data = NULL;
    if (e->state == IN_TBL_LONG) {
        // TODO: this path does not benefit from prefetching. I could add a
        // third stage here
        __u32 K = bpf_ntohl(key->data);
        __u32 base = e->long_entry;
        __u32 rel_off8 = K & 0xff;
        __u32 off = base + rel_off8;
        arena_lpm_dri_long_entry_t *e2 = &dri->tbl_long[off];
        data = e2->data;
        cast_kern(data)
        return data;
    }

    data = e->data
    cast_kern(data);
    P((void *)data);
    return data;
}

#else
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    void *area; /* pointer to the Arena memory region */
    __u32 area_size;
    __u32 key_size; /* the size of the key used for query */
    __u32 max_entries;
    __u32 value_size; /* the size of value associated with each key */
    arena_lpm_dri_t **dri_ptr; /* out */
    __u32 *allocated_pages; /* out */
} arena_lpm_dri_alloc_t;

static long userspace_arena_lpm_dri_alloc(arena_lpm_dri_alloc_t *arg)
{
    if (arg->area == NULL)
        return -EINVAL;
    /* Only supporting IPv4 for now */
    if (arg->key_size != sizeof(lpm_dri_key_t))
        return -EINVAL;

    // TODO: maybe we do not need this, ...
    /* We are actually limited to 4GB of memory, limit the size of values */
    if (arg->value_size > MAX_VAL_SZ)
        return -EINVAL;

    __u64 data_pool_sz = (arg->value_size + sizeof(mem_region_t)) * arg->max_entries;
    __u64 tbl_24_sz = (TBL24_COUNT * sizeof(arena_lpm_dri_entry_t));
    __u64 tbl_long_sz = (TBL_LONG_COUNT * sizeof(arena_lpm_dri_long_entry_t));
    __u64 mem_sz = sizeof(arena_lpm_dri_t) + tbl_24_sz + tbl_long_sz + data_pool_sz;
    __u32 num_pages = COUNT_OBJ(mem_sz, PAGE_SIZE);
    printf("DEBUG: require %u pages\n", num_pages);
    __u64 total_req_mem = (num_pages * PAGE_SIZE);

    // Make sure memory area has enough space
    if (arg->area_size < total_req_mem) {
        return -ENOMEM;
    }

    userspace_alloc_pages(arg->area, num_pages);
    if (arg->allocated_pages != NULL) {
        *arg->allocated_pages = num_pages;
    }

    __u64 available_memory = total_req_mem - sizeof(arena_lpm_dri_t) - tbl_24_sz - tbl_long_sz;

    arena_lpm_dri_t *dri = arg->area;
    dri->tbl_24 = (arena_lpm_dri_entry_t *)(dri + 1);
    dri->tbl_24_sz = tbl_24_sz;
    dri->tbl_long = (arena_lpm_dri_long_entry_t *)((__u8 __arena *)dri->tbl_24 + tbl_24_sz);
    dri->tbl_long_sz = tbl_long_sz;
    dri->value_size = arg->value_size;
    dri->tbl_long_free_chunks = TBL_LONG_COUNT / TBL_LONG_CHUNK;
    dri->tbl_long_alloc_chunks = 0;

    void __arena *mempool = (void __arena *)dri->tbl_long + dri->tbl_long_sz;
    if (create_mem_region_obj(mempool, available_memory, &dri->mem) != 0) {
        return -EINVAL;
    }

    // NOTE: I am relying on the eBPF MAP allocation to set all the Arena area
    // to zero.
    
    for (__u64 i = 0; i < TBL24_COUNT; i++) {
        memset(&dri->tbl_24[i], 0, sizeof(arena_lpm_dri_entry_t));
    }
    for (__u64 i = 0; i < TBL_LONG_COUNT; i++) {
        memset(&dri->tbl_long[i], 0, sizeof(arena_lpm_dri_long_entry_t));
    }

    *arg->dri_ptr = dri;
    return 0;
}

static inline int __alloc_chunk(arena_lpm_dri_t *dri)
{
    if (dri->tbl_long_alloc_chunks >= dri->tbl_long_free_chunks) {
        return -ENOSPC;
    }
    __u32 base = dri->tbl_long_alloc_chunks * TBL_LONG_CHUNK;
    dri->tbl_long_alloc_chunks++;
    return base;
}

/*
 * @desc: How it works:
 *      when inserting a new rule with perfix larger than 24 there are scenarios.
 *      1) the coresponding entry in the tbl_24 (using first 24 bit of the key)
 *      is empty:
 *              Allocate a 256 entry long chunk on tbl_8 and update the
 *              relevant part with the new key. relevant part could be a subset
 *              of 256 entries, depending on the prefixlen.
 *      2) The coresponding entry in the tbl_24 is a rule with prefixlen
 *      smaller than or equal to 24:
 *          Allocate a 256 entry chunk, set all the entries to point to data
 *          from the rule in the tbl_24 entry. update the tbl_24 entry to point
 *          to the long table. In 256 chunk update the relevant region with the
 *          new key and data.
 *      3) The coresponding entry in the tbl_24 is a pointer to long_table:
 *          Walk the long table and update the relevant entries only if they do
 *          not belong to a more specific rule (longer prefix len)
 *
 * @param dri: pointer to the main data structure
 * @param key: pointer to the key
 * @param data_obj: object ot point to
 * @returns: zero on success
 * */
static long __add_long_entry(arena_lpm_dri_t *dri, lpm_dri_key_t *key,
        void *data_obj)
{
    assert(key->prefixlen > 24);
    __u32 K = ntohl(key->data);
    __u32 off24 = K >> 8; // offset into the tbl_24
    __u32 rel_off8 = K & 0xff; // relative offset into the tbl_long (we need to get a base pointer)
    __u32 affected_entries = 1 << (key->prefixlen - 24);
    int base = 0;

    arena_lpm_dri_entry_t *ent = &dri->tbl_24[off24];
    if (ent->state == NOT_SET) {
        base = __alloc_chunk(dri);
        if (base < 0) {
            return -ENOSPC;
        }
        ent->state      = IN_TBL_LONG;
        ent->prefixlen  = 24; // we do not need to set this as the state indicates we need to walk further
        ent->long_entry = base;
        for (__u32 i = 0; i < affected_entries; i++) {
            __u32 off = base + rel_off8 + i;
            arena_lpm_dri_long_entry_t *e = &dri->tbl_long[off];
            e->valid = 1;
            e->prefixlen = key->prefixlen;
            e->data = data_obj;
        }
    } else if (ent->state == IN_TBL_24) {
        void *old_obj = ent->data;
        __u32 old_prefixlen = ent->prefixlen;
        base = __alloc_chunk(dri);
        if (base < 0) {
            return -ENOSPC;
        }
        ent->state = IN_TBL_LONG;
        ent->prefixlen = 24;
        ent->long_entry = base;
        for (__u32 i = 0; i < TBL_LONG_CHUNK; i++) {
            __u32 off = base + 0 + i;
            arena_lpm_dri_long_entry_t *e = &dri->tbl_long[off];
            e->valid = 1;
            e->prefixlen = old_prefixlen;
            e->data = old_obj;
        }
        for (__u32 i = 0; i < affected_entries; i++) {
            __u32 off = base + rel_off8 + i;
            arena_lpm_dri_long_entry_t *e = &dri->tbl_long[off];
            e->valid = 1;
            e->prefixlen = key->prefixlen;
            e->data = data_obj;
        }
    } else if (ent->state == IN_TBL_LONG) {
        base = ent->long_entry;
        for (__u32 i = 0; i < affected_entries; i++) {
            __u32 off = base + rel_off8 + i;
            arena_lpm_dri_long_entry_t *e = &dri->tbl_long[off];
            if (e->valid == 1 && e->prefixlen > key->prefixlen) {
                // this entry belongs to a more specific rule
                continue;
            }
            e->valid = 1;
            e->prefixlen = key->prefixlen;
            e->data = data_obj;
        }
    }
    return 0;
}

static long userspace_arena_lpm_dri_update_elem(arena_lpm_dri_t *dri,
        lpm_dri_key_t *key, void *value, __u64 flag)
{
    // allocate a new data object and copy value into it
    // TODO: how do we support delete or overwrittin? should we doing pointer
    // counting?
    __u8 __arena *data_obj = just_alloc(&dri->mem, dri->value_size);
    if (data_obj == NULL) {
        return -ENOMEM;
    }
    memcpy(data_obj, value, dri->value_size);

    if (key->prefixlen > 24) {
        /* TODO: to be implemented */
        /* return -1; */
        return __add_long_entry(dri, key, data_obj);
    }

    /* bool f = false; */
    /* if (strncmp(data_obj, "hello 520948", 12) == 0) { */
    /*     f = true; */
    /* } */


    // key->prefixlen == 0 --> what does this mean? it matches anything?
    __u64 affected_entries = 1 << (24 - key->prefixlen);
    __u64 mask = 0;
    if (key->prefixlen > 0) {
        mask = ~(affected_entries - 1);
    }
    __u32 K = ntohl(key->data);
    __u64 begin_offset = (__u64)(K >> 8) & mask;

    // The entries that we need to update start at ``begin_offset''. We need to
    // consider ``affected_entries'' number of them. If the entry already has a
    // value (the state isn't  NOT_SET) we should keep the value belonging to
    // the longer prefix.
    // If the length of the prefixes (?) match, then the newer value (the
    // current update) should be kept.

    arena_lpm_dri_entry_t *e       = &dri->tbl_24[begin_offset];
    __u8 __arena *tbl_end = (__u8 __arena *)dri->tbl_24 + dri->tbl_24_sz;
    assert ((__u8 *)(e + 1) < tbl_end);
    assert ((__u8 *)(e + affected_entries + 1) < tbl_end);

    for (__u64 i = 0; i < affected_entries; i++, e++) {
        if (e->state == NOT_SET) {
            goto _update;
        } else if (e->state == IN_TBL_24) {
           if (e->prefixlen <= key->prefixlen) {
               goto _update;
           }
        } else {
            // TODO: not implemented yet
            assert(0);
        }
        continue;

_update:
        /* if (f) { */
        /*     printf("writing the value to %llu\n", begin_offset + i); */
        /* } */
        /* if (begin_offset +i == 9961196) { */
        /*     printf("* write to 9961196 (range: %llu): %s\n", affected_entries, data_obj); */
        /*     printf("Orig: %x K: %x  mask: %llx\n", key->data, K, mask); */
        /* } */

        e->state = IN_TBL_24;
        e->prefixlen = key->prefixlen;
        e->data = data_obj;
    }
    return 0;
}
#endif
// vim: et ts=4 sw=4:
