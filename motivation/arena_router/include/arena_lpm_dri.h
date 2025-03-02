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
#define TBL24_COUNT (1 << 24)
#define TBL_LONG_COUNT (1 << 14)

enum {
    NO_SET = 0,
    IN_TBL_24 = 1,
    IN_TBL_LONG = 2,
};

struct lpm_dri_entry {
    __u8 state;
    __u32 prefixlen; // what the prefixlen of the currently written data
    union {
        __u8 __arena *data;
        __u8 __arena *long_entry;
    };
} __packed;
typedef struct lpm_dri_entry __arena arena_lpm_dri_entry_t;

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
    __u8 __arena *tbl_long;
    __u32 tbl_long_sz; /* number of bytes */
    __u32 value_size;
    mem_handle_t mem;
};
typedef struct lpm_dri __arena arena_lpm_dri_t;

#if defined(__BPF__)
#include <bpf/bpf_endian.h>

static __always_inline
void __arena *arena_lpm_dri_lookup_elem(arena_lpm_dri_t *dri, lpm_dri_key_t *key)
{
    cast_kern(dri);

    if (key->prefixlen != 32) {
        // TODO: I have not thought about what it means to query with range as
        // a key
        return NULL;
    }

    __u64 offset = bpf_ntohl(key->data)  >> 8;
    arena_lpm_dri_entry_t *e = &dri->tbl_24[offset];
    if (e->state != IN_TBL_24) {
        // TODO: Either not present or not implemented :)
        return NULL;
    }

    void __arena *data = e->data
    cast_kern(data);
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
    __u64 tbl_long_sz = (TBL_LONG_COUNT * 0);
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
    dri->tbl_long = (__u8 __arena *)dri->tbl_24 + tbl_24_sz;
    dri->tbl_long_sz = tbl_long_sz;
    dri->value_size = arg->value_size;

    void *mempool = dri->tbl_long + dri->tbl_long_sz;
    if (create_mem_region_obj(mempool, available_memory, &dri->mem) != 0) {
        return -EINVAL;
    }

    // NOTE: I am relying on the eBPF MAP allocation to set all the Arena area
    // to zero.
    
    for (__u64 i = 0; i < TBL24_COUNT; i++) {
        memset(&dri->tbl_24[i], 0, sizeof(arena_lpm_dri_entry_t));
    }

    *arg->dri_ptr = dri;
    return 0;
}

static long userspace_arena_lpm_dri_update_elem(arena_lpm_dri_t *dri,
        lpm_dri_key_t *key, void *value, __u64 flag)
{
    if (key->prefixlen > 24) {
        /* TODO: to be implemented */
        return -1;
    }

    // allocate a new data object and copy value into it
    // TODO: how do we support delete or overwrittin? should we doing pointer
    // counting?
    __u8 __arena *data_obj = just_alloc(&dri->mem, dri->value_size);
    if (data_obj == NULL) {
        return -ENOMEM;
    }
    memcpy(data_obj, value, dri->value_size);

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
        if (e->state == NO_SET) {
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
