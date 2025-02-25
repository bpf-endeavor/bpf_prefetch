// SPDX-License-Identifier: GPL-2.0-only
/*
 * Longest prefix match list implementation
 *
 * Copyright (c) 2016,2017 Daniel Mack
 * Copyright (c) 2016 David Herrmann
 */
/* A LPM Trie implementation using eBPF Arena
 * @author Farbod Shahinfar
 * */
/* Make sure that eBPF program is compiled with `-D __BPF__` */
#pragma once
#include <linux/bpf.h>
#include <errno.h>
#include "stddef.h"
#include "compiler.h"
#include "bpf_arena_common.h"
#include "arena_mm.h"


/* the first 4 byte of the key (an int) is used to communicate the prefix
 * length.
 * */
typedef struct {
    __u32 prefixlen;
    __u8 data[0];
} __packed _key_t;

#define TRIE_MAX_HEIGHT 1 << 15
#define LPM_TREE_NODE_FLAG_IM 1
#define MIN_KEY_SIZE sizeof(_key_t)
#define NODE_SIZE(trie) (sizeof(arena_lpm_trie_node_t) + (trie)->value_size + (trie)->key_size)

#define KEY_DATA_OFFSET (offsetof(_key_t, data))
#define get_node_key(trie, node) ((void __arena *)(node)->data)
#define get_node_value(trie, node)((void __arena *)(node)->data + ((trie)->key_size - KEY_DATA_OFFSET))

struct lpm_trie_node;

struct lpm_trie_node {
    struct lpm_trie_node __arena *child[2];
    __u32 prefixlen;
    __u32 flags;
    __u8 data[0]; /* key+value stored for this node */
};

struct lpm_trie {
    struct lpm_trie_node __arena *root; /* pointer to the root of the trie */
    mem_handle_t mem; /* the memory pool for allocating nodes */
    __u64 n_entries; /* current number of entries */
    __u64 max_entries; /* maximum number of entries */
    __u64 max_prefixlen; /* maximum size of the prefix in bits */
    __u64 key_size;
    __u64 value_size;
    __u32 height; /* what is the current height of the tree */
};

typedef struct lpm_trie_node __arena arena_lpm_trie_node_t;
typedef struct lpm_trie __arena arena_lpm_trie_t;

#define MIN(a,b) (a < b ? a : b)

#if defined __BPF__
#define be16_to_cpu(x) bpf_ntohs(x)
#define be32_to_cpu(x) bpf_htonl(x)
#define assert(x)
#else
#include <arpa/inet.h>
#include <assert.h>
#define be16_to_cpu(x) ntohs(x)
#define be32_to_cpu(x) ntohl(x)
#define bpf_printk(...)
#endif

static __always_inline __u32 fls(__u32 x)
{
// NOTE: x must not be zero
#if defined(__BPF__)
    int i = 0;
    for (i = 0; i < 32; i++) {
        if ((x & 0x1) != 0) {
            break;
        }
        i++;
        x >>= 1;
    }
    return i;
#else
    // This is 100x (or more ) faster than what is above! (eBPF is fucked)
    int r = __builtin_ffs(x);
    printf("%d\n", r);
    return r - 1;
#endif
}

static __always_inline int extract_bit(const __u8 *data, __u64 index)
{
    if (index >= 32)
        return 0;

    __u8 byte = index / 8;
    __u8 off = 7 - (index % 8);
    __u8 mask = 1 << off;
    int t =!!(data[byte] & mask);  
    assert (t == 0 || t == 1);
    return t;
}

static __u64 __longest_prefix_match(const arena_lpm_trie_t *trie,
        const arena_lpm_trie_node_t *node,
        const _key_t *key)
{
    __u32 limit = MIN(node->prefixlen, key->prefixlen);
    __u32 prefixlen = 0;
    __u32 diff = 0;

    void __arena *node_key = get_node_key(trie, node);
    /* bpf_printk("here what do you think: %p -- > %x", node_key, *(__u32 __arena*)node_key); */

    /* int k = 0; */
    const __u32 key_sz = trie->key_size - KEY_DATA_OFFSET;
    switch(key_sz) {
        case 16: /* ipv6 */
            /* TODO: ... */
            break;
        case 4: /* ipv4 */
            diff = be32_to_cpu(*(__u32 *)node_key ^ *(__u32 *)key->data);
            if (diff == 0) {
                prefixlen = 32;
            } else {
                prefixlen += 32 - fls(diff);
            }
            if (prefixlen >= limit)
                return limit;
            if (diff)
                return prefixlen;
            break;
    }
    return prefixlen;
}

#ifdef __BPF__
/* BPF helpers */

typedef struct {
    _key_t *key;
    arena_lpm_trie_t *trie;
    arena_lpm_trie_node_t *node;
    arena_lpm_trie_node_t * found;
    int err;
} walk_state_t;

static long __lookup_walk_nodes(__u64 _i, void *_ctx)
{
    /* bpf_printk("walk: @%d", _i); */
    walk_state_t *ws = _ctx;
    if (ws->node == NULL) {
        /* bpf_printk("node is null!"); */
        return 1;
    }

    arena_lpm_trie_t *trie = ws->trie;
    arena_lpm_trie_node_t *node = ws->node;
    __u32 __arena *p  = get_node_key(trie, node);
    /* bpf_printk("node key: ptr: %p val: %x", p, *p); */
    /* bpf_printk("child left: %p",  node->child[0]); */
    /* bpf_printk("child right: %p", node->child[1]); */

    unsigned int next_bit = 0;
    __u64 matchlen = 0;

    /* Determine the longest prefix of @node that matches @key.
     * If it's the maximum possible prefix for this trie, we have
     * an exact match and can return it directly.
     */
    matchlen = __longest_prefix_match(trie, node, ws->key);
    /* bpf_printk("%x | %x   matchlen: %d", *(__u32 __arena*)node->data, *(__u32 *)ws->key->data, matchlen); */
    if (matchlen == trie->max_prefixlen) {
        ws->found = node;
        /* bpf_printk("found something 1"); */
        return 1;
    }

    /* If the number of bits that match is smaller than the prefix
     * length of @node, bail out and return the node we have seen
     * last in the traversal (ie, the parent).
     */
    if (matchlen < node->prefixlen)
        return 1;

    /* Consider this node as return candidate unless it is an
     * artificially added intermediate one.
     */
    if (!(node->flags & LPM_TREE_NODE_FLAG_IM)) {
        /* bpf_printk("found something 2"); */
        ws->found = node;
    }

    /* If the node match is fully satisfied, let's see if we can
     * become more specific. Determine the next bit in the key and
     * traverse down.
     */
    next_bit = extract_bit(ws->key->data, node->prefixlen);
    arena_lpm_trie_node_t *next = node->child[next_bit];
    cast_kern(next);
    ws->node = next;
    return 0;
}

static __always_inline
void __arena *arena_trie_lookup_elem(arena_lpm_trie_t *trie, void *_key)
{
    cast_kern(trie);
    arena_lpm_trie_node_t *root = trie->root;
    cast_kern(root);
    /* bpf_printk("let's see how well we can see the LPM"); */
    /* bpf_printk("entries: %d/%d", trie->n_entries, trie->max_entries); */
    /* bpf_printk("key_size: %d", trie->key_size); */
    /* bpf_printk("value_size: %d", trie->value_size); */
    /* bpf_printk("height: %d", trie->height); */
    /* bpf_printk("root: %p", root); */
    if (root != NULL) {
        __u32 __arena*p  = get_node_key(trie, root);
        /* bpf_printk("root key: ptr: %p val: %x", p, *p); */
        /* bpf_printk("child left: %p", root->child[0]); */
        /* bpf_printk("child right: %p", root->child[1]); */
    }

    walk_state_t ws = {
        .key = _key,
        .trie = trie,
        .node = root,
        .found = NULL,
        .err = 0,
    };

    if (ws.key->prefixlen > trie->max_prefixlen)
        return NULL;

    /* Start walking the trie from the root node ... */

    /* bpf_printk("start walking"); */
    if (bpf_loop(TRIE_MAX_HEIGHT, __lookup_walk_nodes, &ws, 0) < 0) {
        return NULL;
    }

    if (ws.found == NULL)
        return NULL;

    arena_lpm_trie_node_t *found = ws.found;
    cast_kern(found);
    return found->data + trie->key_size;
}

#else
/* User-space helpers */
#include <stdio.h>
#include <string.h>

typedef struct {
    void *area;
    __u32 area_size;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 flags;
    arena_lpm_trie_t **trie_ptr; /* out */
} arena_lpm_alloc_args_t;

static int userspace_arena_trie_alloc(arena_lpm_alloc_args_t *arg)
{
    if (arg->key_size < MIN_KEY_SIZE)
        return -EINVAL;

    // only support key size of 8(ipv4) and 20(ipv6)
    if (arg->key_size != 8) //  && arg->key_size != 20
        return -EINVAL;

    /* Allocate all the pages required for the data structure */
    const __u64 node_sz = NODE_SIZE(arg) + sizeof(mem_region_t); // the second part is the overhead memory allocator
    const __u64 mem_pool_sz = (arg->max_entries * node_sz);
    __u64 mem_sz = sizeof(arena_lpm_trie_t) + mem_pool_sz;
    __u64 num_pages = COUNT_OBJ(mem_sz, PAGE_SIZE);
    userspace_alloc_pages(arg->area, num_pages);
    printf("number of pages we are using: %llu\n", num_pages);
    __u64 available_memory = (num_pages * PAGE_SIZE) - sizeof(arena_lpm_trie_t);

    arena_lpm_trie_t *trie = arg->area;
    void *area = trie+1; /* mem region that we can use for nodes */
    trie->root = NULL;
    if (create_mem_region_obj(area, available_memory, &trie->mem)!= 0)
        return -1;
    trie->n_entries = 0;
    trie->max_entries =arg->max_entries;
    trie->max_prefixlen = (arg->key_size - KEY_DATA_OFFSET) * 8;
    trie->key_size = arg->key_size;
    trie->value_size = arg->value_size;
    trie->height = 0;

    /* Pass the trie object to the caller */
    *arg->trie_ptr = trie;

    return 0;
}

static arena_lpm_trie_node_t *lpm_trie_node_alloc(arena_lpm_trie_t *trie)
{
    arena_lpm_trie_node_t *node;
    const __u64 node_size = NODE_SIZE(trie);

    static __u64 counter = 0;
    node = (void *)trie->mem.first + (counter * node_size);
    counter++;
    /* node = just_alloc(&trie->mem, node_size); */
    if (!node)
        return NULL;

    node->flags = 0;

    return node;
}

static long userspace_arena_trie_update_elem(arena_lpm_trie_t *trie,
        void *_key, void *value, __u64 flags)
{
    arena_lpm_trie_node_t *node, *im_node = NULL, *new_node = NULL;
    arena_lpm_trie_node_t *free_node = NULL;
    arena_lpm_trie_node_t **slot;
    _key_t *key = _key;
    unsigned int next_bit;
    __u64 matchlen = 0;
    int ret = 0;
    __u32 height = 0;

    if (key->prefixlen > trie->max_prefixlen)
        return -EINVAL;

    if (trie->n_entries == trie->max_entries) {
        return -ENOSPC;
    }

    /* Allocate and fill a new node */
    new_node = lpm_trie_node_alloc(trie);
    if (new_node == NULL) {
        return -ENOMEM;
    }

    trie->n_entries++;

    new_node->prefixlen = key->prefixlen;
    new_node->child[0] = NULL;
    new_node->child[1] = NULL;
    void __arena* node_key = get_node_key(trie, new_node);
    void __arena* node_val = get_node_value(trie, new_node);
    memcpy(node_key, key->data, trie->key_size - KEY_DATA_OFFSET);
    memcpy(node_val, value, trie->value_size);
    /* printf("node key should be: %x\n", *(uint32_t*)node_key); */

    /* Now find a slot to attach the new node. To do that, walk the tree
     * from the root and match as many bits as possible for each node until
     * we either find an empty slot or a slot that needs to be replaced by
     * an intermediate node.
     */
    slot = &trie->root;
    height++;
    while ((node = *slot) != NULL) {
        /* printf("walking..."); */
        /* how much do these two node match ? */
        matchlen = __longest_prefix_match(trie, node, key);
        if (node->prefixlen != matchlen || // node does not include our key
                node->prefixlen == key->prefixlen || // we will not get more detailed than this node
                node->prefixlen == trie->max_prefixlen // we reached the end of key prefix space 
                ) {
            height--;
            break;
        }
        // Node matches our key but we may find a better fit
        next_bit = extract_bit(key->data, node->prefixlen);
        slot = &node->child[next_bit];
        height++;
    }

    /* Let's limit the height of our trie so that we can garauntee an upper
     * bound when doing lookup in the eBPF program
     * */
    if (height > TRIE_MAX_HEIGHT) {
        ret = -ENOSPC;
        goto out;
    }

    /* If the slot is empty (a free child pointer or an empty root),
     * simply assign the @new_node to that slot and be done.
     */
    if (!node) {
        *slot = new_node;
        goto out;
    }

    /* If the slot we picked already exists, replace it with @new_node
     * which already has the correct data array set.
     */
    if (node->prefixlen == matchlen) {
        new_node->child[0] = node->child[0];
        new_node->child[1] = node->child[1];

        if (!(node->flags & LPM_TREE_NODE_FLAG_IM))
            trie->n_entries--;

        *slot = new_node;
        free_node = node;

        goto out;
    }

    /* If the new node matches the prefix completely, it must be inserted
     * as an ancestor. Simply insert it between @node and *@slot.
     */
    if (matchlen == key->prefixlen) {
        next_bit = extract_bit(node->data, matchlen);
        new_node->child[next_bit] = node;
        *slot = new_node;
        goto out;
    }

    /* we need an intermediate node */
    im_node = lpm_trie_node_alloc(trie);
    if (!im_node) {
        ret = -ENOMEM;
        goto out;
    }

    im_node->prefixlen = matchlen;
    im_node->flags |= LPM_TREE_NODE_FLAG_IM;
    void __arena *im_node_key = get_node_key(trie, im_node);
    memcpy(im_node_key, node->data, trie->key_size - KEY_DATA_OFFSET);

    /* Now determine which child to install in which slot */
    if (extract_bit(key->data, matchlen)) {
        im_node->child[0] = node;
        im_node->child[1] = new_node;
    } else {
        im_node->child[0] = new_node;
        im_node->child[1] = node;
    }

    /* Finally, assign the intermediate node to the determined slot */
    *slot = im_node;

out:
    if (ret) {
        if (new_node)
            trie->n_entries--;

        just_free(new_node);
        just_free(im_node);
    }

    just_free(free_node);

    return ret;
}

#endif

// vim: et ts=4 sw=4
