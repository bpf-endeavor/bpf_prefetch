#pragma once
#include <errno.h>
#include "list.h"
#include "common/arena_common.h"
#include "common/my_junk.h"
#include "hash/jhash.h"

#ifdef REFETCH
#include "honey/prefetching.h"
#endif

#define MAX_BUCKET_LENGHT 8
#define EXTRACT_KEY(htab, elm) (((void __arena*)(elm)) + sizeof(hashtab_elem_t))
#define EXTRACT_VAL(htab, elm) (((void __arena*)(elm)) + sizeof(hashtab_elem_t) + sizeof(my_key_t))
#define HTAB_ENTRY_SZ (sizeof(hashtab_elem_t) + sizeof(my_key_t ) + sizeof(my_value_t))

#if !defined(__BPF__) || !defined(__bpf__)
#define bpf_printk(...)
#endif


/* Type definitions ---------- */
#ifndef HTAB_KEY_DEFINED
/* Warnning: make sure the key and value types defined in eBPF and userspace
 * program match */
typedef struct {
    char data[4];
} __packed my_key_t;

typedef struct {
    char data[32];
} __packed my_value_t;
#endif

typedef __u16 keysz_t;
typedef __u16 valsz_t;

struct htab_bucket {
    struct arena_list_head head;
};
typedef struct htab_bucket __arena htab_bucket_t;

struct htab {
    htab_bucket_t *buckets;
    int n_buckets;
    void __arena *elems; // memory for elements
    __u64 elems_sz; // bytes
    __u64 elems_used; // bytes
};
typedef struct htab __arena htab_t;

struct hashtab_elem {
    struct arena_list_node hash_node;
    int hash;
    /* Key, and value would be here */
};
typedef struct hashtab_elem __arena hashtab_elem_t;
/* ----------------- */


static __always_inline
void __arena* __htab_entry_get(htab_t *htab)
{
    const __u64 elem_sz = HTAB_ENTRY_SZ;
    const __u64 available_mem = htab->elems_sz - htab->elems_used;
    if (available_mem < elem_sz) {
        return NULL;
    }
    void __arena *e = htab->elems + htab->elems_used;
    htab->elems_used += elem_sz;
    return e;
}

static __always_inline
void __htab_entry_put(htab_t *h, void __arena *p)
{
    /* TODO: implement a useful memory management system */
    return;
}

static inline htab_bucket_t *__select_bucket(htab_t *htab, __u32 hash)
{
    htab_bucket_t *b = htab->buckets;
    cast_kern(b);
    return &b[hash & (htab->n_buckets - 1)];
}

static inline arena_list_head_t *select_bucket(htab_t *htab, __u32 hash)
{
    return &__select_bucket(htab, hash)->head;
}

static __always_inline hashtab_elem_t *lookup_elem_raw(arena_list_head_t *head, __u32 hash,
        void *key, keysz_t key_sz)
{
    /*bpf_printk("sizeof hash_elem_t: %llu\n", sizeof(hashtab_elem_t));*/
    void __arena *tmp;
    cast_kern(head);
    hashtab_elem_t *l = arena_container_of(head->first, hashtab_elem_t,
            hash_node);
    cast_kern(l);
    for (__u16 i = 0; i < MAX_BUCKET_LENGHT; i++) {
        if (l == NULL) {
            /* bpf_printk("bucket was null ??"); */
            break;
        }
        if (l->hash != hash) {
            /* bpf_printk("hash did not matched"); */
            tmp = l->hash_node.next;
            l = arena_container_of(tmp, hashtab_elem_t, hash_node);
            cast_kern(l);
            continue;
        }
        void __arena *l_key = EXTRACT_KEY(htab, l);
        if (my_memcmp((void *)l_key, key, key_sz) == 0) {
            /*bpf_printk("hash matched: %u", hash);*/
            /*bpf_printk("key matched: %x=%x", *(__u32 *)l_key, *(__u32 *)key);*/
            /*bpf_printk("linked list offset: %d", i);*/
            /*char __arena*v = EXTRACT_VAL(htab, l);*/
            /*cast_kern(v);*/
            /*char tmp[32] = {};*/
            /*__builtin_memcpy(tmp, v, 31);*/
            /*bpf_printk("val: %s", v);*/
            /*bpf_printk("val offset: %llu", (__u64)v - (__u64)l);*/
            /*for (int i = 0; i < sizeof(htab_t) + sizeof(my_key_t) + sizeof(my_value_t); i++) {*/
            /*for (int i = 0; i < 31; i++) {*/
            /*    bpf_printk("%c", ((char *)v)[i]);*/
            /*}*/
            /*bpf_printk("val: %s", v);*/
            return l;
        }

        tmp = l->hash_node.next;
        l = arena_container_of(tmp, hashtab_elem_t, hash_node);
        cast_kern(l);
    }
    /* bpf_printk("nothing matched!"); */
    return NULL;
}

static inline int htab_hash(void *key, keysz_t sz)
{
    switch (sz) {
        case 4:
            return jhash_1word(*(__u32 *)key, JHASH_INITVAL);
            break;
        case 8:
            return jhash_2words(*(__u32 *)key, *((__u32 *)key + 1),
                    JHASH_INITVAL);
            break;
        default:
            break;
    }
    return jhash(key, sz, JHASH_INITVAL);
}

static inline void __arena *htab_lookup_elem(htab_t *htab, void *key)
{
    hashtab_elem_t *l_old = 0;
    arena_list_head_t *head = 0;
    int hash = 0;

    cast_kern(htab);
    hash = htab_hash(key, sizeof(my_key_t));
    head = select_bucket(htab, hash);
    /*bpf_printk("hash: %u", hash); */
    l_old = lookup_elem_raw(head, hash, key, sizeof(my_key_t));
    if (l_old != NULL) {
        void __arena *l_val = EXTRACT_VAL(htab, l_old);
        cast_kern(l_val);
        return l_val;
    }
    /* bpf_printk("elem used: %d", htab->elems_used); */
    return NULL;
}


#ifdef PREFETCH
struct partial_lookup_state {
    void __arena *head;
    int hash;
};

static inline void __arena *htab_lookup_elem_p1(htab_t *htab, void *key,
        struct partial_lookup_state *s)
{
    s->head = NULL;
    s->hash = 0;

    cast_kern(htab);
    s->hash = htab_hash(key, sizeof(my_key_t));
    s->head = select_bucket(htab, s->hash);
    P((void *)s->head);
    return NULL;
}

static inline void __arena *htab_lookup_elem_p2(htab_t *hatb, void *key,
        struct partial_lookup_state *s)
{
    /*bpf_printk("hash: %u", hash); */
    hashtab_elem_t *l_old = NULL;
    l_old = lookup_elem_raw(s->head, s->hash, key, sizeof(my_key_t));
    if (l_old != NULL) {
        void __arena *l_val = EXTRACT_VAL(htab, l_old);
        cast_kern(l_val);
        return l_val;
    }
    return NULL;
}
#endif

static inline int htab_update_elem(htab_t *htab, void *key, void *value)
{
    hashtab_elem_t *l_new = NULL, *l_old;
    arena_list_head_t *head;
    void *l_val;

    cast_kern(htab);
    int hash = htab_hash(key, sizeof(my_key_t));
    head = select_bucket(htab, hash);
    l_old = lookup_elem_raw(head, hash, key, sizeof(my_key_t));

    if (l_old) {
        /* we have this key in hash map just update the value */
        l_val = (void *)EXTRACT_VAL(htab, l_val);
        my_memcpy(l_val, value, sizeof(my_value_t));
        return 0;
    }

    l_new = __htab_entry_get(htab);
    if (l_new == NULL)
        return -ENOMEM;

    l_new->hash = hash;
    void *l_key = (void *)EXTRACT_KEY(htab, l_new);
    my_memcpy(l_key, key, sizeof(my_key_t));
    l_val = l_key + sizeof(my_key_t);
    my_memcpy(l_val, value, sizeof(my_value_t));

    list_add_head(&l_new->hash_node, head);
    return 0;
}

#ifndef __BPF__ /* THIS IS FOR THE USERSPACE */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static inline size_t round_down_pow_two(size_t x)
{
    size_t tmp = x;
    size_t counter = 0;
    while (tmp) {
        tmp >>= 1;
        counter++;
    }
    return 1 << counter;
}

static inline size_t round_up_pow_two(size_t x)
{
    // check if it is already power of two
    if ((x & (x - 1)) == 0) {
        return x;
    }
    return round_down_pow_two(x) << 1;
}

static inline int htab_init_userspace_2(void *area, __u32 max_entries,
        htab_t **htab_ptr /* out */, uint32_t *used_pages /* out */)
{
#define COUNT_OBJ(A, B) ((((A) + (B)) - 1) / (B))
#define ROUND_UP(N, S) (COUNT_OBJ(N, S) * (S))

    /* memory size that I need for the htab structure it self */
    uint64_t htab_size_rounded = ROUND_UP(sizeof(htab_t), 64);
    /* number of buckets that I want */
    const int n_buckets = round_up_pow_two(max_entries);
    /* amount of memory that I want to allocate for bucket and htab */
    const int mem_sz_buckets =
        n_buckets * sizeof(htab_bucket_t) + htab_size_rounded;
    /* amount of memory that I want for the entries */
    const int mem_sz_entries = max_entries * HTAB_ENTRY_SZ;
    unsigned long total_mem_sz = mem_sz_buckets + mem_sz_entries;
    /* total number of pages that I need */
    const int count_pages = COUNT_OBJ(total_mem_sz, PAGE_SIZE);
    /* printf("DEBUG: Arena: required number of pages: %d\n", count_pages); */

    {
        /* Make sure the requested number of pages are allocated. Try to access
         * them to make sure. If it is not allocated the fault signal should
         * cause the kernel to allocate it.  */
        __u8 *ptr = area;
        for (size_t i = 0; i < count_pages; i++) {
            *(__u32 *)&ptr[PAGE_SIZE * i + 0] = 0x0000;
        }
    }

    if (used_pages != NULL) {
        /* report the number pages we used from Arena. This is useful if the
         * app wants to create multiple htabs in the Arena */
        *used_pages = count_pages;
    }

    htab_t *htab = area;
    void __arena *buckets = area + htab_size_rounded;
    void __arena *elems = area + mem_sz_buckets;

    memset(buckets, 0, mem_sz_buckets);

    htab->buckets = buckets;
    htab->n_buckets = n_buckets;
    /*printf("number of buckets: %lu\n", num_buckets);*/
    htab->elems = elems;
    htab->elems_sz = mem_sz_entries;
    htab->elems_used = 0;

    *htab_ptr = htab;
    return 0;
}

static inline int htab_init_userspace(void *area, __u32 max_entries,
        htab_t **htab_ptr /* out */)
{
    return htab_init_userspace_2(area, max_entries, htab_ptr, NULL);
}

static inline int htab_update_elem_userspace(htab_t *htab,
        void *key, void *value)
{
    return htab_update_elem(htab, key, value);
    /* hashtab_elem_t *l_new = NULL, *l_old; */
    /* arena_list_head_t *head; */

    /* int hash = htab_hash(key, sizeof(my_key_t)); */
    /* head = select_bucket(htab, hash); */
    /* l_old = lookup_elem_raw(head, hash, key, sizeof(my_key_t)); */

    /* /1* TODO: I need a memory management on top of this raw memory *1/ */
    /* const __u64 elem_sz = sizeof(hashtab_elem_t) + sizeof(my_key_t) + */
    /*     sizeof(my_value_t); */
    /* if (htab->elems_sz - htab->elems_used > elem_sz) { */
    /*     l_new = htab->elems + htab->elems_used; */
    /*     htab->elems_used += elem_sz; */
    /*     /1* printf("new elem hash: %u  addr: %p\n", hash, l_new); *1/ */
    /* } else { */
    /*     l_new = NULL; */
    /* } */
    /* if (!l_new) */
    /*     return -ENOMEM; */
    /* l_new->hash = hash; */
    /* void *l_key = EXTRACT_KEY(htab, l_new); */
    /* memcpy(l_key, key, sizeof(my_key_t)); */
    /* void *l_val = l_key + sizeof(my_key_t); */
    /* memcpy(l_val, value, sizeof(my_value_t)); */
    /* /1* printf("l_val: %s @%llu\n", (char *)l_val, (__u64)l_val - (__u64)l_new); *1/ */
    /* /1* printf("sizeof hash_elem_t: %llu\n", sizeof(hashtab_elem_t)); *1/ */

    /* /1* TODO: make sure the depth of list does not exceed a value (BPF is */
    /*  * bounded, it is fine if XDP can not find it but just to control the */
    /*  * experiments, I must know what conditions arises) *1/ */
    /* list_add_head_userspace(&l_new->hash_node, head); */
    /* if (l_old) { */
    /*     printf("THIS MUST NOT HAPPEN\n"); */
    /*     list_del(&l_old->hash_node); */
    /*     /1* bpf_free(l_old); *1/ */
    /* } */
    /* return 0; */
}
#endif
// vim: et ts=4 sw=4:
