#pragma once
#include <errno.h>
#include "list.h"
#include "common/my_junk.h"
#include "hash/jhash.h"

#ifndef HTAB_KEY_DEFINED
#define HTAB_KEY_DEFINED
typedef struct {
    char data[4];
} __packed my_key_t;

typedef struct {
    char data[32];
} __packed my_value_t;
#endif

typedef __u16 keysz_t;
typedef __u16 valsz_t;
#define EXTRACT_KEY(htab, elm) (((void __arena*)(elm)) + sizeof(hashtab_elem_t))
#define EXTRACT_VAL(htab, elm) (((void __arena*)(elm)) + sizeof(hashtab_elem_t) + sizeof(my_key_t))

#ifndef __BPF__
#define bpf_printk(...)
#endif

struct htab_bucket {
    struct arena_list_head head;
};
typedef struct htab_bucket __arena htab_bucket_t;

struct htab {
    htab_bucket_t *buckets;
    int n_buckets;
    /* NOTE: use a free list or maple tree for tracking the elements slabs :)!
     * What am I doing here is just a hack to test the idea */
    void *elems;
    __u64 elems_sz;
    __u64 elems_used;
    /* --------------------------- */
};
typedef struct htab __arena htab_t;

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

struct hashtab_elem {
    struct arena_list_node hash_node;
    int hash;
    /* Key, and value would be here */
};
typedef struct hashtab_elem __arena hashtab_elem_t;

static __always_inline hashtab_elem_t *lookup_elem_raw(arena_list_head_t *head, __u32 hash,
        void *key, keysz_t key_sz)
{
    /*bpf_printk("sizeof hash_elem_t: %llu\n", sizeof(hashtab_elem_t));*/
    /*bpf_printk("here");*/
    void __arena *tmp;
    cast_kern(head);
    hashtab_elem_t *l = arena_container_of(head->first, hashtab_elem_t, hash_node);
    cast_kern(l);
    /*bpf_printk("there");*/
    for (__u16 i = 0; i < 8; i++) {
        if (l == NULL) {
            /*bpf_printk("bucker was null ??");*/
            break;
        }
        if (l->hash != hash) {
            /*bpf_printk("hash did not matched");*/
            goto next_item;
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
next_item:
        tmp = l->hash_node.next;
        l = arena_container_of(tmp, hashtab_elem_t, hash_node);
        cast_kern(l);
    }
    bpf_printk("nothing matched!");
    return NULL;

    /*const __u32 loop_upper_limit = 8;*/
    /*__u32 loop_counter = 0;*/
    /*list_for_each_entry(l, head, hash_node) {*/
    /*    if (l->hash == hash) {*/
    /*        void __arena*l_key = EXTRACT_KEY(htab, l);*/
    /*        if (my_memcmp((void *)l_key, key, key_sz) == 0) {*/
    /*            return l;*/
    /*        }*/
    /*    }*/
    /*    loop_counter++;*/
    /*    if (loop_counter >= loop_upper_limit)*/
    /*        break;*/
    /*}*/
    /**/
    /*return NULL;*/
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
    return NULL;
}

/* static inline int htab_update_elem(htab_t *htab, void *key, void *value) */
/* { */
/*     hashtab_elem_t *l_new = NULL, *l_old; */
/*     arena_list_head_t *head; */

/*     cast_kern(htab); */
/*     int hash = htab_hash(key, htab->key_sz); */
/*     head = select_bucket(htab, hash); */
/*     l_old = lookup_elem_raw(head, hash, key, htab->key_sz); */

/*     l_new = bpf_alloc(sizeof(hashtab_elem_t) + htab->key_sz + htab->val_sz); */
/*     if (!l_new) */
/*         return -ENOMEM; */
/*     l_new->hash = hash; */
/*     void *l_key = EXTRACT_KEY(htab, l_new); */
/*     my_memcpy(l_key, key, htab->key_sz); */
/*     void *l_val = l_key + htab->key_sz; */
/*     my_memcpy(l_val, value, htab->val_sz); */

/*     list_add_head(&l_new->hash_node, head); */
/*     if (l_old) { */
/*         list_del(&l_old->hash_node); */
/*         bpf_free(l_old); */
/*     } */
/*     return 0; */
/* } */

/* static inline void htab_init(htab_t *htab, keysz_t key_sz, valsz_t val_sz) */
/* { */
/*     const int count_pages = 10; */
/*     void __arena *buckets = bpf_arena_alloc_pages(&arena, */
/*             NULL, count_pages, NUMA_NO_NODE, 0); */

/*     cast_user(buckets); */
/*     htab->buckets = buckets; */
/*     htab->n_buckets = count_pages * PAGE_SIZE / sizeof(struct htab_bucket); */
/*     htab->key_sz = key_sz; */
/*     htab->val_sz = val_sz; */
/* } */

#ifndef __BPF__ /* THIS IS FOR THE USERSPACE */

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

static inline int htab_init_userspace(void *area, __u32 max_entries,
        htab_t **htab_ptr /* out */)
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
    const int mem_sz_entries = max_entries *  sizeof(my_value_t);
    const int count_bucket_page = COUNT_OBJ(mem_sz_buckets, PAGE_SIZE);
    const int count_value_page = COUNT_OBJ(mem_sz_entries, PAGE_SIZE);
    /* total number of pages that I need */
    const int count_pages = count_bucket_page + count_value_page;
    printf("requred number of pages: %d (%d + %d)\n",
            count_pages, count_bucket_page, count_value_page);

    {
        /* Make sure the requested number of pages are allocated. Try to access
         * them to make sure. If it is not allocated the fault signal should
         * cause the kernel to allocate it.  */
        __u8 *ptr = area;
        for (size_t i = 0; i < count_pages; i++) {
            *(__u32 *)&ptr[PAGE_SIZE * i + 0] = 0x0000;
        }
    }

    htab_t *htab = area;
    void __arena *buckets = area + htab_size_rounded;
    void __arena *elems = area + (count_bucket_page * PAGE_SIZE);

    /* NOTE: I think we do not need to initilize buckets (linked-lists)
     * because they are all set to zero uppon allocation (test this).
     * */
    htab->buckets = buckets;
    htab->n_buckets = n_buckets;
    /*printf("number of buckets: %lu\n", num_buckets);*/
    htab->elems = elems;
    htab->elems_sz = count_value_page * PAGE_SIZE;
    htab->elems_used = 0;

    *htab_ptr = htab;
    return 0;
}

static inline int htab_update_elem_userspace(htab_t *htab,
        void *key, void *value)
{
    hashtab_elem_t *l_new = NULL, *l_old;
    arena_list_head_t *head;

    int hash = htab_hash(key, sizeof(my_key_t));
    head = select_bucket(htab, hash);
    l_old = lookup_elem_raw(head, hash, key, sizeof(my_key_t));

    /* TODO: I need a memory management on top of this raw memory */
    const __u64 elem_sz = sizeof(hashtab_elem_t) + sizeof(my_key_t) +
        sizeof(my_value_t);
    if (htab->elems_sz - htab->elems_used > elem_sz) {
        l_new = htab->elems + htab->elems_used;
        htab->elems_used += elem_sz;
        /* printf("new elem hash: %u  addr: %p\n", hash, l_new); */
    } else {
        l_new = NULL;
    }
    if (!l_new)
        return -ENOMEM;
    l_new->hash = hash;
    void *l_key = EXTRACT_KEY(htab, l_new);
    memcpy(l_key, key, sizeof(my_key_t));
    void *l_val = l_key + sizeof(my_key_t);
    memcpy(l_val, value, sizeof(my_value_t));
    /*printf("l_val: %s @%llu\n", (char *)l_val, (__u64)l_val - (__u64)l_new);*/
    /*printf("sizeof hash_elem_t: %llu\n", sizeof(hashtab_elem_t));*/

    /* TODO: make sure the depth of list does not exceed a value (BPF is
     * bounded, it is fine if XDP can not find it but just to control the
     * experiments, I must know what conditions arises)*/
    list_add_head_userspace(&l_new->hash_node, head);
    if (l_old) {
        printf("THIS MUST NOT HAPPEN\n");
        list_del(&l_old->hash_node);
        /* bpf_free(l_old); */
    }
    return 0;
}
#endif
// vim: et ts=4 sw=4:
