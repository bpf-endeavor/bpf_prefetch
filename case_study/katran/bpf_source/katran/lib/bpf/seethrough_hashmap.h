#ifndef __SEETHROUGH_HASHMAP_H
#define __SEETHROUGH_HASHMAP_H
#include "jhash.h"

/* I am trying to implement a hash-map similar to the one implemented in eBPF
 * runtime. But the goal is to have more control over its code so we can
 * prefetch.
 * */


/* How does the map works
 *
 * key -- hash --> index ->[btable] --> bucket_t ->[Compare] --> Match lookup the (atable)
 *                     Lookup the ntable for the next node <_/
 *
 * */

/*
 * @param __name: name of the map
 * @param __key_t: type of the key used for lookup
 * @param __val_t: type of value that is stored in the map
 * @param __bucket_size: maximum number of nodes inside a bucket
 * @param __num_bucket: number of buckets
 * @param __max_entries: maximum number of entries that we want to store
 * */
#define S_HASH_MAP(__name, __key_t, __val_t, __bucket_size, __num_bucket, __max_entries)        \
                                                                                                \
typedef struct {                                                                                \
	__u32 next; /* next node */                                                                 \
	__u32 hash; /* hash of the key */                                                           \
	__u32 ptr;  /* pointer to the value entry (atable index) */                                 \
	__u32 freelist_next;                                                                        \
	__key_t key; /* key of the stored value */                                                  \
} __name##_node_t;                                                                              \
                                                                                                \
typedef struct {                                                                                \
	__u32 first;                                                                                \
} __name##_bucket_t;                                                                            \
                                                                                                \
typedef struct {                                                                                \
	__u32 freelist_next;                                                                        \
	__val_t v;                                                                                  \
} __name##_val_entry_t;                                                                         \
                                                                                                \
struct {                                                                                        \
	__uint(type,  BPF_MAP_TYPE_ARRAY);                                                          \
	__type(key,   __u32);                                                                       \
	__type(value, __name##_bucket_t);                                                           \
	__uint(max_entries, __num_bucket);                                                          \
} __name##_btable SEC(".maps");                                                                 \
                                                                                                \
struct {                                                                                        \
	__uint(type,  BPF_MAP_TYPE_ARRAY);                                                          \
	__type(key,   __u32);                                                                       \
	__type(value, __name##_node_t);                                                             \
	__uint(max_entries, __max_entries);                                                         \
} __name##_ntable SEC(".maps");                                                                 \
                                                                                                \
struct {                                                                                        \
	__uint(type,  BPF_MAP_TYPE_ARRAY);                                                          \
	__type(key,   __u32);                                                                       \
	__type(value, __name##_val_entry_t);                                                        \
	__uint(max_entries, __max_entries);                                                         \
} __name##_atable SEC(".maps");                                                                 \
                                                                                                \
static __u32 __name##_free2use_node_index = 1;                                                  \
static __u32 __name##_free2use_entry_index = 1;                                                 \
                                                                                                \
static inline __attribute__((always_inline)) __val_t *__name##_lookup(__key_t *key)             \
{                                                                                               \
	__name##_bucket_t *b = NULL;                                                                \
	__name##_node_t *n = NULL;                                                                  \
	__name##_val_entry_t *e = NULL;                                                             \
	__u32 hash = jhash(key, sizeof(*key), JHASH_INITVAL);                                       \
	__u32 index = hash % __num_bucket;                                                          \
	/* Find the bueckt */                                                                       \
	/* bpf_printk("btable-index: %d", index); */                                                \
	b = bpf_map_lookup_elem(&__name##_btable, &index);                                          \
	if (b == NULL)                                                                              \
		return NULL;                                                                            \
	/* Walk the nodes in the bucket and check for a match */                                    \
	index = b->first;                                                                           \
	for (__u16 i = 0; i < __bucket_size; i++) {                                                 \
		if (index == 0) {                                                                       \
			/* end of chain of nodes */                                                         \
			return NULL;                                                                        \
		}                                                                                       \
		n = bpf_map_lookup_elem(&__name##_ntable, &index);                                      \
		if (n == NULL) {                                                                        \
			bpf_printk("The node chain is broken!");                                            \
			return NULL;                                                                        \
		}                                                                                       \
		if (n->hash != hash) {                                                                  \
			/* not a match go to next */                                                        \
			index = n->next;                                                                    \
			continue;                                                                           \
		}                                                                                       \
		if (__builtin_memcmp(key, &n->key, sizeof(*key)) != 0) {                                \
			/* not a match go to next */                                                        \
			index = n->next;                                                                    \
			continue;                                                                           \
		}                                                                                       \
		/* Get the entry and return the value */                                                \
		index = n->ptr;                                                                         \
		if (index == 0) {                                                                       \
			bpf_printk("__lookup: pointer is null!");                                           \
			return NULL;                                                                        \
		}                                                                                       \
		e = bpf_map_lookup_elem(&__name##_atable, &index);                                      \
		if (e == NULL) {                                                                        \
			bpf_printk("__lookup: entry pointer was wrong!");                                   \
			return NULL;                                                                        \
		}                                                                                       \
		return &e->v;                                                                           \
	}                                                                                           \
	/* Did not found a match for the key */                                                     \
	return NULL;                                                                                \
}                                                                                               \
                                                                                                \
static inline __attribute__((always_inline)) int __name##_update(__key_t *key, __val_t *val)    \
{                                                                                               \
	__u32 x;                                                                                    \
	__name##_bucket_t *b = NULL;                                                                \
	__name##_node_t *n = NULL;                                                                  \
	__name##_val_entry_t *e = NULL;                                                             \
	__val_t *r = NULL;                                                                          \
	__u32 hash = 0;                                                                             \
	__u32 index = 0;                                                                            \
	__u32 node_index = 0;                                                                       \
	/* Allocate a node (find a free node) */                                                    \
	node_index = index = __name##_free2use_node_index;                                          \
	n = bpf_map_lookup_elem(&__name##_ntable, &index);                                          \
	if (n == NULL) {                                                                            \
		bpf_printk("out of nodes!");                                                            \
		return -1;                                                                              \
	}                                                                                           \
	__name##_free2use_node_index = n->freelist_next;                                            \
	if (n->ptr != 0) {                                                                          \
		bpf_printk("got a node which was not empty");                                           \
		return -1;                                                                              \
	}                                                                                           \
	/* Allocate an entry */                                                                     \
	index = __name##_free2use_entry_index;                                                      \
	e = bpf_map_lookup_elem(&__name##_atable, &index);                                          \
	if (e == NULL) {                                                                            \
		bpf_printk("out of entries!");                                                          \
		return -1;                                                                              \
	}                                                                                           \
	__name##_free2use_entry_index = e->freelist_next;                                           \
	/* Find the bucket */                                                                       \
	hash = jhash(key, sizeof(*key), 123);                                                       \
	index = hash % __num_bucket;                                                                \
	b = bpf_map_lookup_elem(&__name##_btable, &index);                                          \
	if (b == NULL) {                                                                            \
		/* This must never happen */                                                            \
		return -1;                                                                              \
	}                                                                                           \
	/* Add the node pointer to the head of the node chain */                                    \
	n->next = b->first;                                                                         \
	b->first = node_index;                                                                      \
	/* Update the node to point to the allocated entry */                                       \
	n->hash = hash;                                                                             \
	__builtin_memcpy(&n->key, key, sizeof(*key));                                               \
	n->ptr = x;                                                                                 \
	/* Store value on the entry object */                                                       \
	__builtin_memcpy(&e->v, val, sizeof(*val));                                                 \
	return 0;                                                                                   \
}                                                                                               \

#endif                                                                                          
