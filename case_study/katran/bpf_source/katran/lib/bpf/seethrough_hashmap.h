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


#define S_HASH_MAP(__name, __key_t, __val_t, __bucket_size, __num_bucket, __max_entries)            \
                                                                                                    \
typedef struct {                                                                                    \
	__u32 next; /* next node */                                                                 \
	__u32 hash; /* hash of the key */                                                           \
	__u32 ptr;  /* pointer to the value entry (atable index) */                                 \
	__key_t key; /* key of the stored value */                                                  \
} __name##_node_t;                                                                                  \
                                                                                                    \
typedef struct {                                                                                    \
	__name##_node_t first;                                                                      \
} __name##_bucket_t;                                                                                \
                                                                                                    \
typedef struct {                                                                                    \
	__u32 freelist_next;                                                                        \
	__val_t v;                                                                                  \
} __name##_val_entry_t;                                                                             \
                                                                                                    \
struct {                                                                                            \
	__uint(type,  BPF_MAP_TYPE_ARRAY);                                                          \
	__type(key,   __u32);                                                                       \
	__type(value, __name##_bucket_t);                                                           \
	__uint(max_entries, __num_bucket);                                                          \
} __name##_btable SEC(".maps");                                                                     \
                                                                                                    \
struct {                                                                                            \
	__uint(type,  BPF_MAP_TYPE_ARRAY);                                                          \
	__type(key,   __u32);                                                                       \
	__type(value, __name##_node_t);                                                             \
	__uint(max_entries, __max_entries);                                                         \
} __name##_ntable SEC(".maps");                                                                     \
                                                                                                    \
struct {                                                                                            \
	__uint(type,  BPF_MAP_TYPE_ARRAY);                                                          \
	__type(key,   __u32);                                                                       \
	__type(value, __name##_val_entry_t);                                                        \
	__uint(max_entries, __max_entries);                                                         \
} __name##_atable SEC(".maps");                                                                     \
                                                                                                    \
/* a simple pointer to show how far from the atable we have allocated */                            \
static __u32 __name##_free2use_index = 1;                                                           \
                                                                                                    \
static inline __attribute__((always_inline)) __val_t *__name##_lookup(__key_t *key)                 \
{                                                                                                   \
	void *__ptr = NULL;                                                                         \
	__name##_bucket_t *b = NULL;                                                                \
	__val_t *r = NULL;                                                                          \
	__u32 hash = jhash(key, sizeof(*key), JHASH_INITVAL);                                       \
	__u32 index = hash % __num_bucket;                                                          \
	__u32 ptr;                                                                                  \
	/* bpf_printk("btable-index: %d", index); */                                                \
	b = bpf_map_lookup_elem(&__name##_btable, &index);                                          \
	if (b == NULL)                                                                              \
		return NULL;                                                                        \
                                                                                                    \
	for (__u16 i = 0; i < __bucket_size; i++) {                                                 \
		if (b->nodes[i].hash != hash) {                                                     \
			continue;                                                                   \
		} else {                                                                            \
			ptr = b->nodes[i].ptr;                                                      \
			if (__builtin_memcmp(key, &b->nodes[i].key, sizeof(*key)) == 0) {           \
				/* bpf_printk("match: %d", i); */                                   \
				/* found the value */                                               \
				if (ptr == 0) {                                                     \
					bpf_printk("__lookup: pointer is null!");                   \
					return NULL;                                                \
				}                                                                   \
				r = bpf_map_lookup_elem(&__name##_atable, &ptr);                    \
				/* bpf_printk("p: %p  a: %p", __ptr, r); */                         \
				return r;                                                           \
			} else {                                                                    \
				/* bpf_printk("same hash not match: %d", i); */                     \
			}                                                                           \
		}                                                                                   \
	}                                                                                           \
	/* did not found */                                                                         \
	return NULL;                                                                                \
}                                                                                                   \
                                                                                                    \
static inline __attribute__((always_inline)) int __name##_update(__key_t *key, __val_t *val)        \
{                                                                                                   \
	__u32 x;                                                                                    \
	__name##_bucket_t *b = NULL;                                                                \
	__val_t *r = NULL;                                                                          \
	__u32 hash = jhash(key, sizeof(*key), 123);                                                 \
	__u32 index = hash % __num_bucket;                                                          \
	__u32 node_index = -1;                                                                      \
	b = bpf_map_lookup_elem(&__name##_btable, &index);                                          \
	if (b == NULL)                                                                              \
		return -1;                                                                          \
	for (__u16 i = 0; i < __bucket_size; i++) {                                                 \
		/* NOTE: this update (also lookup) routing has race conditions */                   \
		if (b->nodes[i].ptr != 0) {                                                         \
			/* this node is used; */                                                    \
			continue;                                                                   \
		}                                                                                   \
		node_index = i;                                                                     \
		goto __found_empty_node;                                                            \
	}                                                                                           \
	/* did not found empty node */                                                              \
	bpf_printk("__update: bucket was full!");                                                   \
	return -1;                                                                                  \
                                                                                                    \
__found_empty_node:                                                                                 \
		x = __name##_used_index;                                                            \
		__name##_used_index += 1;                                                           \
		if (x > __max_entries) {                                                            \
			bpf_printk("__update: out of value slots");                                 \
			return -1;                                                                  \
		}                                                                                   \
		b->nodes[node_index].hash = hash;                                                   \
		__builtin_memcpy(&b->nodes[node_index].key, key, sizeof(*key));                     \
		b->nodes[node_index].ptr = x;                                                       \
		r = bpf_map_lookup_elem(&__name##_atable, &x);                                      \
		if (r == NULL) {                                                                    \
			/* this must never happen */                                                \
			bpf_printk("__update: allocated index does not exists!");                   \
			return -1;                                                                  \
		}                                                                                   \
		__builtin_memcpy(r, val, sizeof(*val));                                             \
		return 0;                                                                           \
}                                                                                                   \

#endif
