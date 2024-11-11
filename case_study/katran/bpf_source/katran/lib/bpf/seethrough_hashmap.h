#ifndef __SEETHROUGH_HASHMAP_H
#define __SEETHROUGH_HASHMAP_H

/* BPF seethrough hashmap
 * Farbod Shahinfar 2024
 * */

/* I am trying to implement a hash-map similar to the one implemented in eBPF
 * runtime. But the goal is to have more control over its code so we can
 * prefetch.
 * */

/* How does the map works:
 *
 * key -- hash --> index ->[btable] --> bucket_t ->[Compare] --> Match lookup the (atable)
 *                     Lookup the ntable for the next node <_/
 *
 * */

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@netfilter.org)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */

static inline unsigned int _x_rol32(unsigned int word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((unsigned int)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix - mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= _x_rol32(c, 4);  c += b;	\
	b -= a;  b ^= _x_rol32(a, 6);  a += c;	\
	c -= b;  c ^= _x_rol32(b, 8);  b += a;	\
	a -= c;  a ^= _x_rol32(c, 16); c += b;	\
	b -= a;  b ^= _x_rol32(a, 19); a += c;	\
	c -= b;  c ^= _x_rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= _x_rol32(b, 14);		\
	a ^= c; a -= _x_rol32(c, 11);		\
	b ^= a; b -= _x_rol32(a, 25);		\
	c ^= b; c -= _x_rol32(b, 16);		\
	a ^= c; a -= _x_rol32(c, 4);		\
	b ^= a; b -= _x_rol32(a, 14);		\
	c ^= b; c -= _x_rol32(b, 24);		\
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitrary value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline __attribute__((always_inline))
__u32 _x_jhash(const void *key, unsigned short length, unsigned int initval)
{
	unsigned int a, b, c;
	const unsigned char *k = key;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	for (unsigned short _i = 0; _i < 4; _i++) { /* the upper limit on the length is 60 bytes */
		if (length <= 12) {
			break;
		}
		a += *(unsigned int *)k;
		b += *(unsigned int *)(k + 4);
		c += *(unsigned int *)(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	switch (length) {
	case 12: c += (unsigned int)k[11]<<24;
	case 11: c += (unsigned int)k[10]<<16;
	case 10: c += (unsigned int)k[9]<<8;
	case 9:  c += k[8];
	case 8:  b += (unsigned int)k[7]<<24;
	case 7:  b += (unsigned int)k[6]<<16;
	case 6:  b += (unsigned int)k[5]<<8;
	case 5:  b += k[4];
	case 4:  a += (unsigned int)k[3]<<24;
	case 3:  a += (unsigned int)k[2]<<16;
	case 2:  a += (unsigned int)k[1]<<8;
	case 1:  a += k[0];
		 __jhash_final(a, b, c);
		 break;
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}


/*
 * @param __name: name of the map
 * @param __key_t: type of the key used for lookup
 * @param __val_t: type of value that is stored in the map
 * @param __bucket_size: maximum number of nodes inside a bucket
 * @param __num_bucket: number of buckets (THIS MUST BE POWER OF 2)
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
} __attribute__((aligned(8))) __name##_node_t;                                                  \
                                                                                                \
typedef struct {                                                                                \
	__u32 first;                                                                                \
} __name##_bucket_t;                                                                            \
                                                                                                \
typedef struct {                                                                                \
	__u32 freelist_next;                                                                        \
	__val_t v;                                                                                  \
} __attribute__((aligned(8))) __name##_val_entry_t;                                             \
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
static inline __always_inline                                                                   \
int __name##_lookup(__key_t *key, __val_t **out)                                                \
{                                                                                               \
	if (key == NULL || out == NULL) return -1;                                                  \
	__name##_bucket_t *b = NULL;                                                                \
	__name##_node_t *n = NULL;                                                                  \
	__name##_val_entry_t *e = NULL;                                                             \
	__u32 hash = _x_jhash(key, sizeof(*key), JHASH_INITVAL);                                    \
	__u32 index = hash & (__num_bucket - 1);                                                    \
	/* bpf_printk("btable-index: %u %u %u", index, hash, __num_bucket); */                      \
	/* Find the bueckt */                                                                       \
	b = bpf_map_lookup_elem(&__name##_btable, &index);                                          \
	if (b == NULL)                                                                              \
		return -1;                                                                              \
	/* Walk the nodes in the bucket and check for a match */                                    \
	index = b->first;                                                                           \
	for (__u16 i = 0; i < __bucket_size; i++) {                                                 \
		if (index == 0) {                                                                       \
			/* end of chain of nodes */                                                         \
			/* bpf_printk("end of chain %d", i); */                                             \
			return -1;                                                                          \
		}                                                                                       \
		n = bpf_map_lookup_elem(&__name##_ntable, &index);                                      \
		if (n == NULL) {                                                                        \
			bpf_printk("The node chain is broken!");                                            \
			return -1;                                                                          \
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
			return -1;                                                                          \
		}                                                                                       \
		e = bpf_map_lookup_elem(&__name##_atable, &index);                                      \
		if (e == NULL) {                                                                        \
			bpf_printk("__lookup: entry pointer was wrong!");                                   \
			return -1;                                                                          \
		}                                                                                       \
		*out = &e->v;                                                                           \
		return 0;                                                                               \
	}                                                                                           \
	bpf_printk("__lookup: node chain limit reached");                                           \
	/* Did not found a match for the key */                                                     \
	return -1;                                                                                  \
}                                                                                               \
                                                                                                \
/* static inline __attribute__((always_inline)) */                                              \
int __name##_update(__key_t *key, __val_t *val)                                                 \
{                                                                                               \
	if (key == NULL || val == NULL) return -1;                                                  \
	__name##_bucket_t *b = NULL;                                                                \
	__name##_node_t *n = NULL;                                                                  \
	__name##_val_entry_t *e = NULL;                                                             \
	__val_t *r = NULL;                                                                          \
	__u32 hash = 0;                                                                             \
	__u32 index = 0;                                                                            \
	__u32 node_index = 0;                                                                       \
	/* Find the bucket */                                                                       \
	hash = _x_jhash(key, sizeof(*key), JHASH_INITVAL);                                          \
	index = hash & (__num_bucket - 1);                                                          \
	/* bpf_printk("bucket: %d", index); */                                                      \
	b = bpf_map_lookup_elem(&__name##_btable, &index);                                          \
	if (b == NULL) {                                                                            \
		/* This must never happen */                                                            \
		return -1;                                                                              \
	}                                                                                           \
	/* Go through the bucket and check if the key already exists */                             \
	index = b->first;                                                                           \
	for (__u16 i = 0; i < __bucket_size; i++) {                                                 \
		if (index == 0) {                                                                       \
			/* end of chain of nodes */                                                         \
			break;                                                                              \
		}                                                                                       \
		n = bpf_map_lookup_elem(&__name##_ntable, &index);                                      \
		if (n == NULL) {                                                                        \
			bpf_printk("__update: the chain is broken");                                        \
			return -1;                                                                          \
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
		/* found a match */                                                                     \
		index = n->ptr;                                                                         \
		if (index == 0) {                                                                       \
			bpf_printk("__update: node pointer is null!");                                      \
			return -1;                                                                          \
		}                                                                                       \
		e = bpf_map_lookup_elem(&__name##_atable, &index);                                      \
		if (e == NULL) {                                                                        \
			bpf_printk("__update: entry pointer was wrong!");                                   \
			return -1;                                                                          \
		}                                                                                       \
		goto got_the_entry;                                                                     \
	}                                                                                           \
	/* Did not found the key in the map */                                                      \
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
	/* bpf_printk("__update: node: %d  entry: %d\n", node_index, index); */                     \
	/* Add the node pointer to the head of the node chain */                                    \
	n->next = b->first;                                                                         \
	b->first = node_index;                                                                      \
	/* Update the node to point to the allocated entry */                                       \
	n->hash = hash;                                                                             \
	__builtin_memcpy(&n->key, key, sizeof(*key));                                               \
	n->ptr = index;                                                                             \
got_the_entry:                                                                                  \
	/* Store value on the entry object */                                                       \
	__builtin_memcpy(&e->v, val, sizeof(*val));                                                 \
	return 0;                                                                                   \
}                                                                                               \

#endif
