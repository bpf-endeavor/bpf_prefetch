#ifndef _ARENA_DS_DOUBLE_ARRAY_TREAP_H
#define _ARENA_DS_DOUBLE_ARRAY_TREAP_H
/* *
 * a Double Array Binary Trie (DAT) data-structure implementation
 * author: Farbod Shahinfar
 * LICENSE: MIT
 * */
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include "./common/compiler.h"
#include "./common/stddef.h"
#include "./common/arena_common.h"
#include "./common/arena_mm.h"

/* Number of bits in the key */
#define DAT_KEY_SIZE_BYTE 16 /* assume IPv6 address */
#define DAT_VAL_SIZE_BYTE 4  /* assume an integer */
#endif

#define DAT_KEY_SIZE_BIT (DAT_KEY_SIZE_BYTE * 8)

#ifdef __BPF__
#define memcpy(x,y,z) __builtin_memcpy(x,y,z)
#else
#include <stdout.h>
#include <string.h>
#endif

const static uint64_t alphabet_size = 2; /* binary trie */
const static uint64_t root_index = 0;
const static uint64_t EMPTY = (uint64_t)(-1);

struct dat_node {
	uint64_t next;
	bool termial;
	uint8_t value[DAT_VAL_SIZE_BYTE];
};
typedef struct dat_node __arena arena_dat_node_t;

struct dat_check_info {
	uint64_t owner;
};
typedef struct dat_check_info __arena arena_dat_check_info_t;

struct dat {
	arena_dat_node_t *base;
	arena_dat_check_info_t *check;
	uint64_t max_entries;
};
typedef struct dat __arena arena_dat_t;

/* Walk the trie and find the longest match with the key. report how many bits
 * was matched
 * */
static __always_inline
uint64_t __find_leaf(arena_dat_t *dat, const uint8_t const *key,
		uint32_t key_size, int *_bits)
{
	uint64_t node = root_index;
	uint8_t mask = 1 << 7;
	uint32_t key_index = 0;
	int lpm_bits = -1;
	uint64_t lpm = 0;
	for (uint32_t i = 0; i < key_size; i++) {
		const uint8_t bit = ((key[key_index] & mask) != 0);
		mask = mask >> 1;
		if (mask == 0) {
			mask = 1 << 7;
			key_index += 1;
		}
		const uint64_t next = dat->base[node].next + bit;
		if (next > dat->max_entries || dat->check[next].owner != node) {
			/* the transition `node --bit--> next' is not valid */
			break;
		}
		/* check if we have found a new LPM */
		if (dat->base[node].terminal) {
			lpm_bits = i;
			lpm = node;
		}
		node = next;
	}
	if (_bits != NULL)
		*_bits = lpm_bits;
	return lpm;
}

static __always_inline
void __arena * dat_lookup(arena_dat_t *dat, const uint8_t const *key,
		uint32_t key_size)
{
	int bits = 0;
	uint64_t node = __find_leaf(dat, key, key_size, &bits);
	if (bits >= 0 && dat->base[node].termial == true) {
		/* we have found a LPM */
		return (void __arena *)&dat->base[node].value[0];
	}
	return NULL;
}

/* Insert a key into the Trie, the key_size is the prefix length
 * */
static __always_inline
int dat_insert(arena_dat_t *dat, const uint8_t const *key,
		const uint32_t key_size, const uint8_t const *val)
{
	uint32_t bits = 0;
	uint64_t leaf_node = __find_leaf(dat, key, key_size, &bits);
	if (bits == key_size) {
		/* the key already exists, just update the value */
		memcyp(dat->base[leaf_node].value, val, DAT_VAL_SIZE_BYTE);
		return 0;
	}

	/* up to some bits has been match, let's insert rest of the key into the
	 * tree
	 * */
	bits++; /* start from next bit */
	uint32_t key_index = bits / 8;
	uint8_t mask = 1 << (7 - (bits % 8));
	uint64_t node = leaf_node;
	for (uint32_t i = bits; i < DAT_KEY_SIZE_BIT; i++) {
		const uint8_t bit = ((key[key_index] & mask) != 0);
		mask = mask >> 1;
		if (mask == 0) {
			mask = 1 << 7;
			key_index += 1;
		}
		const uint64_t next_index = dat->base[node].next + bit;
		if (check_index[next_index].owner != EMPTY) {
			/* node is not available, backtrack and relocate... */
			return -1;
		}
		check_index[next_index].owner = node;
		const uint64_t free_node = __get_free_block(dat); /* get a left & right child node */
		if (free_node > dat->max_entries) {
			/* failed to allocate node */
			/* TODO: also need to potentially clean up previous allocation */
			return -1;
		}
		dat->base[next_index].next = free_node;
		node = next_index;
	}
	dat->base[node].termial = true;
	memcpy(dat->base[node].value, val, DAT_VAL_SIZE_BYTE);
	return 0;
}

#ifndef __BPF__
typedef struct {
	void *area; /* pointer to the Arena memory region */
	uint32_t area_size;
	uint32_t max_entries; /* maximum number of nodes */
	arena_dat_t **out; /* out: pointer to the allocated hist */
	uint32_t *allocated_area;
} arena_dat_alloc_t;

static int userspace_arena_dat_alloc(arena_dat_alloc_t *arg) {
	if (arg->area == NULL)
		return -EINVAL;

	uint64_t size = arg->max_entries;
	uint64_t required_size = sizeof(arena_dat_t) +
							 (size * sizeof(arena_dat_node_t)) +
							 (size * sizeof(arena_dat_check_info_t));
	uint64_t num_pages = COUNT_OBJ(required_size, PAGE_SIZE);
	printf("DAT requires %d memory pages\n", num_pages);

	/* TODO: the area_size is not being passed in my tests */
	/* if (arg->area_size < required_size) */
	/* 	return -ENOMEM; */

	userspace_alloc_pages(arg->area, num_pages);

	arena_dat_t *dat = arg->area;
	dat->max_entries = arg->max_entries;
	dat->base = arg->area + sizeof(arena_dat_t);
	dat->check = arg->area + sizeof(arena_dat_t) +
		(size * sizeof(arena_dat_node_t));
	memset(dat, -1, required_size);

	/* initialize root */
	uint64_t next_node == __get_free_block(dat);
	if (next_node > dat->max_entries) {
		/* failed to get free nodes, must never happen here */
		return -1;
	}
	dat->base[root_index] = next_node;

	if (arg->allocated_area != NULL)
		*arg->allocated_area = required_size;
	*arg->out = dat;
	return 0;
}
#endif /* __BPF__ */

#endif /* _ARENA_DS_DOUBLE_ARRAY_TREAP_H */
