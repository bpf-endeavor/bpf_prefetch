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

/* Trie structure config */
#ifndef DAT_KEY_SIZE_BYTE
#define DAT_KEY_SIZE_BYTE 16 /* assume IPv6 address */
#endif

#ifndef DAT_VAL_SIZE_BYTE
#define DAT_VAL_SIZE_BYTE 4  /* assume an integer */
#endif
/* ------------------- */

#define DAT_KEY_SIZE_BIT (DAT_KEY_SIZE_BYTE * 8)

// #define __DEBUG 1

#ifdef __BPF__
#define memcpy(x,y,z) __builtin_memcpy(x,y,z)
	#ifdef __DEBUG
		#define printf(...) bpf_printk(__VA_ARGS__)
	#else
		#define bpf_printk(...) ;
		#define printf(...) ;
	#endif
#else
#include <stdio.h>
#include <string.h>
	#ifdef __DEBUG
		#define bpf_printk(...) printf(__VA_ARGS__)
	#else
		#define bpf_printk(...) ;
		#define printf(...) ;
	#endif
#endif

#define member_size(type, member) (sizeof( ((type *)0)->member ))
#define get_bit(key, i) (!!(key[i / 8] & (1 << (7 - (i % 8))) ))

const static uint64_t alphabet_size = 2; /* binary trie */
const static uint64_t root_index = 1;
// const static uint64_t EMPTY = (uint64_t)(-1);
const static uint64_t EMPTY = (uint64_t)(0);

struct dat_node {
	uint64_t next;
	bool terminal;
};
typedef struct dat_node __arena arena_dat_node_t;

struct dat_check_info {
	uint64_t owner;
};
typedef struct dat_check_info __arena arena_dat_check_info_t;

struct dat_value {
	uint8_t value[DAT_VAL_SIZE_BYTE];
};
typedef struct dat_value __arena arena_dat_value_t;

struct dat {
	arena_dat_node_t *base;
	arena_dat_check_info_t *check;
	arena_dat_value_t *values;
	uint64_t max_entries;
	/* a stack tracking free blocks */
	uint64_t stk_size;
	uint64_t stk_ptr;
	uint64_t __arena *free_stk;
};
typedef struct dat __arena arena_dat_t;

static __always_inline
uint64_t __get_free_block(arena_dat_t *dat, uint64_t owner)
{
	if (dat->stk_ptr >= dat->stk_size) {
		/* No free block available */
		return -ENOSPC;
	}

	const uint64_t index = dat->free_stk[dat->stk_ptr++];
	if (index + 1 > dat->max_entries) {
		/* wrong nodes inserted into the stack */
		return -EINVAL;
	}

	if (dat->check[index].owner != EMPTY ||
			dat->check[index + 1].owner != EMPTY)
	{
		/* something is wrong, trying to use non-free nodes */
		return -EINVAL;
	}

	dat->check[index].owner = owner;
	dat->check[index + 1].owner = owner;
	return index;
}

static __always_inline
int __put_used_block(arena_dat_t *dat, uint64_t index)
{
	if (index % 2 != 0) {
		/* not aligned, something is wrong */
		return -1;
	}
	/* TODO: implment this ... */
	return -1;
}

/* Walk the trie and find the longest match with the key. report how many bits
 * was matched
 * */
static __always_inline
uint64_t __find_leaf(arena_dat_t *dat, const uint8_t * const key,
		uint32_t key_size, int *_bits)
{
	uint64_t node = root_index;
	uint8_t mask = 1 << 7;
	uint32_t key_index = 0;
	uint32_t i = 0;
	for (; i < key_size && i < DAT_KEY_SIZE_BIT && key_index < DAT_KEY_SIZE_BYTE; i++) {
		const uint8_t bit = ((key[key_index] & mask) != 0);
		mask = mask >> 1;
		if (mask == 0) {
			mask = 1 << 7;
			key_index += 1;
		}
		const uint64_t next = dat->base[node].next + bit;
		if (next >= dat->max_entries) {
			break;
		}
 		if (dat->check[next].owner != node) {
			/* the transition `node --bit--> next' is not valid */
			bpf_printk("stopping search beacause: node: %d  bit: %d  next:%d  owner: %d\n",
					node, bit, next, dat->check[next].owner);
			break;
		}
		node = next;
	}
	if (_bits != NULL)
		*_bits = i;
	return node;
}

static __always_inline
uint64_t __find_lpm(arena_dat_t *dat, const uint8_t * const key,
		uint32_t key_size)
{
	uint64_t node = root_index, lpm = EMPTY;
	for (uint16_t i = 0; i < key_size && i < DAT_KEY_SIZE_BIT; i++) {
		const uint64_t bit = get_bit(key, i);
		uint64_t next = dat->base[node].next + bit;
		if (dat->check[next].owner != node)
			break;
		/* check if we have found a new LPM */
		if (dat->base[node].terminal)
			lpm = node;
		node = next;
	}
	return lpm;
}

static __always_inline
void __arena * dat_lookup(arena_dat_t *dat, const uint8_t * const key,
		uint32_t key_size)
{
	const uint64_t node = __find_lpm(dat, key, key_size);
	if (node != EMPTY) {
		return (void __arena *)dat->values[node].value;
	}
	return NULL;
}

/* Insert a key into the Trie, the key_size is the prefix length
 * */
static __always_inline
int dat_insert(arena_dat_t *dat, const uint8_t * const key,
		const uint32_t key_size, const uint8_t * const val)
{
	int bits = -1;
	uint64_t leaf_node = __find_leaf(dat, key, key_size, &bits);
	bits++; /* the __find_leaf matched until (including) this bit in the key */
	if (bits == key_size) {
		/* the key already exists, just update the value */
		/* bpf_printk("updating an existing node\n"); */
		memcpy(dat->values[leaf_node].value, val, DAT_VAL_SIZE_BYTE);
		return 0;
	} else if (bits > key_size) {
		bpf_printk("what is happening?");
		return -1;
	} else if (bits < 0 ) {
		printf("insert: something is wrong\n");
		return -1;
	}

	/* up to some bits has been match, let's insert rest of the key into the
	 * tree
	 * */

	/* uint32_t key_index = bits / 8; */
	/* uint8_t mask = 1 << (7 - (bits % 8)); */
	uint64_t node = leaf_node;
	uint64_t last_node = -1;
	for (uint32_t i = bits; i < DAT_KEY_SIZE_BIT && i < key_size; i++) {
		/* const uint8_t bit = ((key[key_index] & mask) != 0); */
		const uint8_t bit = get_bit(key, i);
		/* mask = mask >> 1; */
		/* if (mask == 0) { */
		/* 	mask = 1 << 7; */
		/* 	key_index += 1; */
		/* } */
		if (dat->base[node].next != EMPTY) {
			printf("inserting, next node is already linked!!\n");
			return -EINVAL;
		}
		const uint64_t free_node = __get_free_block(dat, node); /* get a left & right child node */
		if (free_node > dat->max_entries) {
			/* failed to allocate node */
			/* TODO: also need to potentially clean up previous allocation */
			return -ENOMEM;
		}
		dat->base[node].next = free_node;
		const uint64_t next_node = free_node + bit;
		last_node = node;
		node = next_node;
	}

	dat->base[last_node].terminal = true;
	memcpy(dat->values[last_node].value, val, DAT_VAL_SIZE_BYTE);
	// printf("store: %d: %d\n", node, *(uint32_t *)val);
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

	if (arg->max_entries % 2 != 0) {
		/* number of entries must be multiple of odd. we are allocating two
		 * nodes at a time and start from one root node allocated. */
		return -EINVAL;
	}

	const uint64_t size = arg->max_entries;
	const uint64_t stack_entries = (size / alphabet_size) - 1;
	const uint64_t required_size = sizeof(arena_dat_t) +
						(size * sizeof(arena_dat_node_t)) +
						(size * sizeof(arena_dat_check_info_t)) +
						(size * sizeof(arena_dat_value_t)) +
						(stack_entries * sizeof(uint64_t));
	const uint64_t num_pages = COUNT_OBJ(required_size, PAGE_SIZE);
	bpf_printk("DAT requires %lu memory pages\n", num_pages);

	/* TODO: the area_size is not being passed in my tests */
	/* if (arg->area_size < required_size) */
	/* 	return -ENOMEM; */

	userspace_alloc_pages(arg->area, num_pages);

	arena_dat_t *dat = arg->area;
	memset(dat, 0, required_size);

	dat->max_entries = arg->max_entries;
	dat->base = (void *)(dat + 1);
	dat->check = (void *)(dat->base) + (size * sizeof(arena_dat_node_t));
	dat->values = (void *)(dat->check) + (size * sizeof(arena_dat_check_info_t));
	dat->free_stk = (void *)(dat->values) + (size * sizeof(arena_dat_value_t));

	 /* initialize connections */
	for (int i = 0; i < size; i++) {
		dat->base[i].next = EMPTY;
		dat->base[i].terminal = false;
		dat->check[i].owner = EMPTY;
	}

	/* initialize free stack */
	for (int i = 0; i < stack_entries; i++) {
		dat->free_stk[i] = (i * alphabet_size) + 2;
	}
	dat->stk_ptr = 0;
	dat->stk_size = stack_entries;
	printf("stack size: %lu\n", stack_entries);

	/* initialize root */
	const uint64_t next_node = __get_free_block(dat, root_index);
	if (next_node > dat->max_entries) {
		/* failed to get free nodes, must never happen here */
		return -1;
	}
	dat->base[root_index].next = next_node;

	if (arg->allocated_area != NULL)
		*arg->allocated_area = required_size;
	*arg->out = dat;
	return 0;
}
#endif /* __BPF__ */

#endif /* _ARENA_DS_DOUBLE_ARRAY_TREAP_H */
