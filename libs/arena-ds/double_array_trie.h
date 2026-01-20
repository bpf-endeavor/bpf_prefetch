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

#include "honey/prefetching.h"

/* Trie structure config */
#ifndef DAT_KEY_SIZE_BYTE
#define DAT_KEY_SIZE_BYTE 16 /* assume IPv6 address */
#endif

#ifndef DAT_VAL_SIZE_BYTE
#define DAT_VAL_SIZE_BYTE 4  /* assume an integer */
#endif
/* ------------------- */

#define DAT_KEY_SIZE_BIT (DAT_KEY_SIZE_BYTE * 8)

/* #define __DEBUG 1 */

#ifdef __BPF__
#define memcpy(x,y,z) __builtin_memcpy(x,y,z)
	#ifdef __DEBUG
		#define log(...) bpf_printk(__VA_ARGS__)
	#else
		#define log(...) ;
	#endif
#else
#include <stdio.h>
#include <string.h>
	#ifdef __DEBUG
		#define log(...) printf(__VA_ARGS__)
	#else
		#define log(...) ;
	#endif
#endif

#define member_size(type, member) (sizeof( ((type *)0)->member ))
#define get_bit(key, i) (!!(key[i / 8] & (1 << (7 - (i % 8))) ))

const static uint32_t alphabet_size = 2; /* binary trie */
const static uint32_t root_index = 1;
const static uint32_t EMPTY = (uint64_t)(0);

#define TERMINAL_MASK (1 << 31)
#define IS_TERMINAL(flag) (!!(flag & TERMINAL_MASK))
#define EXTRACT_VALUE_INDEX(flag) (flag & (~TERMINAL_MASK))

struct dat_node {
	uint32_t next;
	uint32_t value_flag;
} __packed;
typedef struct dat_node __arena arena_dat_node_t;

struct dat_check_info {
	uint32_t owner;
} __packed;
typedef struct dat_check_info __arena arena_dat_check_info_t;

struct dat_value {
	uint8_t value[DAT_VAL_SIZE_BYTE];
} __packed;
typedef struct dat_value __arena arena_dat_value_t;

struct dat {
	arena_dat_node_t *base;
	/* arena_dat_check_info_t *check; */
	arena_dat_value_t *values;
	uint32_t __arena *free_stk;
	uint32_t __arena *value_free_stk;
	uint32_t node_count;
	/* a stack tracking free value blocks */
	uint32_t value_count;
	uint32_t value_stk_ptr;
	/* a stack tracking free blocks */
	uint32_t stk_size;
	uint32_t stk_ptr;
} __attribute__((aligned(8)));
typedef struct dat __arena arena_dat_t;

static __always_inline
uint32_t __get_free_block(arena_dat_t *dat, uint32_t owner)
{
	if (dat->stk_ptr >= dat->stk_size) {
		/* No free block available */
		return -ENOSPC;
	}

	const uint32_t index = dat->free_stk[dat->stk_ptr++];
	if (index + 1 > dat->node_count) {
		/* wrong nodes inserted into the stack */
		return -EINVAL;
	}

	/* if (dat->check[index].owner != EMPTY || */
	/* 		dat->check[index + 1].owner != EMPTY) */
	/* { */
	/* 	/1* something is wrong, trying to use non-free nodes *1/ */
	/* 	return -EINVAL; */
	/* } */

	/* dat->check[index].owner = owner; */
	/* dat->check[index + 1].owner = owner; */
	return index;
}

static __always_inline
int __put_used_block(arena_dat_t *dat, uint32_t index)
{
	if (index % 2 != 0) {
		/* not aligned, something is wrong */
		return -1;
	}
	/* TODO: implment this ... */
	return -1;
}

static __always_inline
int __get_value(arena_dat_t *dat) {
	if (dat->value_stk_ptr > dat->value_count) {
		return -ENOSPC;
	}
	int index = dat->value_free_stk[dat->value_stk_ptr++];
	if (index > dat->value_count) {
		/* something wrong internally */
		return -EINVAL;
	}
	return index;
}

// TODO: implement the function freeing values... useful when deleting nodes

/* Walk the trie and find the longest match with the key. report how many bits
 * was matched
 * */
static __always_inline
uint32_t __find_leaf(arena_dat_t *dat, const uint8_t * const key,
		uint32_t key_size, int *_bits)
{
	uint32_t node = root_index;
	uint16_t i = 0;
	for (; i < key_size && i < DAT_KEY_SIZE_BIT; i++) {
 		if (dat->base[node].next == EMPTY)
			break;
		const uint16_t bit = get_bit(key, i);
		const uint32_t next = dat->base[node].next + bit;
		node = next;
	}
	if (_bits != NULL)
		*_bits = i;
	return node;
}

static __always_inline
uint32_t __find_lpm(arena_dat_t *dat, const uint8_t * const key,
		uint32_t key_size)
{
	uint32_t node = root_index, lpm = EMPTY;
	for (uint16_t i = 0; i < key_size && i < DAT_KEY_SIZE_BIT; i++) {
		/* check if we have found a new LPM */
		if (IS_TERMINAL(dat->base[node].value_flag))
			lpm = node;

		/* check if it is a leaf */
		if (dat->base[node].next == EMPTY)
			break;

		const uint16_t bit = get_bit(key, i);
		const uint32_t next = dat->base[node].next + bit;
		node = next;
	}
	return lpm;
}

static __always_inline
void __arena * dat_lookup(arena_dat_t *dat, const uint8_t * const key,
		uint32_t key_size)
{
	const uint32_t node = __find_lpm(dat, key, key_size);
	if (node != EMPTY) {
		uint32_t index = EXTRACT_VALUE_INDEX(dat->base[node].value_flag);
		return (void __arena *)dat->values[index].value;
	}
	return NULL;
}


/* Implement a fine-grained API for DAT lookup */
struct dat_partial_lookup_state {
	uint16_t offset;
	uint32_t node;
	uint32_t lpm;
	bool done;
};

static __always_inline
void dat_lookup_partial_init(arena_dat_t *dat,
		struct dat_partial_lookup_state *s)
{
	s->offset = 0;
	s->node = root_index;
	s->lpm = EMPTY;
	s->done = false;
}

static __always_inline
void __arena *dat_lookup_partial(arena_dat_t *dat, const uint8_t *const key,
		uint32_t key_size, struct dat_partial_lookup_state *s)
{
	/* prevent from calling this after the search is finished */
	/* if (s->done) */
	/* 	return NULL; */

	const uint16_t i = s->offset;
	const uint32_t node = s->node;

	/* check the loop condition */
	if (!(i < key_size && i < DAT_KEY_SIZE_BIT)) {
		goto ret_resp;
	}

	/* check if we have found a new LPM */
	if (IS_TERMINAL(dat->base[node].value_flag))
		s->lpm = node;

	/* check if it is a leaf */
	if (dat->base[node].next == EMPTY)
		goto ret_resp;

	const uint16_t bit = get_bit(key, i);
	const uint32_t next = dat->base[node].next + bit;
	s->node = next;

	/* prefetch next node */
	P((void *)&dat->base[next]);

	s->offset++;

	return NULL;

ret_resp:
		s->done = true;
		if (s->lpm == EMPTY)
			return NULL;
		const uint32_t lpm = s->lpm;
		uint32_t index = EXTRACT_VALUE_INDEX(dat->base[lpm].value_flag);
		return (void __arena *)dat->values[index].value;
}
/* ----------------------------------------------- */

/* Insert a key into the Trie, the key_size is the prefix length
 * */
static __always_inline
int dat_insert(arena_dat_t *dat, const uint8_t * const key,
		const uint32_t key_size, const uint8_t * const val)
{
	int bits = -1;
	uint32_t leaf_node = __find_leaf(dat, key, key_size, &bits);
	if (bits == key_size) {
		/* the key already exists, just update the value */
		/* log("updating an existing node\n"); */
		uint32_t val_index = 0;
		if (IS_TERMINAL(dat->base[leaf_node].value_flag)) {
			// it has a value associated with it
			val_index = EXTRACT_VALUE_INDEX(dat->base[leaf_node].value_flag);
		} else {
			val_index = __get_value(dat);
			if (val_index > dat->value_count) {
				// failed to allocate
				return -2;
			}
			dat->base[leaf_node].value_flag = (val_index | TERMINAL_MASK);
		}
		memcpy(dat->values[val_index].value, val, DAT_VAL_SIZE_BYTE);
		return 0;
	} else if (bits > key_size) {
		log("what is happening? %d > %d\n", bits, key_size);
		return -1;
	} else if (bits < 0 ) {
		log("insert: something is wrong\n");
		return -1;
	}

	/* up to some bits has been match, let's insert rest of the key into the
	 * tree
	 * */
	uint32_t node = leaf_node;
	/* uint32_t last_node = -1; */
	for (uint16_t i = bits; i < DAT_KEY_SIZE_BIT && i < key_size; i++) {
		const uint16_t bit = get_bit(key, i);
		if (dat->base[node].next != EMPTY) {
			log("inserting, next node is already linked!!\n");
			return -EINVAL;
		}
		const uint32_t free_node = __get_free_block(dat, node); /* get a left & right child node */
		if (free_node > dat->node_count) {
			/* failed to allocate node */
			/* TODO: also need to potentially clean up previous allocation */
			return -ENOMEM;
		}
		dat->base[node].next = free_node;
		const uint32_t next_node = free_node + bit;
		/* last_node = node; */
		node = next_node;
	}

	/* if (last_node > dat->node_count) { */
	/* 	log("something is wrong with last node\n"); */
	/* } */

	int val_index = __get_value(dat);
	if (val_index > dat->value_count) {
		log("no free value block");
		return -ENOSPC;
	}
	dat->base[node].value_flag = val_index | TERMINAL_MASK;
	memcpy(dat->values[val_index].value, val, DAT_VAL_SIZE_BYTE);
	// log("store: %d: %d\n", node, *(uint32_t *)val);
	return 0;
}

#ifndef __BPF__
typedef struct {
	void *area; /* pointer to the Arena memory region */
	uint32_t area_size;
	uint32_t max_entries; /* maximum number of nodes */
	uint32_t max_nodes;
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

	const uint64_t size = arg->max_nodes;
	const uint64_t value_count = arg->max_entries;
	const uint64_t stack_entries = (size / alphabet_size) - 1;
	const uint64_t required_size = sizeof(arena_dat_t) +
						(size * sizeof(arena_dat_node_t)) +
						(size * sizeof(arena_dat_check_info_t)) +
						(value_count * sizeof(arena_dat_value_t)) +
						(stack_entries * sizeof(uint32_t)) +
						(value_count * sizeof(uint32_t));
	const uint64_t num_pages = COUNT_OBJ(required_size, PAGE_SIZE);
	log("DAT requires %lu memory pages\n", num_pages);

	/* TODO: the area_size is not being passed in my tests */
	/* if (arg->area_size < required_size) */
	/* 	return -ENOMEM; */

	userspace_alloc_pages(arg->area, num_pages);

	arena_dat_t *dat = arg->area;
	memset(dat, 0, required_size);

	dat->node_count = arg->max_nodes; // maximum number of nodes we have

	dat->base = (void *)(dat + 1);
	/* dat->check = (void *)(dat->base) + (size * sizeof(arena_dat_node_t)); */
	/* dat->values = (void *)(dat->check) + (size * sizeof(arena_dat_check_info_t)); */
	dat->values = (void *)(dat->base) + (size * sizeof(arena_dat_node_t));
	dat->free_stk = (void *)(dat->values) + (value_count * sizeof(arena_dat_value_t));
	dat->value_free_stk = (void *)(dat->free_stk) + (stack_entries * sizeof(uint32_t));

	 /* initialize connections */
	for (int i = 0; i < size; i++) {
		dat->base[i].next = EMPTY;
		dat->base[i].value_flag = 0;
		/* dat->check[i].owner = EMPTY; */
	}

	/* initialize value stack */
	dat->value_stk_ptr = 0;
	dat->value_count = value_count; // maximum number of values we can store
	for (int i = 0; i < value_count; i++) {
		dat->value_free_stk[i] = i;
	}

	/* initialize free stack */
	for (int i = 0; i < stack_entries; i++) {
		dat->free_stk[i] = (i * alphabet_size) + 2;
	}
	dat->stk_ptr = 0;
	dat->stk_size = stack_entries;

	/* initialize root */
	const uint64_t next_node = __get_free_block(dat, root_index);
	if (next_node > dat->node_count) {
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
