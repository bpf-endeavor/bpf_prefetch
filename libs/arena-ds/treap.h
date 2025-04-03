#pragma once
/* *
 * a Treap data structure implementation
 * author: Farbod Shahinfar
 * LICENSE: MIT
 * */

#include <errno.h>
#include "./common/compiler.h"
#include "./common/stddef.h"
#include "./common/arena_common.h"
#include "./common/arena_mm.h"

#ifdef __BPF__
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#define assert(...)
#else
#include <assert.h>
#define bpf_printk(...)
#endif


#ifndef TREAP_MAX_SIZE
#define TREAP_MAX_SIZE 128
#endif

#ifndef TREAP_MAX_HEIGHT
// the max height is used to make while loops, ... bounded
#define TREAP_MAX_HEIGHT 16
#endif

// user can define its own key by defining the key size and following functions
// and struct (NOTE: it looks ugly do something better later)
#ifndef TREAP_KEY_SIZE
#define TREAP_KEY_SIZE 4
struct treap_key {
	uint8_t data[TREAP_KEY_SIZE];
} __packed;

static __always_inline
int treap_key_less_than(struct treap_key *a, struct treap_key *b)
{
	return *((uint32_t *)&a->data) < *((uint32_t *)&b->data);
}

static __always_inline
int treap_key_eq(struct treap_key *a, struct treap_key *b)
{
	return *((uint32_t *)&a->data) == *((uint32_t *)&b->data);
}
#endif

struct treap_node {
	struct treap_key key;
	uint32_t priority;
	struct treap_node __arena *left;
	struct treap_node __arena *right;
};
typedef struct treap_node __arena arena_treap_node_t;
typedef arena_treap_node_t * __arena arena_treap_link_t;

struct treap {
	arena_treap_node_t *root;
	struct treap_node nodes[TREAP_MAX_SIZE];
	uint32_t used; // number of nodes in the treap --> Top of the stack (TREAP_MAX_SIZE - used - 1)
	uint32_t stack[TREAP_MAX_SIZE]; // stack of free nodes
};
typedef struct treap __arena arena_treap_t;

/* get the highest priority node (a.k.a. root)
 * */
static __always_inline
arena_treap_node_t *treap_top(arena_treap_t *t) {
	return t->root;
}

// TODO: the program logic may become too complex (what to do?)
static __bpf_always_inline
void __treap_find(arena_treap_t *t, struct treap_key *key,
		arena_treap_node_t **node_out,
		arena_treap_link_t **node_parent_link)
{
	*node_out = NULL;
	*node_parent_link = NULL;

	arena_treap_node_t *ptr = t->root;
	arena_treap_link_t *link = &t->root;
	uint32_t k;
	for (k = 0; k < TREAP_MAX_HEIGHT; k++) {
		if (ptr == NULL) {
			// key does not exists in the treap (or there is a bug in
			// implementation of the treap)
			return;
		}
		// TODO: maybe I could optimize it with having only one comparison
		void *k = (void *)&ptr->key;
		cast_kern(k);
		if (treap_key_less_than(key, k)) {
			// less
			link = &ptr->left;
			ptr = ptr->left;
		} else {
			// greater or equal
			if (treap_key_eq(key, k)) {
				// found it
				*node_parent_link = link;
				*node_out = ptr;
				return;
			}
			link = &ptr->right;
			ptr = ptr->right;
		}
	}
	// did not found the result in the bounded height
	return;
}

/* fint the node with the given key
 * */
static __bpf_always_inline
arena_treap_node_t *treap_find(arena_treap_t *t, struct treap_key *key)
{
	arena_treap_node_t *n;
	arena_treap_link_t *link;
	__treap_find(t, key, &n, &link);
	return n;
}

enum ROTATE_DIR {
	LEFT,
	RIGHT,
};

static __always_inline
arena_treap_link_t * __get_parent_link(arena_treap_node_t *p, arena_treap_node_t *n)
{
	if (p->left == n) {
		return &p->left;
	} else if (p->right == n) {
		return &p->right;
	}
	bpf_printk("1. this is unexpected!");
	return NULL;
}

static __always_inline
void __rotate(arena_treap_link_t *link, enum ROTATE_DIR dir)
{
	// these names represents the initial state, after rotation the parent will
	// become the child and child will be the parent
	arena_treap_node_t *parent, *child;

	parent = *link;
	if (parent == NULL) {
		// nothing to do
		return;
	}

	if (dir == RIGHT) {
		child = parent->left;
		if (child == NULL) {
			// nothing to do
			return;
		}

		*link = child;
		arena_treap_node_t *left_right = child->right;
		child->right = parent;
		parent->left = left_right;
	} else if (dir == LEFT) {
		child = parent->right;
		if (child == NULL) {
			// nothing to do
			return;
		}

		*link = child;
		arena_treap_node_t *right_left = child->left;
		child->left = parent;
		parent->right = right_left;
	}
}

static __always_inline
arena_treap_node_t * __treap_alloc_node(arena_treap_t *t)
{
	if (t->used >= TREAP_MAX_SIZE) {
		// pool of nodes has been exausted
		return NULL;
	}
	uint32_t top_stack = TREAP_MAX_SIZE - t->used -1;
	t->used++;
	uint32_t index = t->stack[top_stack];
	arena_treap_node_t *new = &(t->nodes[index]);
	// TODO: the compiler/verifier failed to realize `new` is a pointer to
	// Arena (find why, can be a bug)
	cast_kern(new);
	// initialize
	new->left = NULL;
	new->right = NULL;
	if (new == NULL) {
		bpf_printk("this is very weird (index: %d)", index);
	}
	return new;
}

static __always_inline
void __treap_free_node(arena_treap_t *t, arena_treap_node_t *n)
{
	// NOTE: we are not checking if the give node is actually valid pointer.
	// Becareful!
	if (t->used <= 0) {
		// Something is very wrong
		return;
	}

	t->used--;
	uint32_t top_stack = TREAP_MAX_SIZE - t->used - 1;
	uint64_t delta = (void *)n - (void *)&(t->nodes[0]);
	uint64_t index = delta / sizeof(t->nodes[0]);
	/* if (index > TREAP_MAX_SIZE) { */
	/* 	bpf_printk("unexpected index %lld > %lld", index, TREAP_MAX_SIZE); */
	/* 	bpf_printk("debug info: %p  base: %p", n, &(t->nodes[0])); */
	/* 	bpf_printk("debug info: size node: %d", sizeof(t->nodes[0])); */
	/* } */
	t->stack[top_stack] = index;
}

#ifdef __BPF__
typedef struct {
	void *ptrs[TREAP_MAX_HEIGHT];
} __packed _path_ptrs_t;
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, _path_ptrs_t);
	/* __uint(map_flags, BPF_F_MMAPABLE); */
	__uint(max_entries, 1); /* number of pages */
} path_ptr_arr_map SEC(".maps");
#endif

static __bpf_always_inline
int treap_insert(arena_treap_t *t, struct treap_key *k, uint32_t priority)
{
	// get a node
	arena_treap_node_t *n = __treap_alloc_node(t);
	if (n == NULL) {
		return -ENOSPC;
	}
	__builtin_memcpy(n->key.data, k->data, TREAP_KEY_SIZE);
	n->priority = priority;

	// find the right place on the binary tree
	arena_treap_node_t *ptr = t->root;
	arena_treap_link_t *link = &t->root;

	uint32_t i; // path len
#ifdef __BPF__
	arena_treap_node_t **path = NULL;
	_path_ptrs_t *tmp = NULL;
	int zero = 0;
	tmp = bpf_map_lookup_elem(&path_ptr_arr_map, &zero);
	if (tmp == NULL) {
		// must never happen!
		return -1;
	}
	path = (arena_treap_node_t **)tmp->ptrs;
#else
	arena_treap_node_t *path[TREAP_MAX_HEIGHT] = {};
#endif

	// I want a bounded loop since I am planing to use it in eBPF
	for (i = 0; i < TREAP_MAX_HEIGHT; i++) {
		if (ptr == NULL)
			break;
		path[i] = ptr;
		void *_k = (void *)&ptr->key;
		cast_kern(_k);
		if (treap_key_less_than(k, _k)) {
			link = &ptr->left;
			ptr = ptr->left;
		} else {
			link = &ptr->right;
			ptr = ptr->right;
		}
	}
	// did not found the empty space in the bounded height
	if (i >= TREAP_MAX_HEIGHT) {
		__treap_free_node(t, n); // free the node we reserved
		return -2;
	}

	// assign the node to the empty place we found
	*link = n;

	int parent_index = i;
	for (uint32_t k = 0; k < TREAP_MAX_HEIGHT; k++) {
		if (parent_index <= 0) {
			// we reached the root (rotate the node to the root)
			break;
		}
		parent_index--;
		arena_treap_node_t *p = path[parent_index];
		arena_treap_link_t *grand_p_link = NULL;
		if (n->priority > p->priority) {
			// do rotation
			if (parent_index > 0)
				grand_p_link = __get_parent_link(path[parent_index - 1], p);
			else
				grand_p_link = &t->root;
			if (p->left == n) {
				// do a right rotation rooted at parent
				__rotate(grand_p_link, RIGHT);
			} else {
				// do a left rotation rooted at parent
				__rotate(grand_p_link, LEFT);
			}
		}
	}
	return 0;
}

static __bpf_always_inline
arena_treap_node_t *__get_imidiate_succesor(arena_treap_node_t *n,
		arena_treap_link_t **out_link)
{
	arena_treap_node_t *leaf = n->right;
	arena_treap_link_t *link = &n->right;
	uint32_t k;
	if (n->right == NULL)
		return NULL;
	for (k = 0; k < TREAP_MAX_HEIGHT; k++) {
		if (leaf->left == NULL)
			break;
		link = &leaf->left;
		leaf = leaf->left;
	}
	if (k >= TREAP_MAX_HEIGHT) {
		// failed to do it in a bounded size
		return NULL;
	}
	*out_link = link;
	return leaf;
}

// Bubble down the node fixing the heap property
static __bpf_always_inline
int __fix_sub_tree_heap_property_down(arena_treap_node_t *ptr, arena_treap_link_t *ptr_link)
{
	// The state of the treap is as follows:
	//   * the binary search property is valid
	//   * the heap property is possiblly not, because we moved replace a node
	//     with its next successor

	// How to fix the heap property ?
	// Each left and right sub-tree of replaced node are valid treaps.
	// 1. If the node priority is more than both, we are good
	// 2. Otherwise, rotate the node toward the sub-tree with lower priority
	//    e.g., if the priority for the top of sub-tree is 5 and for the right is 8, we rotate left.
	// 3. Goto 1! [Repeat until we exit at step 1].

	// Why it works? at each rotation, the node with higher priority will
	// bubble up ... (not 100% sure actually)


	uint32_t p = ptr->priority;
	uint32_t k;
	// we do not need to update the ptr, the ptr is the node we want to
	// buble down.
	for (k = 0; k < TREAP_MAX_HEIGHT; k++) {
		uint32_t left_p, right_p;
		if (ptr->left == NULL) {
			if (ptr->right == NULL) {
				// we are good
				break;
			} else if (p >= ptr->right->priority) {
				// we are good
				break;
			} else {
					__rotate(ptr_link, LEFT);
					ptr_link = &((*ptr_link)->left);
			}
		} else if (ptr->right == NULL) {
			// NOTE: we know the left is not null
			left_p = ptr->left->priority;
			if (p >= ptr->left->priority) {
				// we are good
				break;
			} else {
					__rotate(ptr_link, RIGHT);
					ptr_link = &((*ptr_link)->right);
			}
		} else {
			left_p = ptr->left->priority;
			right_p = ptr->right->priority;
			if (p >= left_p) {
				if (p >= right_p) {
					// we are good
					break;
				} else {
					// right_p > left_p --> rotate to the side with lower priority (LEFT)
					__rotate(ptr_link, LEFT);
					ptr_link = &((*ptr_link)->left);
				}
			} else {
				// left_p > p
				if (left_p <= right_p) {
					__rotate(ptr_link, LEFT);
					ptr_link = &((*ptr_link)->left);
				} else {
					__rotate(ptr_link, RIGHT);
					ptr_link = &((*ptr_link)->right);
				}
			}
		}
	}
	if (k >= TREAP_MAX_HEIGHT) {
		bpf_printk("error: could not fix tree in the bounded number of iterations\n");
		return -1;
	}
	return 0;
}

static __bpf_always_inline
int treap_delete(arena_treap_t *t, struct treap_key *key)
{
	int ret;
	arena_treap_node_t *n;
	arena_treap_link_t *link;
	__treap_find(t, key, &n, &link);
	if (n == NULL) {
		// key does not exist
		return -1;
	}
	if (n->left == NULL) {
		if (n->right == NULL) {
			// it is a leaf, just remove the node
			*link = NULL;
		} else {
			// has one child (the right child)
			*link = n->right;
		}
	} else {
		// has left child
		if (n->right == NULL) {
			// has one child (the left child)
			*link = n->left;
		} else {
			// We need to move the node down, find the imidiate
			// successor (the left most left node of the right
			// sub-tree)
			arena_treap_link_t *leaf_link = NULL;
			arena_treap_node_t *leaf = __get_imidiate_succesor(n, &leaf_link);
			if (leaf == NULL) {
				// failed to do it in a bounded size
				return -2;
			}

			// swap the node with the leaf and then remove the node
			// .. we know leaf does not have a left, if it does not
			// have a right then just remove the node. if it has a
			// right child then put the right child in place of
			// leaf.
			*leaf_link = leaf->right;
			leaf->right = n->right;
			leaf->left = n->left;
			*link = leaf;
			// node has been removed and everything is almost okay
			// except that moving leaf to the nodes position may
			// have disturbed the heap property
			ret = __fix_sub_tree_heap_property_down(leaf, link);
			if (ret != 0) {
				return -3;
			}
		}
	}

	// return the node to the stack of free nodes :)
	__treap_free_node(t, n);
	return 0;
}

static __always_inline
uint8_t treap_has_space(arena_treap_t *t)
{
	return t->used < TREAP_MAX_SIZE;
}

// empty the treap
static __always_inline
void treap_reset(arena_treap_t *t)
{
	t->root = NULL;
	t->used = 0;
	for (uint32_t k = 0; k < TREAP_MAX_SIZE; k++)
		t->stack[TREAP_MAX_SIZE - k - 1] = k;
}

#ifndef __BPF__
typedef struct {
	void *area; /* pointer to the Arena memory region */
	uint32_t area_size;
	uint32_t key_size; /* the size of the key used for query */
	uint32_t max_entries; // max treap_size
	uint32_t max_height; // max height of the treap
	arena_treap_t **treap_out; /* out: pointer to the allocated treap */
	uint32_t *allocated_pages; /* out: number of allocated pages */
} arena_treap_alloc_t;

// This is code is for the user-space program
static int userspace_arena_treap_alloc(arena_treap_alloc_t *arg)
{

	if (arg->area == NULL)
		return -EINVAL;
	// TODO: right now the total number of objects are defined at compile time
	if (arg->key_size != TREAP_KEY_SIZE)
		return -EINVAL;
	if (arg->max_entries != TREAP_MAX_SIZE)
		return -EINVAL;
	if (arg->max_height != TREAP_MAX_HEIGHT)
		return -EINVAL;

	uint64_t mem_sz = sizeof(arena_treap_t);
	uint64_t num_pages = COUNT_OBJ(mem_sz, PAGE_SIZE);
	uint64_t total_req_mem = num_pages * PAGE_SIZE;
	/* if (total_req_mem > arg->area_size) */
	/* 	return -ENOMEM; */

	userspace_alloc_pages(arg->area, num_pages);
	if (arg->allocated_pages != NULL)
		*arg->allocated_pages = num_pages;

	arena_treap_t *t = arg->area;
	for (uint32_t k = 0; k < TREAP_MAX_SIZE; k++)
		t->stack[TREAP_MAX_SIZE - k - 1] = k;
	*arg->treap_out = t;
	return 0;
}
#endif
