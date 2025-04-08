// Some helpers for the CVM Prefetching scenario
#pragma once

#define PREFETCH 1
#include "honey/prefetching.h"

#define BATCH_SIZE 16

/* This is for creating a batch of incoming keys and processing them all
 * together
 * */
typedef struct {
	__u32 write_off;
	struct treap_key keys[BATCH_SIZE];
} batch_t;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, batch_t);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
} batch_map SEC(".maps");

/* Struct for holding the state while doing batch processing. Mostly for
 * avoiding the stack memory limitation
 * */
typedef struct {
	/* List of nodes and their parent links that we find */
	arena_treap_node_t *nodes[BATCH_SIZE];
	arena_treap_link_t *links[BATCH_SIZE];
	/* which node, link index is valid */
	bool valid[BATCH_SIZE];
	/* fp_t rnd_u[BATCH_SIZE]; */
} batch_proc_state_t;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, batch_proc_state_t);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
} batch_proc_state_map SEC(".maps");

/* Batch values into an array. Return the pointer to the batch when it is full
 * otherwise return NULL
 * */
static __always_inline
batch_t *__make_batch(__u32 key_data)
{
	__u32 zero = 0;
	batch_t *batch = NULL;
	batch = bpf_map_lookup_elem(&batch_map, &zero);
	if (batch == NULL)
		return NULL;

	if (batch->write_off >= BATCH_SIZE) {
		// this must never happen
		batch->write_off = 0;
		return NULL;
	}

	*(__u32 *)&(batch->keys[batch->write_off].data) = key_data;
	/* bpf_printk("key: %d", *r); */
	batch->write_off++;

	if (batch->write_off != BATCH_SIZE) {
		// continue batching
		return NULL;
	}
	return batch;
}

static __always_inline
void __treap_find_batch(arena_treap_t *t,
		batch_t *batch, batch_proc_state_t *state)
{
	// check the treap is not empty
	if (t->root == NULL)
		return;

	// prefetch the root because we are going to start our walk from there
	P((void *)t->root);

	// initialize all the pointer to the root
	for (__u32 i = 0; i < BATCH_SIZE; i++) {
		state->links[i] = &t->root;
		state->nodes[i] = t->root;
		state->valid[i] = false;
	}

	for (__u32 k = 0; k < TREAP_MAX_SIZE; k++) {
		for (__u32 i = 0; i < BATCH_SIZE; i++) {
			if (state->valid[i] == true) {
				// search has been finished for this
				continue;
			}

			struct treap_key *key = &(batch->keys[i]);
			arena_treap_node_t *ptr = state->nodes[i];
			if (ptr == NULL) {
				// this key does not exist in the treap
				state->links[i] = NULL;
				state->valid[i] = true;
				continue;
			}

			void *k = (void *)&ptr->key;
			cast_kern(k);
			if (treap_key_less_than(key, k)) {
				state->links[i] = &ptr->left;
				state->nodes[i] = ptr->left;
				// prefetch the next node we are going to compare with
				P((void *)ptr->left);
			} else {
				if (treap_key_eq(key, k)) {
					// found it
					state->valid[i] = true;
				} else {
					state->links[i] = &ptr->right;
					state->nodes[i] = ptr->right;
					// prefetch the next node we are going to compare with
					P((void *)ptr->right);
				}
			}
		}
	}

	for (__u32 i = 0; i < BATCH_SIZE; i++) {
		if (state->valid[i] == false) {
			// did not found the result in the bounded height
			state->nodes[i] = NULL;
			state->links[i] = NULL;
			state->valid[i] = true;
		}
	}
}

static __always_inline
int __treap_delete_batch(arena_treap_t *t, batch_t *batch,
		batch_proc_state_t *state)
{
	int ret;
	__treap_find_batch(t, batch, state);
	for (__u32 i = 0; i < BATCH_SIZE; i++) {
		/* TODO: The part in the loop seems to be the same as the code
		 * in the treap.h . Maybe if I have in intermediate function I
		 * can avoid duplicate code
		 * */

		arena_treap_node_t *n = state->nodes[i];
		arena_treap_link_t *link = state->links[i];

		if (n == NULL) {
			// key does not exists, to the next item in the batch
			continue;
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
				// TODO: It seems we can not overlap this
				// because the packets have diverged...

				// We need to move the node down, find the imidiate
				// successor (the most left  child of the right sub-tree)
				arena_treap_link_t *leaf_link = NULL;
				arena_treap_node_t *leaf = __get_imidiate_succesor(n, &leaf_link);
				if (leaf == NULL) {
					// failed to do it in a bounded size
					// TODO: error missed
					state->valid[i] = false;
					continue;
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
					// TODO: error missed
					state->valid[i] = false;
					continue;
				}
			}
		}

		// return the node to the stack of free nodes :)
		__treap_free_node(t, n);
	}
	return 0;
}

/* Implement logic for batch updating the Treap data-structure (buffer used for
 * holding the <key, priority> pairs in the CVM algorithm)
 * */
static __always_inline
int __treap_batch_update(arena_treap_t *t, batch_t *batch)
{
	int ret;
	__u32 zero = 0;
	batch_proc_state_t *state = NULL;
	state = bpf_map_lookup_elem(&batch_proc_state_map, &zero);
	if (state == NULL) {
		// this must never happen
		return -1;
	}

	__treap_delete_batch(t, batch, state);
	for (__u32 i = 0; i < BATCH_SIZE; i++) {
		if (state->valid[i] == false) {
			// make sure we did not fail at delete
			return -2;
		}
		fp_t u = fp_random();
		/* state->rnd_u[i] = u; */

		if (u > p)
			continue;

		if (treap_has_space(t)) {
			ret = treap_insert(t, &batch->keys[i], u);
			if (ret != 0) {
				return -3;
			}
			continue;
		}

		// u < p and |B| = s
		arena_treap_node_t *top = treap_top(t);
		if (u > top->priority) {
			p = u;
			continue;
		} else {
			p = top->priority;
			ret = treap_delete(t, (void *)&top->key);
			if (ret != 0) {
				bpf_printk(TAG"failed to replace the node (delete): %d", ret);
				return -4;
			}
			ret = treap_insert(t, &batch->keys[i], u);
			if (ret != 0) {
				bpf_printk(TAG"failed to replace the node (insert): %d", ret);
				return -5;
			}
		}
	}
	return 0;
}

