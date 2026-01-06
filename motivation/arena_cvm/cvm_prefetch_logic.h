// Some helpers for the CVM Prefetching scenario
#pragma once

#define PREFETCH 1
#include "honey/prefetching.h"

// maxsize is 32 because we use uint32_t as a bitmap
#define BATCH_SIZE 16

#define BPF_GLOBAL_FUNC int __attribute__((noinline))

#define BITMAP_GET(val, index) ((val & (1 << index)) != 0)
#define BITMAP_SET(val, index) val |= (1 << index)
#define BITMAP_CLR(val, index) val &= (~(1 << index))

#define MAX(a,b) (a > b ? a : b)

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
	/* which node, link index is valid */
	uint32_t valid; // A bitmap that reports issues with processing k_i
	/* List of nodes and their parent links that we find (or NULL) */
	arena_treap_node_t *nodes[BATCH_SIZE];
	arena_treap_link_t *links[BATCH_SIZE];
	/* fp_t max_u_B[BATCH_SIZE]; // what is the maximum probability in buffer before applying the next keys in the batch */
	fp_t rnd_u[BATCH_SIZE];
	fp_t max_remove_prob[BATCH_SIZE]; // maximum prob deleted after k_i
	__u8 deleted[BATCH_SIZE]; // number of nodes deleted after k_i
	uint8_t lookup_finished; // number of keys that we have finished the lookup. This is for early termination of treap walk
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

struct find_loop_ctx {
	__u32 index;
	batch_t *batch;
	batch_proc_state_t *state;
};

static long __find_inner_loop(__u32 _index, void *_ctx)
{
	struct find_loop_ctx *ctx = _ctx;
	__u32 i = ctx->index;
	ctx->index = (ctx->index + 1) % BATCH_SIZE;
	batch_t *batch = ctx->batch;
	batch_proc_state_t *state = ctx->state;

	if (BITMAP_GET(state->valid, i)) {
		// search has been finished for this
		return 0; // continue;
	}

	struct treap_key *key = &(batch->keys[i]);
	arena_treap_node_t *ptr = state->nodes[i];
	if (ptr == NULL) {
		// this key does not exist in the treap
		state->links[i] = NULL;
		BITMAP_SET(state->valid, i);
		state->lookup_finished++;
		/* bpf_printk("set valid index: %d",i); */
		/* return 0; // continue; */
		goto check_termination;
	}

	void *k = (void *)&ptr->key;
	cast_kern(k);
	int64_t cmp = treap_key_cmp(key, k);
	if (cmp == 0) {
		// found it
		BITMAP_SET(state->valid, i);
		state->lookup_finished++;
		/* bpf_printk("set valid index: %d",i); */
		goto check_termination;
	} else if (cmp < 0) {
		state->links[i] = &ptr->left;
		state->nodes[i] = ptr->left;
		// prefetch the next node we are going to compare with
		P((void *)ptr->left);
	} else {
		state->links[i] = &ptr->right;
		state->nodes[i] = ptr->right;
		// prefetch the next node we are going to compare with
		P((void *)ptr->right);
	}
	return 0;

check_termination:
	if (state->lookup_finished == BATCH_SIZE)
		return 1; // break;
	return 0;
}

/* BPF_GLOBAL_FUNC */
static __always_inline int
treap_find_batch(batch_t *batch, batch_proc_state_t *state)
{
	state->lookup_finished = 0;
	// initialize all the pointer to the root and set all of the results as invalid
	for (__u32 i = 0; i < BATCH_SIZE; i++) {
		state->links[i] = &treap->root;
		state->nodes[i] = treap->root;
		BITMAP_CLR(state->valid, i);
	}

	// check the treap is empty
	if (treap->root == NULL)
		goto done;

	// prefetch the root because we are going to start our walk from there
	P((void *)treap->root);

	// Note: the logic required a nested loop. But the loops could be merged
	struct find_loop_ctx loop_ctx = {
		.index = 0,
		.batch = batch,
		.state = state,
	};
	bpf_loop(BATCH_SIZE * TREAP_MAX_HEIGHT, __find_inner_loop, &loop_ctx, 0);

done:
	for (__u32 i = 0; state->lookup_finished != BATCH_SIZE && i < BATCH_SIZE; i++) {
		if (BITMAP_GET(state->valid, i) == 0) {
			// did not found the result in the bounded height
			state->nodes[i] = NULL;
			state->links[i] = NULL;
			BITMAP_SET(state->valid, i);
			state->lookup_finished++;
			/* bpf_printk("set valid index: %d",i); */
		}
	}
	return 0;
}

struct delete_loop_ctx  {
	__u32 index;
	batch_t *batch;
	batch_proc_state_t *state;
};

static long __delete_inner_loop(__u32 _index, void *_ctx)
{
	struct delete_loop_ctx *ctx = _ctx;
	__u32 i = ctx->index;
	ctx->index++;
	batch_t *batch = ctx->batch;
	batch_proc_state_t *state = ctx->state;

	int ret;
	arena_treap_node_t *n = state->nodes[i];
	arena_treap_link_t *link = state->links[i];

	if (n == NULL) {
		// key does not exists, to the next item in the batch
		return 0;
	}

	if (n->left == NULL) {
		*link = n->right;
	} else {
		// has left child
		if (n->right == NULL) {
			// has one child (the left child)
			*link = n->left;
		} else {
			// TODO: It seems we can not overlap this
			// because the packets have diverged...

			// We need to move the node down, find the immediate
			// successor (the most left  child of the right sub-tree)
			arena_treap_link_t *leaf_link = NULL;
			arena_treap_node_t *leaf = __get_immediate_succesor(n, &leaf_link);
			if (leaf == NULL) {
				// failed to do it in a bounded size
				// TODO: error missed
				bpf_printk("failed to __get_immediate...");
				BITMAP_CLR(state->valid, i);
				return 0; // continue;
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
				bpf_printk("failed to __fix_sub...");
				BITMAP_CLR(state->valid, i);
				return 0; // continue;
			}
		}
	}

	// return the node to the stack of free nodes :)
	__treap_free_node(treap, n);
	return 0; // continue;
}

/*  insert/delete are wrapped in a global function to be evaluated as a
 *  separate program and help with passing the complexity limit
 *  */
BPF_GLOBAL_FUNC
subprog_treap_insert(struct treap_key *k, fp_t u) {
	if (k == NULL)
		return -10;
	return treap_insert(treap, k, u);
}

BPF_GLOBAL_FUNC __attribute__((optnone))
subprog_treap_delete(__u64 x) {
	struct treap_key __arena *key = (void __arena *)x;
	cast_kern(key);
	return treap_delete(treap, (void *)key);
}

struct update_loop_ctx {
	__u32 index;
	batch_proc_state_t *state;
	batch_t *batch;
	int ret;
};

static long __update_inner_loop(__u32 _index, void *_ctx)
{
	struct update_loop_ctx *ctx = _ctx;
	int ret;
	batch_proc_state_t *state = ctx->state;
	batch_t *batch = ctx->batch;
	__u32 i = ctx->index;
	ctx->index++;

	if (i > BATCH_SIZE) {
		// must never happen
		bpf_printk("very unexpected :)");
		return 1;
	}

	fp_t u = state->rnd_u[i];

	if (u > p)
		return 0; // continue;

	// Assume we haven't deleted the elements after k_i, would we have free space?
	int free_space = TREAP_MAX_SIZE - treap->used - state->deleted[i];
	if (free_space > 0) {
		ret = subprog_treap_insert(&batch->keys[i], u);
		if (ret != 0) {
			bpf_printk("failed to insert");
			ctx->ret = -1;
			return 1;
		}
		return 0; // continue;
	}

	// u < p and |B| = s
	arena_treap_node_t *top = treap_top(treap);
	// Assume we haven't deleted the elements after k_i. Would we have a different max probability?
	fp_t max_probability = top->priority;
	fp_t max_removed = state->max_remove_prob[i];
	bool root_already_removed = false;
	if (max_probability < max_removed) {
		root_already_removed = true;
		max_probability = max_removed;
	}

	if (u > max_probability) {
		p = u;
		return 0; // continue;
	} else {
		p = max_probability;

		// we might have already removed the root
		if (!root_already_removed) { 
			__u64 x = (__u64)&top->key;
			ret = subprog_treap_delete((__u64)x);
			if (ret != 0) {
				bpf_printk(TAG"failed to replace the node (delete): %d", ret);
				ctx->ret = -4;
				return 1;
			}
		}

		ret = subprog_treap_insert(&batch->keys[i], u);
		if (ret != 0) {
			bpf_printk(TAG"failed to replace the node (insert): %d", ret);
			ctx->ret = -5;
			return 1;
		}
	}
	return 0;
}

static int __always_inline
treap_delete_batch(batch_t *batch, batch_proc_state_t *state)
{
	int ret;
	treap_find_batch(batch, state);

	// We are going to delete the nodes we found in the buffer. Count how many
	// nodes we are going to delete.
	struct delete_loop_ctx loop_ctx = {
		.index = 0,
		.batch = batch,
		.state = state,
	};
	bpf_loop(BATCH_SIZE, __delete_inner_loop, &loop_ctx, 0);

	// find the maximum probability that was removed from treap after k_i
	state->max_remove_prob[BATCH_SIZE - 1] = 0;
	for (__u32 i = BATCH_SIZE - 2; i > -1; i--) {
		__u32 next = i + 1;
		arena_treap_node_t *next_n = state->nodes[next];
		fp_t u = next_n == NULL ? 0 : next_n->priority;
		state->max_remove_prob[i] = MAX(state->max_remove_prob[next], u);
	}
	// find the number of nodes that have been deleted after k_i
	state->deleted[BATCH_SIZE - 1] = 0;
	for (__u32 i = BATCH_SIZE - 2; i > -1; i--) {
		__u32 next = i + 1;
		uint8_t was_deleted = state->nodes[next] == NULL ? 0 : 1;
		state->deleted[i] = state->deleted[next] + was_deleted;
	}

	return 0;
}

/* Implement logic for batch updating the Treap data-structure (buffer used for
 * holding the <key, priority> pairs in the CVM algorithm)
 *
 * How: we have a batch of keys. The update algorithm is as follows.
 * TODO: write this part
 * */
static __always_inline
int treap_batch_update(arena_treap_t *t, batch_t *batch)
{
	int ret;
	__u32 zero = 0;
	batch_proc_state_t *state = NULL;
	state = bpf_map_lookup_elem(&batch_proc_state_map, &zero);
	if (state == NULL) {
		// this must never happen
		return -100;
	}

	treap_delete_batch(batch, state);

	for (__u32 i = 0; i < BATCH_SIZE; i++) {
		if (BITMAP_GET(state->valid, i) == 0) {
			// make sure we did not fail at delete
			bpf_printk("delete failed for index: %d", i);
			return -2;
		}
		fp_t u = fp_random();
		state->rnd_u[i] = u;
	}

	struct update_loop_ctx loop_ctx = {
		.index = 0,
		.batch = batch,
		.state = state,
		.ret = 0,
	};
	bpf_loop(BATCH_SIZE, __update_inner_loop, &loop_ctx, 0);
	if (loop_ctx.ret < 0)
		return loop_ctx.ret;
	return 0;
}

