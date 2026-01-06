#ifndef _BAX_CVM_TREAP_H
#define _BAX_CVM_TREAP_H
#include <stdint.h>
typedef struct ipv4_lpm_key {
    uint32_t data;
} __attribute__((packed)) my_key_t;
// static_assert (sizeof(my_key_t) == 4);

/* bring Treap data-structure from the library */
// #define TREAP_KEY_SIZE sizeof(my_key_t) // default key-size is 4; if
// defining this also should provide comparison functions
// #define TREAP_MAX_SIZE (1 << 14)
#define TREAP_MAX_SIZE 128
#define TREAP_MAX_HEIGHT 64
#include "arena-ds/treap.h"
#include "arena-ds/fixed-point/fp.h"


#ifdef __BPF__
/* TODO: check if these functions work in a more general case and add them to arena-ds/treap.h */

typedef struct {
	bool valid;
	arena_treap_node_t *node;
	arena_treap_link_t *link;
	struct treap_key key;
} lookup_partial_state_t;

static __always_inline
int treap_batch_lookup_p1(arena_treap_t *t, struct treap_key *k,
		lookup_partial_state_t *p)
{
		p->link = &t->root;
		p->node = t->root;
		p->valid = false;
		__builtin_memcpy(&p->key, k, sizeof(struct treap_key));
		if (t->root == NULL)
			return 1; // early terminate (treap is empty)
		return 0;
}

static __always_inline
int treap_batch_lookup_p2(arena_treap_t *t, struct treap_key *unused,
		lookup_partial_state_t *p)
{
	arena_treap_node_t *ptr = p->node;
	if (ptr == NULL) {
		/* This key does not exist in the Treap */
		p->link = NULL;
		p->valid = true;
		return 1;
	}

	struct treap_key *key = &p->key;
	void __arena *ptr_key = (void __arena *)(&ptr->key);
	cast_kern(ptr_key);
	int64_t cmp = treap_key_cmp(key, (void *)ptr_key);
	if (cmp == 0) {
		/* Found the matching key */
		p->valid = true;
		return 1;
	} else if (cmp < 0) {
		/* Explore the left sub-graph */
		p->link = &ptr->left;
		p->node = ptr->left;
		P((void *)(ptr->left));
	} else {
		/* Explore the right sub-grph */
		p->link = &ptr->right;
		p->node = ptr->right;
		P((void *)(ptr->right));
	}

	// notify to continue the lookup process
	return 0;
}

/* Delete operation involves looking up a key and updating pointers to remove
 * it from the tree.
 *
 * This API deletes a node based on state of a previous lookup operation.
 * Useful in combiniation with batch lookup.
 * */
static __always_inline
int treap_delete_node_after_lookup(arena_treap_t *t, lookup_partial_state_t *p)
{
	arena_treap_node_t *n = p->node;
	arena_treap_link_t *link = p->link;

	if (n == NULL) {
		return 1;
	}

	if (n->left == NULL) {
		*link = n->right;
	} else {
		// has left child
		if (n->right == NULL) {
			// has one child (the left child)
			*link = n->left;
		} else {
			// NOTE: batch treap: It seems we can not overlap this
			// because the fixing sub tree becomes a mess
			// (I dont know how to do it)
			// TODO: BAX failed to parse the apostrophy for contraction of
			// "do not". It is a weird limitation

			// We need to move the node down, find the immediate
			// successor (the most left  child of the right sub-tree)
			arena_treap_link_t *leaf_link = NULL;
			arena_treap_node_t *leaf = __get_immediate_succesor(n, &leaf_link);
			if (leaf == NULL) {
				// failed to do it in a bounded size
				// NOTE: batch treap: error missed
				bpf_printk("failed to __get_immediate...");
				p->valid = false;
				return -1;
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
			int ret = __fix_sub_tree_heap_property_down(leaf, link);
			if (ret != 0) {
				// NOTE: batch treap: error missed
				bpf_printk("failed to __fix_sub...");
				p->valid = false;
				return -1;
			}
		}
	}
	__treap_free_node(t, n);
	return 0;
}
#endif /* __BPF__ */

#endif
