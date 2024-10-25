#ifndef __ROUTING_H
#define __ROUTING_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "libs/jhash.h"
#include "honey/report_throughput.h"
#include "honey/prefetching.h"

#define MAX_ROUTES (1 << 20)
#define ROUTE_MAX_HOST_LENGTH 64
#define ROUNDED_VALUE_SIZE round(sizeof(routing_elem_t), 8)
#define ROUNDED_BVAL_SIZE round(sizeof(bucket_t), 8)

typedef struct {
	__u64 upstream;
	__u64 counter;
	__u64 dummy[6];
}  __attribute__((aligned(64))) routing_elem_t;

typedef struct {
	char data[ROUTE_MAX_HOST_LENGTH];
} routing_key_t;

#define BUCKET_SIZE 32
#define NUMBER_OF_BUCKETS 50000

typedef struct {
	__u32 hash[BUCKET_SIZE];
	__u32 ptr[BUCKET_SIZE];
	routing_key_t key[BUCKET_SIZE];
} bucket_t;

/* a simple pointer to show how far from the atable we have allocated */
static __u32 used_index = 1;

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, bucket_t);
	__uint(max_entries, NUMBER_OF_BUCKETS);
} btable SEC(".maps");

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, routing_elem_t);
	__uint(max_entries, MAX_ROUTES);
} atable SEC(".maps");

sinline routing_elem_t *__lookup(routing_key_t *key)
{
	void *__ptr = NULL;
	bucket_t *b = NULL;
	routing_elem_t *r = NULL;
	__u32 hash = jhash(key->data, sizeof(*key), 123);
	__u32 index = hash % NUMBER_OF_BUCKETS;
	__u32 node_index = hash % BUCKET_SIZE;
	__u32 ptr;
#ifdef PREFETCH
	b = (void *)__btable_addr + index * ROUNDED_BVAL_SIZE;
	P(b);
	P(&b->hash[16]);
	P(&b->key[node_index]);
#endif
	/* bpf_printk("btable-index: %d", index); */
	b = bpf_map_lookup_elem(&btable, &index);
	if (b == NULL)
		return NULL;

	if(b->hash[node_index] == hash) {
			if (__builtin_memcmp(key, &b->key[node_index], sizeof(*key)) == 0) {
				ptr = b->ptr[node_index]; 
				if (ptr == 0) {
					bpf_printk("__lookup: pointer is null! (fast path)");
					return NULL;
				}
				r = bpf_map_lookup_elem(&atable, &ptr);
				return r;
			}
	}

	for (__u16 i = 0; i < BUCKET_SIZE; i++) {
		if (b->hash[i] != hash) {
			continue;
		} else {
			ptr = b->ptr[i]; 
#ifdef PREFETCH
			__ptr = (void *)__atable_addr + ptr * ROUNDED_VALUE_SIZE;
			P(__ptr);
#endif
			if (__builtin_memcmp(key, &b->key[i], sizeof(*key)) == 0) {
				/* bpf_printk("match: %d", i); */
				/* found the value */
				if (ptr == 0) {
					bpf_printk("__lookup: pointer is null!");
					return NULL;
				}
				r = bpf_map_lookup_elem(&atable, &ptr);
				/* bpf_printk("p: %p  a: %p", __ptr, r); */
				return r;
			} else {
				/* bpf_printk("same hash not match: %d", i); */
			}
		}
	}
	/* did not found */
	return NULL;
}

static __u32 predictable_index = 0;
sinline int __update(routing_key_t *key, routing_elem_t *val)
{
	__u32 x;
	bucket_t *b = NULL;
	routing_elem_t *r = NULL;
	__u32 hash = jhash(key->data, sizeof(*key), 123);
	__u32 index = hash % NUMBER_OF_BUCKETS;
	b = bpf_map_lookup_elem(&btable, &index);
	if (b == NULL)
		return -1;
	/* make our hash table a bit more predictable */
	__u32 node_index =  hash % BUCKET_SIZE;
	if (b->ptr[node_index] == 0) {
		// oh cool! we got a predictable index
		predictable_index++;
		/* bpf_printk("pred: %d", predictable_index); */
		goto __found_empty_node;
	}
	for (__u16 i = 0; i < BUCKET_SIZE; i++) {
		/* NOTE: this update (also lookup) routing has race conditions */
		if (b->ptr[i] != 0) {
			// this node is used;
			continue;
		}
		node_index = i;
		goto __found_empty_node;
	}
	/* did not found empty node */
	bpf_printk("__update: bucket was full!");
	return -1;

__found_empty_node:
		x = __sync_fetch_and_add(&used_index, 1);
		if (x > MAX_ROUTES) {
			bpf_printk("__update: out of value slots");
			return -1;
		}
		b->hash[node_index] = hash;
		__builtin_memcpy(&b->key[node_index], key, sizeof(*key));
		b->ptr[node_index] = x;
		r = bpf_map_lookup_elem(&atable, &x);
		if (r == NULL) {
			/* this must never happen */
			bpf_printk("__update: allocated index does not exists!");
			return -1;
		}
		__builtin_memcpy(r, val, sizeof(*val));
		return 0;
}

int prog_route(CONTEXT *ctx, __u16 host_start_off, __u16 host_end_off)
{
	void *data = GET_DATA(ctx);
	void *data_end = GET_DATAEND(ctx);
	char *host = data + (host_start_off & OFFSET_MASK);
	__u16 host_len = host_end_off - host_start_off;
	routing_elem_t *r = NULL;
	routing_key_t key;
	P(host);
	__builtin_memset(&key, 0, sizeof(key));

	if (host_end_off < host_start_off || host_len > ROUTE_MAX_HOST_LENGTH) {
		bpf_printk("wierd err");
		return ABORTED;
	}
	if ((void *)(host + ROUTE_MAX_HOST_LENGTH) > data_end) {
		bpf_printk("routing: out of range");
		return ABORTED;
	}
	/* Copy the host to the routing key */
	for (int i = 0; i < ROUTE_MAX_HOST_LENGTH; i++) {
		if (i >= host_len) break;
		key.data[i] = host[i];
	}

	/* Lookup the routing rule */
	/* r = bpf_map_lookup_elem(&routing_table, &key); */
	r = __lookup(&key);
	if (r == NULL) {
		/* For experiment purposes, if the rule is not found add a rule
		 * (initializing the rule table)
		 * */
		/* bpf_printk("this must never happen %d\n", hash); */
		/* bpf_printk("this must never happen\n"); */
		/* insert a value to the map so the test works after some time */
		routing_elem_t val;
		__builtin_memset(&val, 0, sizeof(val));
		val.upstream = 123;
		/* bpf_map_update_elem(&routing_table, &key, &val, BPF_NOEXIST); */
		__update(&key, &val);
		return ABORTED;
	}

	r->counter += 1;
	if (r->upstream == 2)
		return DROP;
	report_tput();
	return DROP;
}

#endif // __ROUTING_H
