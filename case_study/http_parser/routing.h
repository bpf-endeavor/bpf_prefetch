#ifndef __ROUTING_H
#define __ROUTING_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "libs/jhash.h"
#include "report_throughput.h"
#include "prefetching.h"

#define MAX_ROUTES (1 << 20)
#define ROUTE_MAX_HOST_LENGTH 64

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
	__u32 hash;
	routing_key_t key;
	__u32 ptr;
} node_t;

typedef struct {
	node_t nodes[BUCKET_SIZE];
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

/* struct { */
/* 	__uint(type, BPF_MAP_TYPE_HASH); */
/* 	__type(key, routing_key_t); */
/* 	__type(value, routing_elem_t); */
/* 	__uint(max_entries, MAX_ROUTES); */
/* } routing_table SEC(".maps"); */

/* #ifdef PREFETCH */
/* #define TRACK_B_SIZE 32 */
/* typedef struct { */
/* 	__u8 h; */
/* 	void *b[TRACK_B_SIZE]; */
/* } __attribute__((aligned(64))) tracker_t; */

/* struct { */
/* 	__uint(type, BPF_MAP_TYPE_ARRAY); */
/* 	__type(key, __u32); */
/* 	__type(value, tracker_t); */
/* 	__uint(max_entries, MAX_ROUTES); */
/* } popularity_track SEC(".maps"); */
/* #endif */

#ifdef PREFETCH
static volatile int __init = 0;
static __u64 atable_addr = 0;
#endif

sinline routing_elem_t *__lookup(routing_key_t *key)
{
#ifdef PREFETCH
	void *__ptr;
#endif 
	bucket_t *b = NULL;
	node_t *n = NULL;
	routing_elem_t *r = NULL;
	__u32 hash = jhash(key->data, sizeof(*key), 123);
	__u32 index = hash % NUMBER_OF_BUCKETS;
	b = bpf_map_lookup_elem(&btable, &index);
	if (unlikely(b == NULL))
		return NULL;

	for (__u16 i = 0; i < BUCKET_SIZE; i++) {
		n = &b->nodes[i];
		if (n->hash != hash) {
#ifdef PREFETCH
			if (i % 2 == 0) {
				__ptr = &b->nodes[i+4];
				P(__ptr);
				P(__ptr + 64);
			}
#endif
			continue;
		} else {
			__u32 ptr = n->ptr; 
#ifdef PREFETCH
			__ptr = (void *)(round(atable_addr + (ptr * sizeof(routing_elem_t)), 8));
			/* potential hit: we can prefetch the actual data while we check if keys match */
			P(__ptr);
#endif
			if (__builtin_memcmp(key, &n->key, sizeof(*key)) == 0) {
				/* found the value */
				if (ptr == 0) {
					bpf_printk("__lookup: pointer is null!");
					return NULL;
				}
				r = bpf_map_lookup_elem(&atable, &ptr);
#ifdef PREFETCH
				/* bpf_printk("prefetched: %p  actual: %p", __ptr, r); */
#endif
				return r;
			}
		}
	}
	/* did not found */
	return NULL;
}

sinline int __update(routing_key_t *key, routing_elem_t *val)
{
	bucket_t *b = NULL;
	node_t *n = NULL;
	routing_elem_t *r = NULL;
	__u32 hash = jhash(key->data, sizeof(*key), 123);
	__u32 index = hash % NUMBER_OF_BUCKETS;
	b = bpf_map_lookup_elem(&btable, &index);
	if (b == NULL)
		return -1;
	for (__u16 i = 0; i < BUCKET_SIZE; i++) {
		/* NOTE: this update (also lookup) routing has race conditions */
		n = &b->nodes[i];
		if (n->ptr != 0) {
			// this node is used;
			continue;
		}
		__u32 x = __sync_fetch_and_add(&used_index, 1);
		if (x > MAX_ROUTES) {
			bpf_printk("__update: out of value slots");
			return -1;
		}
		n->hash = hash;
		__builtin_memcpy(&n->key, key, sizeof(*key));
		n->ptr = x;
		r = bpf_map_lookup_elem(&atable, &x);
		if (r == NULL) {
			/* this must never happen */
			bpf_printk("__update: allocated index does not exists!");
			return -1;
		}
		__builtin_memcpy(r, val, sizeof(*val));
		return 0;
	}
	/* did not found empty node */
	bpf_printk("__update: bucket was full!");
	return -1;
}

int prog_route(CONTEXT *ctx, __u16 host_start_off, __u16 host_end_off)
{
#ifdef PREFETCH
	if (unlikely(__init == 0)) {
		/* Get the address of first index of the array.
		 * We use if for prefetching values, later in the code.
		 * */
		__init = 1;
		__u32 zero = 0;
		routing_elem_t *__tmp = bpf_map_lookup_elem(&atable, &zero);
		atable_addr = (__u64)__tmp ;
		bpf_printk("-----");
	}
#endif
	void *data = GET_DATA(ctx);
	void *data_end = GET_DATAEND(ctx);
	char *host = data + (host_start_off & OFFSET_MASK);
	__u16 host_len = host_end_off - host_start_off;
	routing_elem_t *r = NULL;
	routing_key_t key;
	__builtin_memset(&key, 0, sizeof(key));

	if (host_end_off < host_start_off || host_len > ROUTE_MAX_HOST_LENGTH) {
		bpf_printk("wierd err");
		return ABORTED;
	}
	if ((void *)(host + ROUTE_MAX_HOST_LENGTH) > data_end) {
		bpf_printk("routing: out of range");
		return ABORTED;
	}

	for (int i = 0; i < ROUTE_MAX_HOST_LENGTH; i++) {
		if (i >= host_len) break;
		key.data[i] = host[i];
	}

/* #ifdef PREFETCH */
/* 	__u32 hash = jhash(host, host_len, 123); */
/* 	__u32 index = hash % MAX_ROUTES; */
/* 	tracker_t *t = bpf_map_lookup_elem(&popularity_track, &index); */
/* 	if (t == NULL) { */
/* 		bpf_printk("must never happen"); */
/* 		return ABORTED; */
/* 	} */
/* 	for (int i = 0; i < TRACK_B_SIZE; i++) { */
/* 		if (t->b[i] == 0) { */
/* 			break; */
/* 		} else { */
/* 			P(t->b[i]); */
/* 		} */
/* 	} */
/* #endif */

	/* r = bpf_map_lookup_elem(&routing_table, &key); */
	r = __lookup(&key);
	if (unlikely(r == NULL)) {
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

/* #ifdef PREFETCH */
/* 	void *n = (void *)((__u64)r - sizeof(key)); */
/* 	for (int i = 0; i < TRACK_B_SIZE; i++) { */
/* 		if (t->b[i] == n) { */
/* 			goto _out; */
/* 		} else if (t->b[i] == 0) { */
/* 			t->b[i] = n; */
/* 			t->h = i; */
/* 			goto _out; */
/* 		} else { */
/* 			continue; */
/* 		} */
/* 	} */
/* 	if (t->h >= TRACK_B_SIZE) { */
/* 		bpf_printk("This must not happen"); */
/* 		return ABORTED; */
/* 	} */
/* 	t->b[t->h] = n; */
/* 	bpf_printk("index: %d:%d %p\n", index, t->h, n); */
/* 	t->h = (t->h + 1) % TRACK_B_SIZE; */
/* _out: */
/* #endif */

	__sync_fetch_and_add(&r->counter, 1);
	if (r->upstream == 2)
		return DROP;
	report_tput();
	return DROP;
}

#endif // __ROUTING_H
