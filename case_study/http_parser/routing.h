#ifndef __ROUTING_H
#define __ROUTING_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "jhash.h"
#include "report_throughput.h"

#define MAX_ROUTES (1 << 20)
#define ROUTE_MAX_HOST_LENGTH 60

typedef struct {
	__u64 upstream;
	__u64 counter;
	__u64 dummy[6];
}  __attribute__((aligned(64))) routing_elem_t;

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, routing_elem_t);
	__uint(max_entries, MAX_ROUTES);
} routing_table SEC(".maps");

int prog_route(CONTEXT *ctx, __u16 host_start_off, __u16 host_end_off)
{
	void *data = GET_DATA(ctx);
	void *data_end = GET_DATAEND(ctx);
	char *host = data + (host_start_off & OFFSET_MASK);
	__u16 host_len = host_end_off - host_start_off;
	if (host_end_off < host_start_off || host_len > ROUTE_MAX_HOST_LENGTH) {
		bpf_printk("wierd err");
		return ABORTED;
	}
	if ((void *)(host + ROUTE_MAX_HOST_LENGTH) > data_end) {
		bpf_printk("routing: out of range");
		return ABORTED;
	}
	__u32 hash = jhash(host, host_len, 123);
	__u32 index = hash % MAX_ROUTES;
	/* bpf_printk("%s --> %d", host, index); */
	routing_elem_t *r = bpf_map_lookup_elem(&routing_table, &index);
	if (r == NULL) {
		bpf_printk("this must never happen %d\n", hash);
		return ABORTED;
	}
	__sync_fetch_and_add(&r->counter, 1);
	if (r->upstream == 2)
		return DROP;
	report_tput();
	return DROP;
}

#endif // __ROUTING_H
