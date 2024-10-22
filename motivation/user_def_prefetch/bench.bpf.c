/* Goal:
 * 1. Test if bpf_prefetch is working
 * 2. See if it is any good
 * */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#define SERVER_PORT 8080

#include "honey/prefetching.h"
#include "honey/report_throughput.h"
#include "honey/is_relevant.h"
#include "honey/rand.h"

#define VALUE_SIZE 4 // int
#define SLICES 5
#define SLICE_SIZE 55
#define ENTRIES (512 * 1024 * 1024)

#define ROUND(x, y) (((x-1) | (y-1)) + 1)
#define STRIDE 1025

typedef struct {
	char data[VALUE_SIZE];
} __attribute__((packed)) value_t;

struct {
	__uint(type,        BPF_MAP_TYPE_ARRAY);
	__type(key,         __u32);
	__type(value,       value_t);
	__uint(max_entries, ENTRIES);
} atable SEC(".maps");

volatile static __u32 has_init = 0;
volatile static __u32 __my_seed = 0;

#ifdef PREFETCH
/* Address of the first element of the array */
volatile static __u64 __tab_addr = 0;
volatile static __u64 __last_addr = 0;

static inline void __prefetch_next_pkt_touch(void)
{
	/* __u32 s = seed; /1* it is the current seed *1/ */
	__u32 tmp, tmp2, index;
	void *p;

	/*
	 *
	 * */
	/* if (__my_seed % 2 != 0) */
	/* 	return; */

	/* This is extra computation cost for prefetching next element */
	/* index = (__my_seed + (1 * STRIDE)) % ENTRIES; */
	/* p = (void *)__tab_addr + ROUND((index * VALUE_SIZE), 8); */
	/* P(p); */
	/* p += STRIDE * VALUE_SIZE; */
	/* P1(p); */

	p = (void *)__last_addr + STRIDE * ROUND(VALUE_SIZE, 8);
	/* bpf_printk("p: %p", p); */
	/* P(p); */

	/* Fetch the two touch from now */
	p = p + STRIDE * ROUND(VALUE_SIZE, 8);
	P1(p);

	/* for (int i = 0; i < 2 * SLICES; i++) */
	/* 	s = __rand_seeded(s); */

	/* /1* for (int k = 0; k < 1; k++) { *1/ */
	/* 	index = 0; */
	/* 	for (int i = 0; i < SLICES; i++) { */
	/* 		tmp = s = __rand_seeded(s); */
	/* 		tmp = tmp % SLICE_SIZE; */
	/* 		/1* bpf_printk("g: %d -> %d", i, tmp); *1/ */
	/* 		tmp2 = 1; */
	/* 		for (int j = SLICES - 1 - i; j > 0; j--) */
	/* 			tmp2 *= SLICE_SIZE; */
	/* 		index += tmp * tmp2; */
	/* 	} */
	/* 	p = (void *)__tab_addr + ROUND((index * VALUE_SIZE), 8); */
	/* 	P(p); */
	/* 	/1* bpf_printk("p: %p  index: %d", p, index); *1/ */
	/* /1* } *1/ */

}
#endif

static inline int __touch(void)
{
	__u32 tmp, tmp2, index;
	volatile value_t *v;

	index = __my_seed % ENTRIES;
	__my_seed += STRIDE;
	/* for (int i = 0; i < SLICES; i++) { */
	/* 	tmp = __rand() % SLICE_SIZE; */
	/* 	/1* tmp = __rand_predictable(__my_seed++) % SLICE_SIZE; *1/ */
	/* 	/1* bpf_printk("a: %d -> %d", i, tmp); *1/ */
	/* 	tmp2 = 1; */
	/* 	for (int j = SLICES - 1 - i; j > 0; j--) */
	/* 		tmp2 *= SLICE_SIZE; */
	/* 	index += tmp * tmp2; */
	/* } */
	/* if (index > ENTRIES) { */
	/* 	bpf_printk("error when calculating index"); */
	/* 	return -1; */
	/* } */
	v = bpf_map_lookup_elem(&atable, &index);
	if (v == NULL) {
		bpf_printk("This must never happen!");
		return -1;
	}

#ifdef PREFETCH
	__last_addr = (__u64)v;
#endif
	/* bpf_printk("l: %p  index: %d", v, index); */
	return *(int *)v->data;
}

static inline void __init(void)
{
	int i, ii;
	value_t *v;
	bpf_for(i, 0, ENTRIES) {
		ii = i;
		v = bpf_map_lookup_elem(&atable, &ii);
		if (!v) {
			bpf_printk("failed to init array!");
			return;
		}
		*(int *)v->data = ii;
	}
#ifdef PREFETCH
	ii = 0;
	v = bpf_map_lookup_elem(&atable, &ii);
	if (!v) { bpf_printk("failed to init table address!"); return; }
	__tab_addr = (__u64)v;
#endif
}

SEC("xdp")
int prog(struct xdp_md *xdp)
{
	if (has_init == 0) {
		has_init = 1;
		__init();
		bpf_printk("-----");
	}
	int v;
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	int *out = data;
	if (!is_relevant(data, data_end))
		return XDP_PASS;
#ifdef PREFETCH
	__prefetch_next_pkt_touch();
#endif
	v = __touch();
	*out = v;
	report_tput();
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
