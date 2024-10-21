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

static inline int __touch(void)
{
	__u32 tmp, tmp2, index;
	volatile value_t *v;

	index = 0;
	for (int i = 0; i < SLICES; i++) {
		tmp = __rand() % SLICE_SIZE;
		tmp2 = 1;
		for (int j = SLICES - 1 - i; j > 0; j--)
			tmp2 *= SLICE_SIZE;
		index += tmp * tmp2;
	}
	if (index > ENTRIES) {
		bpf_printk("error when calculating index");
		return -1;
	}
	v = bpf_map_lookup_elem(&atable, &index);
	if (v == NULL) {
		bpf_printk("This must never happen!");
		return -1;
	}
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
	v = __touch();
	*out = v;
	report_tput();
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
