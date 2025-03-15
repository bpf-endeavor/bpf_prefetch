#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "arena-ds/common/stddef.h"

// One Gigabyte
#define ARENA_MAX_PAGES (1 << 18)

/* I need this dummy function to register arena with the XDP while not using
 * any sleepable function (it is from a kernel module that you have to load) */
long my_kfunc_reg_arena(void *p__map) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, ARENA_MAX_PAGES); /* number of pages */
} arena SEC(".maps");

#include "shared_struct.h"

#include "treap.h"
#include "arena-ds/fixed-point/fp.h"
#include "xdp_helpers.h"

#define TAG "bpf-cvm: "

#include "report_tput.h"

// The user-space will set the reference to the data-structure
arena_treap_t *treap = NULL;
fp_t p;

static __always_inline
uint64_t cvm_estimate(void)
{
	return (uint64_t)((double)treap->used / fp_to_float(p));
}

SEC("xdp")
int cvm_main(struct xdp_md *xdp)
{
	if (treap == NULL) {
		bpf_printk(TAG"can not see the data-structure (probably something went wrong in the user-space)");
		my_kfunc_reg_arena(&arena);
		return XDP_PASS;
	}

	int ret;
	void *data = (void *)(__u64)(xdp->data);
	void *data_end = (void *)(__u64)(xdp->data_end);
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth+1);
	struct udphdr *udp = (void *)(ip + 1);
	uint32_t *r = (void *)(udp + 1);
	if ((void *)(r + 1) > data_end)
		return XDP_PASS;
	__u16 tmp_port = bpf_ntohs(udp->dest);
	if (!(tmp_port >= 8000 && tmp_port < 8128))
		return XDP_PASS;

	struct treap_key key = {.data = *r};
	// check if the key is in the buffer and delete it
	treap_delete(treap, &key);
	uint32_t u = fp_random();
	if (u > p)
		goto _done;
	if (treap_has_space(treap)) {
		ret = treap_insert(treap, &key, u);
		if (ret != 0) {
			bpf_printk(TAG"failed to insert");
			return XDP_DROP;
		}
		goto _done;
	}
	// u < p and |B| = s
	arena_treap_node_t *top = treap_top(treap);
	if (u > top->priority) {
		p = u;
		goto _done;
	} else {
		p = top->priority;
		ret = treap_delete(treap, (void *)&top->key);
		if (ret != 0) {
			bpf_printk(TAG"failed to replace the node (delete)");
			return XDP_DROP;
		}
		ret = treap_insert(treap, &key, u);
		if (ret != 0) {
			bpf_printk(TAG"failed to replace the node (insert)");
			return XDP_DROP;
		}
		goto _done;
	}

_done:
	if (report_tput()) {
		bpf_printk(TAG"Size estimate: %lld", cvm_estimate());
	}
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
