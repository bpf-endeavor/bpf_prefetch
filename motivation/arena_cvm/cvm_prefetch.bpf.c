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
#define SECOND 1000000000L

#include "report_tput.h"

// The user-space will set the reference to the data-structure
arena_treap_t *treap = NULL;
fp_t p;
static uint64_t last_cvm_report;

static __always_inline
uint64_t cvm_estimate(void)
{
	return ((uint64_t)treap->used * FP_SCALE) / ((uint64_t)p);
}

static __always_inline
void reset(void)
{
	treap_reset(treap);
	p = (1 << 31); // FP_ONE
	last_cvm_report = 0;
}

// break steps into seperate functions to make things a bit tidy
#include "cvm_prefetch_logic.h"

SEC("xdp")
int cvm_prefetch_main(struct xdp_md *xdp)
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
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	__u16 tmp_port = bpf_ntohs(udp->dest);
	if (!(tmp_port >= 8000 && tmp_port < 8128))
		return XDP_PASS;

	batch_t * batch = __make_batch(*r);
	if (batch == NULL) {
		return XDP_DROP;
	}

	ret = __treap_batch_update(treap, batch);
	if (ret < 0) {
		bpf_printk("batch update failed: %d", ret);
		reset();
		return XDP_DROP;
	}

	report_tput();
	// report estimate every few seconds
	uint64_t ts = bpf_ktime_get_coarse_ns();
	uint64_t dur = ts - last_cvm_report;
	if (dur > 5*SECOND) {
		if (last_cvm_report == 0) {
			last_cvm_report = ts;
		} else {
			bpf_printk(TAG"Size estimate: %lld", cvm_estimate());
			reset();
			last_cvm_report = ts;
		}
	}
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

