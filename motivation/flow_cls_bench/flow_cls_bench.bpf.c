#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include "struct_def.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,  flow_key_t);
	__type(value, flow_state_t);
	__uint(max_entries, 1 << 19);
} policy_map SEC(".maps");

static __u64 counter = 0;
static __u64 last_report = 0;

static inline __attribute__((always_inline)) void report_tput(void)
{
	__u64 ts, delta;
	__u64 t = __sync_fetch_and_add(&counter, 1);
	if (last_report == 0) {
		ts = bpf_ktime_get_ns();
		last_report = ts;
		return;
	}

	if ((t % 1024) != 0) {
		return;
	}

	ts = bpf_ktime_get_ns();
	delta = ts - last_report;
	if (delta >= 1000000000LL) {
		bpf_printk("throughput: %ld (pps)", counter);
		counter = 0;
		last_report = ts;
	}
}

SEC("xdp")
int xdp_prog(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = NULL;
	struct udphdr *l4 = NULL;
	flow_key_t flow_key;
	__u16 doff = 0;
	flow_state_t *flow_state = NULL;

	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("packet too small for IP header!");
		return XDP_ABORTED;
	}
	if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}
	doff = ip->ihl * 4;
	l4 = (struct udphdr *)((__u8 *)ip + doff);
	if ((void *)(l4 + 1) > data_end) {
		bpf_printk("packet too small for UDP/TCP!");
		return XDP_ABORTED;
	}

	flow_key.src_ip = bpf_ntohl(ip->saddr);
	flow_key.src_port = bpf_ntohs(l4->source);
	flow_key.dst_ip = bpf_ntohl(ip->daddr);
	flow_key.dst_port = bpf_ntohs(l4->dest);
	flow_key.protocol = ip->protocol;

	bpf_printk("recv: 0x%x:%hu", flow_key.src_ip, flow_key.src_port);

	flow_state = bpf_map_lookup_elem(&policy_map, &flow_key);
	if (flow_state == NULL) {
		bpf_printk("Unexpected flow not found!");
		return XDP_ABORTED;
	}

	/* __sync_fetch_and_add(&flow_state->counter, 1); */

	report_tput();
	switch (flow_state->verdict) {
		case XDP_ABORTED:
			return XDP_ABORTED;
		case XDP_DROP:
			return XDP_DROP;
		case XDP_PASS:
			return XDP_PASS;
		case XDP_TX:
			return XDP_TX;
		default:
			return XDP_ABORTED;
	}
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
