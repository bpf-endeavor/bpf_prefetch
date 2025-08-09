#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "honey/report_throughput.h"
#include "honey/rand.h"

#define SERVER_PORT 8080

enum match_status {
	MATCH = 32,
	NOT_MATCH = 33,
};

enum test_verdict {
	TEST_PASSES = 200,
	TEST_FAILED = 500,
};

static inline __attribute__((always_inline))
int swap_address(void *data, void *data_end, struct ethhdr *eth,
		struct iphdr *ip, struct udphdr *udp)
{
	/* __u64 tmp64; */
	__u32 tmp32;
	__u16 tmp16;
	tmp32 = *(__u32 *)eth->h_source;
	tmp16 = *(__u16 *)&eth->h_source[4];

	*(__u32 *)eth->h_source = *(__u32 *)eth->h_dest;
	*(__u16 *)&eth->h_source[4] = *(__u16 *)eth->h_dest;
	*(__u32 *)eth->h_dest = tmp32;
	*(__u16 *)&eth->h_dest[4] = tmp16;

	tmp32 = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp32;

	tmp16 = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp16;

	// swapping address does not require updating checksum
	/* udp->check = 0; */
	/* ip->check = 0; */

	/* tmp64 = 0; */
	/* ipv4_csum_inline(ip, &tmp64); */
	/* ip->check = bpf_htons((short)tmp64); */

	return 0;
}

static inline __attribute__((always_inline))
int parse_headers(void *data, void *data_end, struct ethhdr **eth,
		struct iphdr **ip, struct udphdr **udp)
{
	int size;
	*eth = data;
	/* bpf_printk("|| %p & %p", data, data_end); */
	if ((void *)(*eth + 1) > data_end) {
		size = (__u64)data_end - (__u64)data;
		bpf_printk("packet smaller than ETH header (%d B)", size);
		return NOT_MATCH;
	}

	if ((*eth)->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("packet not a IP");
		return NOT_MATCH;
	}

	*ip = (struct iphdr *)(*eth + 1);
	if ((void *)((*ip) + 1) > data_end) {
		bpf_printk("packet smaller than IP header");
		return NOT_MATCH;
	}

	if ((*ip)->protocol != IPPROTO_UDP) {
		bpf_printk("packet not a UDP");
		return NOT_MATCH;
	}

	// TODO: check ip address

	// ip header size
	size = (*ip)->ihl * 4;
	*udp = (struct udphdr *)(data + sizeof(struct ethhdr) + size);
	/* bpf_printk(": ihl=%d  udp @%d", size, (__u64)*udp - (__u64)data); */
	if ((void *)((*udp) + 1) > data_end) {
		bpf_printk("packet smaller than the UDP header");
		return NOT_MATCH;
	}

	if ((*udp)->dest != bpf_htons(SERVER_PORT)) {
		bpf_printk("Port address does not match: %d", (*udp)->dest);
		return NOT_MATCH;
	}

	return MATCH;
}

SEC("xdp")
int bbb_random(struct xdp_batch_md *batch)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;

	__u32 pkt_cntr = 0;

	if (batch == NULL) {
		bpf_printk("wow, we received a NULL context!");
		return TEST_FAILED;
	}

	const __u32 batch_size = batch->size;
	if (batch_size == 0) {
		bpf_printk("wow, we recieved an empty batch!");
		return TEST_FAILED;
	}

#pragma clang loop unroll_count(XDP_MAX_BATCH_SIZE)
	for (int i = 0; i < XDP_MAX_BATCH_SIZE; i++) {
		if (i >= batch_size)
			break;

		void *data = (void *)(__u64)batch->buffs[i].data;
		void *data_end = (void *)(__u64)batch->buffs[i].data_end;

		if (parse_headers(data, data_end, &eth, &ip, &udp) != MATCH) {
			// ignore
			bpf_printk("failed to parse header @ %d", i);
			batch->actions[i] = XDP_PASS;
			continue;
		}

		// randomly select an action
		int action = __rand() % 3;
		switch(action) {
			case 1:
				batch->actions[i] = XDP_PASS;
				break;
			case 2:
				swap_address(data, data_end, eth, ip, udp);
				batch->actions[i] = XDP_TX;
				break;
			case 3:
				batch->actions[i] = XDP_DROP;
				break;
		}

		pkt_cntr += 1;
	}

	report_tput_batch(pkt_cntr);

	return 0;
}

char _licsence[] SEC("license") = "GPL";
