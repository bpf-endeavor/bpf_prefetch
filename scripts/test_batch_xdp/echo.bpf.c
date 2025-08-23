#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

// #define DEBUG_ASSERT_IN_ORDER_PKTS 1
#define REPORT_THROUGHPUT 1
#define MODIFY_PAYLOAD 1

#ifdef REPORT_THROUGHPUT
#include "honey/report_throughput.h"
#endif

#ifdef DEBUG_ASSERT_IN_ORDER_PKTS
static int my_counter = 0;
#endif

enum test_verdict {
	TEST_PASSES = 200,
	TEST_FAILED = 500,
};

enum match_status {
	MATCH = 32,
	NOT_MATCH = 33,
};

#define SERVER_PORT 8080

static inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16); }
	return ~csum;
}

static inline
void ipv4_csum_inline(void *iph, __u64 *csum)
{
	__u32 i;
	__u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += bpf_ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
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
		// bpf_printk("packet smaller than ETH header (%d B)", size);
		return NOT_MATCH;
	}

	if ((*eth)->h_proto != bpf_htons(ETH_P_IP)) {
		// bpf_printk("packet not a IP");
		return NOT_MATCH;
	}

	*ip = (struct iphdr *)(*eth + 1);
	if ((void *)((*ip) + 1) > data_end) {
		// bpf_printk("packet smaller than IP header");
		return NOT_MATCH;
	}

	if ((*ip)->protocol != IPPROTO_UDP) {
		// bpf_printk("packet not a UDP");
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

static inline __attribute__((always_inline))
int swap_address(void *data, void *data_end, struct ethhdr *eth,
		struct iphdr *ip, struct udphdr *udp)
{
	__u64 tmp64;
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

	udp->check = 0;
	ip->check = 0;

	tmp64 = 0;
	ipv4_csum_inline(ip, &tmp64);
	ip->check = bpf_htons((short)tmp64);

	return 0;
}

SEC("xdp")
int bbb_echo(struct xdp_batch_md *batch)
{
	/* __u32 size; */
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;

	__u32 tx_cntr = 0;

	if (batch == NULL) {
		bpf_printk("wow, we received a NULL context!");
		return TEST_FAILED;
	}

	const __u32 batch_size = batch->size;
	if (batch_size == 0) {
		bpf_printk("wow, we recieved an empty batch!");
		return TEST_FAILED;
	}

	// Farbod: we can not use normal loops becaues the compiler generates
	// negative offsets into the batch which causes issue in
	// `xdp_batch_convert_ctx_access`
	#pragma clang loop unroll_count(XDP_MAX_BATCH_SIZE)
	for (int i = 0; i < XDP_MAX_BATCH_SIZE; i++) {
		if (i >= batch_size)
			break;

		struct xdp_md *xdp = &batch->buffs[i];

		void *data = (void *)(__u64)xdp->data;
		void *data_end = (void *)(__u64)xdp->data_end;

		if (parse_headers(data, data_end, &eth, &ip, &udp) != MATCH) {
			// ignore
			// bpf_printk("failed to parse header @ %d", i);
			batch->actions[i] = XDP_PASS;
			continue;
		}

#ifdef DEBUG_ASSERT_IN_ORDER_PKTS
		int *seq = (int *)(udp + 1);
		if ((void *)(seq + 1) > data_end) {
			batch->actions[i] = XDP_ABORTED;
			continue;
		}
		if (*seq != my_counter) {
			bpf_printk("expected %d received %d", my_counter, *seq);
			my_counter = *seq;
		}
		my_counter++;
#endif

#ifdef MODIFY_PAYLOAD
		// remember what was the length of ip header
		__u32 ip_hdr_sz = ip->ihl * 4;
		const __u32 header_size = sizeof(struct ethhdr) + ip_hdr_sz +
			sizeof(struct udphdr);
		const __u64 target_size = header_size + 30 /* new payload size */;

		__u64 size = data_end - data;
		int delta = target_size - size;
		if (bpf_xdp_adjust_tail(xdp, delta) != 0) {
			bpf_printk("failed to adjust packet length (%d)", delta);
			batch->actions[i] = XDP_ABORTED;
			continue;
		}

		// renew the pointers, satisfying the verifier
		xdp = &batch->buffs[i];
		data = (void *)(__u64)xdp->data;
		data_end = (void *)(__u64)xdp->data_end;
		eth = (struct ethhdr *)data;
		ip = (struct iphdr *)(eth + 1);
		udp = (struct udphdr *)((__u8 *)ip + ip_hdr_sz);

		char *payload = (char *)(udp + 1);

		if ((void *)(payload + 30) > data_end) {
			bpf_printk("failed to extend the payload size");
			batch->actions[i] = XDP_ABORTED;
			continue;
		}

		// copy response to the packet
		__builtin_memcpy(payload, "hello from the other siiiide\n\0", 30); 

		/* bpf_printk("successfully modified the payload"); */

		// For some reason I need to do this check to satisfy the
		// verifier. Most probably it is because the IP header is
		// variable length
		if ((void *)(ip + 1) > data_end) {
			bpf_printk("failed to extend the payload size");
			batch->actions[i] = XDP_ABORTED;
			continue;
		}

		// update the packet length fields, the checksum is updated in
		// swap_address
		ip->tot_len = bpf_htons(target_size - sizeof(struct ethhdr));
		udp->len = bpf_htons(target_size - sizeof(struct ethhdr) - ip_hdr_sz);
#endif

		swap_address(data, data_end, eth, ip, udp);

		batch->actions[i] = XDP_TX;
		tx_cntr += 1;

		/* size = (__u64)data_end - (__u64)data; */
		/* bpf_printk("data = %p    data_end = %p    size = %d", */
		/* 		data, data_end, size); */
		// batch->actions[i] = XDP_DROP;
	}

#ifdef REPORT_THROUGHPUT
	report_tput_batch(tx_cntr);
#endif

	return 0;
}

char _licsence[] SEC("license") = "GPL";
