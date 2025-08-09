#pragma once

#ifndef SERVER_PORT
#pragma GCC error "SERVER_PORT is not defined"
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "csum.h"

struct udp_packet {
	void *data;
	void *data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
};

static inline __attribute__((always_inline))
int parse_headers(void *data, void *data_end, struct udp_packet *upkt)
{
	int size;
	upkt->data = data;
	upkt->data_end = data_end;

	if ((data + 14 + 20 + 8) > data_end)
		return 1;

	upkt->eth = data;
	if ((upkt->eth)->h_proto != bpf_htons(ETH_P_IP)) {
		// bpf_printk("packet not a IP");
		return 1;
	}

	upkt->ip = (struct iphdr *)(upkt->eth + 1);
	if ((upkt->ip)->protocol != IPPROTO_UDP) {
		// bpf_printk("packet not a UDP");
		return 1;
	}

	// TODO: check ip address

	// ip header size
	size = (upkt->ip)->ihl * 4;
	upkt->udp = (struct udphdr *)(data + sizeof(struct ethhdr) + size);
	/* bpf_printk(": ihl=%d  udp @%d", size, (__u64)*udp - (__u64)data); */
	if ((void *)((upkt->udp) + 1) > data_end) {
		bpf_printk("packet smaller than the UDP header");
		return 1;
	}

	if ((upkt->udp)->dest != bpf_htons(SERVER_PORT)) {
		bpf_printk("Port address does not match: %d", (upkt->udp)->dest);
		return 1;
	}

	return 0;
}

static inline __attribute__((always_inline))
int swap_address(struct udp_packet *upkt)
{
	struct ethhdr *eth = upkt->eth;
	struct iphdr *ip = upkt->ip;
	struct udphdr *udp = upkt->udp;

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

	return 0;
}

static inline __attribute__((always_inline))
int update_csum(struct udp_packet *upkt)
{
	__u64 tmp64;
	upkt->udp->check = 0;
	upkt->ip->check = 0;

	tmp64 = 0;
	ipv4_csum_inline(upkt->ip, &tmp64);
	upkt->ip->check = bpf_htons((short)tmp64);
	return 0;
}

static inline __attribute__((always_inline))
int update_udp_pkt_with_payload(struct xdp_md *xdp, struct udp_packet *upkt,
		void *val, int val_size /* it must be const expression */)
{
	// remember what was the length of ip header
	__u32 ip_hdr_sz = upkt->ip->ihl * 4;
	const __u32 header_size = sizeof(struct ethhdr) + ip_hdr_sz +
		sizeof(struct udphdr);
	const __u64 target_size = header_size + val_size /* new payload size */;

	__u64 size = upkt->data_end - upkt->data;
	int delta = target_size - size;
	if (bpf_xdp_adjust_tail(xdp, delta) != 0) {
		bpf_printk("failed to adjust packet length (%d)", delta);
		return 1;
	}

	// renew the pointers, satisfying the verifier
	// xdp = &batch->buffs[i];
	upkt->data = (void *)(__u64)xdp->data;
	upkt->data_end = (void *)(__u64)xdp->data_end;
	upkt->eth = (struct ethhdr *)upkt->data;
	upkt->ip = (struct iphdr *)(upkt->eth + 1);
	upkt->udp = (struct udphdr *)((__u8 *)upkt->ip + ip_hdr_sz);

	char *payload = (char *)(upkt->udp + 1);

	if ((void *)(payload + val_size) > upkt->data_end) {
		bpf_printk("failed to extend the payload size");
		return 1;
	}

	// copy response to the packet
	__builtin_memcpy(payload, val, val_size); 

	/* bpf_printk("successfully modified the payload"); */

	// For some reason I need to do this check to satisfy the
	// verifier. Most probably it is because the IP header is
	// variable length
	if ((void *)(upkt->ip + 1) > upkt->data_end) {
		bpf_printk("failed to extend the payload size");
		return 1;
	}

	upkt->ip->tot_len = bpf_htons(target_size - sizeof(struct ethhdr));
	upkt->udp->len = bpf_htons(target_size - sizeof(struct ethhdr) - ip_hdr_sz);

	swap_address(upkt);
	update_csum(upkt);

	return 0;
}
