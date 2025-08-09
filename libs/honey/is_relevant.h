#ifndef __IS_RELEVANT_H
#define __IS_RELEVANT_H

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

static inline __attribute__((always_inline))
int is_relevant(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return 0;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;
	if (ip->protocol != IPPROTO_UDP)
		return 0;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return 0;
	return 1;
}

#endif
