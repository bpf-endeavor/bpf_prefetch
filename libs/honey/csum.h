#pragma once
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>

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

