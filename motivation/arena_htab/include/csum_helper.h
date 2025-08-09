#ifndef _CSUM_HELPER
#define _CSUM_HELPER
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Check-sum calculation helpers */
struct csum_loop_ctx {
	unsigned short *next_iph_u16;
	void *data_end;
	unsigned long long *csum;
};

static inline unsigned short
csum_fold_helper(unsigned long long csum)
{
	int i;
	#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16) {
			csum = (csum & 0xffff) + (csum >> 16);
		}
	}
	return ~csum;
}

static inline void
ipv4_csum_inline(void *iph, unsigned long long *csum)
{
	unsigned int i;
	unsigned short *next_iph_u16 = (unsigned short *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += bpf_ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

static long
csum_loop(unsigned int i, void *_ctx)
{
	struct csum_loop_ctx *ctx = (struct csum_loop_ctx *)_ctx;
	if ((void *)(ctx->next_iph_u16 + 1) > ctx->data_end) {
		return 1;
	}
	*ctx->csum += bpf_ntohs(*ctx->next_iph_u16);
	ctx->next_iph_u16++;
	return 0;
}

static inline void
ipv4_l4_csum_inline(void *data_end, void *l4_hdr, struct iphdr *iph,
		unsigned long long *csum)
{
	unsigned int ip_addr;
	unsigned short *next_iph_u16;
	unsigned char *last_byte;

	/* Psuedo header */
	ip_addr = bpf_ntohl(iph->saddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	ip_addr = bpf_ntohl(iph->daddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	*csum += (unsigned short)iph->protocol;
	*csum += (unsigned short)((long)data_end - (long)l4_hdr);

	next_iph_u16 = (unsigned short *)l4_hdr;
	const unsigned short length = (unsigned long long)data_end - (unsigned long long)next_iph_u16;
	const unsigned short nr = length / 2;
	struct csum_loop_ctx loop_ctx = {
		.next_iph_u16 = next_iph_u16,
		.data_end = data_end,
		.csum = csum,
	};
	bpf_loop(nr, (void *)csum_loop, &loop_ctx, 0);
	if (loop_ctx.next_iph_u16 != data_end) {
		last_byte = (unsigned char *)next_iph_u16;
		if ((void *)(last_byte + 1) <= data_end) {
			*csum += (unsigned short)(*last_byte) << 8;
		}
	}
	*csum = csum_fold_helper(*csum);
}
/* ------------------------------------------------------------- */
#endif
