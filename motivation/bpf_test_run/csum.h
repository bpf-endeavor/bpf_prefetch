#ifndef CSUM_H
#define CSUM_H
#include <arpa/inet.h>
#include <linux/ip.h>
static inline unsigned short
csum_fold_helper(unsigned long csum)
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
ipv4_csum_inline(void *iph, unsigned long *csum)
{
	unsigned int i;
	unsigned short *next_iph_u16 = (unsigned short *)iph;
	for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

static void
ipv4_l4_csum_inline(void *data_end, void *l4_hdr, struct iphdr *iph, unsigned long *csum)
{
	unsigned int ip_addr;
	unsigned short *next_iph_u16;
	unsigned char *last_byte;
	/* Psuedo header */
	ip_addr = ntohl(iph->saddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	ip_addr = ntohl(iph->daddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	*csum += (unsigned short)iph->protocol;
	*csum += (unsigned short)((long)data_end - (long)l4_hdr);
	next_iph_u16 = (unsigned short *)l4_hdr;
	const unsigned short length = (unsigned long long)data_end - (unsigned long long)next_iph_u16;
	const unsigned short nr = length / 2;
	for (int i = 0; i < nr; i++) {
		*csum += ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	/* printf("len: %d, %d\n", length, nr); */
	if ((void *)next_iph_u16 < data_end) {
		last_byte = (unsigned char *)next_iph_u16;
		if ((void *)(last_byte + 1) <= data_end) {
			*csum += ((unsigned short)(*last_byte)) << 8;
		}
	}
	*csum = csum_fold_helper(*csum);
}
#endif
