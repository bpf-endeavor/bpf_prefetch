#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

enum test_verdict {
	TEST_PASSES = 200,
	TEST_FAILED = 500,
};

enum match_status {
	MATCH = 32,
	NOT_MATCH = 33,
};

#define SERVER_PORT 8080

static const char *hex_tbl = "0123456789abcdef";
#define GET_LOWER_BITS(x) (hex_tbl[(x & 0x0f)])
#define GET_UPPER_BITS(x) (hex_tbl[((x & 0xf0) >> 4)])
#define FILL_WITH_HEX(dst_char, src_bytes, i) { \
	dst_char[i * 3]     = GET_UPPER_BITS(src_bytes[i]); \
	dst_char[i * 3 + 1] = GET_LOWER_BITS(src_bytes[i]); \
	dst_char[i * 3 + 2] = ':'; \
}

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
unsigned int process_pkt(struct xdp_md *pkt)
{
	/* void *data; */
	/* void *data_end; */
	/* struct ethhdr *eth; */
	/* /1* struct iphdr *ip; *1/ */
	/* /1* struct udphdr *l4; *1/ */
	/* char dst_mac[20]; */
	/* char src_mac[20]; */

	/* data = NULL; */
	/* data = (void *)(__u64)pkt->data; */
	/* data_end = (void *)(__u64)pkt->data_end; */
	/* // check if the driver is sending a malformed batch to the */
	/* // program */
	/* if (data == NULL) { */
	/* 	bpf_printk("!! this is not expected!!"); */
	/* 	return XDP_PASS; */
	/* } */

	/* bpf_printk("ptr: %p", data); */

	/* eth = data; */
	/* if ((void *)(eth + 1) > data_end) { */
	/* 	bpf_printk("!! small pakcet"); */
	/* 	return XDP_PASS; */
	/* } */

	/* for (__u16 i = 0; i < 6; i++) { */
	/* 	FILL_WITH_HEX(dst_mac, eth->h_dest, i) */
	/* 		FILL_WITH_HEX(src_mac, eth->h_source, i) */
	/* } */
	/* src_mac[17] = '\0'; */
	/* dst_mac[17] = '\0'; */
	/* bpf_printk("Eth: src-mac: %s  dst-mac: %s", src_mac, dst_mac); */
	return XDP_DROP;
}

static inline __attribute__((always_inline))
int parse_headers(void *data, void *data_end, struct ethhdr **eth,
		struct iphdr **ip, struct udphdr **udp)
{
	int size;
	*eth = data;
	if ((void *)(*eth + 1) > data_end) {
		bpf_printk("packet smaller than ETH header");
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
	bpf_printk(": ihl=%d  udp @%d", size, (__u64)*udp - (__u64)data);
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
	void *data, *data_end;
	/* __u32 size; */
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;

	if (batch == NULL) {
		bpf_printk("wow, we received a NULL context!");
		return TEST_FAILED;
	}

	const __u32 batch_size = batch->size;
	if (batch_size == 0) {
		bpf_printk("wow, we recieved an empty batch!");
		return TEST_FAILED;
	}

	bpf_printk("----------------------------------------------------");
	bpf_printk("batch size: %d", batch_size);

	// Farbod: we can not use normal loops becaues the compiler generates
	// negative offsets into the batch which causes issue in
	// `xdp_batch_convert_ctx_access`
	#pragma clang loop unroll_count(XDP_MAX_BATCH_SIZE)
	for (int i = 0; i < XDP_MAX_BATCH_SIZE; i++) {
		if (i >= batch_size)
			break;

		data = (void *)(__u64)batch->buffs[i].data;
		data_end = (void *)(__u64)batch->buffs[i].data_end;

		if (parse_headers(data, data_end, &eth, &ip, &udp) != MATCH) {
			// ignore
			batch->actions[i] = XDP_PASS;
			continue;
		}

		swap_address(data, data_end, eth, ip, udp);

		bpf_printk("tx...");
		batch->actions[i] = XDP_TX;

		/* size = (__u64)data_end - (__u64)data; */
		/* bpf_printk("data = %p    data_end = %p    size = %d", */
		/* 		data, data_end, size); */
		// batch->actions[i] = XDP_DROP;
	}

	return 0;
}

char _licsence[] SEC("license") = "GPL";
