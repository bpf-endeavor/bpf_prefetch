#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

static const char *hex_tbl = "0123456789abcdef";
#define GET_LOWER_BITS(x) (hex_tbl[(x & 0x0f)])
#define GET_UPPER_BITS(x) (hex_tbl[((x & 0xf0) >> 4)])
#define FILL_WITH_HEX(dst_char, src_bytes, i) { \
	dst_char[i * 3]     = GET_UPPER_BITS(src_bytes[i]); \
	dst_char[i * 3 + 1] = GET_LOWER_BITS(src_bytes[i]); \
	dst_char[i * 3 + 2] = ':'; \
}

SEC("xdp")
int bbb_xdp_prog(struct xdp_batch_md *batch)
{
	struct xdp_md *pkt;
	void *data;
	void *data_end;
	struct ethhdr *eth;
	/* struct iphdr *ip; */
	/* struct udphdr *l4; */
	char dst_mac[20];
	char src_mac[20];

	if (batch == NULL) {
		bpf_printk("wow, we received a NULL context!");
		return -1;
	}


	bpf_printk("----------------------------------------------------");
	bpf_printk("batch size: %d", batch->size);
	for (int k = 0; k < batch->size && k < XDP_MAX_BATCH_SIZE; k++) {
		// pkt can not be null because its a pointer into the context
		// data structure
		pkt = &batch->buffs[k];
		data = (void *)(__u64)pkt->data;
		data_end = (void *)(__u64)pkt->data_end;
		// check if the driver is sending a malformed batch to the
		// program
		if (data == NULL) {
			bpf_printk("!! this is not expected!!");
			continue;
		}

		eth = data;
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("!! small pakcet");
			continue;
		}

		for (int i = 0; i < 6; i++) {
			FILL_WITH_HEX(dst_mac, eth->h_dest, i)
			FILL_WITH_HEX(src_mac, eth->h_source, i)
		}
		src_mac[17] = '\0';
		dst_mac[17] = '\0';
		batch->actions[k] = XDP_DROP;
		bpf_printk("Eth: src-mac: %s  dst-mac: %s", src_mac, dst_mac);
	}

	return 0;
}

char _licsence[] SEC("license") = "GPL";
