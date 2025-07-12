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

SEC("xdp")
int bbb_simple(struct xdp_batch_md *batch)
{
	void *data, *data_end;
	__u32 size, batch_size;
	struct xdp_md *pkt = NULL;

	if (batch == NULL) {
		bpf_printk("wow, we received a NULL context!");
		return TEST_FAILED;
	}

	batch_size = batch->size;
	if (batch_size == 0) {
		bpf_printk("wow, we recieved an empty batch!");
		return TEST_FAILED;
	}

	bpf_printk("----------------------------------------------------");
	bpf_printk("batch size: %d", batch_size);

	/* For some reason this is different from what we get in the for loop */
	pkt = &batch->buffs[0];
	data = (void *)(__u64)pkt->data;
	data_end = (void *)(__u64)pkt->data_end;
	size = (__u64)data_end - (__u64)data;
	bpf_printk("data = %p    data_end = %p    size = %d",
			data, data_end, size);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TEST_FAILED;
	for (int i = 0; i < 6; i++) {
		bpf_printk("eth: %x", eth->h_source[i]);
	}

	batch->actions[0] = XDP_DROP;
	return TEST_PASSES;
}

char _licsence[] SEC("license") = "GPL";
