/* Goal:
 * 1. Test if bpf_prefetch is working
 * 2. See if it is any good
 * */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

/* Define the unofficial helper function */
static long (*bpf_prefetch)(void *ptr__ign) = (void *) 212;

SEC("xdp")
int prog(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	char *p = (char *)data;
	bpf_prefetch(p);
	bpf_printk("hello: %s", p);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
