#ifndef __MY_BPF_COMMONS
#define __MY_BPF_COMMONS

#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include "my_bpf/csum_helpers.h"

/* Make sure these types are defined */
#ifndef __u32
typedef unsigned char        __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
#endif

#ifndef NULL
#define NULL 0
#endif

#define sinline static inline __attribute__((__always_inline__))
#ifndef mem_barrier
#define mem_barrier asm volatile("": : :"memory")
#endif

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif

#define ABS(val) ((val) < 0) ? (-(val)) : (val)
#define CAP(val, cap) (val > cap ? cap : val)
#define SIGNED(val, neg) (neg ? -val : val)

static inline __attribute__((__always_inline__))
int __adjust_skb_size(struct __sk_buff *skb, __u16 new_size)
{
	/* Addjust SKB size */
	/* TODO: (Farbod) this is ridiculous: use two calls to
	 * bpf_skb_adjust_room size to allow for changing skb size upto
	 * 8KByte */
	__u16 prev_size = skb->len;
	int shrink = new_size < prev_size;
	int total_delta = ABS(prev_size - new_size);
	int delta = CAP(total_delta, 0x0fff); /* delta that we can do in one function call */
	total_delta -= delta; /* rest of the delta */
	if (bpf_skb_adjust_room(skb, SIGNED(delta, shrink), 0, 0) <  0) {
		bpf_printk("failed to resize the packet");
		return -1;
	}
	if (total_delta && bpf_skb_adjust_room(skb, SIGNED(total_delta, shrink), 0, 0) < 0) {
		/* If three is left over packet size change, try to do it one more time */
		bpf_printk("failed to resize the packet (2)");
		bpf_printk("prev: %d new: %d", prev_size, new_size);
		return -1;
	}
	return 0;
}

static inline __attribute__((__always_inline__))
int __adjust_skb_size_2(struct __sk_buff *skb, __u16 new_size, __u16 *tot_resize)
{
	/* Addjust SKB size */
	/* TODO: (Farbod) this is ridiculous: use two calls to
	 * bpf_skb_adjust_room size to allow for changing skb size upto
	 * 8KByte */
	__u16 prev_size = skb->len;
	int shrink = new_size < prev_size;
	int total_delta = ABS(prev_size - new_size);
	int delta = CAP(total_delta, 0x0fff); /* delta that we can do in one function call */
	total_delta -= delta; /* rest of the delta */
	if (bpf_skb_adjust_room(skb, SIGNED(delta, shrink), 0, 0) <  0) {
		bpf_printk("failed to resize the packet");
		return -1;
	}
	if (total_delta && bpf_skb_adjust_room(skb, SIGNED(total_delta, shrink), 0, 0) < 0) {
		/* If three is left over packet size change, try to do it one more time */
		bpf_printk("failed to resize the packet (2)");
		bpf_printk("prev: %d new: %d", prev_size, new_size);
		return -1;
	}
	*tot_resize = total_delta;
	return 0;
}

static inline int
__prepare_headers_before_pass(struct xdp_md *xdp)
{
	struct ethhdr *eth = (void *)(__u64)xdp->data;
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	void *data_end = (void *)(__u64)xdp->data_end;
	if ((void *)(udp + 1) > data_end)
		return -1;
	const __u32 new_packet_len = ((__u64)data_end - (__u64)xdp->data);
	const __u32 new_ip_len  = new_packet_len - sizeof(struct ethhdr);
	const __u32 new_udp_len = new_ip_len - sizeof(struct iphdr);
	/* bpf_printk("ip len: %d", new_ip_len); */
	/* bpf_prinkt("udp len: %d", new_udp_len); */
	__u64 csum;
	/* IP fields */
	ip->tot_len = bpf_htons(new_ip_len);
	ip->ttl = 64;
	ip->frag_off = 0;
	ip->check = 0;
	csum = 0;
	ipv4_csum_inline(ip, &csum);
	ip->check = bpf_htons(csum);

	/* UDP  fields */
	udp->len = bpf_htons(new_udp_len);
	udp->check = 0;

	/* csum = 0; */
	/* ipv4_l4_csum_inline(data_end, udp, ip, &csum); */
	/* udp->check = bpf_htons(csum); */
	return 0;
}
#endif
