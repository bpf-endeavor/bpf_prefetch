/* This program tries to use the Arena map from Mogu to reply to network
 * queries from XDP hook point
 * (Basically sharing Arena between two eBPF programs but one is XDP)
 * */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "stddef.h"
#include "compiler.h"
#include "csum_helper.h"

/* I need this dummy function to register arena with the XDP while not using
 * any sleepable function (it is from a kernel module that you have to load) */
long my_kfunc_reg_arena(void *p__map) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 100); /* number of pages */
} arena SEC(".maps");

#include "shared_struct.h"
/* The htab requires an Arena MAP named ``arena'' to be defined before */
#include "bpf_arena_htab.h"

htab_t *rules = NULL;

static inline int
__prepare_headers_before_send(struct xdp_md *xdp)
{
  struct ethhdr *eth = (void *)(__u64)xdp->data;
  struct iphdr *ip = (struct iphdr *)(eth + 1);
  struct udphdr *udp = (struct udphdr *)(ip + 1);
  if ((void *)(udp + 1) > (void *)(__u64)xdp->data_end)
    return -1;
  /* Swap MAC */
  __u8 tmp;
  for (int i = 0; i < 6; i++) {
    tmp = eth->h_source[i];
    eth->h_source[i] = eth->h_dest[i];
    eth->h_dest[i] = tmp;
  }
  /* Swap IP */
  __u32 tmp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp_ip;
  /* Swap port */
  __u16 tmp_port = udp->source;
  udp->source = udp->dest;
  udp->dest = tmp_port;

  const __u32 new_packet_len = ((__u64)xdp->data_end - (__u64)xdp->data);
  const __u32 new_ip_len  = new_packet_len - sizeof(struct ethhdr);
  const __u32 new_udp_len = new_ip_len - sizeof(struct iphdr);
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
  /* UDP checksum ? */
  /* udp->check = 0; */
  /* csum = 0; */
  /* ipv4_l4_csum_inline((void *)(__u64)xdp->data_end, udp, ip, */
  /*     &csum); */
  /* udp->check = bpf_ntohs(csum); */

  /* no checksum */
  udp->check = 0;
  /* bpf_printk("data: %s", (char *)(__u64)xdp->data + DATA_OFFSET); */
  return 0;
}

SEC("xdp")
int macchiato_main(struct xdp_md *xdp)
{
    bpf_printk("macchiato: hello world");

    if (rules == NULL) {
        /* just to make sure this program uses the arena */
        my_kfunc_reg_arena(&arena);
        bpf_printk("macchiato: not seeing the memory!");
        return XDP_PASS;
    }

    void *data = (void *)(__u64)(xdp->data);
    void *data_end = (void *)(__u64)(xdp->data_end);
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth+1);
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    __u16 tmp_port = bpf_ntohs(udp->dest);
    if (!(tmp_port >= 8000 && tmp_port < 8128))
        return XDP_PASS;

    bpf_printk("macchiato: about to do the lookup");
    my_key_t k = {
        .zero = 0,
        .dport = udp->dest,
    };
    my_value_t __arena *v = htab_lookup_elem(rules, &k);
    if (v == NULL) {
        bpf_printk("macchiato: did not found anything!");
        return XDP_PASS;
    }
    bpf_printk("macchiato: says %s (%p)", v->msg, v);
    for (int i = 0; i < 30; i++) {
        bpf_printk("%x", ((__u8 *)v)[i]);
    }
    /*return XDP_PASS;*/
    char tmp[32];
    my_memcpy(tmp, (void *)v, 30);

    char *payload = (char *)(udp + 1);
    const __u16 target_size = sizeof(my_value_t);
    {
        // check if we need to change the payload size to match our reply
        __u16 payload_len = (__u64)data_end - (__u64)payload;
        short delta = target_size - payload_len;
        if (delta != 0) {
            if (bpf_xdp_adjust_tail(xdp, delta) != 0) {
                bpf_printk("failed to resize the packet (%d)", delta);
                return XDP_PASS;
            }
            data = (void *)(__u64)xdp->data;
            data_end = (void *)(__u64)xdp->data_end;
            payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
        }
    }
    if ((void *)(payload + target_size) > data_end) {
        bpf_printk("Not enough space even after resizing. This must never happen!");
        return XDP_DROP;
    }
    __builtin_memcpy(payload, tmp, 31); // <------- 
    // send reply back to netcat!
    //
    bpf_printk("about to TX!");
    __prepare_headers_before_send(xdp);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
