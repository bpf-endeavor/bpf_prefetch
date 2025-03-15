#pragma once
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "csum_helper.h"

static __always_inline int __prepare_headers_before_send(struct xdp_md *xdp)
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
