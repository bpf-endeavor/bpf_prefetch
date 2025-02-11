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
#include "shared_struct.h"
#include "xdp_helpers.h"

#define TAG "cappucchino: "

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  my_key_t);
    __type(value, my_value_t);
    __uint(max_entries, 1 << 19);
} rules SEC(".maps");

SEC("xdp")
int cappuccino_main(struct xdp_md *xdp)
{
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

    my_key_t k = { .zero = 0, .dport = udp->dest, };
    my_value_t *v = bpf_map_lookup_elem(&rules, &k);
    if (v == NULL) {
        bpf_printk(TAG"did not found anything!");
        return XDP_PASS;
    }

    char *payload = (char *)(udp + 1);
    const __u16 target_size = sizeof(my_value_t);
    {
        // check if we need to change the payload size to match our reply
        __u16 payload_len = (__u64)data_end - (__u64)payload;
        short delta = target_size - payload_len;
        if (delta != 0) {
            if (bpf_xdp_adjust_tail(xdp, delta) != 0) {
                bpf_printk(TAG"failed to resize the packet (%d)", delta);
                return XDP_PASS;
            }
            data = (void *)(__u64)xdp->data;
            data_end = (void *)(__u64)xdp->data_end;
            payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
        }
    }
    if ((void *)(payload + target_size) > data_end) {
        bpf_printk(TAG"Not enough space even after resizing. This must never happen!");
        return XDP_DROP;
    }
    __builtin_memcpy(payload, (void *)v, target_size);
    // send reply back to netcat!
    __prepare_headers_before_send(xdp);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
