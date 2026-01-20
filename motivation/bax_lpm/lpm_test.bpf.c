// vim: et ts=4 sw=4:
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "include/shared_struct.h"
#include "include/xdp_helpers.h"

#define TAG "LPM baseline: "
#define BATCH_SIZE 32

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, my_key_t);
    __type(value, my_value_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_ENTRIES);
} ipv4_lpm_map SEC(".maps");

SEC("xdp")
int lpm_test_main(struct xdp_md *xdp)
{
    void *data = (void *)(__u64)(xdp->data);
    void *data_end = (void *)(__u64)(xdp->data_end);
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth+1);
    struct udphdr *udp = (void *)(ip + 1);
    /* query is inside the UDP payload */
    __u32 *r = (__u32 *)(udp + 1);
    if ((void *)(r + 1) > data_end)
        return XDP_PASS;
    __u16 tmp_port = bpf_ntohs(udp->dest);
    if (!(tmp_port >= 8000 && tmp_port < 8128))
        return XDP_PASS;

    my_key_t k = {
        .prefixlen = 32,
        .data = *r,
    };
    my_value_t *v = bpf_map_lookup_elem(&ipv4_lpm_map, &k);
    if (v == NULL) {
        bpf_printk(TAG"did not found! id=%d!", k.data);
        return XDP_DROP;
    }

    __u16 target_size = sizeof(my_value_t);
    char *payload = (char *)(udp + 1);
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

    if ((void *)(payload + sizeof(my_value_t)) > data_end) {
        bpf_printk(TAG"not enough space after adjusting the packet size");
        return XDP_DROP;
    }

    __builtin_memcpy(payload, v, sizeof(my_value_t));
    payload += sizeof(my_value_t);

    // send reply back to netcat!
    __prepare_headers_before_send(xdp);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
