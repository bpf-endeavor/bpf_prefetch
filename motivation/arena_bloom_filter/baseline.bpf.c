// vim: et ts=4 sw=4:
/* This is the baseline program, using the BPF_MAP_TYPE_HASH for implementing a
 * key-value store
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
#include "shared_struct.h"
#include "xdp_helpers.h"

#define TAG "baseline: "

#define BATCH_SIZE 32

enum {
    MAY_PRESENT,
    NOT_PRESENT,
};

struct _value_batch {
    __u8 vals[BATCH_SIZE]; // was present in bloom filter or not?
} __packed;

struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __type(value, my_value_t);
    __uint(max_entries, 2000000);
    __uint(map_extra, 5); // default is 5 hash functions
} bloom_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,  __u32);
    __type(value, struct _value_batch);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

SEC("xdp")
int baseline_main(struct xdp_md *xdp)
{
    void *data = (void *)(__u64)(xdp->data);
    void *data_end = (void *)(__u64)(xdp->data_end);
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth+1);
    struct udphdr *udp = (void *)(ip + 1);
    req_t *r = (void *)(udp + 1);
    if ((void *)(r + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 tmp_port = bpf_ntohs(udp->dest);
    if (!(tmp_port >= 8000 && tmp_port < 8128)) {
        return XDP_PASS;
    }

    __u16 count_req = r->count_req;
    if (count_req > BATCH_SIZE) {
        bpf_printk(TAG"To many requested keys");
        return XDP_DROP;
    }

    int zero = 0;
    struct _value_batch *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (scratch == NULL) {
        bpf_printk(TAG"faild to get scratch memory");
        return XDP_DROP;
    }

    for (int i = 0; i < count_req; i++) {
        my_value_t k;
        my_value_t *kptr = &r->reqs[i];
        if ((void *)(kptr + 1) > data_end) {
            bpf_printk(TAG"requested id @%d out of packet range", i);
            return XDP_DROP;
        }
        __builtin_memcpy(&k, kptr->data, sizeof(my_value_t));
        long flag = bpf_map_peek_elem(&bloom_filter, &k);
        scratch->vals[i] = flag == 0 ? MAY_PRESENT : NOT_PRESENT;
        /* bpf_printk(TAG"%d: %d", k.data[0], flag); */
    }

    __u16 target_size = sizeof(resp_t) * count_req;
    char *payload = (char *)(udp + 1);
    {
        // check if we need to change the payload size to match our reply
        __u16 payload_len = (__u64)data_end - (__u64)payload;
        short delta = target_size - payload_len;
        if (delta != 0) {
            if (bpf_xdp_adjust_tail(xdp, delta) != 0) {
                bpf_printk(TAG"failed to resize the packet (%d)", delta);
                return XDP_DROP;
            }
            data = (void *)(__u64)xdp->data;
            data_end = (void *)(__u64)xdp->data_end;
            payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
        }
    }

    for (int i = 0; i < count_req; i++) {
        if ((void *)(payload + sizeof(resp_t)) > data_end) {
            bpf_printk(TAG"not enough space after adjusting the packet size");
            return XDP_DROP;
        }
        if (scratch->vals[i] == NOT_PRESENT) {
            __builtin_memcpy(payload, "NOT_P\n", 6);
        } else {
            __builtin_memcpy(payload, "MAY_P\n", 6);
        }
        payload += sizeof(resp_t);
    }

    // send reply back to netcat!
    __prepare_headers_before_send(xdp);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
