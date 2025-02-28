#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "shared_struct.h"
#include "xdp_helpers.h"
#include "arena_lpm_dri.h"

long my_kfunc_reg_arena(void *p__map) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 100000); /* number of pages */
} arena SEC(".maps");

arena_lpm_dri_t *dri = NULL;

#define BATCH_SIZE 32
struct _value_batch {
    my_value_t vals[BATCH_SIZE];
} __packed;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,  __u32);
    __type(value, struct _value_batch);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

#define TAG "DRI router: "

SEC("xdp")
int dri_router_main(struct xdp_md *xdp)
{
    if (dri == NULL) {
        bpf_printk(TAG"can not see DRI data structure");
        my_kfunc_reg_arena(&arena);
        return XDP_PASS;
    }

    void *data = (void *)(__u64)(xdp->data);
    void *data_end = (void *)(__u64)(xdp->data_end);
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth+1);
    struct udphdr *udp = (void *)(ip + 1);
    req_t *r = (void *)(udp + 1);
    if ((void *)(r + 1) > data_end)
        return XDP_PASS;
    __u16 tmp_port = bpf_ntohs(udp->dest);
    if (!(tmp_port >= 8000 && tmp_port < 8128))
        return XDP_PASS;

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
        if ((void *)&r->reqs[i + 1] > data_end) {
            bpf_printk(TAG"requested id @%d out of packet range", i);
            return XDP_DROP;
        }
        lpm_dri_key_t k = {
            .prefixlen = 32,
            .data = r->reqs[i],
        };
        my_value_t __arena *v = arena_lpm_dri_lookup_elem(dri, &k);
        if (v == NULL) {
            bpf_printk(TAG"did not id=%x (@%d)!", k.data, i);
            return XDP_DROP;
        }
        /* TODO: can I avoid copying the data into the scratch ? */
        /* keep the data on the scratch */
        __builtin_memcpy(&scratch->vals[i], (void *)v, sizeof(my_value_t));
    }

    __u16 target_size = sizeof(my_value_t) * count_req;
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

    for (int i = 0; i < count_req; i++) {
        if ((void *)(payload + sizeof(my_value_t)) > data_end) {
            bpf_printk(TAG"not enough space after adjusting the packet size");
            return XDP_DROP;
        }

        __builtin_memcpy(payload, &scratch->vals[i], sizeof(my_value_t));
        payload += sizeof(my_value_t);
    }

    // send reply back to netcat!
    __prepare_headers_before_send(xdp);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
// vim: et ts=4 sw=4:
