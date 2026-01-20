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

#define ARENA_MAX_PAGES (1 << 20)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, ARENA_MAX_PAGES); /* number of pages */
} arena SEC(".maps");

/* I need this dummy function to register arena with the XDP while not using
 * any sleepable function (it is from a kernel module that you have to load) */
long my_kfunc_reg_arena(void *p__map) __ksym;

#include "include/dat.h"

#define TAG "DAT baseline: "

arena_dat_t *dat = NULL;

SEC("xdp")
int dat_test_main(struct xdp_md *xdp)
{
    if (dat == NULL) {
        bpf_printk("something is wrong! arena was not initialized");
        my_kfunc_reg_arena(&arena);
        return XDP_PASS;
    }

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

    __u8 *tmp = (void *)r;
    my_value_t __arena *v = dat_lookup(dat, tmp, 32 /* key size bits*/);
    if (v == NULL) {
        bpf_printk(TAG"did not found! ip=%d.%d.%d.%d!", tmp[0], tmp[1], tmp[2], tmp[3]);
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

    __builtin_memcpy(payload, (void *)v, sizeof(my_value_t));
    payload += sizeof(my_value_t);

    // send reply back to netcat!
    __prepare_headers_before_send(xdp);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
