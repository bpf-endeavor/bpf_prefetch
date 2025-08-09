/* This is a test program comparing the performance of normal XDP using 
 * a htab (Arena implementation) against a batch aware XDP doing prefetching.
 *
 * Then we investigate if have a batch of packets for different
 * programs/operations can reduce the effectiveness of batching since some of
 * the packets will wait an do no-op.
 * */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#define SERVER_PORT 8080

// common functions used in my experimetns for receiving and sending packets, ...
#include "honey/exp_proto.h"
#include "honey/report_throughput.h"
#include "arena-ds/htab.h"

// enable prefetch instruction (the kernel must support it)
#define PREFETCH
#include "honey/prefetching.h"

/* I need this dummy function to register arena with the XDP while not using
 * any sleepable function (it is from a kernel module that you have to load) */
long my_kfunc_reg_arena(void *p__map) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 100000); /* number of pages */
} arena SEC(".maps");

htab_t *map = NULL;

SEC("xdp")
int key_val_main(struct xdp_md *xdp)
{
    if (map == NULL) {
        bpf_printk("htab is not initialized");
        my_kfunc_reg_arena(&arena);
        return XDP_ABORTED;
    }

    struct udp_packet _upkt = {
        .data = (void *)(__u64)xdp->data,
        .data_end = (void *)(__u64)xdp->data_end,
    };
    struct udp_packet *upkt = &_upkt;

    char *payload;
    my_value_t __arena * val = NULL;
    my_key_t key;

    if(parse_headers(upkt->data, upkt->data_end, upkt) != 0)
        return XDP_PASS;

    payload = (char *)(upkt->udp + 1);
    if ((void *)(payload + sizeof(my_key_t)) > upkt->data_end) {
        bpf_printk("failed to get the key");
        return XDP_DROP;
    }

    *(int *)&key.data = *(int *)payload;
    val = htab_lookup_elem(map, &key);
    if (val == NULL) {
        bpf_printk("did not found the entry");
        return XDP_DROP;
    }

    // bpf_printk("reponse");
    update_udp_pkt_with_payload(xdp, upkt, (void *)val, sizeof(my_value_t));

    report_tput();

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";

/* vim: set et ts=4 sw=4: */
