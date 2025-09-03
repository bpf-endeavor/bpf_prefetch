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

// enable prefetch instruction (the kernel must support it)
#define PREFETCH 1
#include "honey/prefetching.h"

// common functions used in my experimetns for receiving and sending packets, ...
#include "honey/exp_proto.h"
#include "honey/report_throughput.h"
#include "arena-ds/htab.h"

/* I need this dummy function to register arena with the XDP while not using
 * any sleepable function (it is from a kernel module that you have to load) */
long my_kfunc_reg_arena(void *p__map) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 200000); /* number of pages */
} arena SEC(".maps");

htab_t *map = NULL;


typedef struct {
    int phase;
    /* struct udp_packet upkt; */
    my_key_t key;
    struct partial_lookup_state plookup;
} batch_state_t;

typedef struct {
    batch_state_t pkt[XDP_MAX_BATCH_SIZE];
} batch_state_wrapper_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, batch_state_wrapper_t);
    __uint(max_entries, 1);
} batch_state_map SEC(".maps");

/* A normal XDP program returning responses from a hash-map
 * */
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

#define ACTION(act, index) batch->actions[index] = act
#define PASS(k) ACTION(XDP_PASS, k)
#define DROP(k) ACTION(XDP_DROP, k)
#define TX(k)   ACTION(XDP_TX, k)

static inline __attribute__((always_inline))
int fib(int n)
{
    if (n < 0) return 0;
    if (n == 0 || n == 1) return 1;

    int a, b, c;
    a = b = c = 1;
    for (int i = 2; i < 10 && i < n; i++) {
        c = a + b;
        a = b;
        b = c;
    }
    return b;
}

/* A batch-aware XDP program returning responses from a hash-map
 * */
SEC("xdp")
int bbb_key_val_main(struct xdp_batch_md *batch)
{
    if (map == NULL) {
        bpf_printk("htab is not initialized");
        my_kfunc_reg_arena(&arena);
        return XDP_ABORTED;
    }

    __u32 pkt_cntr = 0;

    int zero = 0;
    batch_state_wrapper_t *bs;
    bs = bpf_map_lookup_elem(&batch_state_map, &zero);
    if (bs == NULL) {
        bpf_printk("batch state not found! unexpected");
        return XDP_ABORTED;
    }

// #pragma clang loop unroll(full)
    for (int k = 0; k < XDP_MAX_BATCH_SIZE; k++) {
        if (k >= batch->size) {
            break;
        }

        bs->pkt[k].phase = 0;

        struct xdp_md *xdp = &batch->buffs[k];
        /* struct udp_packet *upkt = &bs->pkt[k].upkt; */
        struct udp_packet _upkt;
        struct udp_packet *upkt = &_upkt;
        upkt->data = (void *)(__u64)xdp->data;
        upkt->data_end = (void *)(__u64)xdp->data_end;

        char *payload;

        if(parse_headers(upkt->data, upkt->data_end, upkt) != 0) {
            PASS(k);
            continue;
        }

        payload = (char *)(upkt->udp + 1);
        if ((void *)(payload + sizeof(my_key_t)) > upkt->data_end) {
            bpf_printk("failed to get the key");
            DROP(k);
            continue;
        }

        my_key_t *key = &bs->pkt[k].key;
        *(int *)&key->data = *(int *)payload;
        my_value_t __arena * val = NULL;

        // This will prefetch the pointer to the bucket
        val = htab_lookup_elem(map, key);
        if (val == NULL) {
            bpf_printk("did not found the entry");
            DROP(k);
            continue;
        }

        /* bpf_printk("reponse"); */
        update_udp_pkt_with_payload(xdp, upkt, (void *)val, sizeof(my_value_t));
        TX(k);

        pkt_cntr++;
    }

    report_tput_batch(pkt_cntr);

    return 0;
}

/* A batch-aware XDP program that uses prefetch instructions when accessing
 * hash-map for responding to requests
 * */
SEC("xdp")
int bbb_pf_key_val_main(struct xdp_batch_md *batch)
{
    if (map == NULL) {
        bpf_printk("htab is not initialized");
        my_kfunc_reg_arena(&arena);
        return XDP_ABORTED;
    }

    __u32 pkt_cntr = 0;

    int zero = 0;
    batch_state_wrapper_t *bs;
    bs = bpf_map_lookup_elem(&batch_state_map, &zero);
    if (bs == NULL) {
        bpf_printk("batch state not found! unexpected");
        return XDP_ABORTED;
    }

// #pragma clang loop unroll(full)
    for (int k = 0; k < XDP_MAX_BATCH_SIZE; k++) {
        if (k >= batch->size) {
            break;
        }

        bs->pkt[k].phase = 0;

        struct xdp_md *xdp = &batch->buffs[k];
        /* struct udp_packet *upkt = &bs->pkt[k].upkt; */
        struct udp_packet _upkt;
        struct udp_packet *upkt = &_upkt;
        upkt->data = (void *)(__u64)xdp->data;
        upkt->data_end = (void *)(__u64)xdp->data_end;

        char *payload;

        if(parse_headers(upkt->data, upkt->data_end, upkt) != 0) {
            PASS(k);
            continue;
        }

        payload = (char *)(upkt->udp + 1);
        if ((void *)(payload + sizeof(my_key_t)) > upkt->data_end) {
            bpf_printk("failed to get the key");
            DROP(k);
            continue;
        }

        my_key_t *key = &bs->pkt[k].key;
        *(int *)&key->data = *(int *)payload;

        // This will prefetch the pointer to the bucket
        htab_lookup_elem_p1(map, key, &bs->pkt[k].plookup);
        bs->pkt[k].phase = 1;
    }

    /* if (fib(batch->size) == 4) { */
    /*     bpf_printk("what"); */
    /* } */

    // this will prefetch the first item in the bucket
#pragma clang unroll loop(full)
    for (int k = 0; k < XDP_MAX_BATCH_SIZE; k++) {
        if (k >= batch->size) {
            break;
        }
        P(*(void **)bs->pkt[k].plookup.head);
    }

    /* if (fib(batch->size) == 4) { */
    /*     bpf_printk("what"); */
    /* } */


// #pragma clang loop unroll(full)
    for (int k = 0; k < XDP_MAX_BATCH_SIZE; k++) {
        if (k >= batch->size)
            break;

        if (bs->pkt[k].phase != 1)
            continue;

        struct xdp_md *xdp = &batch->buffs[k];
        /* struct udp_packet *upkt = &bs->pkt[k].upkt; */
  
        my_key_t *key = &bs->pkt[k].key;

        my_value_t __arena * val = NULL;
        val = htab_lookup_elem_p2(map, key, &bs->pkt[k].plookup);
        if (val == NULL) {
            bpf_printk("did not found the entry");
            DROP(k);
            continue;
        }

        /* TODO: fix the design so that I do not need to re-calculate pointers
         * */
        struct udp_packet _upkt;
        struct udp_packet *upkt = &_upkt;
        upkt->data = (void *)(__u64)xdp->data;
        upkt->data_end = (void *)(__u64)xdp->data_end;
        upkt->eth = upkt->data;
        upkt->ip = upkt->eth + 1;
        upkt->udp = upkt->ip + 1;
        if (upkt->udp + 1 > upkt->data_end)
            return XDP_ABORTED; // never happens

        /* bpf_printk("reponse"); */
        update_udp_pkt_with_payload(xdp, upkt, (void *)val, sizeof(my_value_t));
        TX(k);

        pkt_cntr++;
    }

    report_tput_batch(pkt_cntr);

    return 0;
}

char _license[] SEC("license") = "GPL";

/* vim: set et ts=4 sw=4: */
