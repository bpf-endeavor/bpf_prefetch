/* This program uses prefetching to improve the performance
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

#include "shared_struct.h"
/* The htab requires an Arena MAP named ``arena'' to be defined before */
#include "bpf_arena_htab.h"

#include "xdp_helpers.h"

htab_t *rules = NULL;

#define BATCH_SIZE 32
struct _value_batch {
    my_key_t keys[BATCH_SIZE];
    my_value_t vals[BATCH_SIZE];
} __packed;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,  __u32);
    __type(value, struct _value_batch);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

#define TAG "talkh: "

SEC("xdp")
int bbb_talkh_main(struct xdp_batch_md *batch)
{
    bpf_printk("here");
    if (rules == NULL) {
        /* just to make sure this program uses the arena */
        my_kfunc_reg_arena(&arena);
        bpf_printk(TAG"not seeing the memory!");
        return XDP_PASS;
    }

    for (int k = 0; k < XDP_MAX_BATCH_SIZE; k++) {
        if (k >= batch->size)
            break;

        struct xdp_md *xdp = &batch->buffs[k];
        void *data = (void *)(__u64)(xdp->data);
        void *data_end = (void *)(__u64)(xdp->data_end);
        struct ethhdr *eth = data;
        struct iphdr *ip = (void *)(eth+1);
        struct udphdr *udp = (void *)(ip + 1);
        req_t *r = (void *)(udp + 1);

        if ((void *)(r + 1) > data_end)
            goto xdp_pass;

        __u16 tmp_port = bpf_ntohs(udp->dest);
        if (!(tmp_port >= 8000 && tmp_port < 8128))
            goto xdp_pass;

        __u16 count_req = r->count_req;
        if (count_req > BATCH_SIZE) {
            bpf_printk(TAG"To many requested keys");
            goto xdp_drop;
        }

        int zero = 0;
        struct _value_batch *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
        if (scratch == NULL) {
            bpf_printk(TAG"faild to get scratch memory");
            goto xdp_drop;
        }

        void *tmp[BATCH_SIZE] = {};
        arena_list_head_t *head = NULL;
        hashtab_elem_t *el = NULL;
        cast_kern(rules);
        /* Stage one, find the bucket and prefetch the bucket */
        for (int i = 0; i < count_req && i < BATCH_SIZE; i++) {
            if ((void *)&r->reqs[i + 1] > data_end) {
                bpf_printk(TAG"requested id @%d out of packet range", i);
                goto xdp_drop;
            }
            scratch->keys[i].dport = r->reqs[i];
            int hash = htab_hash(&scratch->keys[i] , sizeof(my_key_t));
            head = select_bucket(rules, hash);
            cast_kern(head);
            tmp[i] = (void *)head;
            P(tmp[i]);
        }

        for (int i = 0; i < count_req && i < BATCH_SIZE; i++) {
            head = (arena_list_head_t *)tmp[i];
            el = arena_container_of(head->first, hashtab_elem_t, hash_node);
            cast_kern(el);
            tmp[i] = (void *)el;
            P(tmp[i]);
        }

        /* Stage two, fetch the data from the bucket */
        for (int i = 0; i < count_req; i++) {
            el = (hashtab_elem_t *)tmp[i];
            if (el == NULL) {
                bpf_printk(TAG"did not id=%d (@%d)!", scratch->keys[i].dport, i);
                goto xdp_drop;
            }
            my_value_t __arena *v = EXTRACT_VAL(rules, el);
            cast_kern(v);
            /* TODO: can I avoid copying the data into the scratch ? */
            /* keep the data on the scratch */
            /* NOTE: for some reason I have to cast `v' to void*, and I don't know
             * why */
            __builtin_memcpy(&scratch->vals[i], (void *)v, sizeof(my_value_t));

            // for making sure the responses are correct
            /* bpf_printk("- %d: %s", scratch->keys[i], scratch->vals[i].msg); */
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
                    goto xdp_drop;
                }
                data = (void *)(__u64)xdp->data;
                data_end = (void *)(__u64)xdp->data_end;
                payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
            }
        }

        for (int i = 0; i < count_req; i++) {
            if ((void *)(payload + sizeof(my_value_t)) > data_end) {
                bpf_printk(TAG"not enough space after adjusting the packet size");
                goto xdp_drop;
            }

            __builtin_memcpy(payload, &scratch->vals[i], sizeof(my_value_t));
            payload += sizeof(my_value_t);
            /* prefetch the memory area for next response */
        }

        /* send reply back to netcat! */
        __prepare_headers_before_send(xdp);
        batch->actions[k] = XDP_TX;
        continue;

xdp_pass:
        bpf_printk("pass");
        batch->actions[k] = XDP_PASS;
        continue;
xdp_drop:
        bpf_printk("drop");
        batch->actions[k] = XDP_DROP;
        continue;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

/* vim: set et ts=4 sw=4: */
