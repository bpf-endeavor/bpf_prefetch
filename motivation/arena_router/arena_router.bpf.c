/* This program uses the Arena to implement a hashtable
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

/* I need this dummy function to register arena with the XDP while not using
 * any sleepable function (it is from a kernel module that you have to load) */
long my_kfunc_reg_arena(void *p__map) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 100000); /* number of pages */
} arena SEC(".maps");

#include "shared_struct.h"
#include "xdp_helpers.h"

/* htab_t *rules = NULL; */

struct _value_batch {
    my_value_t vals[32];
} __packed;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,  __u32);
    __type(value, struct _value_batch);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

#define TAG "macchiato: "

SEC("xdp")
int arena_router_main(struct xdp_md *xdp)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
