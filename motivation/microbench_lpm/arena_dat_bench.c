// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Cloudflare */

/* Benchmarking Double Array Binary Trie implementation
 * Author: Farbod Shahinfar
 * Date: 18-Jan-2026
 * */

#define __BPF__ 1

// #include <vmlinux.h>
#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// #include "bpf_misc.h"

#define BPF_OBJ_NAME_LEN 16U
#define NR_LOOPS 100000


char _license[] SEC("license") = "GPL";

/* I need this dummy function to register arena with the XDP while not using
 * any sleepable function (it is from a kernel module that you have to load) */
long my_kfunc_reg_arena(void *p__map) __ksym;

#define ARENA_MAX_PAGES (1 << 20)
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, ARENA_MAX_PAGES); /* number of pages */
} arena SEC(".maps");

#include "dat.h"

arena_dat_t *dat = NULL;

long hits;
long duration_ns;

/* Configured from userspace */
__u32 nr_entries;
__u32 prefixlen;
__u8 op;

static uint32_t tmp =0 ;

static int lookup(__u32 index, __u32 *unused)
{
	__u32 key = bpf_get_prandom_u32() % nr_entries;

	/* NOTE: very important, since dut_lookup is not a helper function call
	 * unlike the original benchmark, the compiler will remove it if I do
	 * not use its return value ... */
	void __arena*v = dat_lookup(dat, (uint8_t *)&key, prefixlen);

	if (v == NULL) {
		/* bpf_printk("something is wrong with dat lookup: NULL (%d)", key); */
		tmp++;
		return 0;
	}

	/* uint32_t val = *(uint32_t __arena *)v; */
	/* if (val != key) { */
	/* 	bpf_printk("something is wrong with dat lookup: %d != %d", val, key); */
	/* 	return 0; */
	/* } */

	return 0;
}

/* static int update(__u32 index, __u32 *unused) */
/* { */
/* 	struct trie_key key; */
/* 	u32 val = bpf_get_prandom_u32(); */

/* 	gen_random_key(&key); */
/* 	bpf_map_update_elem(&trie_map, &key, &val, BPF_EXIST); */
/* 	return 0; */
/* } */

static __u32 deleted_entries;

// static int delete (__u32 index, bool *need_refill)
// {
// 	struct trie_key key = {
// 		.data = deleted_entries,
// 		.prefixlen = prefixlen,
// 	};
// 
// 	bpf_map_delete_elem(&trie_map, &key);
// 
// 	/* Do we need to refill the map? */
// 	if (++deleted_entries == nr_entries) {
// 		/*
// 		 * Atomicity isn't required because DELETE only supports
// 		 * one producer running concurrently. What we need is a
// 		 * way to track how many entries have been deleted from
// 		 * the trie between consecutive invocations of the BPF
// 		 * prog because a single bpf_loop() call might not
// 		 * delete all entries, e.g. when NR_LOOPS < nr_entries.
// 		 */
// 		deleted_entries = 0;
// 		*need_refill = true;
// 		return 1;
// 	}
// 
// 	return 0;
// }

SEC("xdp")
int BPF_PROG(run_bench)
{
	if (dat == NULL) {
		bpf_printk("the userspace program has not configured the arena-dat");
		my_kfunc_reg_arena(&arena);
		return -2;
	}
	bool need_refill = false;
	__u64 start, delta;
	int loops;

	start = bpf_ktime_get_ns();

	switch (op) {
	case 1:
		loops = bpf_loop(NR_LOOPS, lookup, NULL, 0);
		break;
	case 2:
		/* loops = bpf_loop(NR_LOOPS, update, NULL, 0); */
		break;
	case 3:
		/* loops = bpf_loop(NR_LOOPS, delete, &need_refill, 0); */
		break;
	default:
		bpf_printk("invalid benchmark operation\n");
		return -1;
	}

	delta = bpf_ktime_get_ns() - start;

	__sync_add_and_fetch(&duration_ns, delta);
	__sync_add_and_fetch(&hits, loops);

	return need_refill;
}

