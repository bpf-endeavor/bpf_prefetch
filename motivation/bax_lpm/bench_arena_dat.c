// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Cloudflare */

/* Benchmarking Double Array Binary Trie implementation
 * Author: Farbod Shahinfar
 * Date: 18-Jan-2026
 * */


#include <argp.h>
#include <linux/if_ether.h>
#include "bench.h"
#include "dat.h"
#include "arena_dat_bench.skel.h"

#define MAX_ENTRIES (100L * 1000L * 1000L + 1)

/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC	1000L
#define USEC_PER_MSEC	1000L
#define NSEC_PER_USEC	1000L
#define NSEC_PER_MSEC	1000000L
#define USEC_PER_SEC	1000000L
#define NSEC_PER_SEC	1000000000L
#define PSEC_PER_SEC	1000000000000LL
#define FSEC_PER_SEC	1000000000000000LL

#define __always_unused __attribute__((__unused__))

static struct ctx {
	struct arena_dat_bench *bench;
} ctx;

static struct {
	__u32 nr_entries;
	__u32 prefixlen;
} args = {
	.nr_entries = 10000,
	.prefixlen = 32,
};

enum {
	ARG_NR_ENTRIES = 9000,
	ARG_PREFIX_LEN,
};

static const struct argp_option opts[] = {
	{ "nr_entries", ARG_NR_ENTRIES, "NR_ENTRIES", 0,
	  "Number of unique entries in the LPM trie" },
	{ "prefix_len", ARG_PREFIX_LEN, "PREFIX_LEN", 0,
	  "Number of prefix bits to use in the LPM trie" },
	{},
};

static error_t lpm_parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;

	switch (key) {
	case ARG_NR_ENTRIES:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > UINT_MAX) {
			fprintf(stderr, "Invalid nr_entries count.");
			argp_usage(state);
		}
		args.nr_entries = ret;
		break;
	case ARG_PREFIX_LEN:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > UINT_MAX) {
			fprintf(stderr, "Invalid prefix_len value.");
			argp_usage(state);
		}
		args.prefixlen = ret;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

const struct argp bench_arena_dat_argp = {
	.options = opts,
	.parser = lpm_parse_arg,
};

static void __lpm_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark doesn't support consumer!\n");
		exit(1);
	}

	if ((1UL << args.prefixlen) < args.nr_entries) {
		fprintf(stderr, "prefix_len value too small for nr_entries!\n");
		exit(1);
	};
}

enum { OP_LOOKUP = 1, OP_UPDATE, OP_DELETE, OP_FREE };

static void lpm_delete_validate(void)
{
	__lpm_validate();

	if (env.producer_cnt != 1) {
		fprintf(stderr,
			"lpm-trie-delete requires a single producer!\n");
		exit(1);
	}
}

static void lpm_free_validate(void)
{
	__lpm_validate();

	if (env.producer_cnt != 1) {
		fprintf(stderr, "lpm-trie-free requires a single producer!\n");
		exit(1);
	}
}

struct trie_key {
	__u32 prefixlen;
	__u32 data;
};

static struct trie_key *keys;
static __u32 *vals;

static void fill_map(arena_dat_t *dat)
{
	if (dat == NULL) {
		printf("BUG, calling fill map with NULL pointer to DAT\n");
		exit(1);
	}

	int err;
	for (size_t i = 0; i < args.nr_entries; i++) {
		err = dat_insert(dat, (uint8_t *)&keys[i].data,
				args.prefixlen, (uint8_t *)&vals[i]);
		if (err != 0) {
			fprintf(stderr, "failed to insert key %lu (err: %d)\n",
					i, err);
			exit(1);
		}
	}
}

static void __lpm_setup(void)
{
	int i;

	/* TODO: load benchmark program */
	ctx.bench = arena_dat_bench__open_and_load();
	if (!ctx.bench) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	ctx.bench->bss->nr_entries = args.nr_entries;
	ctx.bench->bss->prefixlen = args.prefixlen;

	if (arena_dat_bench__attach(ctx.bench)) {
		fprintf(stderr, "failed to attach skeleton\n");
		exit(1);
	}

	keys = calloc(args.nr_entries, sizeof(*keys));
	vals = calloc(args.nr_entries, sizeof(*vals));

	for (i = 0; i < args.nr_entries; i++) {
		struct trie_key *k = &keys[i];
		__u32 *v = &vals[i];

		k->prefixlen = args.prefixlen;
		k->data = i;
		*v = 1;
	}
}

static void lpm_setup(void)
{
	int err;

	__lpm_setup();

	uint32_t allocated_area = 0;
	size_t area_size = 0;
	void *area = NULL;
	arena_dat_t *dat = NULL;
	area = bpf_map__initial_value(ctx.bench->maps.arena, &area_size);
	arena_dat_alloc_t arg = {
		.area = area,
		.area_size = area_size,
		.max_entries = MAX_ENTRIES,
		.out = &dat,
		.allocated_area =  &allocated_area,
	};
	err = userspace_arena_dat_alloc(&arg);
	if (err != 0 || dat == NULL) {
		fprintf(stderr, "Failed to initialize arena & dat!\n");
		exit(1);
	}
	fill_map(dat);
	ctx.bench->bss->dat = dat;
}

static void lpm_lookup_setup(void)
{
	lpm_setup();

	ctx.bench->bss->op = OP_LOOKUP;
}

/* static void lpm_update_setup(void) */
/* { */
/* 	lpm_setup(); */

/* 	ctx.bench->bss->op = OP_UPDATE; */
/* } */

/* static void lpm_delete_setup(void) */
/* { */
/* 	lpm_setup(); */

/* 	ctx.bench->bss->op = OP_DELETE; */
/* } */

/* static void lpm_free_setup(void) */
/* { */
/* 	__lpm_setup(); */
/* 	ctx.bench->bss->op = OP_FREE; */
/* } */

static void lpm_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.bench->bss->hits, 0);
	res->duration_ns = atomic_swap(&ctx.bench->bss->duration_ns, 0);
}

/* For LOOKUP, UPDATE, and DELETE */
static void *lpm_producer(void *unused __always_unused)
{
	int err;
	char in[ETH_HLEN]; /* unused */

	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = in,
		    .data_size_in = sizeof(in), .repeat = 1, );

	while (true) {
		int fd = bpf_program__fd(ctx.bench->progs.run_bench);
		err = bpf_prog_test_run_opts(fd, &opts);
		if (err) {
			fprintf(stderr, "failed to run BPF prog: %d\n", err);
			exit(1);
		}

		if (opts.retval < 0) {
			fprintf(stderr, "BPF prog returned error: %d\n",
				opts.retval);
			exit(1);
		}

		if (ctx.bench->bss->op == OP_DELETE && opts.retval == 1) {
			/* trie_map needs to be refilled */
			arena_dat_t *dat = ctx.bench->bss->dat;
			fill_map(dat);
		}
	}

	return NULL;
}

/* static void *lpm_free_producer(void *unused __always_unused) */
/* { */
/* 	while (true) { */
/* 		struct lpm_trie_map *skel; */

/* 		skel = lpm_trie_map__open_and_load(); */
/* 		if (!skel) { */
/* 			fprintf(stderr, "failed to open skeleton\n"); */
/* 			exit(1); */
/* 		} */

/* 		fill_map(bpf_map__fd(skel->maps.trie_free_map)); */
/* 		lpm_trie_map__destroy(skel); */
/* 	} */

/* 	return NULL; */
/* } */

/* static void free_ops_report_progress(int iter, struct bench_res *res, */
/* 				     long delta_ns) */
/* { */
/* 	double hits_per_sec, hits_per_prod; */
/* 	double rate_divisor = 1000.0; */
/* 	char rate = 'K'; */

/* 	hits_per_sec = res->hits / (res->duration_ns / (double)NSEC_PER_SEC) / */
/* 		       rate_divisor; */
/* 	hits_per_prod = hits_per_sec / env.producer_cnt; */

/* 	printf("Iter %3d (%7.3lfus): ", iter, */
/* 	       (delta_ns - NSEC_PER_SEC) / 1000.0); */
/* 	printf("hits %8.3lf%c/s (%7.3lf%c/prod)\n", hits_per_sec, rate, */
/* 	       hits_per_prod, rate); */
/* } */

/* static void free_ops_report_final(struct bench_res res[], int res_cnt) */
/* { */
/* 	double hits_mean = 0.0, hits_stddev = 0.0; */
/* 	double lat_divisor = 1000000.0; */
/* 	double rate_divisor = 1000.0; */
/* 	const char *unit = "ms"; */
/* 	double latency = 0.0; */
/* 	char rate = 'K'; */
/* 	int i; */

/* 	for (i = 0; i < res_cnt; i++) { */
/* 		double val = res[i].hits / rate_divisor / */
/* 			     (res[i].duration_ns / (double)NSEC_PER_SEC); */
/* 		hits_mean += val / (0.0 + res_cnt); */
/* 		latency += res[i].duration_ns / res[i].hits / (0.0 + res_cnt); */
/* 	} */

/* 	if (res_cnt > 1) { */
/* 		for (i = 0; i < res_cnt; i++) { */
/* 			double val = */
/* 				res[i].hits / rate_divisor / */
/* 				(res[i].duration_ns / (double)NSEC_PER_SEC); */
/* 			hits_stddev += (hits_mean - val) * (hits_mean - val) / */
/* 				       (res_cnt - 1.0); */
/* 		} */

/* 		hits_stddev = sqrt(hits_stddev); */
/* 	} */
/* 	printf("Summary: throughput %8.3lf \u00B1 %5.3lf %c ops/s (%7.3lf%c ops/prod), ", */
/* 	       hits_mean, hits_stddev, rate, hits_mean / env.producer_cnt, */
/* 	       rate); */
/* 	printf("latency %8.3lf %s/op\n", */
/* 	       latency / lat_divisor / env.producer_cnt, unit); */
/* } */

const struct bench bench_dat_lookup = {
	.name = "arena-dat-lookup",
	.argp = &bench_arena_dat_argp,
	.validate = __lpm_validate,
	.setup = lpm_lookup_setup,
	.producer_thread = lpm_producer,
	.measure = lpm_measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};

/* const struct bench bench_lpm_trie_update = { */
/* 	.name = "lpm-trie-update", */
/* 	.argp = &bench_lpm_trie_map_argp, */
/* 	.validate = __lpm_validate, */
/* 	.setup = lpm_update_setup, */
/* 	.producer_thread = lpm_producer, */
/* 	.measure = lpm_measure, */
/* 	.report_progress = ops_report_progress, */
/* 	.report_final = ops_report_final, */
/* }; */

/* const struct bench bench_lpm_trie_delete = { */
/* 	.name = "lpm-trie-delete", */
/* 	.argp = &bench_lpm_trie_map_argp, */
/* 	.validate = lpm_delete_validate, */
/* 	.setup = lpm_delete_setup, */
/* 	.producer_thread = lpm_producer, */
/* 	.measure = lpm_measure, */
/* 	.report_progress = ops_report_progress, */
/* 	.report_final = ops_report_final, */
/* }; */

/* const struct bench bench_lpm_trie_free = { */
/* 	.name = "lpm-trie-free", */
/* 	.argp = &bench_lpm_trie_map_argp, */
/* 	.validate = lpm_free_validate, */
/* 	.setup = lpm_free_setup, */
/* 	.producer_thread = lpm_free_producer, */
/* 	.measure = lpm_measure, */
/* 	.report_progress = free_ops_report_progress, */
/* 	.report_final = free_ops_report_final, */
/* }; */

