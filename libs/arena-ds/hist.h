#pragma once
/*
 * A simple histogram accounting
 * author: Farbod Shahinfar
 * LICENSE: MIT
 * */

#include <errno.h>
#include "./common/compiler.h"
#include "./common/stddef.h"
#include "./common/arena_common.h"

#ifdef __BPF__
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#define assert(...)
#else
#include <assert.h>
#define bpf_printk(...)
#endif

#if (!defined(HIST_START_NUMBER) || !defined(HIST_NUM_BUCKETS) || !defined(HIST_BUCKET_WIDTH))
#error "HIST_START_NUMBER or HIST_NUM_BUCKETS or HIST_BUCKET_WIDTH is not defined!\n"
#endif

#define _HIST_UPPER_BOUND (HIST_START_NUMBER+(HIST_NUM_BUCKETS * HIST_BUCKET_WIDTH))
struct hist {
	unsigned long long buckets[HIST_NUM_BUCKETS + 1];
};

typedef struct hist __arena arena_hist_t;

static inline __attribute__((always_inline))
void hist_record(arena_hist_t *h, unsigned int val)
{
	if (val > _HIST_UPPER_BOUND || val < HIST_START_NUMBER) {
		/* outside of region */
		/* TODO: also report this ? */
		return;
	}

	cast_kern(h);
	unsigned int index = (val - HIST_START_NUMBER) / HIST_BUCKET_WIDTH;
	h->buckets[index]++;
}

static inline __attribute__((always_inline))
void hist_reset(arena_hist_t *h) {
	cast_kern(h);
	__builtin_memset(h, 0, sizeof(arena_hist_t));
}

#ifdef __BPF__
static inline __attribute__((always_inline))
void hist_report(arena_hist_t *h)
{
	cast_kern(h);
	for (int i = 0; i < HIST_NUM_BUCKETS; i++) {
		unsigned int bucket = HIST_START_NUMBER + i * HIST_BUCKET_WIDTH;
		bpf_printk("@bucket %d: %lld", bucket, h->buckets[i]);
	}
}
#else /* Userspace */
#include <stdio.h>
#include <string.h>
void hist_report(arena_hist_t *h)
{
	for (int i = 0; i < HIST_NUM_BUCKETS; i++) {
		unsigned int bucket = HIST_START_NUMBER + i * HIST_BUCKET_WIDTH;
		printf("@bucket %d: %lld\n", bucket, h->buckets[i]);
	}
}

typedef struct {
	void *area; /* pointer to the Arena memory region */
	uint32_t area_size;
	arena_hist_t **out; /* out: pointer to the allocated hist */
	uint32_t *allocated_area;
} arena_hist_alloc_t;

static int userspace_arena_hist_alloc(arena_hist_alloc_t *arg)
{
	if (arg->area == NULL)
		return -EINVAL;
	/* TODO: the area_size is not being passed in my tests */
	/* if (arg->area_size < sizeof(arena_hist_t)) */
	/* 	return -ENOMEM; */
	arena_hist_t *h = arg->area;
	memset(h, 0, sizeof(arena_hist_t));
	*arg->out = h;
	*arg->allocated_area = sizeof(arena_hist_t);
	return 0;
}
#endif

