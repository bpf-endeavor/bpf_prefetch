/* Log the packet processing rate of XDP program every second
 * @author Farbod Shahinfar
 * @date Nov 2024
 * */
#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef TAG
#define TAG
#endif

static __u64 counter = 0;
static __u64 last_report = 0;
static inline __attribute__((always_inline))
int report_tput(void)
{
	__u64 ts, delta;
	/* We must run on a single core */
	__sync_fetch_and_add(&counter, 1);
	ts = bpf_ktime_get_coarse_ns();
	if (last_report == 0) {
		last_report = ts;
		return 0;
	}
	delta = ts - last_report;
	if (delta >= 1000000000L) {
		bpf_printk(TAG"throughput: %ld (pps)", counter);
		counter = 0;
		last_report = ts;
		return 1;
	}
	return 0;
}

