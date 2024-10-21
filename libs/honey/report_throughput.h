#ifndef __REPORT_TPUT_H
#define __REPORT_TPUT_H
#include <bpf/bpf_helpers.h>
static __u64 counter = 0;
static __u64 last_report = 0;

static inline __attribute__((always_inline))
void report_tput(void)
{
	__u64 ts, delta;
	/* We must run on a single core */
	__sync_fetch_and_add(&counter, 1);
	ts = bpf_ktime_get_coarse_ns();
	if (last_report == 0) {
		last_report = ts;
		return;
	}

	delta = ts - last_report;
	if (delta >= 2000000000L) {
		__u64 t = (counter * 1000000) / delta;
		bpf_printk("throughput: %ld(kpps)", t, counter);
		counter = 0;
		last_report = ts;
	}
}
#endif
