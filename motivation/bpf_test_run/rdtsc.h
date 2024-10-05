#ifndef RDTSC_H
#define RDTSC_H
#include <sys/types.h>
#include <x86intrin.h>
static inline
time_t read_tsc(void) {
	_mm_lfence();  // optionally wait for earlier insns to retire before reading the clock
	time_t tsc = __rdtsc();
	_mm_lfence();  // optionally block later instructions until rdtsc retires
	return tsc;
}
#endif
