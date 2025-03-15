#pragma once
#include "../common/stddef.h"
#include "../common/compiler.h"

#ifdef __BPF__
#define rand() bpf_get_prandom_u32()
#define assert(...)
#else
#include <stdlib.h> // rand
#endif

// unsigned fix point arithmetic

typedef uint32_t fp_t;
typedef uint64_t  __fp_d_t;

#define FIX_FRACTION_BITS 31
#define FP_SCALE (1LL << FIX_FRACTION_BITS)
#define FP_FRACTION_MASK ((FP_SCALE) - 1)
#define FP_MAX_FRACTION_VALUE ((double)(0.9999999997671694))
#define FP_ONE FP_SCALE

static __bpf_always_inline
fp_t fp_add(fp_t a, fp_t b)
{
	return a + b;
}

static __bpf_always_inline
fp_t fp_sub(fp_t a, fp_t b)
{
	return a - b;
}

static __bpf_always_inline
fp_t fp_mul(fp_t a, fp_t b)
{
	// Use 64-bit intermediate to prevent overflow
	fp_t product = ( __fp_d_t)a * ( __fp_d_t)b;
	// Scale back to the correct fixed-point format
	return (fp_t)(product >> FIX_FRACTION_BITS);
}

static __bpf_always_inline
fp_t fp_div(fp_t a, fp_t b)
{
	// Scale numerator to maintain precision
	__fp_d_t numerator = (__fp_d_t)a << FIX_FRACTION_BITS;

	// Perform division and return result
	return (fp_t)(numerator / b);
}

static __bpf_always_inline
fp_t fp_from_float(float val)
{
	// TODO: to be implemented
	assert(0);
	return -1;
}

static __bpf_always_inline
double fp_to_float(fp_t val)
{
	__fp_d_t tmp = (__fp_d_t)val;
	return (double)(tmp) / (double)FP_SCALE;
}

static __bpf_always_inline
fp_t fp_random(void)
{
	// get a uniform random number [0, 1)
	int32_t x = rand();
	x &= FP_FRACTION_MASK; // make sure the integer part is zero
	return x;
}
