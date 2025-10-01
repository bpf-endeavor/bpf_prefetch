#ifndef __PREFETCHING_H
#define __PREFETCHING_H

#ifndef barrier
# define barrier() __asm__ __volatile__("": : :"memory")
#endif

#ifdef PREFETCH /* Use this flag to enable prefetching at compile time */
/* Define the unofficial helper function
 * (You need the patch ot use this code)
 * */
static long (*bpf_prefetch)(const void * const ptr__ign) = (void *) 212;
static long (*bpf_prefetch_1)(const void * const ptr__ign) = (void *) 213;
static long (*bpf_prefetch_w)(const void * const ptr__ign) = (void *) 214;
#define P(x) bpf_prefetch(x)
#define P1(x) bpf_prefetch_1(x)
#define Pw(x) bpf_prefetch_w(x)
#else
#define P(x)
#define P1(x)
#define Pw(x)
#endif


#endif // __PREFETCHING_H
