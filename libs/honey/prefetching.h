#ifndef __PREFETCHING_H
#define __PREFETCHING_H

#ifdef PREFETCH /* Use this flag to enable prefetching at compile time */
/* Define the unofficial helper function
 * (You need the patch ot use this code)
 * */
static long (*bpf_prefetch)(void *ptr__ign) = (void *) 212;
static long (*bpf_prefetch_1)(void *ptr__ign) = (void *) 213;
#define P(x) bpf_prefetch(x)
#define P1(x) bpf_prefetch_1(x)
#else
#define P(x)
#define P1(x)
#endif


#endif // __PREFETCHING_H
