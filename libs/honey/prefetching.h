#ifndef __PREFETCHING_H
#define __PREFETCHING_H

#ifdef PREFETCH /* Use this flag to enable prefetching at compile time */
/* Define the unofficial helper function
 * (You need the patch ot use this code)
 * */
static long (*bpf_prefetch)(void *ptr__ign) = (void *) 212;
#define P(x) bpf_prefetch(x)
#else
#define P(x)
#endif


#endif // __PREFETCHING_H
