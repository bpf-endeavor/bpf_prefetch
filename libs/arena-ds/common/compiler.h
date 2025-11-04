#pragma once

/* Some macros and compiler directives
 * */

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif

#ifdef __BPF__
#define __bpf_always_inline __always_inline
#else
#define __bpf_always_inline
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

# define __nobuiltin(X)      __attribute__((no_builtin(X)))

#ifndef NULL
#define NULL ((void *)(0))
#endif
