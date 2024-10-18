#ifndef __COMMON_H
#define __COMMON_H
#define XDP 1
/* #define SK_SKB 1 */

#ifdef XDP
#define CONTEXT struct xdp_md
#define ABORTED XDP_ABORTED
#define PASS XDP_PASS
#define DROP XDP_DROP
#else
#define CONTEXT struct __sk_buff
#define ABORTED SK_DROP
#define PASS SK_PASS
#define DROP SK_DROP
#endif

/* #define DEBUG 1 */
#ifdef DEBUG
#define BPF_TAG "web_server_offload: "
#define DUMP(x, args...) { const char fmt[] = BPF_TAG x; \
	bpf_trace_printk(fmt, sizeof(fmt), ##args); }
#else
#define DUMP(x, args...)
#endif

/* Make sure these types are defined */
#ifndef __u32
typedef unsigned char        __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
#endif

#ifndef NULL
#define NULL 0
#endif

#define sinline static inline __attribute__((__always_inline__))
#define mem_barrier asm volatile("": : :"memory")
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))
#endif

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

/* Some helper macros */
#define GET_DATA(ctx) (void *)(__u64)ctx->data
#define GET_DATAEND(ctx) (void *)(__u64)ctx->data_end

#define BOUND_CHECK(ptr, size, end, action) if (((void *)((char *)ptr + size)) > end) {action;}
#define BOUND_CHECK_INV(ptr, size, end) BOUND_CHECK(ptr, size, end, return INVALID)

#define IS_DIGIT(chr) (chr >= '0' && chr <= '9')
#define CHR_TO_INT(chr) ((chr) - '0')
#define LOWER_CASE(chr) (chr | 0x20)

/* For masking offset related to the packet pointers
 * I am not sure why masking helps with verifier.
 * */
#define OFFSET_MASK 0x0fff

#endif
