/* A set of useful function exposed to eBPF applications through this kernel
 * module
 * */
#include <linux/bpf.h>
long my_memcpy(void *dst, void *src, __u32 sz) __ksym;
long my_strchr(void *src__ign, char c__ign) __ksym;
long my_jhash(void *str, __u32 sz) __ksym;
long my_memmove(void *dst, void *src, __u32 sz) __ksym;
long my_strncmp(void *dst, void *src, __u32 sz) __ksym;
long my_memset(void *dst, char c, __u32 sz) __ksym;

