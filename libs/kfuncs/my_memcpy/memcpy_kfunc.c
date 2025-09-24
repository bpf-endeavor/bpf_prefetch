#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h> /* memcpy */
#include <linux/jhash.h> /* jhash */
#include <linux/btf.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exposing some helper functions used to accelerate eBPF programs used in this project");

/* Define a kfunc function */
__bpf_kfunc_start_defs();

__bpf_kfunc long my_memcpy(void *dst__ign, void *src__ign, __u32 src_sz__ign)
{
	__builtin_memcpy(dst__ign, src__ign, src_sz__ign);
	return 0;
}

__bpf_kfunc long my_strchr(void *src__ign, char c__ign)
{
	char *x = strchr(src__ign, c__ign);
	return (u64)x - (u64)src__ign;
}

__bpf_kfunc long my_jhash(void *src__ign, __u32 sz__ign)
{
	u32 hash = jhash(src__ign, sz__ign, JHASH_INITVAL);
	return hash;
}

__bpf_kfunc long my_memmove(void *dst__ign, void *src__ign, __u32 src_sz__ign)
{
	memmove(dst__ign, src__ign, src_sz__ign);
	return 0;
}

__bpf_kfunc long my_strncmp(void *dst__ign, void *src__ign, __u32 src_sz__ign)
{
	int x = strncmp(dst__ign, src__ign, src_sz__ign);
	return x;
}

__bpf_kfunc_end_defs();

/* Encode the function(s) into BTF */

/*
 * These will probably be the new API
 * */
#define NO_FLAG 0
BTF_KFUNCS_START(bpf_my_memcpy)
BTF_ID_FLAGS(func, my_memcpy, NO_FLAG)
BTF_ID_FLAGS(func, my_strchr, NO_FLAG)
BTF_ID_FLAGS(func, my_jhash, NO_FLAG)
BTF_ID_FLAGS(func, my_memmove, NO_FLAG)
BTF_ID_FLAGS(func, my_strncmp, NO_FLAG)
BTF_KFUNCS_END(bpf_my_memcpy)

/* BTF_SET8_START(bpf_my_memcpy) */
/* BTF_ID_FLAGS(func, my_memcpy, 0) */
/* BTF_SET8_END(bpf_my_memcpy) */

static const struct btf_kfunc_id_set my_memcpy_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &bpf_my_memcpy,
};

static int myinit(void)
{
	int ret;
	/* Register the BTF: XDP */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &my_memcpy_kfunc_set);
	if (ret != 0)
		return ret;

	/* Register the BTF: TC */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &my_memcpy_kfunc_set);
	if (ret != 0)
		return ret;

	pr_info("Load memcpy kfunc\n");
	return 0;
}

static void myexit(void)
{
	pr_info("Unloading memcpy kfunc\n");
}

module_init(myinit)
module_exit(myexit)
