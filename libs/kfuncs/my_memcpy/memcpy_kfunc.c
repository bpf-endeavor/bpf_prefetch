#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h> /* memcpy */
#include <linux/btf.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exposing my_memcpy to XDP programs");

/* Define a kfunc function */
__bpf_kfunc_start_defs();

__bpf_kfunc long my_memcpy(void *dst, __u32 dst__sz, void *src, __u32 src__sz)
{
	__u32 sz = src__sz < dst__sz ? src__sz : dst__sz;
	memcpy(dst, src, sz);
	return sz;
}

__bpf_kfunc_end_defs();

/* Encode the function(s) into BTF */

/*
 * These will probably be the new API
 * */
BTF_KFUNCS_START(bpf_my_memcpy)
BTF_ID_FLAGS(func, my_memcpy, 0)
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
	/* Register the BTF */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &my_memcpy_kfunc_set);
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
