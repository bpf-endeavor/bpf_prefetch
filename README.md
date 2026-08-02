# Beeswax: A Study in eBPF Runtime Support for Cache Efficiency

This is the home repository of **Beeswax** which hosts our prototype for
answering how we can address the cache-miss challenges of eBPF programs
especially when their working size (e.g., number of entries in the MAPs they
use) increase. The full discussion of motivating examples and trade-offs of the
solution can be found in the paper
["Don't Stall Me Now: Hiding Memory Latency in eBPF"](https://fshahinfar1.github.io/papers/dont_stall_me_now_hiding_memory_latency_in_ebpf.pdf)
presented in the ACM SIGCOMM'26, Denvor USA.

Our solution requires few new runtime features:

1. Support for CPU prefetch instructions
2. Supoprt for batch event processing

A modified version of kernel with these supports is available [here](https://github.com/bpf-endeavor/kernel-sw-prefetch).

## About

This repository is meant as the acompanying artifact of our paper and we share
requiremd matterial to understand the details of the system and experiments performed.
This includes code for programs used in experiments, and scripts for prepareing
and setting up the experiment environment. **The step-by-step guide for
reproducing the artifact is found [ARTIFACT.md](./ARTIFACT.md)**

The repository is structured as below:

> TODO: the `case_study` and `motivation` is a weird way of organizing the experiments, and they have lost their meaning. Fix it.
```
.
├── Makefile # Used for preparing experiment envrionment
├── docs # The result of experiments and scripts to plot them are here
├── case_study # This have some programs we explored
├── motivation # Some microbenchmarks
├── docs # The result of experiments and scripts to plot them are here
├── libs
│   ├── arena-ds # Some data structures implmeneted using eBPF Arena feature
│   ├── bax # The libarary and syntax extension for Beeswax
│   ├── honey # Some eBPF library
│   └── kfuncs # Some kernel modules that expose kfuncs needed for eBPF/Beeswax
├── patches # Patches to enable Beeswax support in applications used in evaluation 
└── scripts # Scripts for setting up environment and running experiments
```

## How Beeswax Works? (System Design)

![Beeswax Design Overview](./docs/repository/batch_prefetch_design.jpg)

Beeswax is a recipe for building eBPF programs that can effectively hide memory latency. For this purpose, the programs rely on:

1. Desiging data structure API in multiple phases
2. Prefetch instruction
3. Batch processing
4. Arena MAP for implementing the data structures

A Beeswax program is capable of processing events in batches. As a strating point, we have extended the XDP hook to support batch packet processing (supporting mlx5 and virtio drivers).
Below you can see a simple Beeswax program and layout of its context object. The batch processing programs start with `bbb_` prefix and receive `struct xdp_batch_md *` as context object.

```
SEC("xdp")
int bbb_test_main(struct xdp_batch_md *batch)
{
    // This defines a scope in which Beeswax specific API is usable
    BAX_PROG_BEGIN();

    // batch_size a keyword 
    bpf_printk("batch size: %d", batch_size);

    // ...
    return 0;
}
```

The context object (`batch` in the example above) contains a fixed size array
of original XDP context objects. The program can directly access the context to
retrieve packet by their index from `buffs` array and write the verdict value
(e.g., `XDP_PASS` or `XDP_DROP`) to actions array at the same index. But, this
approach is hard to program and for this reason Beeswax inclues a library that
provides programming support for batch processing.

```
#define XDP_MAX_BATCH_SIZE 32
struct xdp_batch_md {
    __u32 size;
    __u32 __padding__;
    struct xdp_md buffs[XDP_MAX_BATCH_SIZE];
    __u32 actions[XDP_MAX_BATCH_SIZE];
};
```

More specifically, Beeswax programs are organized in multiple stages in which
packets are processed. Every packet is associated with one. Intially all packet
start from the stage indicated by `BAX_DECLARE_INIT_STAGE_NAME`.

During each stage, the packet may finish processing (e.g., marked to be
dropped), stay at same stage, or transition to another stage. The program goes
through stages and processes packets that belong to that stage.

```
...
BAX_DECLARE_INIT_STAGE_NAME(FIRST);

SEC("xdp")
int bbb_test_main(struct xdp_batch_md *batch)
{
    __associate_arena();
    BAX_PROG_BEGIN();
    BAX_INIT_BATCH_STATE();
    finished = 0;

    // batch_size a keyword 
    bpf_printk("batch size: %d", batch_size);

    BAX_STAGE(FIRST, `{
        /* data is a keyword which is a pointer to the begining of the packet */
        struct ethhdr *eth = data; 
        struct iphdr *ip = (void *)(eth+1);
        struct udphdr *udp = (void *)(ip + 1);
        /* query is inside the UDP payload */
        __u32 *r = (__u32 *)(udp + 1);
        if ((void *)(r + 1) > data_end) {
            PASS(); /* packet is too small for our program */
        }
        __u16 tmp_port = bpf_ntohs(udp->dest);
        if (!(tmp_port >= 8000 && tmp_port < 8128)) {
            PASS();
        }

        // ...
    }')

    // ...
    return 0;
}
```


> TODO: write this

### KFuncs Used

Some of the experiments rely on external kfuncs. Use `make load_kmod` to load
the kernel modules.

	1. [libs/kfuncs/my\_memcpy](libs/kfuncs/my_memcpy): some standard string and memory operations
	2. [others/arena\_kmod/kmod](others/arena_kmod/kmod): a dummy kfunc to register Arena map with XDP programs


## Citation
 
 To cite the work use following format:

**Bibtex:**

```
@inproceedings{beeswax,
title={Don't Stall Me Now: Hiding Memory Latency in eBPF},
author={Shahinfar, Farbod and Molè, Marco and Panda, Aurojit and Antichi, Gianni},
year={2026},
booktitle={Special Interest Group on Data Communication (SIGCOMM)},
publisher={ACM}
}
```

**Text:**

Farbod Shahinfar, Marco Molè, Aurojit Panda, and Gianni Antichi. 2026. Don't Stall Me Now: Hiding Memory Latency in eBPF. In Proceedings of the ACM Special Interest Group on Data Communication (SIGCOMM).

