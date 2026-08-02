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

