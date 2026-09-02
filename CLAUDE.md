# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Beeswax is a research artifact for hiding memory latency in eBPF programs through batch processing and CPU prefetch instructions. The core challenge is that eBPF programs experience cache misses when working with large MAP data structures. Beeswax addresses this by decomposing programs into multiple stages where batches of packets make partial progress, allowing the CPU to prefetch data between stages.

**Key paper:** ["Don't Stall Me Now: Hiding Memory Latency in eBPF"](https://fshahinfar1.github.io/papers/dont_stall_me_now_hiding_memory_latency_in_ebpf.pdf) (ACM SIGCOMM'26)

## Build & Development Commands

### Initial Setup (One-time)

```bash
# Install dependencies and build core libraries
make install_deps

# Load kernel modules (required for some experiments)
make load_kmod

# Configure environment for experiments
make configure4exp
```

### Building Programs

All eBPF programs follow a standard build pattern with two Makefiles:

```bash
cd <program_directory>
make  # Builds both eBPF kernel code and userspace loader
```

**Build system:**
- `Makefile`: Main build orchestrator, creates `build/` directory
- `Makefile.bpf`: Compiles eBPF programs with clang, generates vmlinux.h and skeleton files
- `Makefile.user`: Compiles userspace loader using libbpf

### Running Programs

Microbenchmarks and case studies have different entry points:

```bash
# Motivation/Microbench examples
cd motivation/arena_htab
make && ./build/load  # Most microbench programs follow this pattern

# Katran load-balancer experiments
cd case_study/katran
./scripts/run_katran.sh <MODE> <EXP>
# MODE: --baseline, --batch, or --bax
# EXP: --id-routing or --lru-routing
```

### Testing & Measurement

```bash
# Measure cache misses (uses perf)
bash scripts/measure_cache_miss.sh

# Test batch XDP functionality
cd scripts/test_batch_xdp && make
```

## Architecture & Key Concepts

### Beeswax Programming Model

Beeswax programs process packets in batches rather than individually. The key patterns:

1. **Batch Processing Entry Point:** Programs use `SEC("xdp")` with `struct xdp_batch_md *` context and `bbb_` prefix
   - `xdp_batch_md` contains a batch of up to 32 packets plus their verdict array
   - Requires kernel patch: [kernel-sw-prefetch](https://github.com/bpf-endeavor/kernel-sw-prefetch)

2. **Multi-Stage Processing:** Programs are decomposed into stages using `BAX_STAGE(name, {...})`
   - Each packet has associated state in `pkt_state_t` with mandatory `phase[0]` field
   - Transitions between stages using `BAX_NEXT_STAGE(name)`
   - Enables CPU to prefetch data while processing independent packets in other stages

3. **Context Keywords** (within BAX_STAGE blocks):
   - `pkt`: pointer to XDP context
   - `data` / `data_end`: packet buffer boundaries
   - `pstate`: per-packet state
   - `batch_size`: keyword for batch size

### Directory Structure

```
libs/
├── bax/           # Beeswax library & syntax extensions (macros for BAX_STAGE, etc.)
├── honey/         # eBPF helpers for prefetching programs
├── arena-ds/      # Arena-based data structures (hash tables, LPM tries, etc.)
├── kfuncs/        # Kernel function modules (my_memcpy, arena registration)
├── common/        # Shared headers and utilities
└── libbpf/        # Vendored libbpf library

motivation/       # Microbenchmarks exploring design trade-offs
├── arena_htab/   # Hash table with different approaches (cappuccino/lungo/macchiato)
├── microbench_lpm/  # LPM trie benchmarks
├── arena_bloom_filter/
├── arena_router/
└── microbench_bax_stage/

case_study/       # Real application experiments
├── katran/        # Load-balancer (original + batch + bax versions)
└── http_parser/   # HTTP parser

scripts/
├── install_script/    # Dependency installation
├── setup_exp.sh       # Environment configuration
├── katran/            # Katran experiment helpers
└── test_batch_xdp/    # Batch XDP testing

docs/             # Experimental results and plotting scripts
```

### Compilation Dependencies

- **libbpf:** Provides BPF loader API and vmlinux.h generation (vendored in `libs/libbpf/`)
- **vmlinux.h:** Auto-generated from kernel headers, contains kernel type definitions for eBPF
- **clang:** Compiles eBPF programs to BPF bytecode
- **llvm-objdump:** Disassembles compiled objects

### Arena MAP Feature

Many data structures use eBPF Arena MAPs (allocator within BPF):
- Enables complex structures (trees, hash tables) within eBPF
- Requires kernel support and kfunc registration
- Programs use `__associate_arena()` to bind arena to XDP program

## Key Code Patterns

### Microbenchmark Structure

Most microbenchmarks follow this pattern:

```c
typedef struct {
    int phase[0];        // mandatory phase field
    int key;
    struct dat_partial_lookup_state partial_state;  // stage-specific state
    my_value_t __arena *val;
} pkt_state_t;

SEC("xdp")
int bbb_main(struct xdp_batch_md *batch)
{
    BAX_PROG_BEGIN();
    BAX_INIT_BATCH_STATE();
    
    BAX_STAGE(FIRST_LOOKUP, { ... })
    BAX_STAGE(SECOND_PHASE, { ... })
    
    return 0;
}
```

### Prefetch Integration

Programs explicitly use CPU prefetch instructions between stages to hide latency:
- Prefetch addresses computed in one stage
- Switch to processing other packets
- Return to find data in cache when stage resumes

## Important Notes

### Kernel Requirements

Experiments require a custom kernel with Beeswax support. Standard Linux kernels will not support:
- Batch XDP processing
- CPU prefetch instructions in eBPF
- Required kfuncs

The patched kernel is in `others/kernel-sw-prefetch/` with its own `install.sh`.

### Experiment Setup

1. Both DUT (Device Under Test) and workload generator need setup
2. Network configuration (IP/MAC addresses) in scripts must be customized per environment
3. Katran experiments require SSH access from generator to DUT

See `ARTIFACT.md` for detailed reproduction steps.

### Common Issues

- Missing kernel modules: Run `make load_kmod`
- vmlinux.h generation issues: Check clang and kernel headers are installed
- Submodule problems: Run `git submodule update --init`
