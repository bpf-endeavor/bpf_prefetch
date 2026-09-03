# Artifact Reproducibility Guide

## Overview

This guide explains how to reproduce the experiments from "Don't Stall Me Now: Hiding Memory Latency in eBPF" (SIGCOMM'26). The artifact includes:

- **Figure 5**: Katran load-balancer workload analysis (Figures 5)
- **Figure 6**: BMC with Facebook workload (memcached benchmark)
- **Figures 7-10**: LPM router performance (native, Arena, Beeswax variants)
- **Figures 11-12**: LPM trie batch size effects
- **Figures 13-15**: CVM throughput and batch size analysis

All experiments can be run with simple `make` commands from the workload generator machine.

## Hardware Requirements

### CloudLab Setup
- **Platform**: CloudLab (https://www.cloudlab.us/)
- **Machine Type**: Utah cluster, c6525-25g nodes
- **Processor**: AMD EPYC 7302P 16-Core (Zen 2 – Rome)
- **Memory**: 128 GB
- **NICs**: Mellanox Connect-X5 (MT27800 Family)
- **Setup**: Two directly connected servers (DUT + workload generator)

### Network Configuration
Two network interfaces per machine are required:
1. **Control Plane NIC**: For SSH and management (e.g., 192.168.1.0/24)
2. **Experiment NIC**: For traffic (e.g., 10.10.0.0/24) - Direct point-to-point connection

**Critical**: SSH must use the **control plane NIC** to prevent connection loss when experiment traffic causes packet congestion.

## Installation

### Step 1: Setup DUT (Device Under Test)

Clone the repository on the DUT machine:

```bash
git clone https://github.com/bpf-endeavor/bpf_prefetch.git
cd bpf_prefetch
make install_deps
```

Install the custom kernel with Beeswax support:

```bash
cd ./others/kernel-sw-prefetch
./install.sh
```

Reboot to load the new kernel, then continue setup:

```bash
cd /root/bpf_prefetch
make install_deps  # Completes second phase
make load_kmod
make configure4exp
```

This takes ~30-60 minutes depending on network speed and kernel compilation.

### Step 2: Setup Workload Generator Machine

On the workload generator machine:

```bash
git clone https://github.com/bpf-endeavor/bpf_prefetch.git
cd bpf_prefetch
make install_deps_gen
```

This clones and builds:
- **dpdk-client-server**: TCP/UDP traffic generator with Zipf distribution
- **mutilate**: Memcached workload generator for Facebook traces

### Step 3: Configure Experiments

Copy the configuration template:

```bash
cp scripts/config/experiments.conf.template scripts/config/experiments.conf
```

Edit `scripts/config/experiments.conf` to set:

```bash
# Control plane connection to DUT (for SSH)
DUT_CONTROL_IP="192.168.1.100"      # DUT control plane IP
DUT_USER="root"                      # SSH user
DUT_SSH_KEY="$HOME/.ssh/id_rsa"     # SSH key path

# Experiment interface configuration
KATRAN_EXPERIMENT_NIC="10.10.0.1"   # DUT experiment IP
KATRAN_EXPERIMENT_MAC="0c:42:a1:dd:5b:88"  # DUT experiment MAC
GEN_EXPERIMENT_IP="10.10.0.2"       # Generator experiment IP
GEN_NET_PCI="0000:03:00.1"          # Generator DPDK PCI address

# Enable experiments you want to run
KATRAN_ENABLED=true
LPM_ROUTER_ENABLED=true
BMC_ENABLED=true
CVM_ENABLED=true
```

### Step 4: SSH Key Setup (Important!)

Ensure SSH key-based authentication is configured:

```bash
# On DUT
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Copy your public key to authorized_keys
# Then verify from generator machine:
ssh -i ~/.ssh/id_rsa root@DUT_CONTROL_IP "echo 'SSH OK'"
```

## Running Experiments

### Quick Start

Run all experiments from the workload generator machine:

```bash
make run_all_experiments
```

This runs Katran → LPM Router → BMC → CVM sequentially. Expected time: 4-8 hours.

### Run Individual Experiments

**Figure 5: Katran Workload Analysis**
```bash
make run_exp_katran
```
Tests 11 flow counts × 5 Zipf parameters × 3 modes (baseline/batch/bax)
Expected time: 2-3 hours

**Figures 7-10: LPM Router Benchmark**
```bash
make run_exp_lpm_router
```
Tests 3 variants × 3 entry counts × 4 traffic skew parameters
Expected time: 1-2 hours

**Figure 6: BMC with Facebook Workload**
```bash
make run_exp_bmc
```
Runs memcached with mutilate generating Facebook traces
Expected time: 5-10 minutes

**Figures 13-15: CVM Batch Size Analysis**
```bash
make run_exp_cvm
```
Tests 2 variants (native/beeswax) × 6 batch sizes
Expected time: 30-60 minutes

## Results

Results are stored in `output/` directory with the following structure:

```
output/
├── katran/
│   ├── baseline/
│   │   └── TIMESTAMP/
│   │       ├── run_config.txt       # Configuration snapshot
│   │       ├── run.log              # Execution log
│   │       ├── traffic_gen.log      # DPDK output
│   │       ├── perf_before.txt      # Cache stats before traffic
│   │       ├── perf_after.txt       # Cache stats after traffic
│   │       └── throughput.txt       # Extracted metrics
│   ├── batch/
│   └── bax/
├── lpm_router/
│   ├── native/
│   ├── arena/
│   └── beeswax/
├── bmc/
│   └── TIMESTAMP/
│       ├── mutilate.log             # Traffic generator output
│       ├── metrics.txt              # Extracted metrics
│       └── cache_stats.txt          # Cache miss statistics
└── cvm/
    ├── native/
    └── beeswax/
```

## Analysis and Plotting

### Post-Process Katran Results

```bash
cd scripts/katran/workload_analysis_scripts/
python3 clean_exp_results.py ~/bpf_prefetch/output/katran ~/results/katran_processed
python3 improvement_analysis.py ~/results/katran_processed
```

### Plotting Scripts

Various plotting scripts are available in `docs/`:

```bash
# Plot Katran results
python3 docs/case_study/katran/c6525_25g/workload_analysis/improvement_analysis.py

# Plot LPM router results  
python3 docs/improvement.py
```

## Troubleshooting

### SSH Connection Fails

```bash
# Verify control plane connectivity
ssh -i ~/.ssh/id_rsa root@DUT_CONTROL_IP "uname -r"

# Check if custom kernel is loaded (should show 6.15.x)
# If not, kernel installation failed - check others/kernel-sw-prefetch/install.sh
```

### DPDK Traffic Generator Fails

```bash
# Verify DPDK installation
ls -la others/workload-gen/dpdk-client-server/build/

# If missing, rebuild:
make install_deps_gen

# Check DPDK PCI address on generator
dpdk-devbind.py --status
```

### Mutilate Not Found

Mutilate is required for BMC experiment. If missing:

```bash
make install_deps_gen
# Check: ls others/workload-gen/mutilate/mutilate
```

### Experiment Times Out

Increase `EXP_DURATION` in `scripts/config/experiments.conf` or reduce flow counts/batch sizes. Some microbenchmarks are CPU-intensive.

## Comparing with Reference Results

Reference results from our evaluation are stored in `docs/`:

```bash
# Compare Katran results
diff -r output/katran docs/case_study/katran/c6525_25g/workload_analysis/data/results/

# Compare other experiments
ls docs/case_study/
ls docs/motivation/
```

Exact numbers may vary due to system differences, but trends should be consistent.

## Expected Performance

Typical throughput improvements with Beeswax:
- **Katran**: 15-30% improvement over baseline
- **LPM Router**: 20-40% improvement with prefetching
- **BMC**: Reduced cache misses on memcached workload
- **CVM**: 2-5x throughput improvement with multi-phase API

If results are significantly different, check:
1. Kernel version (must be 6.15.x from kernel-sw-prefetch)
2. CPU frequency scaling (should be pinned)
3. Network interface firmware versions
4. System load during experiments (run on idle machine)

## Paper Figures

| Figure | Experiment | Make Command | Output |
|--------|-----------|--------------|--------|
| 5 | Katran workload analysis | `make run_exp_katran` | `output/katran/` |
| 6 | BMC Facebook workload | `make run_exp_bmc` | `output/bmc/` |
| 7-10 | LPM router variants | `make run_exp_lpm_router` | `output/lpm_router/` |
| 11-12 | LPM trie batch size | `make run_exp_lpm_router` | `output/lpm_router/` |
| 13-15 | CVM batch analysis | `make run_exp_cvm` | `output/cvm/` |

## Support

For issues or questions:
1. Check CloudLab status: https://www.cloudlab.us/
2. Verify kernel: `uname -r` (must show 6.15.x)
3. Check git log: See which Beeswax patches are applied
4. Review logs: `cat output/*/*/run.log`

## Citation

If you use this artifact, please cite:

```bibtex
@inproceedings{beeswax,
  title={Don't Stall Me Now: Hiding Memory Latency in eBPF},
  author={Shahinfar, Farbod and Molè, Marco and Panda, Aurojit and Antichi, Gianni},
  year={2026},
  booktitle={Proceedings of the ACM Special Interest Group on Data Communication (SIGCOMM)}
}
```
