# Artifact Reproducibility Guide

## Experiment Machines and Cloudlab Configurations

Hardware: the experiments were performed on [Cloudlab](https://www.cloudlab.us/) platform using machines from [Utah cluster with type c6525-25g](https://www.utah.cloudlab.us/portal/show-nodetype.php?type=c6525-25g).

We used two directly connected servers for each experiment: one served as the
load generator while the other ran the Beeswax program (Figure 1).

![For the experiments to servers are connected directly](./docs/repository/back_to_back_setup.jpg)

Each server is equipped with an AMD EPYC 7302P 16-Core (Zen 2 – Rome) processor
with 0.5 MB of L1, 8 MB of L2, and 128 MB of LLC; has 128 GB of memory; and a
Mellanox Connect-X5 (MT27800 Family) NICs.


This is the profile to use: https://www.cloudlab.us/p/ProgStack/beeswax-artifact
Note: In this repository we'll use the following convention
- Node 0 is the Device Under Test (DUT)
- Node 1 is the generator device.

## Installing Dependencies

**NOTE THE SETUP PROCESS REQUIRES A REBOOT, THE SCRIPTS WILL DO THE REBOOT!**

### Setup DUT (Device Under Test)

> This section assumes that git, make, and build-essential packages are already installed (cloudlab images are like this). Other 3rd-party packages will be installed when following the instructions.

**Time estimate: 1-2 houres** (it performs a kernel compilation which takes time) 

Clone the the repository on DUT machine.

```
git clone https://github.com/bpf-endeavor/bpf_prefetch.git
cd bpf_prefetch
make setup_dut
```

The script will cause a reboot! By this poinrt, a new kernel should be
installed. Reboot the machies to load the new kernel, and later continue
following commands from the root of `bpf_prefetch/` direcotry:

```
make setup_dut # continues from previous step 
make load_kmod
NET_IFACE=<NIC Iface name> make configure4exp
```

> Remember to set `NET_IFACE` to the interface name of the NIC that is used during experiments

### Setup Workload Generator 

```bash
make setup_generators
```

The script will cause a reboot! You should again invoke the `make
setup_generators` to finish the procedure.


### Configurations

**System configurations:**

`configh.sh` holds the variables that help the system know how to connect and
run experiments. Configure them with value (IP addres, MAC address, Interface
names, ...) on both machines.

**Passwordless SSH:**

Make sure both DUT and generator machine have `ssh` access to each other
without password. Some scripts automatically setup DUT and workload generator
and rely on `ssh` for it.

To configure passwordless `ssh`,on both machines, generate a new ssh-key (`ssh-keygen`) and
leave the password empty. Then copy the public key of each machine to the
`~/.ssh/authorized_hosts` of the other machine.


## Figure 5: Katran - L4 Load Balancer

**Instruction:**

- On DUT:

* Make sure you have run `make load_kmod`
* Make sure `make configure4exp` is running (it configures the environment you can close it with Ctrl+C)

- On workload generator machine

```bash
cd beeswax/scripts/katran/workload_analysis_scripts/
./katran_explore_flows
```

- Results

```
cd beeswax/scripts/katran/workload_analysis_scripts/
python3 ./clean_exp_results.py
```

---

**Longer Explanation:**

During setup phase, the script has cloned Katran and applied patches to adopt
Beeswax design. Both the original version and one with Beeswax design is
compiled and are ready for experimentation.

The `./scripts/katran/run_katran.sh` is the script for launching the load-balancer and preparing it for performance measurement.
The flags for running the script is described below. 

```
Usage: run_katran.sh MODE EXP
  MODE: [--baseline | --batch | --bax] which version of Katran to use in experiment
  EXP:  [--id-routing | --lru-routing ] select experiment configuration
```

> **Important note:** The scripts relies on environment values set in `config.sh` in root directory of the repository.

To repeat the experiment in Figure 5 (exploring katran with different workloads
and memory footprint), there is a helper script:
`./script/katran/workload_analysis_scripts/katran_explore_flows.sh`.
This scripts runs on the workload generator machine, and uses `SSH` to connect
to DUT and run `run_katran.sh` script with correct flags.

> The workload generator is configured to stress the system with 3.4 Mpps. This was sufficient to saturate the system in the our testbed. Generating more loads either did not increased throughput or made it worse. Under a different setup/hardware this value must be adjusted.

The script will gather raw data and store them at
`RESULT_DIR=$HOME/results/katran`. For analysing the result you can use the
`./script/katran/workload_analysis_scripts/clean_exp_results.py`


## Figure 6: BMC - In-Kernel Key-Value Cache

**Instruction:**

- On DUT:

* Make sure `make configure4exp` is running (it configures the environment, including the flow-steering rules `run_server.sh` relies on; you can close it with Ctrl+C)

- On workload generator machine

```bash
cd beeswax/scripts/bmc/workload_analysis_scripts/
./bmc_explore_records.sh
```

- Results

Raw results are stored at `$HOME/results/bmc/<mode>/bmc_performance_<num_records>.txt`, one file per record count, for `<mode>` in `baseline` and `batch-pf` (the two configurations shown in Figure 6).

---

**Longer Explanation:**

During setup phase (`make setup_dut`), the script has cloned Memcached and BMC-cache (an in-kernel key-value cache built on top of Memcached) and applied patches to build four variants ready for experimentation: baseline (`enhanced`), with prefetching (`enhanced_prefetch`), batch-aware (`batch`), and batch-aware with prefetching (`batch_prefetch`).

The `./scripts/bmc/run_server.sh` is the script for launching Memcached and, optionally, BMC, preparing them for performance measurement.
The flags for running the script are described below.

```
Usage run_server: default behaviour: only run the memcached
  --bmc-baseline: run with baseline bmc
  --bmc-prefetch: run bmc with prefetching
  --bmc-batch: run with batch aware bmc
  --bmc-batch-pf: run with batch aware bmc + prefetching
```

> **Important note:** The script relies on environment values set in `config.sh` in root directory of the repository, and requires `$NET_IFACE` to be exported to the interface name used for the experiment.

The `./scripts/bmc/run2.sh` script drives the `mutilate`/`mutilateudp` workload generator against the DUT. It sweeps over the record counts used in the paper (1, 1,000, 100,000, 300,000, 500,000, 1,000,000), storing each count's result in its own log file, so it can also be run standalone against an already-running `run_server.sh` for a single manual test.

To repeat the experiment in Figure 6 (exploring BMC with different cache
footprints), there is a helper script:
`./script/bmc/workload_analysis_scripts/bmc_explore_records.sh`.
This script runs on the workload generator machine, and uses `SSH` to connect
to DUT to start `run_server.sh` with the correct flag for each configuration,
then runs `run2.sh` locally to sweep all record counts, before tearing the
server down and moving on to the next configuration.

The script will gather raw data and store them at
`RESULT_DIR=$HOME/results/bmc/<mode>`.


## Application Experiment LPM -- Figure 7-8

### DUT

On tmux open two panes:
1. In the first pane run `cd $HOME/bpf_prefetch && make configure4exp`. This will configure the machine in a predictable way.
2. In the second pane 
```bash
cd $HOME/bpf_prefetch/motivation/bax_lpm
make
sudo ./build/loader.o 
```
The loader takes the following arguments: 
```
Usage: prog OPTIONS
OPTIONS:
        --lpm: use LPM Trie (default option)
        --dat: use the Arena Double Array Trie implementation
        --bax-dat: Beeswax version of Arena Double Array Trie
```
These map to the three bars that appear in Figure 7 of the paper: Native (--lpm), Arena(--dat) and Beeswax (--bax-dat)

Now, let's setup the generator node.


### Generator Setup
In order to perform the experiments with the LPM is necessary to build PCAPs of the traces. It is necessary to build the PCAP with the correct MAC addresses.

The mac addresses of the experiment's interfaces should be in the env variable  $NET_MAC.

On the Generator machine run:
```bash
cd motivation/bax_lpm/scripts/
python gen_pcap.py --src-mac $NET_MAC --dst-mac <mac address of the DUT from the step before> # This will generate the pcaps
```

Before running the actual generator, modify the config.yaml in motivation/bax_lpm/scripts/ with the $NET_PCI variable, which is the PCI address of the NIC.

Now we are ready to generate packets!

```bash
sudo dpdk-replay --config config.yaml
```

By default the config.yaml replays the lpm_zipf_0.pcap trace (Figure 7),
For repoducing Figure 8 change the config.yaml to replay lpm_zipf_0.5.pcap and so on to the lpm_zipf_2.pcap


## Application Experiment LPM -- Figure 10

### DUT

Remember to have make config4exp running in a another terminal/tmux pane.

Here we are changing the code of the application, so it is needed to recompile everytime.

```bash
cd $HOME/bpf_prefetch/motivation/bax_lpm
BPF_CFLAGS="-D BIT_FOR_ITERATION=1" make 
``` 
Change the flag to 1,8,16,32 as in Figure 10.


### Generator 
This is the same setup as you would do for Figure 7.




