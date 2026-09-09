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

### Setup DUT (Device Under Test)

> This section assumes that git, make, and build-essential packages are already installed (cloudlab images are like this). Other 3rd-party packages will be installed when following the instructions.

**Time estimate: 1-2 houres** (it performs a kernel compilation which may take long depending on the system) 

Clone the the repository on DUT machine.

```
git clone https://github.com/bpf-endeavor/bpf_prefetch.git
cd bpf_prefetch
make setup_dut
```

The `setup_dut` is expect to exit completing its task because the rest of
setup requires a kernel with Beeswax support. Install as follows: 

```
cd ./others/kernel-sw-prefetch
./install.sh
```

By this poinrt, a new kernel should be installed. Reboot the machies to load
the new kernel, and later continue following commands from the root of
`bpf_prefetch/` direcotry:

```
make setup_dut # continues from previous step 
make load_kmod
make configure4exp
```

### Setup Workload Generator 


```bash
make setup_generators
source ~/.bashrc  
```


## Application Experiment 1: Katran

During setup phase, the script has cloned Katran and applied patches to adopt
Beeswax design. Both the original version and one with Beeswax design is
compiled and are ready for experimentation.

The `./scripts/katran/run_katran.sh` is the script for launching the load-balancer and preparing it for performance measurement.
The flags for running the script is described below. 

> **Important note:** `OTHER_SERVER_IP` and `DEFAULT_MAC` has to updated in the script based on experiment network configurations.

> TODO: make the script autodiscover these values

```
Usage: run_katran.sh MODE EXP
  MODE: [--baseline | --batch | --bax] which version of Katran to use in experiment
  EXP:  [--id-routing | --lru-routing ] select experiment configuration
```

To repeat the experiment in Figure 5 (exploring katran with different workloads
and memory footprint), there is a helper script:
`./script/katran/workload_analysis_scripts/katran_explore_flows.sh`.
This scripts runs on the workload generator machine, but using `SSH`, it will
also connect to DUT and run `run_katran.sh` script with correct flags.

> **Important note:** There are some IP address and MAC address that needs to be configured in the script in order to correctly work

> TODO: make the script autodiscover these values

The script will gather raw data and store them at `RESULT_DIR=~/results/`. For analysing the result you can use the 
`./script/katran/workload_analysis_scripts/clean_exp_results.py`


## Application Experiment 2: BMC

> TODO: To be written


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




