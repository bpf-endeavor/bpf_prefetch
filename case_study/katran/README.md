# Run Katran

Use `r.sh` script. The katran repository has been built and the useful binaries are included in `bins/`.
The bpf source files are under `bpf_source` directory. Use `make` to build them.

# Workload Generator

I used `dpdk-client-server` repo with a modification to create a lot of flows (changing just the source address).

```
ping 192.168.1.1 -c 3 && make && sudo ./build/app -l 4 -a 03:00.1 -- --client --ip-local 192.168.1.2 --ip-dest 10.10.0.2 --duration 120 --unidir --rate 5000000
```
