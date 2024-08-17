Investigate if the NF using huge number of rules suffer from cache misses.
Then check if this can be mitigated by issuing prefetch instructions.
After find the cases, the prefetch insertion could be implemented into JIT to
make it automatic.

Set of programs to study:

* Katran
* XDP filter
* bpf-iptables
