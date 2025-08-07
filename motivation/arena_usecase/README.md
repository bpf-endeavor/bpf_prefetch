# About

This is an experiment motivating using prefetching with **hash maps** in eBPF.
There are multiple modes:

* Cappuccino: a program using BPF hash map
* Machiato: a program using a hash map implemented using Arena
* Lungo: a program using Arena implementation + doing prefetching
* Talkh: a XDP batch aware program using Arena implementation + doing prefetching


The loader program populates the hash map at begining of the experiment.
The eBPF program uses the one ore more values in the payload of each packet to
lookup the hash map.

> NOTE: Arena works with clang-19, make sure you have the correct version

> NOTE: You need to load the kernel module defining my\_kfunc\_reg\_arena helper
