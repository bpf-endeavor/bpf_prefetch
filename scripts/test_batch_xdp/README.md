These XDP programs are using batch aware API. They are used for testing my
modification to support this feature.

> NOTE 1: the kernel patches for batch aware XDP are at `kernel-sw-prefetch` repo
> NOTE 2: the eBPF loader program is the generic one that I use. The source code is originally from `auto_kern_offload_bench` repo
> NOTE 3: The IO\_URING API was used when testing with `VIRTIO_NET` driver and a VM to create a batch of packest
