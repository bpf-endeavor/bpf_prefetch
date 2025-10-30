# Cache Efficient eBPF: Making eBPF Programs Blazing Fast

## About

...

## Applications

### BMC

...

### Katran


## How to use it

### Install

...

### KFuncs Used

Some of the experiments rely on external kfuncs. Use `make load_kmod` to load
the kernel modules.

	1. [libs/kfuncs/my\_memcpy](libs/kfuncs/my_memcpy): some standard string and memory operations
	2. [others/arena\_kmod/kmod](others/arena_kmod/kmod): a dummy kfunc to register Arena map with XDP programs
