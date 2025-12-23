LLC ?= llc-19
CLANG ?= clang-19

LIBBPF_HEADER=../../deps/usr/include

build_dir ?= build
skel_dir = $(build_dir)/skel

# define headers as dependencies so the program is recompiled after changes
bpf_headers=$(shell find ./include/ -name '*.h')

bax_src = ./cvm.bax
bpf_src = $(build_dir)/cvm.bpf.c
out_obj = $(skel_dir)/cvm.skel.h

# debuging variables ...
# $(info $(out_obj))
# $(info $(bpf_headers))

BPF_CFLAGS ?=
BPF_CFLAGS += -O2 -g
BPF_CFLAGS += -std=gnu17
BPF_CFLAGS += -Werror
BPF_CFLAGS += -Wno-unused-value
BPF_CFLAGS += -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-address-of-packed-member
BPF_CFLAGS += -Wno-incompatible-pointer-types
BPF_CFLAGS += -I ./include/
BPF_CFLAGS += -I ../../libs/
BPF_CFLAGS += -I $(LIBBPF_HEADER)
BPF_CFLAGS += -D __KERNEL__ -D __BPF__
BPF_CFLAGS += -D __BPF_FEATURE_ADDR_SPACE_CAST

EXTRA_CFLAGS ?=

# Rules
.PHONY: all $(build_dir)/cvm.bpf.c

all: $(skel_dir) $(out_obj)

$(build_dir)/cvm.bpf.c: cvm.bax
	/bin/sh ./cbax.sh $< $@

$(skel_dir):
	mkdir -p $@

$(build_dir)/%.ll: $(build_dir)/%.c
	$(CLANG) $(EXTRA_CFLAGS) $(BPF_CFLAGS) -emit-llvm -c $< -o $@

$(build_dir)/%.o: $(build_dir)/%.ll  $(bpf_headers)
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $<
	cp $@ $@.keep

$(skel_dir)/%.skel.h: $(build_dir)/%.bpf.o
	name=$$(echo $@ | cut -d / -f 3 | cut -d '.' -f 1); \
		 bpftool gen skeleton $< name $$name > $@

