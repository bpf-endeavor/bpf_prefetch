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
loader_obj = $(build_dir)/loader

REPO_LIB_DIR = ../../libs/

# debuging variables ...
# $(info $(out_obj))
# $(info $(bpf_headers))

BPF_CFLAGS ?=
BPF_CFLAGS += -target bpf 
BPF_CFLAGS += -O2 -g
BPF_CFLAGS += -std=gnu17
BPF_CFLAGS += -Werror
BPF_CFLAGS += -Wno-unused-value
BPF_CFLAGS += -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-address-of-packed-member
BPF_CFLAGS += -Wno-incompatible-pointer-types
BPF_CFLAGS += -D __KERNEL__ -D __BPF__ -D __bpf__
BPF_CFLAGS += -D __BPF_FEATURE_ADDR_SPACE_CAST
BPF_CFLAGS += -I ./include/ -I ./
BPF_CFLAGS += -I $(REPO_LIB_DIR)
BPF_CFLAGS += -I $(LIBBPF_HEADER)

EXTRA_CFLAGS ?=

# Rules
.PHONY: all clean

all: $(skel_dir) $(out_obj) $(loader_obj)

clean:
	rm $(build_dir)/*.c \
		$(build_dir)/*.ll \
		$(build_dir)/*.o \
		$(build_dir)/*.o.keep \
		$(build_dir)/*.tmp \
		$(skel_dir)/*.h \
		$(skel_dir)/*.tmp \
		$(loader_obj) || true

$(skel_dir):
	mkdir -p $@

$(build_dir)/cvm.bpf.c: cvm.bax
	/bin/sh ../../libs/bax/cbax.sh $< $@

$(build_dir)/cvm.bpf.ll: $(build_dir)/cvm.bpf.c
	$(CLANG) $(EXTRA_CFLAGS) $(BPF_CFLAGS) -emit-llvm -c $< -o $@.tmp
	mv $@.tmp $@

$(build_dir)/cvm.bpf.o: $(build_dir)/cvm.bpf.ll  $(bpf_headers)
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $<
	cp $@ $@.keep

$(skel_dir)/cvm.skel.h: $(build_dir)/cvm.bpf.o
	name=$$(echo $@ | cut -d / -f 3 | cut -d '.' -f 1); \
		 bpftool gen skeleton $< name $$name > $@.tmp
	mv $@.tmp $@

$(loader_obj): loader.c $(skel_dir)/cvm.skel.h
	$(CC) -I $(REPO_LIB_DIR) -I $(skel_dir) \
		-g -O2 loader.c -o $@ -lbpf -lelf -lz
