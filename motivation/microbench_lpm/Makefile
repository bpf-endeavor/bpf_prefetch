CLANG ?= clang-19
LLC ?= llc-19

LD_FLAGS = -lbpf -lelf -lz -lm

OUTDIR = ./build
TARGET = $(OUTDIR)/bench
VMLLINUX_HEADER = $(OUTDIR)/include/vmlinux.h
PROJECT_LIB_DIR = ../../libs

.PHONY: default clean

default: $(OUTDIR) $(VMLLINUX_HEADER) $(TARGET)

clean:
	rm -rf build/ || true

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(VMLLINUX_HEADER):
	mkdir -p $$(dirname $@)
	bpftool btf dump file /lib/modules/$$(uname -r)/build/vmlinux format c > $@
	@# bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(TARGET): bench.c $(OUTDIR)/bench_lpm_trie_map.o $(OUTDIR)/bench_arena_dat.o testing_helpers.c bench.h
	$(CLANG) -O2 -g -Wall -o $@ \
		bench.c \
		testing_helpers.c \
		$(OUTDIR)/bench_lpm_trie_map.o \
		$(OUTDIR)/bench_arena_dat.o \
		$(LD_FLAGS)

$(OUTDIR)/bench_lpm_trie_map.o: bench_lpm_trie_map.c $(OUTDIR)/lpm_trie_map.skel.h $(OUTDIR)/lpm_trie_bench.skel.h
	$(CLANG) -I $(OUTDIR) -O2 -g -Wall -o $@ -c bench_lpm_trie_map.c

$(OUTDIR)/bench_arena_dat.o: bench_arena_dat.c $(OUTDIR)/arena_dat_bench.skel.h
	$(CLANG) -I $(OUTDIR) -I $(PROJECT_LIB_DIR) -O2 -g -Wall -o $@ -c bench_arena_dat.c

$(OUTDIR)/%.skel.h: $(OUTDIR)/%.o
	name=$$(basename $@ | cut -d '.' -f 1); \
		bpftool gen skeleton $< name $$name > $@.tmp
	mv $@.tmp $@

$(OUTDIR)/%.o: $(OUTDIR)/%.ll
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $<

$(OUTDIR)/%.ll: %.c
	$(CLANG) -target bpf -O2 -g \
		-isystem $(OUTDIR)/include/ \
		-I $(PROJECT_LIB_DIR) \
		-D __KERNEL__ -D __BPF__ -D __BPF_FEATURE_ADDR_SPACE_CAST \
		-emit-llvm -c $< -o $@

