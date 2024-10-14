CLANG ?= clang
LLC = llc
CFLAGS = -O2 -g -Wall
OUTDIR = ./build

RUNNER = $(OUTDIR)/runner
RUNNER_HEADERS = $(wildcard *.h)

BPF_FILES = $(wildcard ./benchmarks/*.c)
BPF_OUT   = $(addprefix $(OUTDIR)/, $(addsuffix .o, $(basename $(notdir $(BPF_FILES)))))

LOADER_CFLAGS  = -I $(CURDIR)/../../deps/usr/include
LOADER_LDFLAGS = -L $(CURDIR)/../../deps/usr/lib64 -l:libbpf.a -lelf -lrt -lz
BPF_CFLAGS     = \
		 -I $(CURDIR)/../../deps/usr/include -I ./include/bpf/ \
		 -target bpf \
		 -D __BPF_TRACING__ \
		 -Wall \
		 -Wno-unused-value \
		 -Wno-pointer-sign \
		 -Wno-compare-distinct-pointer-types \
		 -O2 -emit-llvm -c -g \

.PHONY: default bpf clean

default: $(RUNNER) bpf

clean:
	rm -rf $(OUTDIR)

bpf: $(BPF_OUT)

$(RUNNER): runner.c $(RUNNER_HEADERS)
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CLANG) $(CFLAGS) $(LOADER_CFLAGS) -o $(RUNNER) runner.c $(LOADER_LDFLAGS)

$(BPF_OUT): $(OUTDIR)/%.o:./benchmarks/%.c $(wildcard ./include/bpf/*.h)
	echo "$< --> $@" ;
	$(CLANG) -S $(BPF_CFLAGS) -o $@.ll $<
	$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o $@ $@.ll
	$(CLANG) -S -DPREFETCH=1 $(BPF_CFLAGS) -o $@.ll.pf $<
	$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o $@.pf $@.ll.pf
