CLANG ?= clang
LLC = llc
CFLAGS = -O2 -g -Wall
OUTDIR = ./build

RUNNER = $(OUTDIR)/runner
RUNNER_HEADERS =

BPF_FILES = $(wildcard ./*.bpf.c)
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

default: $(OUTDIR) bpf # $(RUNNER) 

clean:
	rm -rf $(OUTDIR)

bpf: $(BPF_OUT)

$(OUTDIR):
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi

# $(RUNNER): runner.c $(RUNNER_HEADERS)
# 	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
# 	$(CLANG) $(CFLAGS) $(LOADER_CFLAGS) -o $(RUNNER) runner.c $(LOADER_LDFLAGS)

$(BPF_OUT): $(OUTDIR)/%.o:./%.c $(wildcard ./*.h)
	@echo "$< --> $@" ;
	@$(CLANG) -S $(BPF_CFLAGS) -o $@.ll $<
	@$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o $@ $@.ll
	rm $@.ll
	@$(CLANG) -S -DPREFETCH=1 $(BPF_CFLAGS) -o $@.ll.pf $<
	@$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o $@.pf $@.ll.pf
	rm $@.ll.pf
