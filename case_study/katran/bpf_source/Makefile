obj := .
src := .

DEBUGBPF = -DDEBUG
INCLUDEFLAGS = -I$(obj)/usr/include \
	       -I$(obj)/include \
	       -I$(obj) \
	       -I ../../../libs/

always = bpf/balancer.bpf.o
always += bpf/healthchecking_ipip.o
always += bpf/healthchecking.bpf.o
always += bpf/xdp_pktcntr.o
always += bpf/xdp_root.o

pf = bpf/balancer.bpf.pf.o

HEADERS = $(wildcard ./katran/lib/bpf/*.h)


# EXTRA_CFLAGS += -DLPM_SRC_LOOKUP=1
EXTRA_CFLAGS += -DMAX_CONN_RATE=5000000
EXTRA_CFLAGS += -DUSE_SEETHROUGH_HASHMAP=1

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang

# Trick to allow make to be run from this directory
all: bpf/ $(always) $(pf)
	# $(MAKE) -C .. $$PWD/

clean:
	rm bpf/*
	# $(MAKE) -C .. M=$$PWD clean
	# @rm -f *~

bpf/:
	mkdir -p bpf/

$(obj)/bpf/%.o: $(src)/katran/lib/bpf/%.c $(HEADERS)
	LLFILE=$$(mktemp); \
	$(CLANG) $(INCLUDEFLAGS) $(EXTRA_CFLAGS) \
	$(DEBUGBPF) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g $< -o $$LLFILE && \
		$(LLC) -march=bpf -filetype=obj -o $@ $$LLFILE; \
		rm $$LLFILE

$(obj)/bpf/%.pf.o: $(src)/katran/lib/bpf/%.c $(HEADERS)
	LLFILE=$$(mktemp); \
	$(CLANG) $(INCLUDEFLAGS) $(EXTRA_CFLAGS) -DPREFETCH=1 \
	$(DEBUGBPF) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g $< -o $$LLFILE && \
		$(LLC) -march=bpf -filetype=obj -o $@ $$LLFILE; \
		rm $$LLFILE

