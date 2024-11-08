obj := .
src := .


DEBUGBPF = -DDEBUG
DEBUGFLAGS = -O0 -g -Wall
PFLAGS = $(DEBUGFLAGS)

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

HOSTCFLAGS += $(INCLUDEFLAGS) $(PFLAGS)
HOSTCFLAGS_bpf_load.o += $(INCLUDEFLAGS) $(PFLAGS) -Wno-unused-variable

# EXTRA_CFLAGS += -DLPM_SRC_LOOKUP=1
# EXTRA_CFLAGS += -DMAX_CONN_RATE=5000000

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang

# Trick to allow make to be run from this directory
all: $(always) $(pf)
	# $(MAKE) -C .. $$PWD/

clean:
	rm bpf/*
	# $(MAKE) -C .. M=$$PWD clean
	# @rm -f *~

$(obj)/bpf/%.o: $(src)/katran/lib/bpf/%.c
	$(CLANG) $(INCLUDEFLAGS) $(EXTRA_CFLAGS) \
	$(DEBUGBPF) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

$(obj)/bpf/%.pf.o: $(src)/katran/lib/bpf/%.c
	$(CLANG) $(INCLUDEFLAGS) $(EXTRA_CFLAGS) -DPREFETCH=1 \
	$(DEBUGBPF) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g $< -o -| $(LLC) -march=bpf -filetype=obj -o $@;

