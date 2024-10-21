CC = clang
LLC = llc
INCLUDES = -I ../deps/usr/include -I ./include/ -I ../../libs
CFLAGS = -g -O2 -Wall
# Pass the name of interface to which XDP program is attached at compile time
ifndef NET_IFACE
$(error "NET_IFACE is not defined")
endif
CFLAGS += -DIFNAME=\"$(NET_IFACE)\"
LDFLAGS = -L ../../deps/ -lbpf -lz -lpthread -lelf

OUTPUT_DIR = ./build/
OUTPUT_DIR_BPF = ./build/bpf/
OUTPUT_DIR_BPF_LL = ./build/bpf/ll

KERN_DIR = ./
KERN_SOURCES  = $(wildcard *.bpf.c)
KERN_OBJECTS  = $(addsuffix .o, $(basename $(KERN_SOURCES)))
_KERN_OBJECTS = $(addprefix $(OUTPUT_DIR_BPF), $(KERN_OBJECTS))
_KERN_SKEL    = $(addprefix $(OUTPUT_DIR_BPF), $(addsuffix .h, $(basename $(KERN_SOURCES))))
KERN_HEADERS  = $(wildcard ./include/mybpf/*.h)

# $(info $(_KERN_SKEL))

BPF_CFLAGS += ${INCLUDES} \
	    -target bpf \
	    -S \
	    -D BPF_PROG \
	    -D__KERNEL__  \
	    -D__BPF_TRACING__ \
	    -D__TARGET_ARCH_x86 \
	    -Wall \
	    -Wno-unused-value -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -g -emit-llvm

OUTPUTS = $(_KERN_OBJECTS) $(_KERN_SKEL) build/bench

.PHONY: all clean check_output_dir

all: check_output_dir $(OUTPUTS)

clean:
	rm -r $(OUTPUT_DIR)

check_output_dir:
	@if [ ! -d ${OUTPUT_DIR} ]; then  mkdir -p ${OUTPUT_DIR} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF} ]; then  mkdir -p ${OUTPUT_DIR_BPF} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF_LL} ]; then  mkdir -p ${OUTPUT_DIR_BPF_LL} ; fi

$(_KERN_OBJECTS): $(OUTPUT_DIR_BPF)%.o:$(KERN_DIR)%.c $(KERN_HEADERS)
	LL_FILE=${OUTPUT_DIR_BPF_LL}/$(notdir $@); \
		$(CC) $(BPF_CFLAGS) -c $< -o $$LL_FILE; \
		$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o "$@" $$LL_FILE;
	LL_FILE=${OUTPUT_DIR_BPF_LL}/$(notdir $@.pf); \
		$(CC) $(BPF_CFLAGS) -c $< -o $$LL_FILE; \
		$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o "$@.pf" $$LL_FILE;

$(_KERN_SKEL): %.h:%.o
	bpftool gen skeleton $< > $@
	bpftool gen skeleton $<.pf name bench_bpf_pf > $@.pf

build/bench: main.c $(_KERN_SKEL)
	$(CC) $(CFLAGS) -o $@ main.c $(LDFLAGS)
