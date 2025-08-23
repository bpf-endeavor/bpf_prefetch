.PHONY: all clean asm

CC=clang
LLC=llc

LIBBPF_HEADER=-I ../../deps/usr/include

BPF_CFLAGS = -S -target bpf -emit-llvm
BPF_CFLAGS += -Wall -g -O3
BPF_CFLAGS += -I ../../libs/
BPF_CFLAGS += $(LIBBPF_HEADER)

bpf_files=$(wildcard *.bpf.c)
targets=$(bpf_files:.c=.o)

all: $(targets)

clean:
	rm -f *.bpf.o *.bpf.o.ll

asm: xdp.bpf.S

%.bpf.S: %.bpf.o
	llvm-objdump -S $< > $@

%.bpf.o: %.bpf.c
	$(CC) $(BPF_CFLAGS) -o $@.ll $<
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $@.ll
