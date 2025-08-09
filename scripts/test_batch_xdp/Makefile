.PHONY: all clean asm

bpf_files=$(wildcard *.bpf.c)
targets=$(bpf_files:.c=.o)

all: $(targets)

clean:
	rm -f *.bpf.o *.bpf.o.ll

asm: xdp.bpf.S

%.bpf.S: %.bpf.o
	llvm-objdump -S $< > $@

%.bpf.o: %.bpf.c
	clang -S \
	-I ../../libs/ \
	-target bpf \
	-Wall \
	-g -O3 -emit-llvm \
	-o $@.ll $<
	llc -mcpu=probe -march=bpf -filetype=obj -o $@ $@.ll
