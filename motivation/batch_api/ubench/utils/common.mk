TARGET=$(SOURCE:.c=.o)
_TARGET=$(realpath $(addprefix $(BUILD_DIR)/, $(TARGET)))

# $(info "target: $(_TARGET)")

.PHONY: all clean load unload

all: $(BUILD_DIR) $(_TARGET)

clean:
	rm $(_TARGET)

# detach XDP program from interface
unload:
	cd $(ROOT) && /bin/bash ./unload.sh

load:
	cd $(ROOT) && /bin/bash ./load.sh $(_TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.bpf.o: %.bpf.c
	clang -S \
	-target bpf \
	-Wall \
	-g -O2 -emit-llvm \
	-o $@.ll $<
	llc -mcpu=probe -march=bpf -filetype=obj -o $@ $@.ll
