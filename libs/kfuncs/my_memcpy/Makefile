MODULE_NAME = kfunc_memcpy_m
KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR ?= $(PWD)/

KMOD = $(BUILD_DIR)/$(MODULE_NAME).ko
KMOD_FILES = memcpy_kfunc.c

.PHONY: default clean load unload

default: $(BUILD_DIR) $(KMOD)

$(BUILD_DIR):
	mkdir -p "$@"

$(KMOD): $(KMOD_FILES)
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) modules

clean:
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) clean

load: unload
	sudo insmod $(KMOD)

unload:
	sudo rmmod $(MODULE_NAME)  || true
