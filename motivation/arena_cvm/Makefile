.PHONY: default clean
build_dir = build

default: $(build_dir)
	# Make eBPF program skeleton object
	$(MAKE) -f Makefile.bpf
	# Make the userspace loader program
	$(MAKE) -f Makefile.user

# create the build dir if not existing
$(build_dir):
	mkdir -p $@

clean:
	if [ -d $(build_dir) ]; then rm -r $(build_dir); fi
