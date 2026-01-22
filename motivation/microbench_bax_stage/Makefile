.PHONY: default clean
build_dir = build

default: $(build_dir)
	$(MAKE) -f Makefile.baxx
	# Make eBPF program skeleton object
	$(MAKE) -f Makefile.bpf
	# Make the userspace loader program
	$(MAKE) -f Makefile.user

# create the build dir if not existing
$(build_dir):
	mkdir -p $@

clean:
	rm -f -r $(build_dir) || true
