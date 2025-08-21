CURDIR = $(shell pwd)
DEPS_DIR = $(CURDIR)/deps


commands = make_project build_libbpf install_deps load_kmod

.PHONY: make_project build_libbpf install_deps

help:
	@for c in ${commands}; do \
		echo "  * $$c"; \
	done

make_project: build_libbpf

build_libbpf: ./libs/libbpf/
	# Update submodules
	git submodule update --init
	# Pull large files
	# git lfs pull # NOTE: I do not need it always, so lets not use large files now
	# # Create 3rd-party deps directory
	if [ ! -d  ${DEPS_DIR} ]; then mkdir -p ${DEPS_DIR}; fi
	# Build libbpf into deps directory
	BUILD_STATIC_ONLY=y DESTDIR=${DEPS_DIR} OBJDIR=${DEPS_DIR} $(MAKE) -C $</src install

install_deps: build_libbpf
	bash $(CURDIR)/scripts/install_script/main.sh

load_kmod:
	if [ ! -d $(CURDIR)/others/arena_kmod/kmod/ ]; then  \
		bash $(CURDIR)/scripts/install_script/main.sh; \
	fi
	$(MAKE) -C $(CURDIR)/others/arena_kmod/kmod/ load
