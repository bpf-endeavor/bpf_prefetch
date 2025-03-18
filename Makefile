CURDIR = $(shell pwd)
DEPS_DIR = $(CURDIR)/deps

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
