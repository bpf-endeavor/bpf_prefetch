CURDIR = $(shell pwd)
DEPS_DIR = $(CURDIR)/deps

make_project: build_libbpf

build_libbpf: ./libs/libbpf/
	# Update submodules
	git submodule update --init
	# # Create 3rd-party deps directory
	if [ ! -d  ${DEPS_DIR} ]; then mkdir -p ${DEPS_DIR}; fi
	# Build libbpf into deps directory
	BUILD_STATIC_ONLY=y DESTDIR=${DEPS_DIR} OBJDIR=${DEPS_DIR} $(MAKE) -C $</src install
