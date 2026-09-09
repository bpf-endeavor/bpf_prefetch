CURDIR = $(shell pwd)
DEPS_DIR = $(CURDIR)/deps


commands = setup_dut setup_generators load_kmod configure4exp

.PHONY: setup_dut setup_generators load_kmod configure4exp

help:
	@for c in ${commands}; do \
		echo "  * $$c"; \
	done

setup_dut:
	git submodule update --init
	bash $(CURDIR)/scripts/install_script/main.sh

setup_generators:
	bash $(CURDIR)/scripts/install_script/setup_generators.sh

load_kmod:
	if [ ! -d $(CURDIR)/others/arena_kmod/kmod/ ]; then  \
		bash $(CURDIR)/scripts/install_script/main.sh; \
	fi
	cd $(CURDIR)/others/arena_kmod/kmod/ && \
		($(MAKE) clean || true) && \
		$(MAKE) && \
		$(MAKE) load
	cd $(CURDIR)/libs/kfuncs/my_memcpy && $(MAKE) && $(MAKE) load

configure4exp:
	bash $(CURDIR)/scripts/setup_exp.sh


