CURDIR = $(shell pwd)
DEPS_DIR = $(CURDIR)/deps


commands = install_deps load_kmod configure4exp install_deps_gen run_all_experiments

.PHONY: make_project build_libbpf install_deps help install_deps_gen run_exp_katran run_exp_lpm_router run_exp_bmc run_exp_cvm run_all_experiments

help:
	@echo "DUT setup commands:"
	@for c in install_deps load_kmod configure4exp; do \
		echo "  * $$c"; \
	done
	@echo ""
	@echo "Workload generator setup:"
	@echo "  * install_deps_gen"
	@echo ""
	@echo "Artifact evaluation (run from workload generator):"
	@for c in run_exp_katran run_exp_lpm_router run_exp_bmc run_exp_cvm run_all_experiments; do \
		echo "  * $$c"; \
	done

# build_libbpf: ./libs/libbpf/
# 	# Update submodules
# 	git submodule update --init
# 	# Pull large files
# 	# git lfs pull # NOTE: I do not need it always, so lets not use large files now
# 	# # Create 3rd-party deps directory
# 	if [ ! -d  ${DEPS_DIR} ]; then mkdir -p ${DEPS_DIR}; fi
# 	# Build libbpf into deps directory
# 	BUILD_STATIC_ONLY=y DESTDIR=${DEPS_DIR} OBJDIR=${DEPS_DIR} $(MAKE) -C $</src install

install_deps:
	git submodule update --init
	bash $(CURDIR)/scripts/install_script/main.sh

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

install_deps_gen:
	@echo "Installing workload generator dependencies..."
	bash $(CURDIR)/scripts/workload_gen/install.sh

run_exp_katran:
	@if [ ! -f $(CURDIR)/scripts/config/experiments.conf ]; then \
		echo "Missing config: cp scripts/config/experiments.conf.template scripts/config/experiments.conf"; \
		exit 1; \
	fi
	bash $(CURDIR)/scripts/experiment_runners/run_katran.sh

run_exp_lpm_router:
	@if [ ! -f $(CURDIR)/scripts/config/experiments.conf ]; then \
		echo "Missing config: cp scripts/config/experiments.conf.template scripts/config/experiments.conf"; \
		exit 1; \
	fi
	bash $(CURDIR)/scripts/experiment_runners/run_lpm_router.sh

run_exp_bmc:
	@if [ ! -f $(CURDIR)/scripts/config/experiments.conf ]; then \
		echo "Missing config: cp scripts/config/experiments.conf.template scripts/config/experiments.conf"; \
		exit 1; \
	fi
	bash $(CURDIR)/scripts/experiment_runners/run_bmc.sh

run_exp_cvm:
	@if [ ! -f $(CURDIR)/scripts/config/experiments.conf ]; then \
		echo "Missing config: cp scripts/config/experiments.conf.template scripts/config/experiments.conf"; \
		exit 1; \
	fi
	bash $(CURDIR)/scripts/experiment_runners/run_cvm.sh

run_all_experiments:
	@if [ ! -f $(CURDIR)/scripts/config/experiments.conf ]; then \
		echo "Missing config: cp scripts/config/experiments.conf.template scripts/config/experiments.conf"; \
		exit 1; \
	fi
	@echo "Running all configured experiments..."
	$(MAKE) run_exp_katran
	$(MAKE) run_exp_lpm_router
	$(MAKE) run_exp_bmc
	$(MAKE) run_exp_cvm
	@echo "All experiments complete. Results: output/"

