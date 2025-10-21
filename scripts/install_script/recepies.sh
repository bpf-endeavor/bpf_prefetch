# Make sure we already have set these
if [ -z "$CURDIR" ] || [ -z "$ROOTDIR" ] || [ -z "$THIRD" ] || [ -z "$KERNEL_SOURCE_DIR" ]; then
	echo Some variables are not defined!
	exit 1
fi

install_pkgs() {
	## INSTALL PACKAGES
	# Disclaimer: these are a set of packages that I use across my projects. Not
	# all of them are exactly related to this repository. Have a look and decide
	# if you want to install them or not.

	PACKAGES=( htop build-essential exuberant-ctags mosh cmake \
		silversearcher-ag pkg-config libelf-dev libdw-dev gcc-multilib python3 \
		python3-pip python3-venv libpcap-dev libpci-dev libnuma-dev flex bison \
		libslang2-dev libcap-dev libssl-dev libncurses-dev jq meson ninja-build \
		python3-pyelftools libyaml-dev libcsv-dev nlohmann-json3-dev gcc g++ \
		doxygen graphviz libhugetlbfs-dev libnl-3-dev libnl-route-3-dev \
		uuid-dev git-lfs libbfd-dev libbinutils gettext libtraceevent-dev \
		libzstd-dev libunwind-dev libreadline-dev numactl neovim \
		iperf libevent-dev autotools-dev automake "linux-tools-$(uname -r)" \
		qemu qemu-system-x86 )

	sudo apt update
	sudo apt install -y "${PACKAGES[@]}"
	pip install scapy flask
}

get_custom_kernel() {
	git clone git@github.com:bpf-endeavor/kernel-sw-prefetch.git $KERNEL_SOURCE_DIR
	cd $KERNEL_SOURCE_DIR || exit 1
	mkdir ./build/
	cd ./build/ || exit 1
	make -C ../ O=$(pwd) defconfig
	# bring config file
	cp $CURDIR/kernel_config .config
	yes '' | make oldconfig

	cores=$(nproc)
	if [ $cores -lt 1 ]; then
		cores=1
	elif [ $cores -gt 32 ]; then
		cores=32
	fi
	make -j $cores
}

bring_bmc() {
	# Print instructions
	# set -x

	PATCH_DIR=$(realpath $ROOTDIR/patches/bmc)
	BMC_DIR=$THIRD/bmc-cache
	MEMCD_DIR=$THIRD/memcached

	if [ -d "$MEMCD_DIR" ]; then
		rm -rf "$MEMCD_DIR"
	fi

	if [ -d "$BMC_DIR" ]; then
		rm -rf "$BMC_DIR"
	fi

	# Memcached
	# sudo apt install -y libevent-dev
	git clone https://github.com/memcached/memcached $MEMCD_DIR
	cd $MEMCD_DIR || exit 1
	git checkout 1.6.31
	./autogen.sh
	./configure
	make -j

	# BMC + patches
	git clone https://github.com/Orange-OpenSource/bmc-cache/ $BMC_DIR
	cd $BMC_DIR/bmc/
	SHA=2997145508e02c55aa92f63a0009ac2a26800810
	git checkout $SHA
	for branch_name in $(ls $PATCH_DIR); do
		git checkout -b $branch_name
		git am $PATCH_DIR/$branch_name/*.patch
		make
		# store different versions of BMC binary
		BIN_DIR=$THIRD/bmc_bins/$branch_name
		mkdir -p $BIN_DIR/
		cp ./bmc ./bmc_kern.o $BIN_DIR/
		make clean
		git checkout $SHA
	done

	set +x
}

install_go() {
	cd $HOME
	which go > /dev/null
	if [ $? -eq 0 ]; then
		V=$(go version | cut -d ' ' -f 3)
		if [ $V = go1.22.3 ]; then
			# we have already installed go
			return
		fi
	fi

	mkdir go_tmp_dir/
	cd go_tmp_dir/
	wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
	sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
	echo "export PATH=\$PATH:/usr/local/go/bin:$HOME/go/bin" | tee -a $HOME/.bashrc
	export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
}

bring_katran() {
	KATRAN_DIR=$THIRD/katran
	if [ -d $KATRAN_DIR ]; then
		echo 'Katran directory already exists'
		exit 1
	fi

	git clone git@github.com:facebookincubator/katran.git $KATRAN_DIR
	cd $KATRAN_DIR
	SHA=bce70c8c4c13fd6e2d9786503f1472e2ca493cfb
	git checkout $SHA

	bash ./build_katran.sh

	# Remove older version of go
	sudo apt -y purge $(sudo apt list --installed 2> /dev/null | grep ^go | cut -d / -f 1)

	# Install a newer version of go
	install_go

	# Compile the grpc client
	cd $KATRAN_DIR/example_grpc/
	sudo apt install protobuf-compiler
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
	go_bin=$HOME/go/bin
	cp $go_bin/protoc-gen-go-grpc $go_bin/protoc-gen-go_grpc
	cd ../

	# Apply patches
	PATCH_DIR=$(realpath $ROOTDIR/patches/katran)
	for branch_name in $(ls $PATCH_DIR); do
		# create a branch and apply the patch
		git checkout -b $branch_name
		git am $PATCH_DIR/$branch_name/*.patch

		# compile
		bash ./build_katran.sh

		# store binaries
		BIN_DIR=$THIRD/katran_bins/$branch_name
		mkdir -p $BIN_DIR/
		mkdir -p $BIN_DIR/bpf
		cp ./_build/deps/bpfprog/bpf/*.o $BIN_DIR/bpf/
		cp ./_build/build/example_grpc/katran_server_grpc $BIN_DIR/

		git checkout $SHA
	done
}

install_clang() {
	## INSTALL CLANG
	cd "$THIRD" || exit 1
	# Arena requires version 19
	CLANG_VERSION=19
	wget https://apt.llvm.org/llvm.sh
	chmod +x llvm.sh
	sudo ./llvm.sh $CLANG_VERSION
	# Configure the clang-14 as clang
	sudo bash "$CURDIR/update-alternatives-clang.sh" $CLANG_VERSION 100
}

bring_arena_kmod() {
	cd "$THIRD" || exit 1
	git clone git@github.com:bpf-endeavor/ebpf-arena-tutorial.git arena_kmod
	ver_major=$(uname -r | cut -d '.' -f 1)
	ver_minor=$(uname -r | cut -d '.' -f 2)
	if [ $ver_major -lt 6 ] -o [ $ver_minor -lt 9 ]; then
		echo "this kernel verison probably does not support arena. skipping..."
		return
	fi
	cd arena_kmod/kmod
	make || exit 1
}

install_kernel_tools() {
	## Install BPFTOOL
	cd "$KERNEL_SOURCE_DIR/tools/bpf/" || exit 1
	make clean
	make -j
	sudo make install

	## Install perf
	cd "$KERNEL_SOURCE_DIR/tools/perf" || exit 1
	make clean
	BUILD_NONDISTRO=1 make
	target=/usr/bin/perf
	if [ -f $target ]; then
		sudo rm $target
	fi
	sudo ln -s "$KERNEL_SOURCE_DIR/tools/perf/perf" $target

	## INSTALL CPU POWER
	cd "$KERNEL_SOURCE_DIR/tools/power/cpupower" || exit 1
	make -j
	sudo make install
	echo /usr/lib64 | sudo tee -a /etc/ld.so.conf.d/tmp.conf
	sudo ldconfig

	## INSTALL x86 Energy
	cd "$KERNEL_SOURCE_DIR/tools/power/x86/x86_energy_perf_policy" || exit 1
	make
	sudo make install
}

install_dwarf() {
	# INSTALL DWARF (required for BTF)
	cd $THIRD || exit 1
	git clone https://github.com/acmel/dwarves.git
	cd dwarves
	git checkout v1.29
	mkdir build/
	cd build/
	cmake ../
	make -j
	sudo make install
	sudo ldconfig
}

