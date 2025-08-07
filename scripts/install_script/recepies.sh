# Make sure we already have set these
if [ -z "$CURDIR" ] || [ -z "$ROOTDIR" ] || [ -z "$THIRD" ] || [ -z "$KERNEL_SOURCE_DIR" ]; then
	echo Some variables are not defined!
	exit 1
fi

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
	set -x

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
	for branch_name in $(ls $PATCH_DIR); do
		git checkout -b $branch_name
		git am $PATCH_DIR/$branch_name/*.patch
		make
		# store different versions of BMC binary
		BIN_DIR=$THIRD/bmc_bins/$branch_name
		mkdir -p $BIN_DIR/
		cp ./bmc ./bmc_kern.o $BIN_DIR/
		make clean
		git checkout main
	done

	set +x
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
	# sudo bash "$CURDIR/update-alternatives-clang.sh" $CLANG_VERSION 100
}

