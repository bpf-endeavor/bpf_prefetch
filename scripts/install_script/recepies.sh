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
