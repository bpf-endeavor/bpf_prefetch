#!/bin/bash
set -e

DEFAULT_MAC="0c:42:a1:dd:57:ec"
FORWARDING_CORE=3

CURDIR=$(dirname $0)
OTHERS=$(realpath $CURDIR/../../others)
KATRAN_DIR=$OTHERS/katran
KATRAN_BUILD_DIR=$KATRAN_DIR/_build/build
DEPS_DIR=$KATRAN_DIR/_build/deps

CLIENT=$KATRAN/example_grpc/katran_client
GRPC_SERVER=${KATRAN_BUILD_DIR}/example_grpc/katran_server_grpc

if [ -z "${NET_IFACE}" ]
then
	echo NET_IFACE is not set
	exit 1
fi

start_server() {

	XDPROOT_LOADER=${KATRAN_BUILD_DIR}/katran/lib/xdproot
	XDPROOT_PIN=/sys/fs/bpf/jmp_${NET_IFACE}

	# Load xdproot
	if [ ! -f "{$XDPROOT_PIN}" ]; then
		CMD="${XDPROOT_LOADER} \
			-bpfprog ${DEPS_DIR}/bpfprog/bpf/xdp_root.o \
			-bpfpath=${XDPROOT_PIN} \
			-intf=${NET_IFACE}"
		sudo sh -c "${CMD}"
	fi

	CMD="${GRPC_SERVER} \
		-balancer_prog=${DEPS_DIR}/bpfprog/bpf/balancer.bpf.o \
		-intf=${NET_IFACE} \
		-hc_forwarding=false \
		-map_path=$XDPROOT_PIN \
		-default_mac $DEFAULT_MAC \
		-forwarding_cores=$FORWARDING_CORE \
		-shutdown_delay 1000 \
		-prog_pos=2"
	sudo sh -c "$CMD"

}

config_lb() {
	$CLIENT -A -t 10.0.0.1:8080
	$CLIENT -a -t 10.0.0.1:8080 -r 192.168.200.102
	$CLIENT -l
}

running=0
on_signal() {
	sudo pkill -SIGINT katran_server_grpc
	running=0
}

main() {
	start_server
	sleep 2
	config_lb

	trap 'config_lb' SIGINT SIGHUP

	echo 'Hit Ctrl+C to terminate ...'
	running=1
	while [ $running -eq 1 ]; do
		sleep 1
	done

	echo Done!
}

main
