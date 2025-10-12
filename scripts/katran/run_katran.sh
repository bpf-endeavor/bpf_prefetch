#!/bin/bash
set -e

# Generate traffic towards this IP
VIRTUAL_IP=10.10.0.1
SERVICE_PORT=8080

OTHER_SERVER_IP=192.168.1.2
DEFAULT_MAC="0c:42:a1:dd:57:ec" # other server's mac
FORWARDING_CORE=3

CURDIR=$(dirname $0)
OTHERS=$(realpath $CURDIR/../../others)
KATRAN_DIR=$OTHERS/katran
KATRAN_BUILD_DIR=$KATRAN_DIR/_build/build
DEPS_DIR=$KATRAN_DIR/_build/deps

CLIENT=$KATRAN_DIR/example_grpc/katran_client
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

	sudo pkill -SIGINT katran_server_grpc || true
	sleep 2

	CMD="${GRPC_SERVER} \
		-balancer_prog=${DEPS_DIR}/bpfprog/bpf/balancer.bpf.o \
		-intf=${NET_IFACE} \
		-hc_forwarding=false \
		-map_path=$XDPROOT_PIN \
		-default_mac $DEFAULT_MAC \
		-forwarding_cores=$FORWARDING_CORE \
		-shutdown_delay 1000 \
		-prog_pos=2"
	$(sudo sh -c "$CMD" 2>&1 1> /dev/null) &
}

config_lb() {
	if [ ! -f $CLIENT ]; then
		echo 'GRPC client was not found'
		on_signal
		exit 1
	fi
	echo configuring...
	$CLIENT -A -t $VIRTUAL_IP:$SERVICE_PORT
	$CLIENT -a -t $VIRTUAL_IP:$SERVICE_PORT -r $OTHER_SERVER_IP
	$CLIENT -l
}

report_stats() {
	$CLIENT -s
}

running=0
on_signal() {
	sudo pkill -SIGINT katran_server_grpc
	running=0
}

main() {
	# configure virtual ip on the machine if it's not already configured
	ip -j addr show lo | jq .[0].addr_info[].local | grep $VIRTUAL_IP &> /dev/null
	if [ $? -ne 0 ]; then
		sudo ip address add $VIRTUAL_IP/24 dev lo
	fi

	start_server
	sleep 2

	pidof katran_server_grpc &> /dev/null
	if [ $? -ne 0 ]; then
		# pidof katran_server_grpc
		# echo $?
		echo "Failed to launch server"
		exit
	fi

	config_lb

	trap 'on_signal' SIGINT SIGHUP

	echo 'Hit Ctrl+C to terminate ...'

	# report_stats

	running=1
	while [ $running -eq 1 ]; do
		sleep 1
	done
	sleep 2

	echo Done!
}

main
