#!/bin/bash

MODE=original

# Generate traffic towards this IP
VIRTUAL_IP=10.10.0.1
SERVICE_PORT=8080

OTHER_SERVER_IP=192.168.1.2
DEFAULT_MAC="0c:42:a1:dd:5e:94" # other server's mac
FORWARDING_CORE=3

CURDIR=$(dirname $0)
OTHERS=$(realpath $CURDIR/../../others)

if [ -z "${NET_IFACE}" ]
then
	echo NET_IFACE is not set
	exit 1
fi

start_server() {

	# XDPROOT_LOADER=${KATRAN_BUILD_DIR}/katran/lib/xdproot
	# XDPROOT_PIN=/sys/fs/bpf/jmp_${NET_IFACE}

	# NOTE: do not load xdproot, our batch processing version does not support
	# transition between batched and non-batched (i.e., xdproot) programs
	#
	# Load xdproot
	# if [ ! -f "{$XDPROOT_PIN}" ]; then
	# 	CMD="${XDPROOT_LOADER} \
	# 		-bpfprog ${DEPS_DIR}/bpfprog/bpf/xdp_root.o \
	# 		-bpfpath=${XDPROOT_PIN} \
	# 		-intf=${NET_IFACE}"
	# 	sudo sh -c "${CMD}"
	# fi

	sudo pkill -SIGINT katran_server_g || true
	sleep 2

	# -map_path=$XDPROOT_PIN -prog_pos=2" \
	CMD="${GRPC_SERVER} \
		-balancer_prog=$BPF \
		-intf=${NET_IFACE} \
		-hc_forwarding=false \
		-default_mac $DEFAULT_MAC \
		-forwarding_cores=$FORWARDING_CORE \
		-shutdown_delay 1000"
	echo "$CMD"
	log_file=/tmp/katran_server_log.txt
	$(sudo sh -c "$CMD" &> $log_file) &
	disown $!
}

config_lb() {
	if [ ! -f $CLIENT ]; then
		echo 'GRPC client was not found'
		clean
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

clean() {
	sudo pkill -SIGINT katran_server_g
	sudo bpftool net detach xdp dev $NET_IFACE
}

running=0
on_signal() {
	echo Interrupted
	running=0
	clean
}

usage() {
	echo "Usage: run_katran.sh [--baseline | --batch ]"
}

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
			-h|--help)
				usage
				exit 0
				;;
			--batch)
				MODE=batch
				shift; shift
				;;
			--baseline)
				MODE=original
				shift; shift
				;;
			*)
				echo unrecognized argument!
				usage
				exit 1
				;;
		esac
	done


	KATRAN_DIR=$OTHERS/katran_bins/$MODE
	CLIENT=$KATRAN_DIR/katran_client
	GRPC_SERVER=${KATRAN_DIR}/katran_server_grpc
	BPF=$KATRAN_DIR/balancer.bpf.o
}

main() {
	trap 'on_signal' SIGINT SIGHUP
	parse_args $@

	# configure virtual ip on the machine if it's not already configured
	ip -j addr show lo | jq .[0].addr_info[].local | grep $VIRTUAL_IP &> /dev/null
	if [ $? -ne 0 ]; then
		sudo ip address add $VIRTUAL_IP/24 dev lo
	fi

	start_server
	sleep 20

	pidof katran_server_grpc > /dev/null
	if [ $? -ne 0 ]; then
		# pidof katran_server_grpc
		# echo $?
		echo "Failed to launch server"
		exit
	fi

	config_lb

	echo "Experiment mode: $MODE"

	echo 'Hit Ctrl+C to terminate ...'

	# report_stats

	running=1
	while [ $running -eq 1 ]; do
		sleep 1
	done
	sleep 2

	echo Done!
}

main $@
