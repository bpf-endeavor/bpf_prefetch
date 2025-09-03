#!/bin/bash
set -e
# set -x

CURDIR=$(dirname $0)

SSH_USER=farbod

DUT_CTRL_IP=128.110.219.139
LOAD_GEN_CTRL_IP=128.110.219.134

DUT_EXP_IP=192.168.1.1
LOAD_GEN_EXP_IP=192.168.1.2

DUT_NET_IFACE=enp65s0f0np0
LOAD_GET_NET_PCI=41:00.0

DUT_EXP_MAC="0c:42:a1:dd:59:18"

CLIENT_DIR=/users/farbod/gen/dpdk-client-server
SERVER_DIR=$(realpath $CURDIR/../../motivation/batch_api/htab_example)

TIME=20

setup_server() {
	# arg1: number of entries
	# arg2: ebpf mode
	mode="--normal"
	case $2 in
		normal) mode="--normal" ;;
		batch) mode="--batch" ;;
		pf_batch) mode="--pf-batch" ;;
	esac
	cmd=" \
		cd $SERVER_DIR; \
		NET_IFACE=$DUT_NET_IFACE sudo ./build/loader.o --entries "$1" "$mode" &> /tmp/t & \
		"
	ssh $SSH_USER@$DUT_CTRL_IP "$cmd"
}

stop_server() {
	cmd=" \
		sudo pkill -INT loader.o; \
		"
	ssh $SSH_USER@$DUT_CTRL_IP "$cmd"
}

generate_load() {
	#arg1 number of entries

	# add some extra seconds so that traffic generator does not stop sooner
	# than expected
	dur=$((TIME + 10))

	# cmd=" \
	# 	cd $CLIENT_DIR;
	# 	sudo ./build/client_udp_number \
	# 		-a $LOAD_GET_NET_PCI --lcores 0@\(2,4\) -n 4 -- \
	# 			--client --ip-local $LOAD_GEN_EXP_IP \
	# 			--ip-dest $DUT_EXP_IP \
	# 			--duration $dur \
	# 			--rate 4000000 \
	# 			--max-num $1 \
	# 			&> /tmp/t & \
	# 	"

	# TODO: God damn it Farbod, what kind of interface have you designed for
	# your traffic generator?
	cmd=" \
		cd $CLIENT_DIR; \
		sudo ./build/client_udp_number \
			-a $LOAD_GET_NET_PCI \
			--lcores 0@\(2,4\),1@\(6,8\),2@\(10,12\) \
			-n 4 -- \
			--client --ip-local $LOAD_GEN_EXP_IP \
			--ip-dest $DUT_EXP_IP --ip-dest $DUT_EXP_IP --ip-dest $DUT_EXP_IP \
			--duration 60 --rate 4000000 \
			--max-num $1 \
			--no-arp $DUT_EXP_MAC \
			--num-queue 3 --num-flow 3 \
			&> /tmp/t & \
		"
	ssh $SSH_USER@$LOAD_GEN_CTRL_IP "$cmd"
}

stop_load() {
	cmd=" \
		sudo pkill -INT client_udp_numb; \
		"
	ssh $SSH_USER@$LOAD_GEN_CTRL_IP "$cmd"
}

do_exp() {
	setup_server $1 $2
	generate_load $1
	echo "waiting $TIME sec ..."
	sleep $TIME
	stop_load
	stop_server

	read_trace 1
	sleep 5
}

# TODO: update this function to SSH to DUT machine and read logs
read_trace() {
	# args: 1, number of seconds to wait
	TMP_FILE=/tmp/tmp_trace.txt
	cat /sys/kernel/tracing/trace_pipe > $TMP_FILE &
	PID=$!
	sleep $1
	kill $PID
	cat $TMP_FILE | sed 's/\([0-9]\+\)(kpps)/\1/'
}

on_signal() {
	stop_load
	stop_server
	echo "Terminated"
	exit 1
}

main() {
	output_dir=$HOME/results/
	mkdir -p $output_dir
	mkdir -p $output_dir/baseline
	mkdir -p $output_dir/batch
	mkdir -p $output_dir/prefetch_batch

	trap on_signal SIGINT SIGHUP

	# clear the log pipe
	read_trace 1

	# entries=( 1 100 1000 10000 100000 500000 1000000 2000000 5000000 7000000 )
	entries=( 1 1000 100000 500000 1000000 1500000 2000000 2500000 3000000 3500000 4000000 5000000 )
	for e in ${entries[@]}; do
		echo "Noraml - Etnries = $e ----"
		do_exp $e normal | tee $output_dir/baseline/$e.txt

		echo "Batch  - Etnries = $e ----"
		do_exp $e batch  | tee $output_dir/batch/$e.txt

		echo "Prefetching Batch  - Etnries = $e ----"
		do_exp $e pf_batch  | tee $output_dir/prefetch_batch/$e.txt
	done
}

main

