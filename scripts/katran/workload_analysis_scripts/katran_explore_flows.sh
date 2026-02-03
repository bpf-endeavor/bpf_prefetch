#!/bin/bash

DUT_SERVER=128.110.219.75
DUT_USER=farbod

DUT_REPO_LOCATION=/users/farbod/bpf_prefetch
DUT_PERF_SCRIPT_LOCATION=$DUT_REPO_LOCATION/scripts
DUT_KATRAN_SCRIPT_LOCATION=$DUT_REPO_LOCATION/scripts/katran
LOAD_GEN_LOCATION=/users/farbod/gen/dpdk-client-server/

EXP_DURATION=30
CPU_CORE=3 # katran is configured to run on this core
DUT_NET_IFACE=enp65s0f0np0
DUT_MAC_ADDR=0c:42:a1:dd:5b:88
# TODO: load gen parameters are hardcoded

PERF_TMP_FILE=/tmp/perf_logs.txt
LOADGEN_TMP_FILE=/tmp/load_gen_log.txt

RESULT_DIR=~/results/


generate_traffic() {
	flows=$1
	zipf_par=$2

	case $flows in
		1) ips=1 ;;
		10) ips=10 ;;
		100) ips=100 ;;
		1000) ips=1000;;
		10000) ips=1000;;
		100000) ips=1000;;
		1000000) ips=1000;;
		2000000) ips=2000;;
		3000000) ips=3000;;
		4000000) ips=4000;;
		5000000) ips=5000;;
		6000000) ips=6000;;
		8000000) ips=8000;;
		*)
			echo Script is broken $flows
			exit 1
			;;
	esac
	ports=$((flows / ips))

	echo "Flows=$flows --> $ips x $ports"

	cd $LOAD_GEN_LOCATION
	sudo ./build/client_tcp_timestamp \
		-a $NET_PCI --lcores "0@(2,4),1@(6,8)" -- \
		--num-queue 2 \
		--client \
		--ip-local 192.168.1.2 \
		--ip-dest 10.10.0.1 \
		--duration $EXP_DURATION --rate 1700000 \
		--no-arp $DUT_MAC_ADDR \
		--zipf-client-addr $flows/$ports/$zipf_par &> $LOADGEN_TMP_FILE
}

tear_down() {
	sudo pkill dpdk-client-s
	ssh $DUT_USER@$DUT_SERVER <<EOF
		sudo pkill -INT run_katran.sh
		sleep 2
		sudo pkill katran_server_g
		PID=\$(ps -x | grep -e "run_katran.sh" | grep -v "grep" | awk '{print \$1}')
		sudo kill \$PID
		sleep 2
EOF
}

gather_perf() {
	ssh $DUT_USER@$DUT_SERVER <<EOF
		cd $DUT_PERF_SCRIPT_LOCATION
		./measure_cache_miss.sh $CPU_CORE
		sleep 2
EOF
}

start_server() {
	mode=$1
	case $mode in
		baseline)
			flag=--baseline ;;
		bax)
			flag=--bax ;;
		*)
			echo Script broken 2
			exit 1
			;;
	esac
	ssh $DUT_USER@$DUT_SERVER <<EOF
		cd $DUT_KATRAN_SCRIPT_LOCATION
		export NET_IFACE=$DUT_NET_IFACE
		./run_katran.sh $flag --lru-routing &> /dev/null < /dev/null &
		sleep 20
EOF
	echo "Server is running..."
	# TODO: make sure that the server is actually running. it might fail.
}

do_exp() {
	flows=$1
	zipf_par=$2
	mode=$3

	# make sure things are stopped
	tear_down &> /dev/null
	sleep 1

	echo "Mode: $mode  flows: $flows  zipf parameter: $zipf_par"
	start_server $mode &> /dev/null

	sleep 5
	generate_traffic $flows $zipf_par &

	sleep 10
	gather_perf &> $PERF_TMP_FILE

	sleep 25
	tear_down &> /dev/null
	sleep 1

	D=$RESULT_DIR/$mode
	mkdir -p $D
	mv $PERF_TMP_FILE $D/perf_${flows}_${zipf_par}.txt
	mv $LOADGEN_TMP_FILE $D/load_${flows}_${zipf_par}.txt
	echo '---------'
}

on_signal() {
	tear_down &> /dev/null
	exit 1
}

main() {
	trap 'on_signal' SIGINT SIGHUP
	flows=( 1 10 100 1000 10000 100000 1000000 2000000 4000000 6000000 8000000 )
	for z in 0 0.5 1.0 1.5 2; do
		for mode in baseline bax; do
			for f in ${flows[@]}; do
				do_exp $f $z $mode
			done
		done
	done
	echo Done
}

main

