#!/bin/bash

DUT_REPO_LOCATION=$(realpath "$(dirname $0)/../../../")
GEN_BMC_SCRIPT_LOCATION=$(realpath "$(dirname $0)/..")

source $DUT_REPO_LOCATION/config.sh
_must_define=( DUT_SERVER DUT_USER DUT_NET_IFACE )
_check_config

DUT_BMC_SCRIPT_LOCATION=$DUT_REPO_LOCATION/scripts/bmc

RESULT_DIR=$HOME/results/bmc/
mkdir -p "$RESULT_DIR"

start_server() {
	mode=$1
	case $mode in
		none)     flag="" ;;
		baseline) flag=--bmc-baseline ;;
		prefetch) flag=--bmc-prefetch ;;
		batch)    flag=--bmc-batch ;;
		batch-pf) flag=--bmc-batch-pf ;;
		*)
			echo "Script is broken: unknown mode $mode"
			exit 1
			;;
	esac
	ssh $DUT_USER@$DUT_SERVER <<EOF
		cd $DUT_BMC_SCRIPT_LOCATION
		export NET_IFACE=$DUT_NET_IFACE
		./run_server.sh $flag &> /dev/null < /dev/null &
		sleep 20
EOF
	echo "Server is running..."
	# TODO: make sure that the server is actually running. it might fail.
}

tear_down() {
	ssh $DUT_USER@$DUT_SERVER <<EOF
		sudo pkill -INT run_server.sh
		sleep 2
		sudo pkill -INT memcached
		sudo pkill -INT bmc
		PID=\$(ps -x | grep -e "run_server.sh" | grep -v "grep" | awk '{print \$1}')
		sudo kill \$PID
		sleep 2
EOF
}

run_records_sweep() {
	cd $GEN_BMC_SCRIPT_LOCATION
	./run2.sh
}

collect_results() {
	mode=$1
	D=$RESULT_DIR/$mode
	mkdir -p $D
	mv $RESULT_DIR/bmc_performance_*.txt $D/
}

do_exp() {
	mode=$1

	# make sure things are stopped
	tear_down &> /dev/null
	sleep 1

	echo "Mode: $mode"
	start_server $mode

	sleep 5
	run_records_sweep

	tear_down &> /dev/null
	sleep 1

	collect_results $mode
	echo '---------'
}

on_signal() {
	tear_down &> /dev/null
	exit 1
}

main() {
	trap 'on_signal' SIGINT SIGHUP
    # modes=( none baseline prefetch batch batch-pf )
    # Figure 6 only has baseline and batch-pf
    modes=( baseline batch-pf )
	for mode in ${modes[@]}; do
		do_exp $mode
	done
	echo Done
}

main
