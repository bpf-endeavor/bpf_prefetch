#! /bin/bash

usage() {
	echo "Make sure the flow-steering rules are setuped for M1 & M2"
	echo "Usage run_server: default behaviour: only run the memcached"
	echo "  --bmc-baseline: run with baseline bmc"
	echo "  --bmc-batch: run with batch aware bmc"
	echo
}
usage

which jq &> /dev/null
if [ $? -ne 0 ]; then
	echo The script requires \"jq\" tool to be installed
	exit 1
fi

if [ -z "$NET_IFACE" ]; then
	echo NET_IFACE is not set. Set it to the interface on which you want to attach BMC
	exit 1
fi

# Global variables
CURDIR=$(dirname $0)
OTHERS=$CURDIR/../../others
MEMCD=$OTHERS/memcached/memcached
IFINDEX=$(ip -j addr show $NET_IFACE | jq .[0].ifindex)
SERVER_IP=192.168.1.1
UDP_PORT=11211
PID_FILE=/tmp/M1_PID

HAS_BMC=0
BMC_MODE=None
while [ $# -gt 0 ]; do
	case $1 in
		--bmc-baseline)
			HAS_BMC=1
			BMC_MODE=original
			shift
			;;
		--bmc-batch)
			HAS_BMC=1
			BMC_MODE=batch
			shift
			;;
		*)
			echo Unsupported parameter \""$1"\"
			exit 1
			;;
	esac
done
if [ $HAS_BMC -ne 0 ]; then
	BMC_BIN=$(realpath $OTHERS/bmc_bins/$BMC_MODE/bmc)
	if [ ! -f $BMC_BIN ]; then
		echo "Internal error: did not found $BMC_BIN"
		exit 1
	fi
fi

clean_up() {
	# Kill memcached
	if [ -f $PID_FILE ]; then
		kill -SIGINT $(cat $PID_FILE)
	else
		pkill -SIGINT memcached
	fi

	# Detach BMC
	if [ $HAS_BMC -eq 1 ]; then
		sudo pkill -SIGINT bmc
		sleep 1
		sudo tc filter del dev $NET_IFACE egress
		sudo tc qdisc del dev $NET_IFACE clsact
		sudo rm /sys/fs/bpf/bmc_tx_filter
	fi

	echo
	echo "BMC Stats:"
	cat /tmp/bmc_stats.txt
	echo ------
}

on_sig() {
	echo on signal...
	quit=1
	clean_up
}

main() {
	trap 'on_sig' SIGINT SIGHUP
	quit=0

	# Make sure nothing is running or open from previous execution
	clean_up &> /dev/null

	# Memcached
	taskset -c 4 \
		$MEMCD -U $UDP_PORT -l $SERVER_IP \
			-m 1024 -M -k -P $PID_FILE -d -t 1 -C 2>&1 > /dev/null

	if [ $HAS_BMC -eq 1 ]; then
		$( sudo $BMC_BIN $IFINDEX 2>&1 > /dev/null ) &
		TMP_PID=$!
		disown $TMP_PID

		sleep 3
		if [ ! -d /proc/$TMP_PID ]; then
			echo "failed to run BMC"
			clean_up
			exit 1
		fi

		$(sudo tc qdisc add dev $NET_IFACE clsact 2>&1 > /dev/null)
		$(sudo tc filter add dev $NET_IFACE egress \
			bpf object-pinned /sys/fs/bpf/bmc_tx_filter 2>&1 > /dev/null)
	fi

	echo "Ctrl-C to stop..."
	while [ "$quit" -ne 1 ]; do
		sleep 1
	done

	echo ...
	clean_up
	echo Done
}

main

