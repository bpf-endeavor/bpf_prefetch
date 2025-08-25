#!/bin/bash
set -e
# set -x

read_trace() {
	# args: 1, number of seconds to wait
	TMP_FILE=/tmp/tmp_trace.txt
	cat /sys/kernel/tracing/trace_pipe > $TMP_FILE &
	PID=$!
	sleep $1
	kill $PID
	cat $TMP_FILE | sed 's/\([0-9]\+\)(kpps)/\1/'
}

main() {
	# if [ $EUID -ne 0 ]; then
	# 	echo Run as root!
	# 	exit 1
	# fi

	cd /proc
	# clear trace logs
	read_trace 1

	for bs in $(seq 1 32); do
		echo Batch size: $bs
		echo $bs > mlx5_xdp_batch
		sleep 1
		read_trace 20
	done
}

main

