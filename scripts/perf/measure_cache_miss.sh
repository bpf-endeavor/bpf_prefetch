#!/bin/bash

VENDOR=$(lscpu | grep Vendor | cut -d : -f 2 | tr -d ' ' | tr -d "\t")
if [ $VENDOR != "AuthenticAMD" ]; then
	echo "This script was tested on AMD. It might not work... check inside"
	exit 1
fi

CORE=$1
sudo perf stat -C $CORE \
	-e cpu-clock \
	-e cycles \
	-e  instructions \
	-e cache-references \
	-e cache-misses \
	-e L1-dcache-loads \
	-e L1-dcache-load-misses \
	-e branches \
	-e branch-misses \
	-e page-faults \
	-e stalled-cycles-frontend \
	-e ex_ret_cops \
	-e de_dis_uop_queue_empty_di0 \
	-e de_dis_dispatch_token_stalls1.load_queue_token_stall \
	-r 3  -- sleep 1

