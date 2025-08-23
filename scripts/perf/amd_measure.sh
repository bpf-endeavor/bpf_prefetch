#!/bin/bash
cpu=$0
sudo perf stat -C $0 \
	-e cycles \
	-e instructions \
	-e branch-instructions \
	-e branch-misses \
	-e cache-references \
	-e cache-misses \
	-e alignment-faults \
	-e page-faults \
	-e dTLB-loads \
	-e dTLB-misses \
	-r 3 -- sleep 1

