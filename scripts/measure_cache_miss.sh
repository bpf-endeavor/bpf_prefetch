#!/bin/bash
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
	-r 3  -- sleep 1
