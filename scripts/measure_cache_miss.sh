#!/bin/bash
CORE=$1
sudo perf stat -C $CORE \
	-e cycles \
	-e  instructions \
	-e cache-references \
	-e cache-misses \
	-e L1-dcache-loads \
	-e L1-dcache-load-misses \
	-r 3  -- sleep 1
