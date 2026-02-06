#!/bin/bash

# data/results/baseline/perf_1_0.txt
files=(
	data/results/baseline/perf_10_0.txt
	data/results/baseline/perf_100_0.txt
	data/results/baseline/perf_1000_0.txt
	data/results/baseline/perf_10000_0.txt
	data/results/baseline/perf_100000_0.txt
	data/results/baseline/perf_1000000_0.txt
	data/results/baseline/perf_2000000_0.txt
	data/results/baseline/perf_4000000_0.txt
	data/results/baseline/perf_6000000_0.txt
	data/results/baseline/perf_8000000_0.txt
)

tput_list=( 2209804.85 2154218.48 2134451.18 2179836.88 1869097.7 1391565.84 1390500.98 1379454.54 1403568.94 1353104.95)


off=0
for f in ${files[@]}; do
	echo -------------------------
	echo $f
	l1=$(cat ${f} | grep  "L1-dcache-load-misses" | awk '{print $1}' | tr -d ',')
	l3=$(cat ${f} | grep  "cache-misses" | awk '{print $1}' | tr -d ',')
	tput=${tput_list[$off]}
	off=$((off+1))
	# echo $l1
	# echo $l3
	# echo $tput
	# exit 0

	l1ppkt=$(echo "$l1/$tput" | bc -l)
	l3ppkt=$(echo "$l3/$tput" | bc -l)
	echo "l1-miss/pkt: $l1ppkt"
	echo "l3-miss/pkt: $l3ppkt"
done

