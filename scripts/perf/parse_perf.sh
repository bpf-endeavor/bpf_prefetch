#! /bin/bash

# Parse a perf stat report and calculate things...
#

# L1 cache-miss per packet
file=$1

get_metric() {
	cat $file | grep "$1" | awk '{print $1}' | tr -d ','
}

ipcs=( $(get_metric "ipc") )
cache_misses=( $(get_metric "cache-misses" ) )
l1_miss=( $(get_metric "L1-dcache-load-misses" ) )
tput=( $(cat $file | grep "tput" | awk '{printf "%d\n", $2*1000000}') )

len=${#l1_miss[@]}
for i in $(seq 0 $(($len - 1)) ); do
	c=${cache_misses[$i]}
	l1=${l1_miss[$i]}
	t=${tput[$i]}

	l1pt=$(echo "$l1 / $t" | bc -l)
	echo "L1 miss/pkt:" $l1pt  = $l1 / $t

	cpt=$(echo "$c / $t" | bc -l)
	echo "cache miss/pkt:" $cpt  = $c / $t
	echo '-------------'
done

# echo $tput

# echo $("$l1_miss / $tput" | bc) = $l1_miss / $tput

