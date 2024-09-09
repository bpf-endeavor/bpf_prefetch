#! /bin/bash
mkdir -p ./pcaps/
tmp=( 100 5000 10000 50000 100000 )
for x in ${tmp[@]} ; do
	python3 ./generate_packets.py -n $x -o ./pcaps/${x}_flows.pcap
done

tmp=( 0 0.5 1 1.5 2 )
for x in ${tmp[@]}; do
	python3 ./generate_packets.py -F -z $x -o ./pcaps/"full_z$x.pcap"
done
