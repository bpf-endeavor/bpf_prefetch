#! /bin/bash
set -e
# set -x

# files=( $(find -name "*.bpf.c") )
# for f in ${files[@]}; do
# 	echo $f:
# 	progs=( "$(grep "bbb_" "$f")" )
# 	for p in ${progs}; do
# 		echo "    - $p"
# 	done
# done


curdir=$(realpath $(dirname $0))
DIR=/users/farbod/bpf-app-offload-measurement/src
cd $DIR

xdp_binary="$curdir/echo.bpf.o"
program=bbb_echo

sudo ./build/loader -b $xdp_binary --xdp $program -i $NET_IFACE

