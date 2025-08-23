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


# Recompile the test programs
make clean || true
make

curdir=$(realpath $(dirname $0))
DIR=$HOME/bpf-app-offload-measurement/src
cd $DIR

# TEST=simple
# TEST=echo
TEST=random

xdp_binary="$curdir/$TEST.bpf.o"
program="bbb_$TEST"

sudo ./build/loader -b $xdp_binary --xdp $program -i $NET_IFACE

