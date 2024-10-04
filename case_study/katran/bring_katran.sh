#!/bin/bash

source ./common.sh

git clone https://github.com/facebookincubator/katran.git $K_DIR
cd $K_DIR
git checkout fd1b7c4ba4024a4e9f070ddb63e0243ad1216b1a
git submodules update --init --recursive

mkdir -p $INSTALL_DIR/deps
pushd $INSTALL_DIR/deps

# FastFloat
git clone https://github.com/fastfloat/fast_float fast_float
mkdir -p fast_float/_build
pushd fsat_float/_build/
cmake ../
make install

popd
./build_katran.sh

BPF_PROG_DIR=$INSTALL_DIR/deps/bpfprog/bpf
BALANCER_PROG=$BPF_PROG_DIR/balancer.bpf.o

mkdir -p ./bpf/
cp $BALANCER_PROG ./bpf/katran.o
