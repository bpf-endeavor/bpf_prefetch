#!/bin/bash

source ./common.sh

#sudo apt install apt install -y protobuf-compiler
#go instlal github.com/golang/protobuf/protoc-gen-go@latest

git clone https://github.com/facebookincubator/katran.git $K_DIR
pushd $K_DIR
git checkout fd1b7c4ba4024a4e9f070ddb63e0243ad1216b1a
git submodules update --init --recursive

mkdir -p $INSTALL_DIR/deps
pushd $INSTALL_DIR/deps

# FastFloat
git clone https://github.com/fastfloat/fast_float fast_float
mkdir -p fast_float/_build
pushd fast_float/_build/
cmake ../
sudo make install

popd && popd
./build_katran.sh

# pushd ./example_grpc/
# ./build_grpc_client.sh

# Back to the directory from which user invocked ths script
popd
SERVER=$INSTALL_DIR/build/example_grpc/katran_server_grpc

mkdir -p ./bins/bpf/
cp $INSTALL_DIR/deps/bpfprog/bpf/* ./bins/bpf/
cp $SERVER ./bins/
