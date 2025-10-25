# Update binaries

CURDIR=$(dirname $0)
OTHERS=$(realpath $CURDIR/../../others)
KATRAN_DIR=$OTHERS/katran
KATRAN_BUILD_DIR=$KATRAN_DIR/_build/build
DEPS_DIR=$KATRAN_DIR/_build/deps

CLIENT=$KATRAN_DIR/example_grpc/katran_client
GRPC_SERVER=${KATRAN_BUILD_DIR}/example_grpc/katran_server_grpc
BPF=${DEPS_DIR}/bpfprog/bpf/balancer.bpf.o

BRANCH=$(cd $KATRAN_DIR; git branch --show)
OUTPUT_DIR=$OTHERS/katran_bins/$BRANCH

if [ ! -d $OUTPUT_DIR ]; then
	mkdir -p $OUTPUT_DIR || (echo failed to create output dir ; exit 1)
fi

cp $CLIENT $OUTPUT_DIR/
cp $GRPC_SERVER $OUTPUT_DIR/
cp $BPF $OUTPUT_DIR/

echo done
