#!/bin/bash
set -e

CURDIR=$(dirname $0)
BMC_DIR=$(realpath $CURDIR/../../others/bmc-cache)
PATCH_DIR=$(realpath $CURDIR/../../patches/bmc)
LAST_UPSTREAM_COMMIT=2997145508e02c55aa92f63a0009ac2a26800810

cd $BMC_DIR || exit 1
BRANCH=$(git branch --show-current)
git format-patch $LAST_UPSTREAM_COMMIT

T=$PATCH_DIR/$BRANCH
if [ ! -d $T ]; then
	mkdir $T
fi

mv *.patch $T

