#!/bin/bash
set -e

CURDIR=$(dirname $0)
OTHERS=$(realpath $CURDIR/../../others)
KATRAN_DIR=$OTHERS/katran
PATCH_DIR=$(realpath $CURDIR/../../patches/katran)
LAST_UPSTREAM_COMMIT=b8e3848427dfae3f04fd7282a1605c1d9e4155d1

cd $KATRAN_DIR || exit 1

BRANCH=$(git branch --show-current)
git format-patch $LAST_UPSTREAM_COMMIT

T=$PATCH_DIR/$BRANCH
if [ ! -d $T ]; then
	mkdir -p $T || (echo "Failed to create patch directory" && exit 1)
fi

mv *.patch $T

