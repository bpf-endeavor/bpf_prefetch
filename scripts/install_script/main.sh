#!/bin/bash

set -e

# !! DESCLAIMER NOTE:
# read the installation script, make sure the commands are compatible with
# your enviroment

CURDIR=$(realpath $(dirname $0))
ROOTDIR=$(realpath "$CURDIR/../../")
THIRD=$(realpath $ROOTDIR/others/)
KERNEL_SOURCE_DIR="$THIRD/kernel-sw-prefetch"

# make sure this directory exists
mkdir -p "$THIRD"

source $CURDIR/recepies.sh
source $CURDIR/setup_process.sh

# How far have we gone
PROGRESS=$(read_progress)
# How many steps we should do
PROCESS_SIZE=${#PROCESS[@]}

while [ $PROGRESS -lt $PROCESS_SIZE ]; do
	func=${PROCESS[$PROGRESS]}
	$func
	PROGRESS=$((PROGRESS+1))
	store_progress $PROGRESS
done
