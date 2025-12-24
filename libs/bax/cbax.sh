#!/bin/sh
IN=$1
OUT=$2

CURDIR="$(realpath "$(dirname "$0")")"

FIND='#include \"bax\/bax\.h\"'
BAX_DIR="$CURDIR"
BAX_HEADER="$BAX_DIR/bax.h"

ESCAPED_BAX_DIR=$(echo "$BAX_DIR" | sed -e 's/\//\\\//g' -e 's/\./\\\./g') 
DEBUG_FILE=./de.txt

format=$(which clang-format)

INTERMEDIATE=$(cat "$IN" | \
	 sed -e "/$FIND/r $BAX_HEADER" | \
	 sed -e "/$FIND/d" | \
	 sed -e "s/\(bax_pre_processor\.m4\)/$ESCAPED_BAX_DIR\/\1/1" | \
	 tee de.txt | m4 -E)

if [ -z "$format" ]; then
	echo "$INTERMEDIATE" > "$OUT"
else
	echo "$INTERMEDIATE" | clang-format > "$OUT"
fi
