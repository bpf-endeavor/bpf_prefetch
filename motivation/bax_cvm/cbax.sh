#!/bin/sh
IN=$1
OUT=$2

FIND='#include \"bax\/bax\.h\"'
BAX_DIR='./../../libs/bax'
BAX_HEADER="$BAX_DIR/bax.h"

ESCAPED_BAX_DIR=$(echo $BAX_DIR | sed -e 's/\//\\\//g' -e 's/\./\\\./g') 
DEBUG_FILE=./de.txt

cat $IN | \
	 sed -e "/$FIND/r $BAX_HEADER" | \
	 sed -e "/$FIND/d" | \
	 sed -e "s/\(bax_pre_processor\.m4\)/$ESCAPED_BAX_DIR\/\1/1" | \
	 tee de.txt | m4 -E | \
	 clang-format > $OUT
