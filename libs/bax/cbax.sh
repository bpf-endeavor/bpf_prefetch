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

if [ $? -ne 0 ]; then
	echo "BAX: Pre-processing failed!"
	echo "$INTERMEDIATE"
	exit 1
fi

# To fix the `enum BAX_phase' location, pass it through the awk script
INTERMEDIATE=$(echo "$INTERMEDIATE" | awk -f "$CURDIR/fix_enum_def.awk")


if [ -z "$format" ]; then
	echo "$INTERMEDIATE" > "$OUT"
else
	STYLE='{"IncludeBlocks": "Preserve", "SortIncludes": "Never"}'
	echo "$INTERMEDIATE" | \
		clang-format -style="$STYLE" > "$OUT"
fi
