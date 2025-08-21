#! /bin/bash

if [ -z "$THIRD" ]; then
	echo "error, the third party directory not set"
	exit 1
fi

PROGFILE="$THIRD/_progress_level.txt"

store_progress() {
	echo "$1" > "$PROGFILE"
}

read_progress() {
	R=$(cat "$PROGFILE")
	if [ -z "$R" ]; then
		echo 0
	else
		echo "$R"
	fi
}

PROCESS=(
	install_pkgs
	install_clang
	get_custom_kernel
	bring_bmc
	bring_arena_kmod
)

