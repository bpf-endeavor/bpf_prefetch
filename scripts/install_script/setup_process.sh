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
	install_dwarf
	get_custom_kernel
	install_kernel_tools
	barrier_make_sure_custom_kernel
	bring_bmc
	bring_arena_kmod
	bring_katran_p1
	bring_katran_p2
	bring_katran_p3
)

