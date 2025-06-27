#! /bin/bash
set -e
set -x

. check_net_iface.sh

# First argument is the path to the bpf binary object
bin="$1"
bin_name=$(echo "$(basename $bin)" | tr '.' '_')
prog_name=""
path="/sys/fs/bpf/${bin_name}_${prog_name}"
sudo bpftool prog load $bin $path type xdp
sudo bpftool net attach xdpdrv pinned $path dev "$NET_IFACE"

