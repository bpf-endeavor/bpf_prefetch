#! /bin/bash

# Instead of using katran contrl plance do things in here

if [ -z "$NET_IFACE" ]; then
	echo "NET_IFACE is not defined"
	exit 1
fi

onsignal() {
	# Unload 
	sudo bpftool net detach xdp dev $NET_IFACE
	sudo rm /sys/fs/bpf/katran
	running=0
}

running=1
trap "onsignal" SIGINT SIGHUP
sudo bpftool prog load ./bpf/katran.o /sys/fs/bpf/katran type xdp dev $NET_IFACE

while [ $running -eq 1 ]; do
	sleep 3;
done
