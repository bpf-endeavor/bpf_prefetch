#! /bin/bash
pci_addr="81:00.1"
iface_name="eno2"
devbind="/users/farbod/dev/dpdk-23.11/usertools/dpdk-devbind.py"
ip_addr="192.168.1.2/24"

usage() {
	echo "usage: $0 bind/unbind"
	exit 1
}

if [ $# -lt 1 -o -z "$1" ]; then
	usage
fi

if [ $1 = "bind" ]; then
	sudo $devbind -s
	sudo ifconfig $iface_name down
	sudo $devbind -u $pci_addr
	sudo $devbind -b vfio-pci $pci_addr
	sudo $devbind -s
elif [ $1 = "unbind" ]; then
	sudo $devbind -s
	sudo $devbind -u $pci_addr
	sudo $devbind -b ixgbe $pci_addr
	sudo ip link set dev $iface_name up
	sudo ip addr add $ip_addr dev $iface_name
	sudo $devbind -s
else
	usage
fi
