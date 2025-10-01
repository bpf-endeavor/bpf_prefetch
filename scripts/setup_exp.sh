#!/bin/bash
set -e
# set -x

RUN=1

CPU_FREQ_AVAIL=false
IS_INTEL=false

function write_to {
	echo $1 | sudo tee $2 > /dev/null
}

function survery {
	# Survey system hardware and configuration
	tmp=$(sudo cpupower  frequency-info | grep governor | cut -d ' ' -f 6)
	if [ $tmp != "Not" ]; then
		CPU_FREQ_AVAIL=true
		echo can configure cpupower governor
	fi

	tmp=$(lscpu | grep "Vendor ID" | awk '{print $3}')
	if [ tmp = "GeniunIntel" ]; then
		IS_INTEL=true
		echo CPU is intel
	fi
}

function on_signal {
	echo "On signal"
	RUN=0

	remove_all_flow_rules $NET_IFACE

	if [ $CPU_FREQ_AVAIL = true ]; then
		sudo cpupower frequency-set -g schedutil > /dev/null
	fi

	if [ $IS_INTEL = true ]; then
		sudo x86_energy_perf_policy normal
		echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
	fi

	sudo cpupower idle-set -D 4 > /dev/null

	write_to 1 /proc/sys/kernel/numa_balancing
	write_to 1 /sys/kernel/mm/ksm/run
	write_to madvise /sys/kernel/mm/transparent_hugepage/enabled
	write_to on /sys/devices/system/cpu/smt/control

	# sudo sysctl -w kernel.bpf_stats_enabled=1
	sudo systemctl start irqbalance
	# sudo ethtool -K $NET_IFACE rx-checksumming on tso on gso on gro on lro off
	echo "Done!"
}

function is_iface_down {
	DEV=$1
	RET=0
	ip link | grep $NET_IFACE | grep DOWN &> /dev/null
	RET=$?
	if [ $RET -eq 0 ]; then
		echo "true"
	else
		echo "false"
	fi
}

function prepare_iface {
	DEV=$1
	IP=$2
	sudo ip link set dev $DEV up
	sudo ip addr add $IP dev $DEV
}

function remove_all_flow_rules {
	DEV=$1
	for x in $(sudo ethtool -u $DEV | grep Filter | cut -d ' ' -f 2); do
		sudo ethtool -U $DEV delete $x
	done
}

function add_flow_rules {
	DEV=$1
	sudo ethtool -U $DEV flow-type udp4 dst-port 8080 action 3
	sudo ethtool -U $DEV flow-type udp4 dst-port 11211 action 3
	sudo ethtool -U $DEV flow-type tcp4 dst-port 8080 action 3
}

function report_nic_numa_node {
	DEV=$1
	x=$(cat /sys/class/net/$DEV/device/numa_node)
	echo "NIC ($DEV) is connected to NUMA $x"
}

function main {
	survery

	TMP=$(is_iface_down $NET_IFACE)
	if [ $TMP = "true" ]; then
		echo "$NET_IFACE is down"
		exit 1
	fi

	report_nic_numa_node $NET_IFACE

	# Update flow rules
	remove_all_flow_rules $NET_IFACE
	add_flow_rules $NET_IFACE

	if [ $CPU_FREQ_AVAIL = true ]; then
		sudo cpupower frequency-set -g performance
	fi

	sudo cpupower idle-set -D 1 > /dev/null

	if [ $IS_INTEL = true ]; then
		sudo x86_energy_perf_policy performance
		echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
	fi

	write_to 0 /proc/sys/kernel/numa_balancing
	write_to 0 /sys/kernel/mm/ksm/run
	write_to never /sys/kernel/mm/transparent_hugepage/enabled
	write_to off /sys/devices/system/cpu/smt/control

	sudo sysctl -w kernel.bpf_stats_enabled=0
	sudo systemctl stop irqbalance

	# sudo ethtool -K $NET_IFACE rx-checksumming off tso off gso off gro off lro off

	trap "on_signal" SIGINT SIGHUP
	echo "hit Ctrl-C to terminate"
	while [ $RUN -eq 1 ] ; do
		sleep 3
	done
}


if [ "x$NET_IFACE" = "x" ]; then
	echo "NET_IFACE is not set"
	exit 1
fi

main
