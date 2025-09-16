#! /bin/bash

# Some notes
echo "1- pass \`bmc' as the first argument to also configure BMC"
echo "2- Make sure the flow-steering rules are setuped for M1 & M2"
echo

PID_FILE=/tmp/M1_PID

clean_up() {
	# Kill memcached
	if [ -f $PID_FILE ]; then
		kill -SIGINT $(cat $PID_FILE)
	else
		pkill -SIGINT memcached
	fi

	# Detach BMC
	if [ $HAS_BMC -eq 1 ]; then
		sudo pkill -SIGINT bmc ; sudo pkill -SIGINT bmc
		sleep 1
		sudo tc filter del dev $NET_IFACE egress
		sudo tc qdisc del dev $NET_IFACE clsact
		sudo rm /sys/fs/bpf/bmc_tx_filter
	fi
	echo 'closed...'
}

on_sig() {
	quit=1
	clean_up
}

trap 'on_sig' SIGINT SIGHUP
quit=0

CURDIR=$(dirname $0)
OTHERS=$CURDIR/../../others
MEMCD=$OTHERS/memcached/memcached
BMC_BIN=$OTHERS/bmc-cache/bmc/bmc
IFINDEX=3
SERVER_IP=192.168.122.245
UDP_PORT=11211


HAS_BMC=0
if [ "x$1" == "xbmc" ]; then
	echo Running BMC for M1...
	HAS_BMC=1
fi

clean_up

# M1
taskset -c 1 $MEMCD -p 11211 -U $UDP_PORT -l $SERVER_IP -m 1024 -M -k -P $PID_FILE -d -t 1 -C

if [ $HAS_BMC -eq 1 ]; then
	sudo $BMC_BIN $IFINDEX &> /dev/null &
	disown $!
	sleep 3
	sudo tc qdisc add dev $NET_IFACE clsact &> /dev/null
	sudo tc filter add dev $NET_IFACE egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter &> /dev/null
fi

echo "Ctrl-C to stop..."
while [ "$quit" -ne 1 ]; do
    sleep 1
done

echo ...
clean_up
echo Done
