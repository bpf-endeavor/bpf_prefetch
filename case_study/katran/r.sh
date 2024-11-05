#! /bin/bash
source common.sh
SERVER=./bins/katran_server_grpc
OTHER_MAC="9c:dc:71:56:fd:d5"
if [ -z "$NET_IFACE" ]; then
	echo NET_IFACE is not defined
	exit 1
fi
echo "Make sure the other machines MAC address is correct ($OTHER_MAC)"

sudo ip addr show ipip0
if  [ $? -ne 0 ]; then
	echo "Preparing ipip interfaces"
	sudo ip link add name ipip0 type ipip external
	sudo ip link add name ipip60 type ip6tnl external
	sudo ip link set up dev ipip0
	sudo ip link set up dev ipip60
	sudo ip a a 127.0.0.42/32 dev ipip0
	sudo ip a a 10.10.0.2/16 dev lo
	sudo tc qd add  dev $NET_IFACE clsact
	sudo /usr/sbin/ethtool --offload $NET_IFACE lro off
	for sc in $(sysctl -a | awk '/\.rp_filter/ {print $1}'); do  echo $sc ; sudo sysctl ${sc}=0; done
fi


# sudo $SERVER -help
#     -balancer_prog (path to balancer bpf prog) type: string
#       default: "./balancer.bpf.o"
#     -default_mac (mac address of default router. must be in fomrat:
#       xx:xx:xx:xx:xx:xx) type: string default: "00:00:00:00:00:01"
#     -forwarding_cores (comma separed list of forwarding cores) type: string
#       default: ""
#     -hc_forwarding (turn on forwarding path for healthchecks) type: bool
#       default: true
#     -hc_intf (interface for healthchecking) type: string default: ""
#     -healthchecker_prog (path to healthchecking bpf prog) type: string
#       default: "./healthchecking_ipip.o"
#     -intf (main interface) type: string default: "eth0"
#     -ipip6_intf (ip(6)ip6 (v6) encap interface) type: string default: "ipip60"
#     -ipip_intf (ipip (v4) encap interface) type: string default: "ipip0"
#     -lru_size (size of LRU table) type: int64 default: 8000000
#     -map_path (path to pinned map from root xdp prog. default path forces to
#       work in standalone mode) type: string default: ""
#     -numa_nodes (comma separed list of numa nodes to forwarding cores mapping)
#       type: string default: ""
#     -priority (tc's priority for bpf progs) type: int32 default: 2307
#     -prog_pos (katran's position inside root xdp array) type: int32 default: 2
#     -server (Service server:port) type: string default: "0.0.0.0:50051"
#     -shutdown_delay (shutdown delay in milliseconds) type: int32 default: 10000
#

$(sudo $SERVER \
	-balancer_prog ./bpf_source/bpf/balancer.bpf.o \
	-default_mac $OTHER_MAC \
	-forwarding_cores "0" \
	-hc_forwarding false \
	-healthchecker_prog ./bpf_source/bpf/healthchecking_ipip.o \
	-intf $NET_IFACE \
	-server "127.0.0.1:50051" \
	-shutdown_delay 1000) &

sleep 2

./bins/katran_goclient -A -u 10.10.0.2:8080
./bins/katran_goclient -a -u 10.10.0.2:8080 -r 192.168.1.2
./bins/katran_goclient -l

on_signal() {
	pkill -SIGINT katran_server_grpc
	running=0
}
trap 'on_signal' SIGINT SIGHUP
echo "Hit Ctrl-C to terminate ... "
running=1
while [ $running -eq 1 ]; do
	sleep 3
done
