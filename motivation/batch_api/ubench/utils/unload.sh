#!/bin/bash
set -e
. check_net_iface.sh
sudo bpftool net detach xdp dev "$NET_IFACE"

