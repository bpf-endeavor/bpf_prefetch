#!/bin/bash

if [ -z "$NET_IFACE" ]; then
	echo "NET_IFACE is not configured"
	exit 1
fi

./mmwatch 'ethtool -S $NET_IFACE | grep packets_phy'
