#! /bin/bash

if [ -z "$NET_IFACE" ]; then
	echo "NET_IFACE is not set"
	exit 1
fi

