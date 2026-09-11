#!/bin/sh

DUT_SERVER="" # the IP of DUT server's control interface
DUT_USER="" # username to access the other machine 
GEN_EXP_IP="" # experiment IP of the generator (192.168.1.2)
DUT_NET_IFACE="" # the name of the experiment network interface on the DUT machnie (e.g., eth01)
DUT_MAC_ADDR="" # the MAC address of the experimnet network interface
GEN_MAC_ADDR="" # the MAC address of the generator's experiment network interface


_check_config() {
    # The script including this can define an array with `_must_define` and
    # then use this function to enforce it
    for field in ${_must_define[@]}; do
        if [ -z "${!field}" ]; then
            echo "Error:"
            echo "\"$field\" was not defined"
            echo "This script requires all these variables: ${_must_define[@]}"
            exit 1
        fi
    done
}

