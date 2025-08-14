#! /bin/bash

# NOTE: this script is for reading ...
exit 1

sudo apt update
sudo apt install snapd
sudo snapd refresh
sudo snapd core lxd

sudo usermod -a -G lxd $USER

# on cloudlab
sudo mkdir /home/$USER
sudo mount --bind /home/$USER /users/$USER
echo "Edit /etc/passwd and set your home directory to /home/$USER"
echo "Reload/refresh your shell/ ssh connection..."

lxc init --minimal

# add a network for experimenting
lxc network create br1     bridge.driver=native     ipv4.address=none     ipv6.address=none

# create a forward network
lxc network forward create lxdbr0 <host ctrl ip>

