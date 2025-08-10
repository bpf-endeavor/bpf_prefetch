#! /bin/bash
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

