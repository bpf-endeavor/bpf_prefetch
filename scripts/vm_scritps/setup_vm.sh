#!/bin/bash
#set -e
set -x
user_names=( ubuntu )
password=pass
base_port=9991
count_vm=${#user_names[@]}
image="ubuntu:22.04"
net_name="lxdbr0"
host_ip=128.110.219.138
echo Count VMs: $count_vm
for i in $(seq $count_vm); do
	i_=$((i-1))
	user_name="${user_names[i_]}"
	vm_name="test-vm$i"
	echo "* Createing VM $i (name: $vm_name, user: $user_name)"
	lxc launch $image $vm_name --vm -c limits.cpu=8 -c limits.memory=16GiB -d root,size=40GiB
done
sleep 20 # wait some time
lxc list
for i in $(seq $count_vm); do
	i_=$((i-1))
	user_name="${user_names[i_]}"
	vm_name="test-vm$i"
	ssh_port="$(($base_port + i))"
	lxc exec $vm_name -- useradd -s /bin/bash -m $user_name
	lxc exec $vm_name -- usermod -aG sudo $user_name
	lxc exec $vm_name -- bash -c "printf \"$password\n$password\n\" | passwd $user_name"
	lxc exec $vm_name -- rm /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
	lxc exec $vm_name -- systemctl restart sshd

	private_ip=$(lxc info $vm_name | grep inet: | grep global \
		| cut -d : -f 2 | cut -d  ' ' -f 3 | cut -d / -f 1)
	lxc network forward port add $net_name $host_ip tcp $ssh_port $private_ip 22
	echo "connect to VM: ssh $user_name@$host_ip -p $ssh_port"
	echo "---------------------------------------------------"
done

