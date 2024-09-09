#!/bin/bash
set -x
echo "boot bl or pf ?"
read b
case $b in
	bl)
		sudo grub-reboot '1>2' ;;
	pf)
		sudo grub-reboot '0' ;;
	*)
		echo unexpected!
esac

