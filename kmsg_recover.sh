#!/bin/bash

LBA=`grep -Ee '^\w+ \w __log_buf$' /proc/kallsyms | sed -Ee 's/(\w+) \w \w+/\1/'`
LBLA=`grep -Ee '^\w+ \w log_buf_len$' /proc/kallsyms | sed -Ee 's/(\w+) \w \w+/\1/'`

modprobe kmsg_recover lb_addr_cur=$LBA lb_len_addr_cur=$LBLA

grub-editenv - list | grep kmsg_recover | sed -Ee 's/kmsg_recover=(.*)/\1/' | tr -d '\n' > /proc/log_buf_memreg
NEW_MEMREG=`cat /proc/log_buf_memreg`
grub-editenv - set "kmsg_recover=$NEW_MEMREG"

head -c 1 /proc/log_buf > /dev/null
HEAD_EXITVAL=$?

if [ $HEAD_EXITVAL -ne 0 ]
	then
		echo "Failed to get past log." 1>&2
		rmmod kmsg_recover
		exit $HEAD_EXITVAL
fi

strings /proc/log_buf

rmmod kmsg_recover
