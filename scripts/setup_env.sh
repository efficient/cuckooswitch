#!/bin/bash

#
# Sets RTE_TARGET and does a "make install"
#
setup_target()
{
    make install T=${RTE_TARGET}
}

#
# Unloads igb_uio.ko.
#
remove_igb_uio_module()
{
	echo "Unloading any existing DPDK UIO module"
	/sbin/lsmod | grep -s igb_uio > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod igb_uio
	fi
}

#
# Loads new igb_uio.ko (and uio module if needed).
#
load_igb_uio_module()
{
	if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko ];then
		echo "## ERROR: Target does not have the DPDK UIO Kernel Module."
		echo "       To fix, please try to rebuild target."
		return
	fi

	remove_igb_uio_module

	/sbin/lsmod | grep -s uio > /dev/null
	if [ $? -ne 0 ] ; then
		if [ -f /lib/modules/$(uname -r)/kernel/drivers/uio/uio.ko ] ; then
			echo "Loading uio module"
			sudo /sbin/modprobe uio
		fi
	fi

	# UIO may be compiled into kernel, so it may not be an error if it can't
	# be loaded.

	echo "Loading DPDK UIO module"
	sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko
	if [ $? -ne 0 ] ; then
		echo "## ERROR: Could not load kmod/igb_uio.ko."
		quit
	fi
}

#
# Unloads the rte_kni.ko module.
#
remove_kni_module()
{
	echo "Unloading any existing DPDK KNI module"
	/sbin/lsmod | grep -s rte_kni > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod rte_kni
	fi
}

#
# Loads the rte_kni.ko module.
#
load_kni_module()
{
    # Check that the KNI module is already built.
	if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko ];then
		echo "## ERROR: Target does not have the DPDK KNI Module."
		echo "       To fix, please try to rebuild target."
		return
	fi

    # Unload existing version if present.
	remove_kni_module

    # Now try load the KNI module.
	echo "Loading DPDK KNI module"
	sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko
	if [ $? -ne 0 ] ; then
		echo "## ERROR: Could not load kmod/rte_kni.ko."
		quit
	fi
}

#
# Creates hugepage filesystem.
#
create_mnt_huge()
{
	echo "Creating /mnt/huge and mounting as hugetlbfs"
	sudo mkdir -p /mnt/huge

	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -ne 0 ] ; then
		sudo mount -t hugetlbfs nodev /mnt/huge
	fi
}

#
# Removes hugepage filesystem.
#
remove_mnt_huge()
{
	echo "Unmounting /mnt/huge and removing directory"
	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -eq 0 ] ; then
		sudo umount /mnt/huge
	fi

	if [ -d /mnt/huge ] ; then
		sudo rm -R /mnt/huge
	fi
}

#
# Removes all reserved hugepages.
#
clear_huge_pages()
{
	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		echo "echo 0 > $d/hugepages/hugepages-2048kB/nr_hugepages" >> .echo_tmp
	done
	echo "Removing currently reserved hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	remove_mnt_huge
}

#
# Creates hugepages on specific NUMA nodes.
#
set_numa_pages()
{
	clear_huge_pages

	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		node=$(basename $d)
		Pages=$1
		echo "echo $Pages > $d/hugepages/hugepages-2048kB/nr_hugepages" >> .echo_tmp
	done
	echo "Reserving hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	create_mnt_huge
}

#
# Print hugepage information.
#
grep_meminfo()
{
	grep -i huge /proc/meminfo
}

export RTE_SDK=$(pwd)/../dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc

# echo $RTE_SDK

pushd "$RTE_SDK"; setup_target; popd

load_igb_uio_module
load_kni_module
set_numa_pages 2048
grep_meminfo
./dpdk_nic_bind.py --status
