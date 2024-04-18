#ifndef _JAILHOUSE_DRIVER_AXVM_H
#define _JAILHOUSE_DRIVER_AXVM_H

#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/uaccess.h>

#include "jailhouse.h"

/* The struct used for parameter passing between the kernel module and ArceOS hypervisor. */


struct arceos_axvm_create_arg {
    // VM ID, set by ArceOS hypervisor.
	__u64 vm_id;
    // Reserved.
	__u64 type;
	// Size of BIOS.
	__u64 bios_size;
    // Physical addr of BIOS, set by ArceOS hypervisor.
	__u64 bios_load_physical_addr;
    // Size of KERNEL.
	__u64 kernel_size;
    // Physical addr of kernel image, set by ArceOS hypervisor.
	__u64 kernel_load_physical_addr;
};


int arceos_cmd_axvm_create(struct jailhouse_axvm_create __user *arg);

#endif /* !_JAILHOUSE_DRIVER_AXVM_H */