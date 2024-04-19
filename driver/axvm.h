#ifndef _JAILHOUSE_DRIVER_AXVM_H
#define _JAILHOUSE_DRIVER_AXVM_H

#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/uaccess.h>

#include "jailhouse.h"

/** The struct used for parameter passing between the kernel module and ArceOS hypervisor.
 *  See arceos/modules/axvm/src/hvc.rs
 */


struct arceos_axvm_create_arg {
    // VM ID, set by ArceOS hypervisor.
	__u64 vm_id;
    // Reserved.
	__u64 vm_type;
    // VM cpu mask.
	__u64 cpu_mask;
	// VM entry point.
	__u64 vm_entry_point;
	// Size of memory.
	__u64 ram_size;
	// Target physical address of memory.
    __u64 ram_base_gpa;

	// BIOS image loaded target guest physical address.
    __u64 bios_load_gpa;
    // Kernel image loaded target guest physical address.
    __u64 kernel_load_gpa;
    // Ramdisk image loaded target guest physical address.
    __u64 ramdisk_load_gpa;

    // Hypervisor physical load address of BIOS, set by ArceOS hypervisor
	// We need to carefully consider the mapping of this kind of address.
	__u64 bios_load_hpa;
	// Hypervisor physical load address of kernel image, set by ArceOS hypervisor.
	// We need to carefully consider the mapping of this kind of address.
	__u64 kernel_load_hpa;
    // Hypervisor physical load address of ramdisk image, set by ArceOS hypervisor.
	// We need to carefully consider the mapping of this kind of address.
	__u64 ramdisk_load_hpa;
};


int arceos_cmd_axvm_create(struct jailhouse_axvm_create __user *arg);

#endif /* !_JAILHOUSE_DRIVER_AXVM_H */