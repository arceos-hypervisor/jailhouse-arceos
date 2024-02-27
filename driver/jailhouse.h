#ifndef _JAILHOUSE_DRIVER_H
#define _JAILHOUSE_DRIVER_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct mem_region {
	unsigned long long start;
	unsigned long long size;
};

struct jailhouse_enable_args {
	struct mem_region hv_region;
	struct mem_region rt_region;
};

#define JAILHOUSE_ENABLE		_IOW(0, 0, struct jailhouse_enable_args)
#define JAILHOUSE_DISABLE		_IO(0, 1)

#define JAILHOUSE_BASE	0xffffff0000000000UL
// #define JAILHOUSE_BASE  0xffffff8000200000UL
#define JAILHOUSE_SIGNATURE	"ARCEOSIM"

/**
 * Hypervisor description.
 * Located at the beginning of the hypervisor binary image and loaded by
 * the driver (which also initializes some fields).
 */
struct jailhouse_header {
	/** Signature "ARCEIMAG" used for basic validity check of the
	 * hypervisor image.
	 * @note Filled at build time. */
	char signature[8];
	/** Size of hypervisor core.
	 * It starts with the hypervisor's header and ends after its bss
	 * section. Rounded up to page boundary.
	 * @note Filled at build time. */
	unsigned long core_size;
	/** Size of the per-CPU data structure.
	 * @note Filled at build time. */
	unsigned long percpu_size;
	/** Entry point (arch_entry()).
	 * @note Filled at build time. */
	int (*entry)(unsigned int);
	/** Configured maximum logical CPU ID + 1.
	 * @note Filled by Linux loader driver before entry. */
	unsigned int max_cpus;
	/** Number of real-time CPUs paritioned, which will be shutdown before
	 * entry and restarted in hypervisor. The others are VM CPUs, which will
	 * call the entry function and run the guest.
	 * @note Filled by Linux loader driver before entry. */
	unsigned int rt_cpus;
};

#endif /* !_JAILHOUSE_DRIVER_H */
