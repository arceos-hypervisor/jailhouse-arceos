/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013-2017
 * Copyright (c) Valentine Sinitsyn, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

/* For compatibility with older kernel versions */
#include <linux/version.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/firmware.h>
#include <linux/kallsyms.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/reboot.h>
#include <linux/io.h>
#include <asm/barrier.h>
#include <asm/smp.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "cell-config.h"
#include "jailhouse.h"
#include "hypercall.h"

#ifdef CONFIG_X86_32
#error 64-bit kernel required!
#endif

#ifndef MSR_IA32_FEAT_CTL
#define MSR_IA32_FEAT_CTL MSR_IA32_FEATURE_CONTROL
#endif
#ifndef FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#define FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX
#endif

#ifdef CONFIG_X86
#define JAILHOUSE_AMD_FW_NAME	"arceos-amd.bin"
#define JAILHOUSE_INTEL_FW_NAME	"arceos-intel.bin"
#endif

MODULE_DESCRIPTION("Management driver for Jailhouse partitioning hypervisor");
MODULE_LICENSE("GPL");
#ifdef CONFIG_X86
MODULE_FIRMWARE(JAILHOUSE_AMD_FW_NAME);
MODULE_FIRMWARE(JAILHOUSE_INTEL_FW_NAME);
#endif
MODULE_VERSION(JAILHOUSE_VERSION);

DEFINE_MUTEX(jailhouse_lock);

static bool jailhouse_enabled;
static void *hypervisor_mem;

static struct device *jailhouse_dev;
static unsigned long hv_core_and_percpu_size;
static int enter_hv_cpus;
static atomic_t call_done;
static int error_code;
static struct resource *hypervisor_mem_res;

static typeof(ioremap_page_range) *ioremap_page_range_sym;

static char *hv_size = "";
module_param(hv_size, charp, S_IRUGO);
MODULE_PARM_DESC(hv_size, "The hypervisor size in string");

#ifdef CONFIG_X86
bool jailhouse_use_vmcall;

static void init_hypercall(void)
{
	jailhouse_use_vmcall = boot_cpu_has(X86_FEATURE_VMX);
}
#else /* !CONFIG_X86 */
static void init_hypercall(void)
{
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
#define __get_vm_area(size, flags, start, end)			\
	__get_vm_area_caller(size, flags, start, end,		\
			     __builtin_return_address(0))
#endif

void *jailhouse_ioremap(phys_addr_t phys, unsigned long virt,
			unsigned long size)
{
	struct vm_struct *vma;

	size = PAGE_ALIGN(size);
	if (virt)
		vma = __get_vm_area(size, VM_IOREMAP, virt,
				    virt + size + PAGE_SIZE);
	else
		vma = __get_vm_area(size, VM_IOREMAP, VMALLOC_START,
				    VMALLOC_END);
	if (!vma)
		return NULL;
	vma->phys_addr = phys;

	if (ioremap_page_range_sym((unsigned long)vma->addr,
				   (unsigned long)vma->addr + size, phys,
				   PAGE_KERNEL_EXEC)) {
		vunmap(vma->addr);
		return NULL;
	}

	return vma->addr;
}

/*
 * Called for each cpu by the JAILHOUSE_ENABLE ioctl.
 * It jumps to the entry point set in the header, reports the result and
 * signals completion to the main thread that invoked it.
 */
static void enter_hypervisor(void *info)
{
	struct jailhouse_header *header = info;
	unsigned int cpu = smp_processor_id();
	int (*entry)(unsigned int);
	int err;

	entry = header->entry + (unsigned long) hypervisor_mem;

	if (cpu < header->max_cpus)
		/* either returns 0 or the same error code across all CPUs */
		err = entry(cpu);
	else
		err = -EINVAL;

	if (err) {
		pr_info("Core [%d] return from arceos, code %d.\n", cpu, err);
		error_code = err;
	}
		
#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	/* on Intel, VMXE is now on - update the shadow */
	if (boot_cpu_has(X86_FEATURE_VMX) && !err) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
		cr4_set_bits_irqsoff(X86_CR4_VMXE);
#else
		cr4_set_bits(X86_CR4_VMXE);
#endif
	}
#endif

	atomic_inc(&call_done);
}

static inline const char * jailhouse_get_fw_name(void)
{
#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_SVM))
		return JAILHOUSE_AMD_FW_NAME;
	if (boot_cpu_has(X86_FEATURE_VMX))
		return JAILHOUSE_INTEL_FW_NAME;
#endif
	return NULL;
}

static void jailhouse_firmware_free(void)
{
	if (hypervisor_mem_res) {
		release_mem_region(hypervisor_mem_res->start,
				   resource_size(hypervisor_mem_res));
		hypervisor_mem_res = NULL;
	}
	vunmap(hypervisor_mem);
	hypervisor_mem = NULL;
}

static int get_iomem_num(void)
{
	int num;
	struct resource *child;

	num = 0;
	child = iomem_resource.child;
	while (child) {
		num++;
		child = child->sibling;
	}

	return num;
}

static inline unsigned long long mem_region_flag(const char *name)
{
	if (!strcmp(name, "System RAM") || !strcmp(name, "RAM buffer"))
		return JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
		       JAILHOUSE_MEM_EXECUTE | JAILHOUSE_MEM_DMA;
	else if (!strcmp(name, "Reserved"))
		return JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
		       JAILHOUSE_MEM_EXECUTE;
	else
		return JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE;
}

static bool get_mem_region_one(struct mem_region *region, const char *name,
			       struct mem_region *reserved,
			       struct jailhouse_memory *regions, int *num)
{
	unsigned long long flags = 0, l_start = 0, l_end = 0;
	unsigned long long s = region->start;
	unsigned long long e = s + region->size;
	unsigned long long res_start = reserved->start;
	unsigned long long res_end = res_start + reserved->size;
	bool ok = true;
	int l_index = 0;

	if (s == e) {
		return true;
	}

	if (s <= res_start && res_end <= e) {
		if (strcmp(name, "Reserved")) {
			return false;
		}
		if (s < res_start) {
			region->start = s;
			region->size = res_start - s;
			ok = get_mem_region_one(region, name, reserved, regions, num);
		}
		if (ok && res_end < e) {
			region->start = res_end;
			region->size = e - res_end;
			ok = get_mem_region_one(region, name, reserved, regions, num);
		}
		return ok;
	} else if (!(e <= res_start || res_end <= s)) {
		pr_err("overlapped with reserved region");
		return false;
	}

	s = round_down(s, PAGE_SIZE);
	e = round_up(e, PAGE_SIZE) - 1;
	if ((*num) == 0) {
		l_start = 0;
		l_end = 0;
	} else {
		l_index = (*num) - 1;
		l_start = regions[l_index].phys_start;
		l_end = regions[l_index].phys_start + regions[l_index].size - 1;
	}
	// check if current region is overlapped with last one
	if (s < l_end) {
		pr_debug("overlap last:(0x%llx 0x%llx) now:(0x%llx 0x%llx)\n",
		       l_start, l_end, s, e);
		s = min(s, l_start);
		e = max(e, l_end);
		// the flags of the merged regions should be OR of two flags of regions
		// for example:  SYSRAM merge with RESERVED region, the merged.flags = SYSRAM.flags |  RESERVED.flags
		flags = regions[l_index].flags;
		(*num)--;
	}

	regions[*num].phys_start = s;
	regions[*num].virt_start = s;
	regions[*num].size = e - s + 1;
	regions[*num].flags = flags | mem_region_flag(name);
	pr_debug("add region %d: %s [0x%llx..0x%llx] 0x%llx\n",
		 *num, name, regions[*num].phys_start,
		 regions[*num].phys_start + regions[*num].size - 1,
		 regions[*num].flags);
	(*num)++;

	return true;
}

/*
 * get_mem_regions - Get the memory regions reported to hypervisor.
 *
 * The start and end addr of memory regions must be PAGE_SIZE align.
 */
static int get_mem_regions(struct jailhouse_memory *regions,
			   struct mem_region *reserved)
{
	int num = 0;
	struct resource *child = iomem_resource.child;

	while (child) {
		struct mem_region region;
		region.start = child->start;
		region.size = child->end - child->start + 1;
		pr_debug("found region: %s [0x%llx..0x%llx]\n", child->name,
			 region.start, region.start + region.size - 1);
		if (!get_mem_region_one(&region, child->name, reserved, regions, &num)) {
			return -1;
		}
		child = child->sibling;
	}
	return num;
}

/*
 * Dump hypervisor memory region and all memory regions reported to hypervisor.
 */
static void dump_mem_regions(struct jailhouse_memory *regions, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		pr_info("region[%d]: [0x%llx - 0x%llx], size=0x%llx, flag=0x%llx\n",
			i, regions[i].phys_start,
			regions[i].phys_start + regions[i].size - 1,
			regions[i].size, regions[i].flags);
	}
}

static void init_system_config(struct jailhouse_system *config,
			       struct mem_region *hv_region,
			       int num_mem_regions,
			       struct jailhouse_memory *mem_regions)
{
	memset(config, 0, sizeof(*config));

	memcpy(config->signature, JAILHOUSE_SYSTEM_SIGNATURE,
	       sizeof(config->signature));
	config->revision = JAILHOUSE_CONFIG_REVISION;
	config->hypervisor_memory.phys_start = hv_region->start;
	config->hypervisor_memory.size = hv_region->size;
	memcpy(config->root_cell.signature, JAILHOUSE_CELL_DESC_SIGNATURE,
	       sizeof(config->root_cell.signature));
	config->root_cell.revision = JAILHOUSE_CONFIG_REVISION;
	strcpy(config->root_cell.name, "linux-root-cell");
	config->root_cell.id = 0;
	config->root_cell.num_memory_regions = num_mem_regions;

	memcpy((void *)config + sizeof(*config), mem_regions,
	       sizeof(*mem_regions) * num_mem_regions);
}

/* See Documentation/bootstrap-interface.txt */
static int jailhouse_cmd_enable(struct mem_region __user *arg)
{
	const struct firmware *hypervisor;
	struct jailhouse_system *config;
	struct jailhouse_header *header;
	unsigned long remap_addr = 0;
	unsigned long config_size;
	const char *fw_name;
	long max_cpus;
	int err;

	int num_iomem, num_mem_regions;
	struct mem_region hv_region;
	struct jailhouse_memory *mem_regions;

	fw_name = jailhouse_get_fw_name();
	if (!fw_name) {
		pr_err("jailhouse: Missing or unsupported HVM technology\n");
		return -ENODEV;
	}

	if (copy_from_user(&hv_region, arg, sizeof(hv_region))) {
		pr_err("jailhouse_cmd_enable: invalid arg: 0x%p\n", arg);
		return -EFAULT;
	}
	if (!hv_region.size) {
		hv_region.size = 256 << 20; // 256M
	}

	if (mutex_lock_interruptible(&jailhouse_lock) != 0)
		return -EINTR;

	err = -EBUSY;
	if (jailhouse_enabled || !try_module_get(THIS_MODULE))
		goto error_unlock;

#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_VMX)) {
		u64 features;

		rdmsrl(MSR_IA32_FEAT_CTL, features);
		if ((features & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX) == 0) {
			pr_err("jailhouse: VT-x disabled by Firmware/BIOS\n");
			err = -ENODEV;
			goto error_put_module;
		}
	}
#endif

	/* Load hypervisor image */
	err = request_firmware(&hypervisor, fw_name, jailhouse_dev);
	if (err) {
		pr_err("jailhouse: Missing hypervisor image %s\n", fw_name);
		goto error_put_module;
	}

	/* Get memory regions */
	num_iomem = get_iomem_num();
	mem_regions = kvmalloc(sizeof(*mem_regions) * num_iomem, GFP_KERNEL);
	if (!mem_regions) {
		err = -ENOMEM;
		goto error_release_fw;
	}
	num_mem_regions = get_mem_regions(mem_regions, &hv_region);
	if (num_mem_regions == -1) {
		err = -EINVAL;
		pr_err("hypervisor memory is overlapped with other memory regions\n");
		goto error_free_mem_regions;
	}
	dump_mem_regions(mem_regions, num_mem_regions);

	pr_info("hypervisor memory region: [0x%llx-0x%llx], 0x%llx\n",
		hv_region.start, hv_region.start + hv_region.size - 1,
		hv_region.size);

	header = (struct jailhouse_header *)hypervisor->data;

	err = -EINVAL;
	if (memcmp(header->signature, JAILHOUSE_SIGNATURE,
		   sizeof(header->signature)) != 0) {
		pr_err("SIGNATURE CHECK FAIL\n");
		goto error_release_fw;
	}

	max_cpus = num_possible_cpus();
	hv_core_and_percpu_size =
		header->core_size + max_cpus * header->percpu_size;
	config_size = sizeof(*config) + num_mem_regions * sizeof(*mem_regions);
	if (hv_core_and_percpu_size >= hv_region.size ||
	    config_size >= hv_region.size - hv_core_and_percpu_size)
		goto error_free_mem_regions;

	remap_addr = JAILHOUSE_BASE;

	/* Unmap hypervisor_mem from a previous "enable". The mapping has to be
	 * redone since the root-cell config might have changed. */
	jailhouse_firmware_free();

	hypervisor_mem_res = request_mem_region(hv_region.start, hv_region.size,
						"RVM hypervisor");
	if (!hypervisor_mem_res) {
		pr_err("jailhouse: request_mem_region failed for hypervisor "
		       "memory.\n");
		pr_notice("jailhouse: Did you reserve the memory with "
			  "\"memmap=\" or \"mem=\"?\n");
		goto error_free_mem_regions;
	}

	/* Map physical memory region reserved for Jailhouse. */
	hypervisor_mem =
		jailhouse_ioremap(hv_region.start, remap_addr, hv_region.size);
	if (!hypervisor_mem) {
		pr_err("jailhouse: Unable to map RAM reserved for hypervisor "
		       "at %08lx\n",
		       (unsigned long)hv_region.start);
		goto error_release_memreg;
	}

	/* Copy hypervisor's binary image at beginning of the memory region
	 * and clear the rest to zero. */
	memcpy(hypervisor_mem, hypervisor->data, hypervisor->size);
	memset(hypervisor_mem + hypervisor->size, 0,
	       hv_region.size - hypervisor->size);

	header = (struct jailhouse_header *)hypervisor_mem;
	header->max_cpus = max_cpus;

	/* Copy system configuration to its target address in hypervisor memory
	 * region. */
	config = (struct jailhouse_system *)(hypervisor_mem +
					     hv_core_and_percpu_size);
	init_system_config(config, &hv_region, num_mem_regions, mem_regions);

	/*
	 * ARMv8 requires to clean D-cache and invalidate I-cache for memory
	 * containing new instructions. On x86 this is a NOP. On ARMv7 the
	 * firmware does its own cache maintenance, so it is an
	 * extraneous (but harmless) flush.
	 */
	flush_icache_range((unsigned long)hypervisor_mem,
			   (unsigned long)(hypervisor_mem + header->core_size));

	error_code = 0;

	preempt_disable();

	header->online_cpus = num_online_cpus();

	/*
	 * Cannot use wait=true here because all CPUs have to enter the
	 * hypervisor to start the handover while on_each_cpu holds the calling
	 * CPU back.
	 */
	atomic_set(&call_done, 0);
	on_each_cpu(enter_hypervisor, header, 0);
	while (atomic_read(&call_done) != num_online_cpus())
		cpu_relax();

	preempt_enable();

	if (error_code) {
		err = error_code;
		goto error_unmap;
	}

	kvfree(mem_regions);
	release_firmware(hypervisor);

	enter_hv_cpus = atomic_read(&call_done);
	jailhouse_enabled = true;

	mutex_unlock(&jailhouse_lock);

	pr_info("The Jailhouse is opening.\n");

	return 0;

error_unmap:
	jailhouse_firmware_free();

error_release_memreg:
	/* jailhouse_firmware_free() could have been called already and
	 * has released hypervisor_mem_res. */
	if (hypervisor_mem_res)
		release_mem_region(hypervisor_mem_res->start,
				   resource_size(hypervisor_mem_res));
	hypervisor_mem_res = NULL;

error_free_mem_regions:
	kvfree(mem_regions);

error_release_fw:
	release_firmware(hypervisor);

error_put_module:
	module_put(THIS_MODULE);

error_unlock:
	mutex_unlock(&jailhouse_lock);
	return err;
}

static void leave_hypervisor(void *info)
{
	void *page;
	int err;

	/* Touch each hypervisor page we may need during the switch so that
	 * the active mm definitely contains all mappings. At least x86 does
	 * not support taking any faults while switching worlds. */
	for (page = hypervisor_mem;
	     page < hypervisor_mem + hv_core_and_percpu_size;
	     page += PAGE_SIZE)
		readl((void __iomem *)page);

	/* either returns 0 or the same error code across all CPUs */
	err = jailhouse_call(JAILHOUSE_HC_DISABLE);
	if (err)
		error_code = err;

#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	/* on Intel, VMXE is now off - update the shadow */
	if (boot_cpu_has(X86_FEATURE_VMX) && !err) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
		cr4_clear_bits_irqsoff(X86_CR4_VMXE);
#else
		cr4_clear_bits(X86_CR4_VMXE);
#endif
	}
#endif

	atomic_inc(&call_done);
}

static int jailhouse_cmd_disable(void)
{
	int err;

	if (mutex_lock_interruptible(&jailhouse_lock) != 0)
		return -EINTR;

	if (!jailhouse_enabled) {
		err = -EINVAL;
		goto unlock_out;
	}

	error_code = 0;

	preempt_disable();

	if (num_online_cpus() != enter_hv_cpus) {
		/*
		 * Not all assigned CPUs are currently online. If we disable
		 * now, we will lose the offlined ones.
		 */

		preempt_enable();

		err = -EBUSY;
		goto unlock_out;
	}

	atomic_set(&call_done, 0);
	/* See jailhouse_cmd_enable while wait=true does not work. */
	on_each_cpu(leave_hypervisor, NULL, 0);
	while (atomic_read(&call_done) != num_online_cpus())
		cpu_relax();

	preempt_enable();

	err = error_code;
	if (err) {
		pr_warn("jailhouse: Failed to disable hypervisor: %d\n", err);
		goto unlock_out;
	}

	jailhouse_enabled = false;
	module_put(THIS_MODULE);

	pr_info("The Jailhouse was closed.\n");

unlock_out:
	mutex_unlock(&jailhouse_lock);

	return err;
}

static long jailhouse_ioctl(struct file *file, unsigned int ioctl,
			    unsigned long arg)
{
	long err;

	switch (ioctl) {
	case JAILHOUSE_ENABLE:
		err = jailhouse_cmd_enable((struct mem_region __user *)arg);
		break;
	case JAILHOUSE_DISABLE:
		err = jailhouse_cmd_disable();
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static const struct file_operations jailhouse_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = jailhouse_ioctl,
	.compat_ioctl = jailhouse_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice jailhouse_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "jailhouse",
	.fops = &jailhouse_fops,
};

static int jailhouse_shutdown_notify(struct notifier_block *unused1,
				     unsigned long unused2, void *unused3)
{
	int err;

	err = jailhouse_cmd_disable();
	if (err && err != -EINVAL)
		pr_emerg("jailhouse: ordered shutdown failed!\n");

	return NOTIFY_DONE;
}

static struct notifier_block jailhouse_shutdown_nb = {
	.notifier_call = jailhouse_shutdown_notify,
};

static int __init jailhouse_init(void)
{
	int err;

#if defined(CONFIG_KALLSYMS_ALL) && LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
#define __RESOLVE_EXTERNAL_SYMBOL(symbol)			\
	symbol##_sym = (void *)kallsyms_lookup_name(#symbol);	\
	if (!symbol##_sym)					\
		return -EINVAL
#else
#define __RESOLVE_EXTERNAL_SYMBOL(symbol)			\
	symbol##_sym = &symbol
#endif
#define RESOLVE_EXTERNAL_SYMBOL(symbol...) __RESOLVE_EXTERNAL_SYMBOL(symbol)

	RESOLVE_EXTERNAL_SYMBOL(ioremap_page_range);

	jailhouse_dev = root_device_register("jailhouse");
	if (IS_ERR(jailhouse_dev))
		return PTR_ERR(jailhouse_dev);

	err = misc_register(&jailhouse_misc_dev);
	if (err)
		goto unreg_dev;

	register_reboot_notifier(&jailhouse_shutdown_nb);

	init_hypercall();

	return 0;

unreg_dev:
	root_device_unregister(jailhouse_dev);
	return err;
}

static void __exit jailhouse_exit(void)
{
	unregister_reboot_notifier(&jailhouse_shutdown_nb);
	misc_deregister(&jailhouse_misc_dev);
	jailhouse_firmware_free();
	root_device_unregister(jailhouse_dev);
}

module_init(jailhouse_init);
module_exit(jailhouse_exit);
