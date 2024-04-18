#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/smp.h>

#include "axvm.h"
#include "main.h"
#include "cell.h"

#include <jailhouse/hypercall.h>

static cpumask_t offlined_cpus;


/// @brief Load image from user address to target physical address provided by arceos-hv.
/// @param image : Here we reuse the jailhouse_preload_image structure from Jailhouse.
///		image->source_address: user address.
///		image->size: image size.
///		image->target_address: target physical address provided by arceos-hv.
int arceos_axvm_load_image(struct jailhouse_preload_image *image) 
{
	void *image_mem;
	int err = 0;
	image_mem = jailhouse_ioremap(image->target_address, 0,
			PAGE_ALIGN(image->size));
	if (!image_mem) {
		pr_err("jailhouse: Unable to map cell RAM at %08llx "
		       "for image loading\n",
		       (unsigned long long)(image->target_address));
		return -EBUSY;
	}
	if (copy_from_user(image_mem,
			   (void __user *)(unsigned long)image->source_address,
			   image->size)) {
		pr_err("jailhouse: Unable to copy image from user %08llx "
		       "for image loading\n",
		       (unsigned long long)(image->source_address));
	}
		err = -EFAULT;
	/*
	 * ARMv7 and ARMv8 require to clean D-cache and invalidate I-cache for
	 * memory containing new instructions. On x86 this is a NOP.
	 */
	flush_icache_range((unsigned long)(image_mem),
			   (unsigned long)(image_mem) + image->size);
#ifdef CONFIG_ARM
	/*
	 * ARMv7 requires to flush the written code and data out of D-cache to
	 * allow the guest starting off with caches disabled.
	 */
	__cpuc_flush_dcache_area(image_mem, image->size);
#endif

	vunmap(image_mem);
	
	return err;
}

/// @brief Create axvm config through HVC.
/// @param arg : Pointer to the user-provided VM creation information..
///		`jailhouse_axvm_create` need to be refactored.
int arceos_cmd_axvm_create(struct jailhouse_axvm_create __user *arg)
{
	unsigned int cpu;
	struct jailhouse_axvm_create vm_cfg;
    int cpu_mask; 
	int err = 0;
	unsigned int cpu_id;
	int vm_id = 0;

	unsigned long arg_phys_addr;
	struct arceos_axvm_create_arg arceos_hvc_axvm_create;
	struct jailhouse_preload_image bios_image;
	struct jailhouse_preload_image kernel_image;

	if (copy_from_user(&vm_cfg, arg, sizeof(vm_cfg)))
		return -EFAULT;
	cpu_mask = vm_cfg.cpu_mask;
	cpu_id = smp_processor_id();
	
	/* Off-line each CPU assigned to the axvm and remove it from the
	 * root cell's set. */
    for (cpu = 0; cpu < sizeof(cpu_mask) * 8; cpu++) {
        if (cpu_mask & (1 << cpu)) {
            if (cpu_online(cpu)) {
				err = cpu_down(cpu);
				pr_err("cpu %d is down err:%d\n", cpu, err);
				if (err)
					goto error_cpu_online;
				cpumask_set_cpu(cpu, &offlined_cpus);
			}
			cpumask_clear_cpu(cpu, &root_cell->cpus_assigned);
        }
    }

	arceos_hvc_axvm_create.vm_id = 0;
	arceos_hvc_axvm_create.type = vm_cfg.type;
	arceos_hvc_axvm_create.bios_size = vm_cfg.size[0];
	arceos_hvc_axvm_create.bios_load_physical_addr = 0;
	arceos_hvc_axvm_create.kernel_size = vm_cfg.size[1];
	arceos_hvc_axvm_create.kernel_load_physical_addr = 0;

	arg_phys_addr = __pa(&arceos_hvc_axvm_create);
	pr_err("Virtual address: %p, Physical address: %lx\n", &arceos_hvc_axvm_create, arg_phys_addr);
	pr_err("[arceos_cmd_axvm_create] current cpu:%d cpu_mask:%d\n", cpu_id, cpu_mask);
	pr_err("[arceos_cmd_axvm_create] BIOS_size: 0x%llx kerbel size 0x%llx\n", 
		arceos_hvc_axvm_create.bios_size, 
		arceos_hvc_axvm_create.kernel_size);
    err = jailhouse_call_arg2(ARCEOS_HC_AXVM_CREATE_CFG, cpu_mask, arg_phys_addr);
	if (err < 0) {
		pr_err("[arceos_cmd_axvm_create] Failed in JAILHOUSE_AXVM_CREATE\n");
		goto error_cpu_online;
	}
	
	pr_err("[arceos_cmd_axvm_create] JAILHOUSE_AXVM_CREATE VM %d success\n", 
		(int) arceos_hvc_axvm_create.vm_id);

	vm_id = (int) arceos_hvc_axvm_create.vm_id;

	// Load image
	pr_err("[arceos_cmd_axvm_create] bios_load_physical_addr: 0x%llx\n", 
		arceos_hvc_axvm_create.bios_load_physical_addr);
	bios_image.source_address = vm_cfg.addr[0];
	bios_image.size = vm_cfg.size[0];
	bios_image.target_address = arceos_hvc_axvm_create.bios_load_physical_addr;
	bios_image.padding = 0;
	err = arceos_axvm_load_image(&bios_image);
	if (err < 0) {
		pr_err("[arceos_cmd_axvm_create] Failed in arceos_axvm_load_image bios_image\n");
		goto error_cpu_online;
	}

	pr_err("[arceos_cmd_axvm_create] kernel_load_physical_addr: 0x%llx\n", 
		arceos_hvc_axvm_create.kernel_load_physical_addr);

	kernel_image.source_address = vm_cfg.addr[1];
	kernel_image.size = vm_cfg.size[1];
	kernel_image.target_address = arceos_hvc_axvm_create.kernel_load_physical_addr;
	kernel_image.padding = 0;

	err = arceos_axvm_load_image(&kernel_image);
		if (err < 0) {
		pr_err("[arceos_cmd_axvm_create] Failed in arceos_axvm_load_image kernel_image\n");
		goto error_cpu_online;
	}

	pr_err("[arceos_cmd_axvm_create] image load success, booting VM %d\n", 
		vm_id);

	err = jailhouse_call_arg1(ARCEOS_HC_AXVM_BOOT, (unsigned long)vm_id);

	return err;

error_cpu_online:
	pr_err("create axvm failed err:%d\n", err);
	for (cpu = 0; cpu < sizeof(cpu_mask) * 8; cpu++) {
        if (cpu_mask & (1 << cpu))  {
			if (!cpu_online(cpu) && cpu_up(cpu) == 0)
				cpumask_clear_cpu(cpu, &offlined_cpus);
			cpumask_set_cpu(cpu, &root_cell->cpus_assigned);
		}
	}
	return err;
}
