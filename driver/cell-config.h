#ifndef _JAILHOUSE_CELL_CONFIG_H
#define _JAILHOUSE_CELL_CONFIG_H

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) sizeof(a) / sizeof(a[0])
#endif

/*
 * Incremented on any layout or semantic change of system or cell config.
 * Also update formats and HEADER_REVISION in pyjailhouse/config_parser.py.
 */
#define JAILHOUSE_CONFIG_REVISION	13

#define JAILHOUSE_CELL_NAME_MAXLEN	31

#define JAILHOUSE_CELL_DESC_SIGNATURE	"ARCEOS"

#define JAILHOUSE_SYSTEM_SIGNATURE	"ARCEOS"

/**
 * The jailhouse cell configuration.
 *
 * @note Keep Config._HEADER_FORMAT in jailhouse-cell-linux in sync with this
 * structure.
 */
struct jailhouse_cell_desc {
	char signature[6];
	__u16 revision;

	char name[JAILHOUSE_CELL_NAME_MAXLEN+1];
	__u32 id; /* set by the driver */

	// __u32 cpu_set_size;
	__u32 num_memory_regions;
} __attribute__((packed));

#define JAILHOUSE_MEM_READ		0x0001
#define JAILHOUSE_MEM_WRITE		0x0002
#define JAILHOUSE_MEM_EXECUTE		0x0004
#define JAILHOUSE_MEM_DMA		0x0008
#define JAILHOUSE_MEM_IO		0x0010
#define JAILHOUSE_MEM_NO_HUGEPAGES	0x0100

struct jailhouse_memory {
	__u64 phys_start;
	__u64 virt_start;
	__u64 size;
	__u64 flags;
} __attribute__((packed));

/**
 * General descriptor of the system.
 */
struct jailhouse_system {
	char signature[6];
	__u16 revision;

	/** Jailhouse's location in memory */
	struct jailhouse_memory hypervisor_memory;
	struct jailhouse_memory rtos_memory;
	struct jailhouse_cell_desc root_cell;
} __attribute__((packed));

static inline __u32
jailhouse_cell_config_size(struct jailhouse_cell_desc *cell)
{
	return sizeof(struct jailhouse_cell_desc) +
		// cell->cpu_set_size +
		cell->num_memory_regions * sizeof(struct jailhouse_memory);
}

static inline __u32
jailhouse_system_config_size(struct jailhouse_system *system)
{
	return sizeof(*system) - sizeof(system->root_cell) +
		jailhouse_cell_config_size(&system->root_cell);
}

static inline const struct jailhouse_memory *
jailhouse_cell_mem_regions(const struct jailhouse_cell_desc *cell)
{
	return (const struct jailhouse_memory *)
		((void *)cell + sizeof(struct jailhouse_cell_desc));
}

#endif /* !_JAILHOUSE_CELL_CONFIG_H */
