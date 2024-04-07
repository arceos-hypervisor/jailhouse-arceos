/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013-2016
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <jailhouse.h>

#define JAILHOUSE_DEVICE	"/dev/jailhouse"

#define HV_PHYS_START		0x40000000
#define HV_MEM_SIZE  		(128 << 20) // 128M
#define RT_MEM_SIZE  		(128 << 20) // 128M

static const struct jailhouse_enable_args enable_args = {
	.hv_region = {
		.start = HV_PHYS_START,
		.size = HV_MEM_SIZE,
	},
	.rt_region = {
		.start = HV_PHYS_START + HV_MEM_SIZE,
		.size = RT_MEM_SIZE,
	}
};

static void __attribute__((noreturn)) help(char *prog, int exit_status)
{
	printf("Usage: %s { COMMAND | --help | --version }\n"
	       "\nAvailable commands:\n"
	       "   enable\n"
	       "   disable\n",
	       basename(prog));
	exit(exit_status);
}

static int open_dev()
{
	int fd;

	fd = open(JAILHOUSE_DEVICE, O_RDWR);
	if (fd < 0) {
		perror("opening " JAILHOUSE_DEVICE);
		exit(1);
	}
	return fd;
}

int main(int argc, char *argv[])
{
	int fd;
	int err;

	if (argc < 2)
		help(argv[0], 1);

	if (strcmp(argv[1], "enable") == 0) {
		fd = open_dev();
		err = ioctl(fd, JAILHOUSE_ENABLE, &enable_args);
		if (err)
			perror("JAILHOUSE_ENABLE");
		close(fd);
	} else if (strcmp(argv[1], "disable") == 0) {
		fd = open_dev();
		err = ioctl(fd, JAILHOUSE_DISABLE);
		if (err)
			perror("JAILHOUSE_DISABLE");
		close(fd);
	} else if (strcmp(argv[1], "--version") == 0) {
		printf("Jailhouse management tool %s\n", JAILHOUSE_VERSION);
		return 0;
	} else if (strcmp(argv[1], "--help") == 0) {
		help(argv[0], 0);
	} else {
		help(argv[0], 1);
	}

	return err ? 1 : 0;
}
