LD = $(CC) $(KBUILD_CFLAGS)
NOSTDINC_FLAGS :=
LINUXINCLUDE := -I$(src)/../driver
KBUILD_CFLAGS := -g -O3 \
	-Wall -Wextra -Wmissing-declarations -Wmissing-prototypes -Werror \
	-D__LINUX_COMPILER_TYPES_H \
	-DJAILHOUSE_VERSION=\"$(shell cat $(src)/../VERSION)\"
KBUILD_LDFLAGS :=

always := jailhouse

$(obj)/%: $(obj)/%.o FORCE
	$(call if_changed,ld)
