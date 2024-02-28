# Check make version
need := 3.82
ifneq ($(need),$(firstword $(sort $(MAKE_VERSION) $(need))))
$(error Too old make version $(MAKE_VERSION), at least $(need) required)
endif

ifeq ($(V),1)
	Q =
else
	Q = @
endif

# no recipes above this one (also no includes)
all: modules

# out-of-tree build for our kernel-module, firmware and inmates
KDIR ?= /lib/modules/`uname -r`/build

kbuild = -C $(KDIR) M=$$PWD $@

PORT ?= 6657

modules clean:
	$(Q)$(MAKE) $(kbuild)

.PHONY: ssh
ssh:
	ssh -p $(PORT) ubuntu@localhost

.PHONY: modules clean ssh
