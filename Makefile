obj-m := rpf.o 

KERNEL ?= 4.12.0-joel-rpf+
KBUILD_DIR ?= /lib/modules/$(KERNEL)/build
KERNEL_DIR ?= ~/projects/linux
MBUILD_DIR ?= ~/projects/mlnx-ofed-kernel-4.3

.PHONY: tags

all:
	make -C $(MBUILD_DIR)

clean:
	make -C $(KBUILD_DIR) M=$$PWD clean

.PHONY: tags

tags:
	ctags -R -f tags . ../common $(KERNEL_DIR)/mm $(KERNEL_DIR)/fs $(KERNEL_DIR)/drivers/nvme/target $(KBUILD_DIR)/drivers/infiniband $(KERNEL_DIR)/include $(KERNEL_DIR)/arch/powerpc
