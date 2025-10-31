obj-m += mod.o

KERNEL_DIR ?= /mnt/work/kernel/KernelSU-Pixel4

PWD := $(shell pwd)

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
