#!/bin/bash
export ARCH=arm64
export SUBARCH=arm64
export CROSS_COMPILE_ARM32=/mnt/work/kernel/gcc-linaro-7.5.0-2019.12-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-
export CROSS_COMPILE=/mnt/work/kernel/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
export KCFLAGS=-w
export CLANG_PATH=/mnt/work/kernel/linux-x86-a20a080107a36d82289e257345bfb9a0acb180cc-clang-r416183b/bin
export PATH=${CLANG_PATH}:${PATH}

make clean
make CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump
adb push mod.ko /sdcard/
adb shell su -c rmmod mod
adb shell su -c insmod /sdcard/mod.ko
adb shell su -c dmesg -c | grep MEMS
