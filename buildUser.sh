/mnt/work/kernel/android-ndk-r21e/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --sysroot /mnt/work/kernel/android-ndk-r21e/toolchains/llvm/prebuilt/linux-x86_64/sysroot/ -target aarch64-linux-android23 main.c
adb push a.out /data/local/tmp
adb shell chmod 777 /data/local/tmp


