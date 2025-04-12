#include <fcntl.h>
#include <cerrno>
#include <android/log.h>
#include <cstring>
#include <jni.h>
#include <unistd.h>
#include <asm-generic/ioctl.h>

#define LOG_TAG "Read: "
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
struct request {
    pid_t pid;
    unsigned long vaddr;
    size_t size;
    unsigned long buffer_addr;
    int status;
};

void read(pid_t pid, u_long address, size_t size) {
    int fd = open("/dev/memscan", O_RDWR);
    LOGE("%d",fd);
    if (fd < 0) {
        LOGE("Failed to open device: %s", strerror(errno));
        return;
    }
    LOGE("%d",fd);
    u_char buff[0xF];
    struct request req{};
    req.pid = pid;
    req.vaddr = address;
    req.size = size;
    req.buffer_addr = (u_long)buff;
    req.status = 0;

    if (ioctl(fd, _IOWR('M', 2, struct request), &req) < 0) {
        LOGE("Read failed: %s", strerror(errno));
        close(fd);
    }

    close(fd);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_hellokernel_FloatingService_read(JNIEnv *env, jobject thiz) {
    read(1, 0x7f000000, 0xF);
}
