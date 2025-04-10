#include <jni.h>
#include <android/log.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#define LOG_TAG "MemScanJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define DEVICE_PATH "/dev/memscan"
#define MEMSCAN_IOCTL_MAGIC 'M'
#define MEMSCAN_SEARCH _IOWR(MEMSCAN_IOCTL_MAGIC, 1, struct search_request)
#define MEMSCAN_READ _IOWR(MEMSCAN_IOCTL_MAGIC, 2, struct read_request)

struct search_request {
    pid_t pid;
    unsigned long pattern_addr;
    size_t pattern_len;
    unsigned long results_addr;
    size_t max_results;
    size_t found_count;
};

struct read_request {
    pid_t pid;
    unsigned long vaddr;
    size_t size;
    unsigned long buffer_addr;
    int status;
};
extern "C" JNIEXPORT jlongArray JNICALL
Java_com_example_hack_MemScanner_searchMemory(
        JNIEnv *env,
        jobject /* this */,
        jint pid,
        jbyteArray pattern,
        jint maxResults) {

    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        LOGE("Failed to open device: %s", strerror(errno));
        return nullptr;
    }

    // Prepare pattern
    jbyte *patternBytes = env->GetByteArrayElements(pattern, nullptr);
    jsize patternLen = env->GetArrayLength(pattern);

    // Allocate results buffer
    unsigned long *results = new unsigned long[maxResults];
    if (!results) {
        LOGE("Failed to allocate results buffer");
        close(fd);
        return nullptr;
    }

    // Prepare request
    struct search_request req;
    req.pid = static_cast<pid_t>(pid);
    req.pattern_addr = reinterpret_cast<unsigned long>(patternBytes);
    req.pattern_len = static_cast<size_t>(patternLen);
    req.results_addr = reinterpret_cast<unsigned long>(results);
    req.max_results = static_cast<size_t>(maxResults);
    req.found_count = 0;

    // Perform IOCTL
    if (ioctl(fd, MEMSCAN_SEARCH, &req) < 0) {
        LOGE("Search failed: %s", strerror(errno));
        delete[] results;
        close(fd);
        return nullptr;
    }

    // Convert results to Java long array
    jlongArray resultArray = env->NewLongArray(static_cast<jsize>(req.found_count));
    if (resultArray != nullptr) {
        jlong *tmpArray = new jlong[req.found_count];
        for (size_t i = 0; i < req.found_count; i++) {
            tmpArray[i] = static_cast<jlong>(results[i]); // 安全转换为64位
        }
        env->SetLongArrayRegion(resultArray, 0, static_cast<jsize>(req.found_count), tmpArray);
        delete[] tmpArray;
    }

    // Clean up
    delete[] results;
    close(fd);
    env->ReleaseByteArrayElements(pattern, patternBytes, 0);

    return resultArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_hack_MemScanner_readMemory(
        JNIEnv *env,
        jobject /* this */,
        jint pid,
        jlong address,
        jint size) {

    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        LOGE("Failed to open device: %s", strerror(errno));
        return nullptr;
    }

    // Allocate buffer
    jbyteArray resultArray = env->NewByteArray(size);
    if (resultArray == nullptr) {
        LOGE("Failed to allocate byte array");
        close(fd);
        return nullptr;
    }

    jbyte *buffer = env->GetByteArrayElements(resultArray, nullptr);

    // Prepare request
    struct read_request req;
    req.pid = static_cast<pid_t>(pid);
    req.vaddr = static_cast<unsigned long>(address);
    req.size = static_cast<size_t>(size);
    req.buffer_addr = reinterpret_cast<unsigned long>(buffer);
    req.status = 0;

    // Perform IOCTL
    if (ioctl(fd, MEMSCAN_READ, &req) < 0) {
        LOGE("Read failed: %s", strerror(errno));
        env->ReleaseByteArrayElements(resultArray, buffer, 0);
        close(fd);
        return nullptr;
    }

    if (req.status != 0) {
        LOGE("Read failed with status: %d", req.status);
        env->ReleaseByteArrayElements(resultArray, buffer, 0);
        close(fd);
        return nullptr;
    }

    // Clean up
    env->ReleaseByteArrayElements(resultArray, buffer, 0);
    close(fd);

    return resultArray;
}
