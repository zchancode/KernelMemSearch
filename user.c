#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#define DEVICE_PATH "/dev/memscan"
#define MEMSCAN_IOCTL_MAGIC 'M'
#define MEMSCAN_SEARCH _IOWR(MEMSCAN_IOCTL_MAGIC, 1, struct search_request)
#define MEMSCAN_READ _IOWR(MEMSCAN_IOCTL_MAGIC, 2, struct read_request)

struct search_request {
    pid_t pid;                  // Process ID to search
    unsigned long pattern_addr; // User-space address of pattern
    size_t pattern_len;         // Length of the pattern
    unsigned long results_addr; // User-space address for results
    size_t max_results;         // Maximum number of results to store
    size_t found_count;         // Actual number of matches found
};

struct read_request {
    pid_t pid;                  // Process ID to read from
    unsigned long vaddr;        // Virtual address to read
    size_t size;               // Number of bytes to read
    unsigned long buffer_addr;  // User-space buffer for data
    int status;                // Return status
};

void hexdump(const unsigned char *buf, size_t size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0) {
            if (i != 0) printf("\n");
            printf("[%04x] ", i);
        }
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    int fd;
    pid_t pid;
    int i;

    if (argc < 2) {
        printf("Usage:\n");
        printf("  Search: %s search <pid> <pattern in hex> <max_results>\n", argv[0]);
        printf("  Read:   %s read <pid> <address> <size>\n", argv[0]);
        return 1;
    }

    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    if (strcmp(argv[1], "search") == 0 && argc == 5) {
        struct search_request req;
        unsigned char *pattern;
        unsigned long *results;

        pid = atoi(argv[2]);
        int max_results = atoi(argv[4]);

        // Convert hex pattern to binary
        char *hex = argv[3];
        size_t pattern_len = strlen(hex) / 2;
        pattern = malloc(pattern_len);
        for (i = 0; i < pattern_len; i++) {
            sscanf(hex + 2*i, "%2hhx", &pattern[i]);
        }

        results = malloc(max_results * sizeof(unsigned long));

        // Initialize request
        req.pid = pid;
        req.pattern_addr = (unsigned long)pattern;
        req.pattern_len = pattern_len;
        req.results_addr = (unsigned long)results;
        req.max_results = max_results;
        req.found_count = 0;

        // Perform search
        if (ioctl(fd, MEMSCAN_SEARCH, &req) < 0) {
            perror("ioctl search failed");
            close(fd);
            return 1;
        }

        printf("Found %zu matches:\n", req.found_count);
        for (i = 0; i < req.found_count; i++) {
            printf("0x%lx\n", results[i]);
        }

        free(pattern);
        free(results);
    }
    else if (strcmp(argv[1], "read") == 0 && argc == 5) {
        struct read_request req;
        unsigned char *buffer;

        pid = atoi(argv[2]);
        unsigned long address = strtoul(argv[3], NULL, 16);
        size_t size = atoi(argv[4]);

        buffer = malloc(size);
        if (!buffer) {
            perror("Failed to allocate buffer");
            close(fd);
            return 1;
        }

        // Initialize request
        req.pid = pid;
        req.vaddr = address;
        req.size = size;
        req.buffer_addr = (unsigned long)buffer;
        req.status = 0;

        // Perform read
        if (ioctl(fd, MEMSCAN_READ, &req) < 0) {
            perror("ioctl read failed");
            free(buffer);
            close(fd);
            return 1;
        }

        if (req.status != 0) {
            printf("Read failed with status %d\n", req.status);
        } else {
            printf("Read %zu bytes from PID %d at 0x%lx:\n", size, pid, address);
            hexdump(buffer, size);
        }

        free(buffer);
    }
    else {
        printf("Invalid command or arguments\n");
    }

    close(fd);
    return 0;
}
