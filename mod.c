#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Enhanced memory scanner with read/write interface");

#define DEVICE_NAME "memscan"
#define MAX_RESULTS 1000
#define MAX_READ_SIZE PAGE_SIZE
#define MEMSCAN_IOCTL_MAGIC 'M'
#define MEMSCAN_SEARCH _IOWR(MEMSCAN_IOCTL_MAGIC, 1, struct search_request)
#define MEMSCAN_READ _IOWR(MEMSCAN_IOCTL_MAGIC, 2, struct read_request)

static char* tag = "MEMSCAN: ";
static int major_num;
static struct class* memscan_class = NULL;
static struct device* memscan_device = NULL;
static struct cdev memscan_cdev;

// Structure to hold search parameters for internal use
struct search_params {
    unsigned char *pattern;
    size_t pattern_len;
    unsigned long *results;
    size_t max_results;
    size_t found_count;
};

// Structure to hold search request from caller
struct search_request {
    pid_t pid;                  // Process ID to search
    unsigned long pattern_addr; // User-space address of pattern
    size_t pattern_len;         // Length of the pattern
    unsigned long results_addr; // User-space address for results
    size_t max_results;         // Maximum number of results to store
    size_t found_count;         // Actual number of matches found
};

// Structure to hold read request
struct read_request {
    pid_t pid;                  // Process ID to read from
    unsigned long vaddr;        // Virtual address to read
    size_t size;               // Number of bytes to read
    unsigned long buffer_addr;  // User-space buffer for data
    int status;                // Return status
};

// Helper function to read physical memory
static bool read_phys_mem(phys_addr_t pa, void *buf, size_t size)
{
    void __iomem *mapped;
    bool ret = true;

    mapped = ioremap_cache(pa, size);
    if (!mapped) {
        printk(KERN_WARNING "%s: Failed to ioremap PA 0x%llx\n", tag, (u64)pa);
        return false;
    }

    memcpy_fromio(buf, mapped, size);
    iounmap(mapped);
    return ret;
}

// Translate virtual address to physical address
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

    pud = pud_offset(pgd, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte))
        return 0;

    if (!pte_present(*pte))
        return 0;

    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);
    return page_addr + page_offset;
}

// Search a memory page for the pattern
static void search_page(struct mm_struct *mm, unsigned long vaddr,
                       struct search_params *params)
{
    phys_addr_t phys_addr;
    unsigned char *page_buf;
    unsigned long page_start;
    int i;

    if (params->found_count >= params->max_results)
        return;

    phys_addr = translate_linear_address(mm, vaddr);
    if (!phys_addr) {
        return;
    }

    page_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!page_buf) {
        return;
    }

    if (!read_phys_mem(phys_addr, page_buf, PAGE_SIZE)) {
        kfree(page_buf);
        return;
    }

    // Search through the page
    page_start = vaddr & PAGE_MASK;
    for (i = 0; i <= PAGE_SIZE - params->pattern_len; i++) {
        if (memcmp(page_buf + i, params->pattern, params->pattern_len) == 0) {
            params->results[params->found_count++] = page_start + i;
            if (params->found_count >= params->max_results)
                break;
        }
    }

    kfree(page_buf);
}

// Walk through VMAs and search for pattern
static void search_process_memory(struct mm_struct *mm, struct search_params *params)
{
    struct vm_area_struct *vma;

    if (!mm) {
        printk(KERN_ERR "%s: mm is NULL!\n", tag);
        return;
    }

    down_read(&mm->mmap_sem);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        unsigned long addr;

        // Skip non-readable areas
        if (!(vma->vm_flags & VM_READ))
            continue;

        // Search each page in this VMA
        for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
            search_page(mm, addr, params);

            if (params->found_count >= params->max_results)
                break;
        }

        if (params->found_count >= params->max_results)
            break;
    }
    up_read(&mm->mmap_sem);
}

// Read memory from specified process
static int read_process_memory(struct read_request *req)
{
    struct task_struct *task;
    phys_addr_t phys_addr;
    unsigned char *kernel_buf = NULL;
    int ret = 0;

    // Validate size
    if (req->size == 0 || req->size > MAX_READ_SIZE) {
        printk(KERN_WARNING "%s: Invalid read size %zu\n", tag, req->size);
        return -EINVAL;
    }

    // Allocate kernel buffer
    kernel_buf = kmalloc(req->size, GFP_KERNEL);
    if (!kernel_buf) {
        printk(KERN_ERR "%s: Failed to allocate read buffer\n", tag);
        return -ENOMEM;
    }

    // Find the task
    task = get_pid_task(find_get_pid(req->pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "%s Can't find process PID: %d\n", tag, req->pid);
        ret = -ESRCH;
        goto out;
    }

    // Translate virtual address
    phys_addr = translate_linear_address(task->mm, req->vaddr);
    if (!phys_addr) {
        printk(KERN_ERR "%s: Failed to translate VA 0x%lx\n", tag, req->vaddr);
        ret = -EFAULT;
        goto out;
    }

    // Read the memory
    if (!read_phys_mem(phys_addr, kernel_buf, req->size)) {
        printk(KERN_ERR "%s: Failed to read memory at VA 0x%lx\n", tag, req->vaddr);
        ret = -EFAULT;
        goto out;
    }

    // Copy to user buffer
    if (copy_to_user((void __user *)req->buffer_addr, kernel_buf, req->size)) {
        printk(KERN_ERR "%s: Failed to copy to user buffer\n", tag);
        ret = -EFAULT;
        goto out;
    }

    req->status = 0; // Success
    printk(KERN_DEBUG "%s: Read %zu bytes from PID %d at VA 0x%lx\n",
           tag, req->size, req->pid, req->vaddr);

out:
    if (kernel_buf)
        kfree(kernel_buf);
    if (task)
        put_task_struct(task);

    return ret;
}

// Main search function using structure parameter
static int search_process(struct search_request *req)
{
    struct task_struct *task;
    struct search_params params;
    unsigned char *pattern = NULL;
    unsigned long *results = NULL;
    int ret = 0;

    // Allocate kernel buffers
    pattern = kmalloc(req->pattern_len, GFP_KERNEL);
    if (!pattern) {
        ret = -ENOMEM;
        goto out;
    }

    results = kmalloc_array(req->max_results, sizeof(unsigned long), GFP_KERNEL);
    if (!results) {
        ret = -ENOMEM;
        goto out;
    }

    // Copy pattern from user space
    if (copy_from_user(pattern, (void __user *)req->pattern_addr, req->pattern_len)) {
        ret = -EFAULT;
        goto out;
    }

    task = get_pid_task(find_get_pid(req->pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "%s Can't find process PID: %d\n", tag, req->pid);
        ret = -ESRCH;
        goto out;
    }

    printk(KERN_DEBUG "%s Searching PID=%d, name=%s\n", tag, req->pid, task->comm);

    params.pattern = pattern;
    params.pattern_len = req->pattern_len;
    params.results = results;
    params.max_results = req->max_results;
    params.found_count = 0;

    search_process_memory(task->mm, &params);

    req->found_count = params.found_count;
    printk(KERN_DEBUG "%s Found %zu matches\n", tag, params.found_count);

    // Copy results back to user space
    if (copy_to_user((void __user *)req->results_addr, results,
                    params.found_count * sizeof(unsigned long))) {
        ret = -EFAULT;
        goto out;
    }

out:
    if (pattern)
        kfree(pattern);
    if (results)
        kfree(results);
    if (task)
        put_task_struct(task);

    return ret;
}

static long memscan_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    if (_IOC_TYPE(cmd) != MEMSCAN_IOCTL_MAGIC) {
        return -ENOTTY;
    }

    switch (_IOC_NR(cmd)) {
        case 1: { // MEMSCAN_SEARCH
            struct search_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            // Validate input parameters
            if (req.pattern_len == 0 || req.pattern_len > PAGE_SIZE) {
                return -EINVAL;
            }

            if (req.max_results == 0 || req.max_results > MAX_RESULTS) {
                return -EINVAL;
            }

            ret = search_process(&req);

            // Copy back the updated structure with found_count
            if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
                return -EFAULT;
            }
            break;
        }

        case 2: { // MEMSCAN_READ
            struct read_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            ret = read_process_memory(&req);

            // Copy back the updated structure with status
            if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
                return -EFAULT;
            }
            break;
        }

        default:
            return -ENOTTY;
    }

    return ret;
}

static int memscan_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int memscan_release(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations memscan_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = memscan_ioctl,
    .open = memscan_open,
    .release = memscan_release,
};

static int __init memscanner_init(void)
{
    dev_t dev = 0;
    int ret;

    // Allocate a major number
    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "%s Failed to allocate char device region\n", tag);
        return ret;
    }
    major_num = MAJOR(dev);

    // Initialize the cdev structure and add it to kernel space
    cdev_init(&memscan_cdev, &memscan_fops);
    ret = cdev_add(&memscan_cdev, dev, 1);
    if (ret < 0) {
        printk(KERN_ERR "%s Failed to add cdev\n", tag);
        unregister_chrdev_region(dev, 1);
        return ret;
    }

    // Create device class
    memscan_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(memscan_class)) {
        printk(KERN_ERR "%s Failed to create device class\n", tag);
        cdev_del(&memscan_cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(memscan_class);
    }

    // Create the device node
    memscan_device = device_create(memscan_class, NULL, dev, NULL, DEVICE_NAME);
    if (IS_ERR(memscan_device)) {
        printk(KERN_ERR "%s Failed to create device\n", tag);
        class_destroy(memscan_class);
        cdev_del(&memscan_cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(memscan_device);
    }

    printk(KERN_INFO "%s Device initialized with major number %d\n", tag, major_num);
    return 0;
}

static void __exit memscanner_exit(void)
{
    dev_t dev = MKDEV(major_num, 0);

    // Clean up the device
    if (memscan_device) {
        device_destroy(memscan_class, dev);
    }
    if (memscan_class) {
        class_destroy(memscan_class);
    }
    cdev_del(&memscan_cdev);
    unregister_chrdev_region(dev, 1);

    printk(KERN_INFO "%s Device unloaded\n", tag);
}

module_init(memscanner_init);
module_exit(memscanner_exit);
