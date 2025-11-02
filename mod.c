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
#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/hugetlb.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Memory reader with read interface");

#define DEVICE_NAME "memread"
#define MAX_READ_SIZE PAGE_SIZE
#define MEMREAD_IOCTL_MAGIC 'M'
#define MEMREAD_READ _IOWR(MEMREAD_IOCTL_MAGIC, 1, struct read_request)

static char* tag = "MEMREAD: ";
static int major_num;
static struct class* memread_class = NULL;
static struct device* memread_device = NULL;
static struct cdev memread_cdev;

struct read_request {
    pid_t pid;
    unsigned long vaddr;
    size_t size;
    unsigned long buffer_addr;
    int status;
};

static bool read_phys_mem(phys_addr_t pa, void __user *buf, size_t size)
{
    void __iomem *mapped;
    bool ret = true;

    printk(KERN_INFO "%s: [PHYS_MEM] Start: pa=0x%llx, size=%zu\n",
    tag, (u64)pa, size);

    if (size == 0 || size > MAX_READ_SIZE) {
    printk(KERN_ERR "%s: [PHYS_MEM] Invalid size: %zu\n", tag, size);
    return false;
    }

    if (pa & (sizeof(void *)-1)) {
    printk(KERN_WARNING "%s: [PHYS_MEM] Unaligned address: 0x%llx\n", tag, (u64)pa);
    }

    if (!pfn_valid(__phys_to_pfn(pa))) {
    printk(KERN_ERR "%s: [PHYS_MEM] Invalid pfn for pa 0x%llx\n", tag, (u64)pa);
    return false;
    }

    printk(KERN_INFO "%s: [PHYS_MEM] Before ioremap_cache\n", tag);
    mapped = ioremap_cache(pa, size);
    if (!mapped) {
    printk(KERN_ERR "%s: [PHYS_MEM] ioremap_cache failed\n", tag);
    return false;
    }
    printk(KERN_INFO "%s: [PHYS_MEM] ioremap_cache succeeded: %p\n", tag, mapped);

    printk(KERN_INFO "%s: [PHYS_MEM] Before copy_to_user\n", tag);
    if (copy_to_user(buf, mapped, size)) {
    printk(KERN_ERR "%s: [PHYS_MEM] copy_to_user failed\n", tag);
    ret = false;
    } else {
    printk(KERN_INFO "%s: [PHYS_MEM] copy_to_user succeeded\n", tag);
    }

    printk(KERN_INFO "%s: [PHYS_MEM] Before iounmap\n", tag);
    iounmap(mapped);
    printk(KERN_INFO "%s: [PHYS_MEM] After iounmap\n", tag);

    printk(KERN_INFO "%s: [PHYS_MEM] Completed: %s\n", tag, ret ? "success" : "failed");
    return ret;
}


static bool read_phys_mem_direct(phys_addr_t pa, void __user *buf, size_t size)
{
    #if defined(CONFIG_ARCH_HAS_DIRECT_PHYS_ACCESS)
    return (copy_from_phys_to_user(buf, pa, size) == 0);
    #else
    return read_phys_mem(pa, buf, size);
    #endif
}


static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

    if (!mm) {
        printk(KERN_ERR "%s: mm is NULL!\n", tag);
        return 0;
    }

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

    pud = pud_offset(pgd, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    //pud -> huge page 1G
    if (pud_huge(*pud)) {
        printk(KERN_ERR "%s: pud huge page\n", tag);
        return 0;
    }

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;

    //pmd -> huge page 2M
    if (pmd_huge(*pmd) || pmd_trans_huge(*pmd)) {
        printk(KERN_ERR "%s: pmd huge page\n", tag);
        return 0;
    }

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte))
        return 0;

    if (!pte_present(*pte))
        return 0;

    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);
    return page_addr + page_offset;
}

static int read_process_memory(struct read_request *req)
{
    struct task_struct *task = NULL;
    phys_addr_t phys_addr;
    size_t remaining;
    uintptr_t current_va;
    void __user *current_buf;
    int ret = 0;

    rcu_read_lock();
    task = pid_task(find_pid_ns(req->pid, &init_pid_ns), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
    }
    rcu_read_unlock();

    if (!task) {
        printk(KERN_ERR "%s Can't find process PID: %d\n", tag, req->pid);
        ret = -ESRCH;
        goto out_cleanup;
    }

    if (!task->mm) {
        printk(KERN_ERR "%s: Process has no memory context\n", tag);
        ret = -EFAULT;
        goto out_cleanup;
    }

    remaining = req->size;
    current_va = req->vaddr;
    current_buf = (void __user *)req->buffer_addr;

    printk(KERN_ERR "%s request pid: %d start: %x size: %d\n", tag, req->pid,req->vaddr,req->size);
    while (remaining > 0) {
        printk(KERN_ERR "%s remaining: %d\n", tag, remaining);
        size_t bytes_in_page, chunk_size;
        bytes_in_page = PAGE_SIZE - (current_va & (PAGE_SIZE - 1));
        chunk_size = (remaining < bytes_in_page) ? remaining : bytes_in_page;
        if (!phys_addr) {
            printk(KERN_ERR "%s: Failed to translate VA 0x%lx at offset %zu\n",
                    tag, current_va, req->size - remaining);
            ret = -EFAULT;
            goto out_cleanup;
        }
        if (!read_phys_mem_direct(phys_addr, current_buf, chunk_size)) {
            printk(KERN_ERR "%s: Failed to read memory at VA 0x%lx, size %zu\n",
                    tag, current_va, chunk_size);
            ret = -EFAULT;
            goto out_cleanup;
        }
        remaining -= chunk_size;
        current_va += chunk_size;
        current_buf += chunk_size;
    }

    req->status = 0;
    printk(KERN_DEBUG "%s: Successfully read %zu bytes from PID %d at VA 0x%lx\n",
            tag, req->size, req->pid, req->vaddr);

    out_cleanup:
    if (task)
        put_task_struct(task);

    return ret;
}


static long memread_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    if (_IOC_TYPE(cmd) != MEMREAD_IOCTL_MAGIC) {
        return -ENOTTY;
    }

    switch (_IOC_NR(cmd)) {
        case 1: {
            struct read_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            ret = read_process_memory(&req);

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

static int memread_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int memread_release(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations memread_fops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = memread_ioctl,
        .open = memread_open,
        .release = memread_release,
};

static int __init memreader_init(void)
{
    dev_t dev = 0;
    int ret;

    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "%s Failed to allocate char device region\n", tag);
        return ret;
    }
    major_num = MAJOR(dev);

    cdev_init(&memread_cdev, &memread_fops);
    ret = cdev_add(&memread_cdev, dev, 1);
    if (ret < 0) {
        printk(KERN_ERR "%s Failed to add cdev\n", tag);
        unregister_chrdev_region(dev, 1);
        return ret;
    }

    memread_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(memread_class)) {
        printk(KERN_ERR "%s Failed to create device class\n", tag);
        cdev_del(&memread_cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(memread_class);
    }

    memread_device = device_create(memread_class, NULL, dev, NULL, DEVICE_NAME);
    if (IS_ERR(memread_device)) {
        printk(KERN_ERR "%s Failed to create device\n", tag);
        class_destroy(memread_class);
        cdev_del(&memread_cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(memread_device);
    }

    printk(KERN_INFO "%s Device initialized with major number %d\n", tag, major_num);
    return 0;
}

static void __exit memreader_exit(void)
{
    dev_t dev = MKDEV(major_num, 0);

    if (memread_device) {
        device_destroy(memread_class, dev);
    }
    if (memread_class) {
        class_destroy(memread_class);
    }
    cdev_del(&memread_cdev);
    unregister_chrdev_region(dev, 1);

    printk(KERN_INFO "%s Device unloaded\n", tag);
}

module_init(memreader_init);
module_exit(memreader_exit);