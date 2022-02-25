#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nasm");
MODULE_DESCRIPTION("Modules that prodives the mapping for a process");
MODULE_VERSION("1.0");

#define UMAPS_PAGE_ALIGN(addr) ((addr) & PAGE_MASK)

static int umaps_open(struct inode *, struct file *);
static int umaps_release(struct inode *, struct file *);
static ssize_t umaps_read(struct file *, char *, size_t, loff_t *);
static ssize_t umaps_write(struct file *, const char *, size_t, loff_t *);
static long umaps_ioctl(struct file *, unsigned int, unsigned long);

static struct mutex umaps_mutex;

static const struct file_operations g_fops = {
  .owner = THIS_MODULE,
  .open = umaps_open,
  .release = umaps_release,
  .unlocked_ioctl = umaps_ioctl,
  .write = umaps_write,
  .read = umaps_read
};

static struct miscdevice g_device = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "umaps",
  .fops = &g_fops,
  .mode = 0666
};

#define UMAPS_IS_MAPPED 0x1
#define UMAPS_GET_PROT 0x10

#define UMAPS_FAILED -1

typedef struct request_s {
  uint64_t pid;
  uint64_t addr;
  uint64_t size;
  uint64_t result;
} request_t;

typedef struct mmap_s {
  uint64_t start;
  uint64_t size;
  int flags;
} _mmap_t;

static bool is_mapped(_mmap_t *mmap, struct vm_area_struct *vma) {
    struct vm_area_struct *vma_area = vma;

    do {
        if (vma_area->vm_start <= UMAPS_PAGE_ALIGN(mmap->start) && vma_area->vm_end >= UMAPS_PAGE_ALIGN(mmap->start) + mmap->size) {
            return true;
        }    

        vma_area = vma_area->vm_next;
    } while (vma_area != vma && vma_area != NULL);

    return false;
}

/*

static bool is_mapped_pid(uint64_t pid, _mmap_t *mmap) {
    struct task_struct *task = pid_task(find_vpid(pid), PIDTYPE_PID);
    struct vm_area_struct *vma = task->mm->mmap;

    return is_mapped(mmap, vma);
}

*/

#define	PROT_NONE	 0x00	/* No access.  */
#define	PROT_READ	 0x04	/* Pages can be read.  */
#define	PROT_WRITE	 0x02	/* Pages can be written.  */
#define	PROT_EXEC	 0x01	/* Pages can be executed.  */

static unsigned long get_prot(_mmap_t* mmap, struct vm_area_struct *vma) {
    struct vm_area_struct *vma_area = vma;
    uint64_t prot = 0;

    do {
        if (vma_area->vm_start <= UMAPS_PAGE_ALIGN(mmap->start) && vma_area->vm_end >= UMAPS_PAGE_ALIGN(mmap->start) + mmap->size) {
            if (vma_area->vm_page_prot.pgprot == UMAPS_FAILED) {
                prot = -EFAULT;
            } 
            
            if (vma_area->vm_page_prot.pgprot & VM_READ) {
                prot |= PROT_READ;
            } 
            
            if (vma_area->vm_page_prot.pgprot & VM_WRITE) {
                prot |= PROT_WRITE;
            } 
            
            if (vma_area->vm_page_prot.pgprot & VM_EXEC) {
                prot |= PROT_EXEC;
            }

            return prot;
        }

        vma_area = vma_area->vm_next;
    } while (vma_area != vma && vma_area != NULL);

    return UMAPS_FAILED;
}

static long umaps_ioctl(struct file *filp, unsigned int request, unsigned long ar) {
    request_t req = {0};
    _mmap_t u_mmap = {0};
    struct task_struct *task = current;

    mutex_lock(&umaps_mutex);

    if (-1 == copy_from_user(&req, (void *)ar, sizeof(request_t))) {
        return -EFAULT;
    }

    u_mmap.start = req.addr;
    u_mmap.size = req.size;

    req.result = 0;
    
    switch (request) {
        /* It checks if an adress is mapped */
        case UMAPS_IS_MAPPED:
          req.result = is_mapped(&u_mmap, task->mm->mmap);
          break;

        /* From a base address and a size returns the protections of this mapping */
        case UMAPS_GET_PROT:
            req.result = get_prot(&u_mmap, task->mm->mmap);
            break;

        default:
          break;
    }

    if (-1 == copy_to_user((void *)ar, &req, sizeof(request_t))) {
        mutex_unlock(&umaps_mutex);
        return -EFAULT;
    }

    mutex_unlock(&umaps_mutex);

    return 0;
}

static int umaps_open(struct inode *inode, struct file *filp) {
    return 0;
}

static int umaps_release(struct inode *inode, struct file *filp) {
    return 0;
}

static ssize_t umaps_read(struct file *filp, char *buf, size_t count, loff_t *f_pos) {
    return 0;
}

static ssize_t umaps_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos) {
    return 0;
}

/*
 * Initialisation function.
 */
static int __init umaps_init(void) {
    if(misc_register(&g_device)) {
        printk(KERN_ERR "Unable to register device\n");
        return -1;
    }

    mutex_init(&umaps_mutex);
    printk(KERN_INFO "umaps: module loaded\n");

    return 0;
}

/*
 * Cleanup function.
 */
static void __exit umaps_exit(void) {
    misc_deregister(&g_device);
}

module_init(umaps_init);
module_exit(umaps_exit);
