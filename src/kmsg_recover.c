#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/page.h>

#define MEMREG_LONGEST_SINGLE 38 // "0x1234567890abcdef$0x1234567890abcdef "

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lea Markov");
MODULE_DESCRIPTION("Kernel log recovery");
MODULE_VERSION("0.1");

int param_set_hex(const char *val, const struct kernel_param *kp){
    return kstrtoul(val, 16, (unsigned long*)kp->arg);
}

int param_get_hex(char *buffer, const struct kernel_param *kp){
    return scnprintf(buffer, PAGE_SIZE, "%lx", *((unsigned long*)kp->arg));
}

const struct kernel_param_ops param_ops_hex = {
    .set = param_set_hex,
    .get = param_get_hex
};

#define param_check_hex(name, p) param_check_ulong(name, p)

// since kallsyms_lookup_name() isn't exported anymore, we have to be dirty
static unsigned long lb_addr_cur = 0; // address of __log_buf
module_param(lb_addr_cur, hex, 0400);

static unsigned long lb_len_addr_cur = 0; // address of log_buf_len
module_param(lb_len_addr_cur, hex, 0400);

static char log_buf_memreg[MEMREG_LONGEST_SINGLE+1];
static char log_buf_memreg_past[MEMREG_LONGEST_SINGLE+1];
static unsigned log_buf_memreg_past_pos;

static unsigned lb_len_past;
static unsigned long lb_phys_past;
static char *lb_virt_past;

static struct proc_dir_entry *pde_log_buf;
static struct proc_dir_entry *pde_log_buf_memreg;

ssize_t buf_read(char *kbuf, unsigned kbuf_len, char __user *buf, size_t len, loff_t *offset){
	int remaining = kbuf_len - *offset;
	if(remaining <= 0){
		return 0;
	}else if(remaining < len){
		len = remaining;
	}
	if(copy_to_user(buf, &kbuf[*offset], len)){
		return -EFAULT;
	}
	*offset += len;
	return len;
}

// user reads the past log_buf, if they set up lb_virt_past
// by writing to /proc/log_buf_memreg
ssize_t log_buf_read(struct file *f, char __user *buf, size_t len, loff_t *offset){
	if(lb_virt_past){
		return buf_read(lb_virt_past, lb_len_past, buf, len, offset);
	}
	
	return -EINVAL;
}

static struct proc_ops pops_log_buf = {
	.proc_read = log_buf_read,
};

int log_buf_memreg_open(struct inode *i, struct file *f){
	log_buf_memreg_past_pos = 0;

	return 0;
}

// user reads current log_buf physical address and size
ssize_t log_buf_memreg_read(struct file *f, char __user *buf, size_t len, loff_t *offset){
	return buf_read(log_buf_memreg, strnlen(log_buf_memreg, MEMREG_LONGEST_SINGLE+1), buf, len, offset);
}

// user writes past log_buf physical address and size
ssize_t log_buf_memreg_write(struct file *f, const char __user *buf, size_t len, loff_t *offset){
	if(log_buf_memreg_past_pos + len > MEMREG_LONGEST_SINGLE){
		return -EINVAL;
	}
	if(copy_from_user(&log_buf_memreg_past[log_buf_memreg_past_pos], buf, len)){
		return -EFAULT;
	}
	log_buf_memreg_past_pos += len;

	return len;
}

// user closes the file and we parse the past memory region entry
int log_buf_memreg_release(struct inode *i, struct file *f){
	int ret;
	
	log_buf_memreg_past[log_buf_memreg_past_pos] = '\0';
	ret = sscanf(log_buf_memreg_past, "0x%x$0x%lx",
			&lb_len_past, &lb_phys_past);
	if(ret != 2){
		return -EINVAL;
	}

	lb_virt_past = ioremap(lb_phys_past, lb_len_past);

	return 0;
}

static struct proc_ops pops_log_buf_memreg = {
	.proc_open = log_buf_memreg_open,
	.proc_read = log_buf_memreg_read,
	.proc_write = log_buf_memreg_write,
	.proc_release = log_buf_memreg_release,
};

static void get_log_buf_pa(char *log_buf, unsigned log_buf_len){
	unsigned long phys = virt_to_phys(log_buf);
	snprintf(log_buf_memreg, MEMREG_LONGEST_SINGLE+1, "0x%x$0x%lx", log_buf_len, phys);
}

static int __init krcvr_init(void){
	unsigned lb_len_cur;
	char *lb_cur;

	if(!(lb_len_addr_cur && lb_addr_cur)){
		return -EINVAL;
	}
	lb_len_cur = *((unsigned *)lb_len_addr_cur);
	lb_cur = (char*)lb_addr_cur;
	
	pr_info("kmsg_recover: lb addr cur=0x%lx\n", lb_addr_cur);
	pr_info("kmsg_recover: lb cur PA=0x%llx", virt_to_phys(lb_cur));
	pr_info("kmsg_recover: lb len addr cur=0x%lx\n", lb_len_addr_cur);
	pr_info("kmsg_recover: lb len=0x%u\n", lb_len_cur);
	
	get_log_buf_pa(lb_cur, lb_len_cur);

	pde_log_buf = proc_create("log_buf",
		S_IFREG | S_IRUSR,
		NULL, // = /proc
		&pops_log_buf);

	pde_log_buf_memreg = proc_create("log_buf_memreg",
		S_IFREG | S_IRUSR,
		NULL, // = /proc
		&pops_log_buf_memreg);
	
	return 0;
}

static void __exit krcvr_exit(void){
	proc_remove(pde_log_buf);
	proc_remove(pde_log_buf_memreg);
}

module_init(krcvr_init);
module_exit(krcvr_exit);
