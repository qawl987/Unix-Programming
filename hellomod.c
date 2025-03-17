/*
* Lab problem set for UNIX programming course
* by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
* License: GPLv2
*/
#include "cryptomod.h"
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include <linux/printk.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
char freq[] =
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000"
"0000000000000000";
int read_byte = 0;
int write_byte = 0;

struct cryptomod_data {
    char *buffer;
    size_t size;
	struct CryptoSetup setup;
}; 
// u8 u8_key = 0x01;
// u8 *aes_key = &u8_key;
size_t key_len = 16;

uint8_t *aes_key = (uint8_t[]) {0x12, 0x34, 0x56, 0x78, 
	0x9A, 0xBC, 0xDE, 0xF0, 
	0x11, 0x22, 0x33, 0x44, 
	0x55, 0x66, 0x77, 0x88};

void pkcs7_pad(char *buffer, int length, int block_size) {
	int padding_length = block_size - (length % block_size);
	for (int i = 0; i < padding_length; i++) {
		buffer[length + i] = padding_length; // Add padding value
	}
}
	
static int test_skcipher(u8 *key, size_t key_len, u8 *data, size_t datasize, int enc)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;

    printk(KERN_INFO "test_skcipher: Starting encryption/decryption. key_len: %zu, data_size: %zu.\n", key_len, datasize);

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "test_skcipher: Failed to allocate skcipher\n");
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, key_len);
    if (err) {
        printk(KERN_ERR "test_skcipher: Failed to set key\n");
        goto out;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "test_skcipher: Failed to allocate request\n");
        err = -ENOMEM;
        goto out;
    }

    sg_init_one(&sg, data, datasize);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, NULL);

    if (enc) {
        printk(KERN_INFO "test_skcipher: Encrypting data\n");
        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    } else {
        printk(KERN_INFO "test_skcipher: Decrypting data\n");
        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    }

    if (err) {
        printk(KERN_ERR "test_skcipher: Encryption/Decryption failed with error %d\n", err);
        goto out;
    }

out:
    if (tfm)
        crypto_free_skcipher(tfm);
    if (req)
        skcipher_request_free(req);
    printk(KERN_INFO "test_skcipher: Operation completed with status %d\n", err);
    return err;
}

static int hellomod_dev_open(struct inode *i, struct file *f) {
	struct cryptomod_data *data;

    // 分配一個 private_data 給這個開啟的檔案
    data = kzalloc(sizeof(struct cryptomod_data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    f->private_data = data; // 綁定到這個 file 結構
    printk(KERN_INFO "hellomod: device opened.\n");
    return 0;
}

static int hellomod_dev_close(struct inode *i, struct file *f) {
	struct cryptomod_data *data = f->private_data;
    if (data) {
        if (data->buffer)
            kfree(data->buffer);
        kfree(data);
    }
    printk(KERN_INFO "hellomod: device closed.\n");
    return 0;
}

static ssize_t hellomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	struct cryptomod_data *data = f->private_data;
    if (!data) return -EINVAL;

    printk(KERN_INFO "hellomod: write %zu bytes @ %llu.\n", len, *off);
	// 釋放舊 buffer
    if(data->buffer){
        kfree(data->buffer);
	}
	printk(KERN_INFO "free data buffer success");
    // 分配新 buffer
    data->buffer = kmalloc(len, GFP_KERNEL);
    if (!data->buffer){
        return -ENOMEM;
	}
	printk(KERN_INFO "allocate buffer success");
    // 從 user space 複製資料到 kernel buffer
    if (copy_from_user(data->buffer, buf, len)) {
        kfree(data->buffer);
        return -EFAULT;
    }

	// Add padding
	pkcs7_pad(data->buffer, len, 16);
	// Print debug
	printk(KERN_INFO "User buffer contents: ");
    for (size_t i = 0; i < 16; i++) {
        printk(KERN_CONT "%c", data->buffer[i]); // Print each byte as hex
    }
    printk(KERN_CONT "\n");

    data->size = 16;

    // 執行 AES 加密
    if (test_skcipher(aes_key, key_len, data->buffer, data->size, 1)) {
		printk(KERN_INFO "crypto_error");
        kfree(data->buffer);
        return -EINVAL;
    }

	for (size_t i = 0; i < len; i++) {
        printk(KERN_CONT "%c", data->buffer[i]); // Print each byte as hex
    }
    printk(KERN_CONT "\n");
    return len;
}

static ssize_t hellomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	struct cryptomod_data *data = f->private_data;
    if (!data || !data->buffer || data->size == 0)
        return 0; // 沒有資料可if讀

    printk(KERN_INFO "hellomod: read %zu bytes @ %llu.\n", len, *off);

    // 分配暫存 buffer 來存放解密結果
    char *temp_buffer = kmalloc(data->size, GFP_KERNEL);
    if (!temp_buffer) return -ENOMEM;

    memcpy(temp_buffer, data->buffer, data->size);

    // 執行 AES 解密
    if (test_skcipher(aes_key, key_len, temp_buffer, data->size, 0)) {
        kfree(temp_buffer);
        return -EINVAL;
    }

    // 把解密後的資料送回 user-space
    if (copy_to_user(buf, temp_buffer, data->size)) {
        kfree(temp_buffer);
        return -EFAULT;
    }

    kfree(temp_buffer);
    return data->size;
}

static long hellomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO "hellomod: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	struct cryptomod_data *data = fp->private_data;
	switch (cmd) {
        case CM_IOC_SETUP:
            if (copy_from_user(&data->setup, (struct CryptoSetup __user *)arg, sizeof(struct CryptoSetup))) {
                return -EFAULT;
            }
            printk(KERN_INFO "hellomod: ioctl SETUP - key_len: %d, io_mode: %d, c_mode: %d\n",
                   data->setup.key_len, data->setup.io_mode, data->setup.c_mode);
            break;

        case CM_IOC_FINALIZE:
            printk(KERN_INFO "hellomod: ioctl FINALIZE\n");
            break;

        case CM_IOC_CLEANUP:
            printk(KERN_INFO "hellomod: ioctl CLEANUP\n");
            break;

        case CM_IOC_CNT_RST:
            printk(KERN_INFO "hellomod: ioctl COUNT RESET\n");
            break;

        default:
            return -EINVAL;
    }
	return 0;
}

static const struct file_operations hellomod_dev_fops = {
	.owner = THIS_MODULE,
	.open = hellomod_dev_open,
	.read = hellomod_dev_read,
	.write = hellomod_dev_write,
	.unlocked_ioctl = hellomod_dev_ioctl,
	.release = hellomod_dev_close
};

static int hellomod_proc_read(struct seq_file *m, void *v) {
	// char buf[] = "`hello, world!` in /proc.\n";
	seq_printf(m, "%s", "0 0\n");
	for (int i = 0; i < 16 * 16; i++) {
        seq_printf(m, "%c ", freq[i]);
        if ((i + 1) % 16 == 0) // New line after every 16 elements
			seq_printf(m, "\n");
    }
	return 0;
}

static int hellomod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, hellomod_proc_read, NULL);
}

static const struct proc_ops hellomod_proc_fops = {
	.proc_open = hellomod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *hellomod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init hellomod_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "cryptomod") < 0)
		return -1;
	if((clazz = class_create("crypto_class")) == NULL)
		goto release_region;
	clazz->devnode = hellomod_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
		goto release_class;
	cdev_init(&c_dev, &hellomod_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("cryptomod", 0, NULL, &hellomod_proc_fops);

	printk(KERN_INFO "cryptomod: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit hellomod_cleanup(void)
{
	remove_proc_entry("cryptomod", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "cryptomod: cleaned up.\n");
}

module_init(hellomod_init);
module_exit(hellomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
