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
#define BUFFER_SIZE 16384
static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
int freq[256] = {0};
static atomic_t read_byte = ATOMIC_INIT(0);
static atomic_t write_byte = ATOMIC_INIT(0);
static DEFINE_MUTEX(freq_lock);

struct cryptomod_data {
    char *buffer;
    size_t size;
    size_t process_len;
	struct CryptoSetup setup;
    bool finalize;
}; 

int pkcs7_pad(char *buffer, int length, int block_size) {
	int padding_length = block_size - (length % block_size);
    if (padding_length == 0) {
        padding_length = block_size;
    }
	for (int i = 0; i < padding_length; i++) {
		buffer[length + i] = padding_length; // Add padding value
	}
    return padding_length;
}
	
static int test_skcipher(u8 *key, size_t key_len, u8 *data, size_t datasize, int mode)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;
    if (mode == ENC) {
        printk(KERN_INFO "test_skcipher: Encrypting %zu bytes.\n", datasize);
    } else {
        printk(KERN_INFO "test_skcipher: Decrypting %zu bytes.\n", datasize);
    }

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, key_len);
    if (err) {
        goto out;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        err = -ENOMEM;
        goto out;
    }

    sg_init_one(&sg, data, datasize);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, NULL);

    if (mode == ENC) {
        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    } else {
        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    }

    if (err) {
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

    // allocate private_data to data
    data = kzalloc(sizeof(struct cryptomod_data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    // Allocate buffer with fixed size
    data->buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!data->buffer) {
        kfree(data);
        return -ENOMEM;
    }
    data->size = 0; // Initialize size to 0
    data->process_len = 0;
    data->finalize = false;

    f->private_data = data; // bind to private_data
    printk(KERN_INFO "device opened.\n");
    return 0;
}

static int hellomod_dev_close(struct inode *i, struct file *f) {
	struct cryptomod_data *data = f->private_data;
    if (data) {
        if (data->buffer)
            kfree(data->buffer);
        kfree(data);
    }
    printk(KERN_INFO "device closed.\n");
    return 0;
}

static ssize_t hellomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	struct cryptomod_data *data = f->private_data;
    if (!data || data->finalize || data->setup.key_len == 0) 
        return -EINVAL;
    if (data->setup.io_mode == ADV) {
        printk(KERN_INFO "ADV mode write, len: %zu, data->size: %zu, process_len:%zu\n", len, data->size, data->process_len);
        if (copy_from_user(data->buffer + data->size, buf, len)) {
            return -EFAULT;
        }
        data->size += len;
<<<<<<< HEAD:hellomod.c
        atomic_add(len, &write_byte);
        // offset: current already encrypted/decrypted byte
        // data->size: total byte
        if (data->setup.c_mode == ENC) {
            // Check if len plus data->size is larger than CM_BLOCK_SIZE(16)
            // Count Encrypted byte
            size_t encrypt_len = (int)((data->size - data->process_len) / CM_BLOCK_SIZE) * CM_BLOCK_SIZE;
            if (encrypt_len) {
                test_skcipher(data->setup.key, data->setup.key_len, data->buffer + data->process_len, encrypt_len, ENC);
                data->process_len += encrypt_len;
=======
        // data->process_len: total byte processed
        // data->size: total byte
        if (data->setup.c_mode == ENC) {
            // Check if len plus data->size is larger than CM_BLOCK_SIZE(16)
            if (data->size >= CM_BLOCK_SIZE) {
                // Count Encrypted byte
                // | process_len | nonprocess_user_data | remain |
                size_t remain = data->size % CM_BLOCK_SIZE;
                size_t process_len = data->size - remain - data->process_len;
                test_skcipher(data->setup.key, data->setup.key_len, data->buffer + data->process_len, process_len, ENC);
                atomic_add(len, &write_byte);
                data->process_len += process_len;
                return len;
>>>>>>> feat/lab2:lab2/hellomod.c
            }
            return len;
        }
        else if (data->setup.c_mode == DEC) {
<<<<<<< HEAD:hellomod.c
            // Count Decrypted byte (data->size over CM_BLOCK_SIZE), reserve at least 16 bytes
            size_t valid_size = data->size % CM_BLOCK_SIZE == 0 ? data->size - CM_BLOCK_SIZE : data->size - (data->size % CM_BLOCK_SIZE);
            size_t decrypt_len = valid_size - data->process_len;
            if (decrypt_len) {
=======
            if (data->size > CM_BLOCK_SIZE) {
                // Count Decrypted byte (data->size over CM_BLOCK_SIZE), reserve at least 16 bytes
                // data->size % CM_BLOCK_SIZE == 0
                // | process_len | nonprocess_user_data | 16 |
                // data->size % CM_BLOCK_SIZE != 0
                // | process_len | nonprocess_user_data | remain |
                size_t valid_size = data->size % CM_BLOCK_SIZE == 0 ? data->size - CM_BLOCK_SIZE : data->size - (data->size % CM_BLOCK_SIZE);
                size_t decrypt_len = valid_size - data->process_len;
>>>>>>> feat/lab2:lab2/hellomod.c
                test_skcipher(data->setup.key, data->setup.key_len, data->buffer + data->process_len, decrypt_len, DEC);
                data->process_len += decrypt_len;
            }
            // printk(KERN_INFO "After ADV mode write, len: %zu, data->size: %zu, process_len:%zu, decrypt_len:%zu\n", len, data->size, data->process_len, decrypt_len);
            return len;
        }
    }
    else {
        printk(KERN_INFO "BASIC: write %zu bytes @ %llu.\n", len, *off);
        // Check if there is enough space in the buffer
        if (data->size + len > BUFFER_SIZE) {
            return -ENOMEM;
        }

        // Copy data from user space to kernel buffer
        if (copy_from_user(data->buffer + data->size, buf, len)) {
            return -EFAULT;
        }

        data->size += len;
        *off += len;
        atomic_add(len, &write_byte);
        return len;
    }
    return -EINVAL;
}

static ssize_t hellomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	struct cryptomod_data *data = f->private_data;
    if (!data || !data->setup.key_len) 
        return -EINVAL;
    // If no data to read
    if (!data || !data->buffer || data->size == 0)
        return 0;
    printk(KERN_INFO "read %zu bytes @ %llu.\n", len, *off);

    if (data->setup.io_mode == ADV) {
        if (data->setup.c_mode == ENC) {
            // Count Encrypted byte
<<<<<<< HEAD:hellomod.c
            size_t read_len = min(data->process_len, len);
            read_len -= read_len % CM_BLOCK_SIZE;
            if (!read_len)
            {
                if (data->finalize)
                    return 0;
                else
                    return -EAGAIN;
            }
=======
            // | process_len | remain |
            size_t available = data->size - (data->size % CM_BLOCK_SIZE);
            size_t read_len = min(available, len);
>>>>>>> feat/lab2:lab2/hellomod.c
            if (copy_to_user(buf, data->buffer, read_len)) {
                return -EFAULT;
            }
            mutex_lock(&freq_lock);
            // Count frequency
            for (size_t i = 0; i < read_len; i++) {
                unsigned char byte = data->buffer[i];
                freq[byte]++;
            }
            mutex_unlock(&freq_lock);
            // Move remain data to the front
            // memmove(dest, src, size)
            memmove(data->buffer, data->buffer + read_len, data->size - read_len);
            data->size -= read_len;
            data->process_len -= read_len;
            atomic_add(read_len, &read_byte);
            return read_len;
        }
        else if (data->setup.c_mode == DEC) {
            // Count Encrypted byte
            // | process_len |
            size_t read_len = min(data->process_len, len);
            read_len -= read_len % CM_BLOCK_SIZE;
            if (!read_len)
            {
                if (data->finalize)
                    return 0;
                else
                    return -EAGAIN;
            }
            if (copy_to_user(buf, data->buffer, read_len)) {
                return -EFAULT;
            }
            // Move remain data to the front
            // memmove(dest, src, size)
            memmove(data->buffer, data->buffer + read_len, data->size - read_len);
            data->size -= read_len;
            data->process_len -= read_len;
            atomic_add(read_len, &read_byte);
            return read_len;
        }
    }
    // If we've already read everything
    if (*off >= data->size)
        return 0;
    size_t available = data->size - *off;
    size_t read_len = min(available, len);
    // 把解密後的資料送回 user-space
    if (copy_to_user(buf, data->buffer + *off, read_len)) {
        return -EFAULT;
    }

    if (data->setup.c_mode == ENC) {
        // Count frequency
        for (size_t i = 0; i < read_len; i++) {
            unsigned char byte = data->buffer[*off + i];
            freq[byte]++;
        }
    }
    *off += read_len;
    // Read byte update
    atomic_add(read_len, &read_byte);
    return read_len;
}

static long hellomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	struct cryptomod_data *data = fp->private_data;
	switch (cmd) {
        case CM_IOC_SETUP:
            if (!(void __user *)arg)
                return -EINVAL;
            if (copy_from_user(&data->setup, (struct CryptoSetup __user *)arg, sizeof(struct CryptoSetup))) {
                return -EBUSY;
            }
            if (data->setup.key_len != 16 && data->setup.key_len != 24 && data->setup.key_len != 32)
                return -EINVAL;
            if (data->setup.io_mode != BASIC && data->setup.io_mode != ADV)
                return -EINVAL;
            if (data->setup.c_mode != ENC && data->setup.c_mode != DEC)
                return -EINVAL;
            printk(KERN_EMERG "ioctl SETUP - key_len: %d, io_mode: %d, c_mode: %d\n",
                   data->setup.key_len, data->setup.io_mode, data->setup.c_mode);
            break;

        case CM_IOC_FINALIZE:
            if (data->setup.io_mode == ADV) {
                if (data->setup.c_mode == ENC) {
                    // Count Encrypted byte
                    int padding_length = pkcs7_pad(data->buffer, data->size, CM_BLOCK_SIZE);
                    data->size += padding_length;
                    // Encrypt range from *off(last encrptyed) to padding
                    size_t process_len = data->size - data->process_len;
                    test_skcipher(data->setup.key, data->setup.key_len, data->buffer + data->process_len, process_len, ENC);
                    // write_byte don't include padding but user data
                    atomic_add(process_len - padding_length, &write_byte);
                    data->process_len += process_len;
                } else if (data->setup.c_mode == DEC) {
                    // print data->size and data->process_len
                    // printk(KERN_INFO "data->size: %zu, data->process_len: %zu\n", data->size, data->process_len);
                    // Count Decrypted byte (data->size over CM_BLOCK_SIZE)
                    // if ((data->size - data->process_len) % CM_BLOCK_SIZE != 0) {
                    //     return 0;
                    // }
                    if (data->size % CM_BLOCK_SIZE != 0)
                        return -EINVAL;
                    test_skcipher(data->setup.key, data->setup.key_len, data->buffer, data->size - data->process_len, DEC);
                    // Check end byte for padding
                    int pad_size = data->buffer[data->size - 1];
                    // Check if last byte chars are all equal last byte
                    for (int i = 1; i <= pad_size; i++) {
                        if (data->buffer[data->size - i] != pad_size) {
                            return -EINVAL;
                        }
                    }
                    // Remove padding
                    data->size -= pad_size;
                    // atomic_add(data->size - data->process_len, &read_byte);
                    data->process_len = data->size;
                    memset(data->buffer + data->size, '\0', pad_size);
                    // printk(KERN_INFO "ioctl FINALIZE - DECRYPT\n");
                } else {
                    return -EINVAL;
                }
                data->finalize = true;
            }
            else if (data->setup.io_mode == BASIC) {
                if(data->setup.c_mode == ENC) {
                    // Add padding
                    int pad_size = pkcs7_pad(data->buffer, data->size, CM_BLOCK_SIZE);
                    data->size += pad_size;
    
                    if (test_skcipher(data->setup.key, data->setup.key_len, data->buffer, data->size, ENC)) {
                        kfree(data->buffer);
                        return -EINVAL;
                    }
                } else if(data->setup.c_mode == DEC) {
                    if (test_skcipher(data->setup.key, data->setup.key_len, data->buffer, data->size, DEC)) {
                        kfree(data->buffer);
                        return -EINVAL;
                    }
                    // Check end byte for padding
                    int pad_size = data->buffer[data->size - 1];
                    // Check if last byte chars are all equal last byte
                    for (int i = 1; i <= pad_size; i++) {
                        if (data->buffer[data->size - i] != pad_size) {
                            return -EINVAL;
                        }
                    }
                    // Remove padding
                    data->size -= pad_size;
                } else {
                    return -EINVAL;
                }
                data->finalize = true;
                fp->f_pos = 0;
            }
            break;

        case CM_IOC_CLEANUP:
            data->size = 0;
            data->process_len = 0;
            data->finalize = false;
            kfree(data->buffer); // Free
            data->buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
            if (!data->buffer) {
                return -ENOMEM;
            }
            printk(KERN_INFO "ioctl CLEANUP\n");
            break;

        case CM_IOC_CNT_RST:
            atomic_set(&write_byte, 0);
            atomic_set(&read_byte, 0);

            mutex_lock(&freq_lock);
            for (int i = 0; i < 256; i++) {
                freq[i] = 0;
            }
            mutex_unlock(&freq_lock);
            printk(KERN_INFO "ioctl COUNT RESET\n");
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
	seq_printf(m, "%d %d\n", atomic_read(&read_byte), atomic_read(&write_byte));
    mutex_lock(&freq_lock);
	for (int i = 0; i < 16 * 16; i++) {
        seq_printf(m, "%d ", freq[i]);
        if ((i + 1) % 16 == 0) // New line after every 16 elements
			seq_printf(m, "\n");
    }
    mutex_unlock(&freq_lock);
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
