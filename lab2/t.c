#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include "cryptomod.h"

#define BASIC_BUFFER_SIZE 1024

struct cryptodev_state
{
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    char *buffer;
    size_t buffer_size;
    size_t encrypt_size;
    size_t decrypt_size;
    size_t max_buffer_size;
    bool finalized;
    enum IOMode io_mode;
    enum CryptoMode c_mode;
};

static atomic_t total_bytes_read = ATOMIC_INIT(0);
static atomic_t total_bytes_written = ATOMIC_INIT(0);
static unsigned int byte_freq[256] = {0};
static DEFINE_MUTEX(freq_lock);

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static int cryptodev_open(struct inode *i, struct file *f)
{
    struct cryptodev_state *state = kzalloc(sizeof(struct cryptodev_state), GFP_KERNEL);
    state->max_buffer_size = BASIC_BUFFER_SIZE + 1;
    state->buffer = (char *)kzalloc(state->max_buffer_size, GFP_KERNEL);
    if (!state)
        return -ENOMEM;
    f->private_data = state;
    return 0;
}

static int cryptodev_close(struct inode *i, struct file *f)
{
    struct cryptodev_state *state = f->private_data;
    if (state)
    {
        if (state->tfm)
            crypto_free_skcipher(state->tfm);
        if (state->req)
            skcipher_request_free(state->req);
        if (state->buffer)
            kfree(state->buffer);
        kfree(state);
    }
    return 0;
}

static ssize_t cryptodev_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
    struct cryptodev_state *state = f->private_data;
    size_t not_copied;

    if (!state->tfm || state->finalized)
        return -EINVAL;

    if ((len + state->buffer_size > BASIC_BUFFER_SIZE) && state->io_mode == BASIC)
        len = BASIC_BUFFER_SIZE - state->buffer_size;

    if (len == 0)
        return -EAGAIN;

    if (state->max_buffer_size < len + state->buffer_size)
    {
        state->max_buffer_size = len + state->buffer_size + 1;
        char *tmp_buffer = (char *)kzalloc(state->max_buffer_size, GFP_KERNEL);
        memcpy(tmp_buffer, state->buffer, state->buffer_size);
        kfree(state->buffer);
        state->buffer = tmp_buffer;
    }

    not_copied = copy_from_user(state->buffer + state->buffer_size, buf, len);
    if (not_copied == len)
        return -EAGAIN;

    state->buffer_size += (len - not_copied);
    atomic_add(len - not_copied, &total_bytes_written);

    if (state->io_mode == ADV)
    {
        if (state->c_mode == ENC)
        {
            int encrypt_size = (int)((state->buffer_size - state->encrypt_size) / CM_BLOCK_SIZE) * CM_BLOCK_SIZE;

            if (encrypt_size)
            {
                struct scatterlist sg;
                DECLARE_CRYPTO_WAIT(wait);

                sg_init_one(&sg, state->buffer + state->encrypt_size, encrypt_size);
                skcipher_request_set_callback(state->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                              crypto_req_done, &wait);
                skcipher_request_set_crypt(state->req, &sg, &sg, encrypt_size, NULL);

                int err = crypto_wait_req(crypto_skcipher_encrypt(state->req), &wait);
                if (err)
                {
                    pr_err("Error encrypting data: %d\n", err);
                }
                pr_debug("Encryption was successful\n");

                state->encrypt_size += encrypt_size;
            }
        }
        else
        {
            int vaild_size = state->buffer_size % CM_BLOCK_SIZE == 0 ? state->buffer_size - CM_BLOCK_SIZE : state->buffer_size - (state->buffer_size % CM_BLOCK_SIZE);
            int decrypt_size = vaild_size - state->decrypt_size;

            if (decrypt_size)
            {
                struct scatterlist sg;
                DECLARE_CRYPTO_WAIT(wait);

                sg_init_one(&sg, state->buffer + state->decrypt_size, decrypt_size);
                skcipher_request_set_callback(state->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                              crypto_req_done, &wait);
                skcipher_request_set_crypt(state->req, &sg, &sg, decrypt_size, NULL);

                int err = crypto_wait_req(crypto_skcipher_decrypt(state->req), &wait);
                if (err)
                {
                    pr_err("Error decrypting data: %d\n", err);
                }
                pr_debug("Decryption was successful\n");

                state->decrypt_size += decrypt_size;
            }
        }
    }

    return len - not_copied;
}

static ssize_t cryptodev_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    struct cryptodev_state *state = f->private_data;

    if (!state->tfm)
        return -EINVAL;

    if (state->c_mode == ENC)
    {
        if (len > state->encrypt_size)
            len = state->encrypt_size;
        if (state->io_mode == ADV)
            len -= len % CM_BLOCK_SIZE;
    }
    else
    {
        if (len > state->decrypt_size)
            len = state->decrypt_size;
        if (state->io_mode == ADV)
            len -= len % CM_BLOCK_SIZE;
    }

    if (!len)
    {
        if (state->finalized)
            return 0;
        else
            return -EAGAIN;
    }
    else
    {
        size_t not_copied = copy_to_user(buf, state->buffer, len);
        if (!state->finalized && not_copied == len)
            return -EAGAIN;

        state->buffer_size -= (len - not_copied);
        if (state->c_mode == ENC)
        {
            state->encrypt_size -= (len - not_copied);
        }
        else
        {
            state->decrypt_size -= (len - not_copied);
        }
        memmove(state->buffer, state->buffer + len - not_copied, state->buffer_size);
        atomic_add(len - not_copied, &total_bytes_read);

        if (state->c_mode == ENC)
        {
            mutex_lock(&freq_lock);
            for (int i = 0; i < len - not_copied; i++)
                byte_freq[(unsigned char)buf[i]]++;
            mutex_unlock(&freq_lock);
        }

        return len - not_copied;
    }
}

static long cryptodev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct cryptodev_state *state = f->private_data;
    struct CryptoSetup setup;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err = 0;

    switch (cmd)
    {
    case CM_IOC_SETUP:
        if (!(void __user *)arg)
            return -EINVAL;
        if (copy_from_user(&setup, (void __user *)arg, sizeof(setup)))
            return -EBUSY;
        if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32)
            return -EINVAL;

        state->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
        if (IS_ERR(state->tfm))
        {
            pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(state->tfm));
            return PTR_ERR(state->tfm);
        }

        err = crypto_skcipher_setkey(state->tfm, setup.key, setup.key_len);
        if (err)
        {
            pr_err("Error setting key: %d\n", err);
            crypto_free_skcipher(state->tfm);
            return err;
        }

        state->req = skcipher_request_alloc(state->tfm, GFP_KERNEL);
        if (!state->req)
        {
            err = -ENOMEM;
            crypto_free_skcipher(state->tfm);
            skcipher_request_free(state->req);
            return err;
        }

        if (setup.io_mode != BASIC && setup.io_mode != ADV)
            return -EINVAL;

        if (setup.c_mode != ENC && setup.c_mode != DEC)
            return -EINVAL;

        state->io_mode = setup.io_mode;
        state->c_mode = setup.c_mode;
        state->buffer_size = 0;
        state->encrypt_size = 0;
        state->decrypt_size = 0;
        state->max_buffer_size = BASIC_BUFFER_SIZE + 1;
        kfree(state->buffer);
        state->buffer = (char *)kzalloc(state->max_buffer_size, GFP_KERNEL);
        break;
    case CM_IOC_FINALIZE:
        if (!state->tfm)
            return -EINVAL;
        state->finalized = true;

        if (state->c_mode == ENC)
        {
            size_t pad_len = CM_BLOCK_SIZE - (state->buffer_size % CM_BLOCK_SIZE);
            if (pad_len == 0)
                pad_len = CM_BLOCK_SIZE;

            if (state->max_buffer_size < pad_len + state->buffer_size)
            {
                state->max_buffer_size = pad_len + state->buffer_size + 1;
                char *tmp_buffer = (char *)kzalloc(state->max_buffer_size, GFP_KERNEL);
                memcpy(tmp_buffer, state->buffer, state->buffer_size);
                kfree(state->buffer);
                state->buffer = tmp_buffer;
            }
            memset(state->buffer + state->buffer_size, pad_len, pad_len);
            state->buffer_size += pad_len;

            if (state->io_mode == BASIC)
            {
                sg_init_one(&sg, state->buffer, state->buffer_size);
                skcipher_request_set_callback(state->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                              crypto_req_done, &wait);
                skcipher_request_set_crypt(state->req, &sg, &sg, state->buffer_size, NULL);
                state->encrypt_size += state->buffer_size;
            }
            else
            {
                sg_init_one(&sg, state->buffer + state->encrypt_size, CM_BLOCK_SIZE);
                skcipher_request_set_callback(state->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                              crypto_req_done, &wait);
                skcipher_request_set_crypt(state->req, &sg, &sg, CM_BLOCK_SIZE, NULL);
                state->encrypt_size += CM_BLOCK_SIZE;
            }

            err = crypto_wait_req(crypto_skcipher_encrypt(state->req), &wait);
            if (err)
            {
                pr_err("Error encrypting data: %d\n", err);
            }
            pr_debug("Encryption was successful\n");
        }
        else
        {
            if (state->buffer_size % CM_BLOCK_SIZE != 0)
                return -EINVAL;

            sg_init_one(&sg, state->buffer, state->buffer_size - state->decrypt_size);
            skcipher_request_set_callback(state->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                          crypto_req_done, &wait);
            skcipher_request_set_crypt(state->req, &sg, &sg, state->buffer_size - state->decrypt_size, NULL);

            err = crypto_wait_req(crypto_skcipher_decrypt(state->req), &wait);
            if (err)
            {
                pr_err("Error decrypting data: %d\n", err);
            }
            pr_debug("Decryption was successful\n");

            uint8_t pad_byte = state->buffer[state->buffer_size - 1];
            if (pad_byte == 0)
                return -EINVAL;
            for (int i = 1; i <= pad_byte; i++)
            {
                if (state->buffer[state->buffer_size - i] != pad_byte)
                {
                    return -EINVAL;
                }
            }

            state->buffer_size -= pad_byte;
            state->decrypt_size = state->buffer_size;
            memset(state->buffer + state->buffer_size, '\0', pad_byte);
        }
        break;
    case CM_IOC_CLEANUP:
        if (!state->tfm)
            return -EINVAL;

        state->buffer_size = 0;
        state->encrypt_size = 0;
        state->decrypt_size = 0;
        state->finalized = false;
        state->max_buffer_size = BASIC_BUFFER_SIZE + 1;
        kfree(state->buffer);
        state->buffer = (char *)kzalloc(state->max_buffer_size, GFP_KERNEL);
        break;
    case CM_IOC_CNT_RST:
        atomic_set(&total_bytes_read, 0);
        atomic_set(&total_bytes_written, 0);

        mutex_lock(&freq_lock);
        for (int i = 0; i < 256; i++)
        {
            byte_freq[i] = 0;
        }
        mutex_unlock(&freq_lock);
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static const struct file_operations cryptodev_fops = {
    .owner = THIS_MODULE,
    .open = cryptodev_open,
    .read = cryptodev_read,
    .write = cryptodev_write,
    .unlocked_ioctl = cryptodev_ioctl,
    .release = cryptodev_close,
};

static char *cryptomod_devnode(const struct device *dev, umode_t *mode)
{
    if (mode == NULL)
        return NULL;
    *mode = 0666;
    return NULL;
}

static ssize_t proc_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    if (*pos > 0)
        return 0;

    char *kbuf;
    kbuf = kmalloc(2048, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    int len = 0;
    len += snprintf(kbuf, 2048, "%d %d\n", atomic_read(&total_bytes_read), atomic_read(&total_bytes_written));

    mutex_lock(&freq_lock);
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
            len += snprintf(kbuf + len, 2048 - len, "%2d ", byte_freq[i * 16 + j]);
        len += snprintf(kbuf + len, 2048 - len, "\n");
    }
    mutex_unlock(&freq_lock);

    if (copy_to_user(buf, kbuf, len))
    {
        kfree(kbuf);
        return -EFAULT;
    }
    kfree(kbuf);
    *pos = len;
    return len;
}

static const struct proc_ops cryptomod_proc_fops = {
    .proc_read = proc_read,
};

static int __init cryptodev_init(void)
{
    if (alloc_chrdev_region(&devnum, 0, 1, "cryptodev") < 0)
        return -1;
    if ((clazz = class_create("upclass")) == NULL)
        goto unregister_region;
    clazz->devnode = cryptomod_devnode;
    if (device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
        goto destroy_class;
    cdev_init(&c_dev, &cryptodev_fops);
    if (cdev_add(&c_dev, devnum, 1) == -1)
        goto destroy_device;

    proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

    printk(KERN_INFO "cryptodev: initialized\n");
    return 0;

destroy_device:
    device_destroy(clazz, devnum);
destroy_class:
    class_destroy(clazz);
unregister_region:
    unregister_chrdev_region(devnum, 1);
    return -1;
}

static void __exit cryptodev_cleanup(void)
{
    remove_proc_entry("cryptomod", NULL);

    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    printk(KERN_INFO "cryptodev: cleaned up\n");
}

module_init(cryptodev_init);
module_exit(cryptodev_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JTR");
MODULE_DESCRIPTION("AES ECB encryption device");