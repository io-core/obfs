// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/obfs/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  obfs regular file handling primitives
 *
 *  Copyright (C) 2020  Charles Perkins
 *      Project Oberon fs support.
 */

#include "obfs.h"


static ssize_t
obfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
        printk("OBFS: in obfs_file_read_iter\n");
/*
        struct file *coda_file = iocb->ki_filp;
        struct inode *coda_inode = file_inode(coda_file);
        struct coda_file_info *cfi = coda_ftoc(coda_file);
        loff_t ki_pos = iocb->ki_pos;
        size_t count = iov_iter_count(to);
        ssize_t ret;

        ret = venus_access_intent(coda_inode->i_sb, coda_i2f(coda_inode),
                                  &cfi->cfi_access_intent,
                                  count, ki_pos, CODA_ACCESS_TYPE_READ);
        if (ret)
                goto finish_read;

        ret = vfs_iter_read(cfi->cfi_container, to, &iocb->ki_pos, 0);

finish_read:
        venus_access_intent(coda_inode->i_sb, coda_i2f(coda_inode),
                            &cfi->cfi_access_intent,
                            count, ki_pos, CODA_ACCESS_TYPE_READ_FINISH);
        return ret;
*/
	return 0;
}



static ssize_t
obfs_file_write_iter(struct kiocb *iocb, struct iov_iter *to)
{
/*
        struct file *coda_file = iocb->ki_filp;
        struct inode *coda_inode = file_inode(coda_file);
        struct coda_file_info *cfi = coda_ftoc(coda_file);
        struct file *host_file = cfi->cfi_container;
        loff_t ki_pos = iocb->ki_pos;
        size_t count = iov_iter_count(to);
        ssize_t ret;

        ret = venus_access_intent(coda_inode->i_sb, coda_i2f(coda_inode),
                                  &cfi->cfi_access_intent,
                                  count, ki_pos, CODA_ACCESS_TYPE_WRITE);
        if (ret)
                goto finish_write;

        file_start_write(host_file);
        inode_lock(coda_inode);
        ret = vfs_iter_write(cfi->cfi_container, to, &iocb->ki_pos, 0);
        coda_inode->i_size = file_inode(host_file)->i_size;
        coda_inode->i_blocks = (coda_inode->i_size + 511) >> 9;
        coda_inode->i_mtime = coda_inode->i_ctime = current_time(coda_inode);
        inode_unlock(coda_inode);
        file_end_write(host_file);

finish_write:
        venus_access_intent(coda_inode->i_sb, coda_i2f(coda_inode),
                            &cfi->cfi_access_intent,
                            count, ki_pos, CODA_ACCESS_TYPE_WRITE_FINISH);
        return ret;
*/
	return 0;
}



/*
 * We have mostly NULLs here: the current defaults are OK for
 * the obfs filesystem.
 */
const struct file_operations obfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int obfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		obfs_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations obfs_file_inode_operations = {
	.setattr	= obfs_setattr,
	.getattr	= obfs_getattr,
};
