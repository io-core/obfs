/*
 *  linux/fs/obfs/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Copyright (C) 1996  Gertjan van Wingerde
 *	Minix V2 fs support.
 *
 *  Modified for 680x0 by Andreas Schwab
 *  Updated to filesystem version 3 by Daniel Aragones
 *
 *  Copyright (C) 2020  Charles Perkins
 *      Project Oberon fs support.
 */

#include <linux/module.h>
#include "obfs.h"
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/highuid.h>
#include <linux/vfs.h>
#include <linux/writeback.h>

static int obfs_write_inode(struct inode *inode,
		struct writeback_control *wbc);
static int obfs_statfs(struct dentry *dentry, struct kstatfs *buf);
static int obfs_remount (struct super_block * sb, int * flags, char * data);

static void obfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	if (!inode->i_nlink) {
		inode->i_size = 0;
		obfs_truncate(inode);
	}
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	if (!inode->i_nlink)
		obfs_free_inode(inode);
}

static void obfs_put_super(struct super_block *sb)
{
	int i;
	struct obfs_sb_info *sbi = obfs_sb(sb);

	if (!sb_rdonly(sb)) {
		mark_buffer_dirty(sbi->s_sbh);
	}
	for (i = 0; i < sbi->s_imap_blocks; i++)
		brelse(sbi->s_imap[i]);
	for (i = 0; i < sbi->s_zmap_blocks; i++)
		brelse(sbi->s_zmap[i]);
	brelse (sbi->s_sbh);
	kfree(sbi->s_imap);
	sb->s_fs_info = NULL;
	kfree(sbi);
}

static struct kmem_cache * obfs_inode_cachep;

static struct inode *obfs_alloc_inode(struct super_block *sb)
{
	struct obfs_inode_info *ei;
	ei = kmem_cache_alloc(obfs_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void obfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(obfs_inode_cachep, obfs_i(inode));
}

static void obfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, obfs_i_callback);
}

static void init_once(void *foo)
{
	struct obfs_inode_info *ei = (struct obfs_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	obfs_inode_cachep = kmem_cache_create("obfs_inode_cache",
					     sizeof(struct obfs_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD|SLAB_ACCOUNT),
					     init_once);
	if (obfs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(obfs_inode_cachep);
}

static const struct super_operations obfs_sops = {
	.alloc_inode	= obfs_alloc_inode,
	.destroy_inode	= obfs_destroy_inode,
	.write_inode	= obfs_write_inode,
	.evict_inode	= obfs_evict_inode,
	.put_super	= obfs_put_super,
	.statfs		= obfs_statfs,
	.remount_fs	= obfs_remount,
};

static int obfs_remount (struct super_block * sb, int * flags, char * data)
{
	struct obfs_sb_info * sbi = obfs_sb(sb);
	struct obfs_super_block * ms;

	sync_filesystem(sb);
	ms = sbi->s_ms;
	if ((bool)(*flags & SB_RDONLY) == sb_rdonly(sb))
		return 0;
	if (*flags & SB_RDONLY) {
		if (ms->s_state & OBFS_VALID_FS ||
		    !(sbi->s_mount_state & OBFS_VALID_FS))
			return 0;
		/* Mounting a rw partition read-only. */
		if (sbi->s_version != OBFS_V3)
			ms->s_state = sbi->s_mount_state;
		mark_buffer_dirty(sbi->s_sbh);
	} else {
	  	/* Mount a partition which is read-only, read-write. */
		if (sbi->s_version != OBFS_V3) {
			sbi->s_mount_state = ms->s_state;
			ms->s_state &= ~OBFS_VALID_FS;
		} else {
			sbi->s_mount_state = OBFS_VALID_FS;
		}
		mark_buffer_dirty(sbi->s_sbh);

		if (!(sbi->s_mount_state & OBFS_VALID_FS))
			printk("OBFS warning: remounting unchecked fs, "
				"running fsck is recommended\n");
		else if ((sbi->s_mount_state & OBFS_ERROR_FS))
			printk("OBFS warning: remounting fs with errors, "
				"running fsck is recommended\n");
	}
	return 0;
}

static int obfs_fill_super(struct super_block *s, void *data, int silent)
{
	struct buffer_head *bh;
	struct buffer_head **map;
	struct obfs_super_block *ms;
	struct obfs3_super_block *m3s = NULL;
	unsigned long i, block;
	struct inode *root_inode;
	struct obfs_sb_info *sbi;
	int ret = -EINVAL;

	sbi = kzalloc(sizeof(struct obfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	s->s_fs_info = sbi;

//	BUILD_BUG_ON(32 != sizeof (struct obfs_inode));
	BUILD_BUG_ON(64 != sizeof(struct obfs2_inode));

	if (!sb_set_blocksize(s, BLOCK_SIZE))
		goto out_bad_hblock;

	if (!(bh = sb_bread(s, 1)))
		goto out_bad_sb;

	ms = (struct obfs_super_block *) bh->b_data;
	sbi->s_ms = ms;
	sbi->s_sbh = bh;
	sbi->s_mount_state = ms->s_state;
	sbi->s_ninodes = ms->s_ninodes;
	sbi->s_nzones = ms->s_nzones;
	sbi->s_imap_blocks = ms->s_imap_blocks;
	sbi->s_zmap_blocks = ms->s_zmap_blocks;
	sbi->s_firstdatazone = ms->s_firstdatazone;
	sbi->s_log_zone_size = ms->s_log_zone_size;
	sbi->s_max_size = ms->s_max_size;
	s->s_magic = ms->s_magic;
	if ( *(__u16 *)(bh->b_data + 24) == MINIX3_SUPER_MAGIC) {
		m3s = (struct obfs3_super_block *) bh->b_data;
		s->s_magic = m3s->s_magic;
		sbi->s_imap_blocks = m3s->s_imap_blocks;
		sbi->s_zmap_blocks = m3s->s_zmap_blocks;
		sbi->s_firstdatazone = m3s->s_firstdatazone;
		sbi->s_log_zone_size = m3s->s_log_zone_size;
		sbi->s_max_size = m3s->s_max_size;
		sbi->s_ninodes = m3s->s_ninodes;
		sbi->s_nzones = m3s->s_zones;
		sbi->s_dirsize = 64;
		sbi->s_namelen = 60;
		sbi->s_version = OBFS_V3;
		sbi->s_mount_state = OBFS_VALID_FS;
		sb_set_blocksize(s, m3s->s_blocksize);
		s->s_max_links = MINIX2_LINK_MAX;
	} else
		goto out_no_fs;

	/*
	 * Allocate the buffer map to keep the superblock small.
	 */
	if (sbi->s_imap_blocks == 0 || sbi->s_zmap_blocks == 0)
		goto out_illegal_sb;
	i = (sbi->s_imap_blocks + sbi->s_zmap_blocks) * sizeof(bh);
	map = kzalloc(i, GFP_KERNEL);
	if (!map)
		goto out_no_map;
	sbi->s_imap = &map[0];
	sbi->s_zmap = &map[sbi->s_imap_blocks];

	block=2;
	for (i=0 ; i < sbi->s_imap_blocks ; i++) {
		if (!(sbi->s_imap[i]=sb_bread(s, block)))
			goto out_no_bitmap;
		block++;
	}
	for (i=0 ; i < sbi->s_zmap_blocks ; i++) {
		if (!(sbi->s_zmap[i]=sb_bread(s, block)))
			goto out_no_bitmap;
		block++;
	}

	obfs_set_bit(0,sbi->s_imap[0]->b_data);
	obfs_set_bit(0,sbi->s_zmap[0]->b_data);

	/* Apparently obfs can create filesystems that allocate more blocks for
	 * the bitmaps than needed.  We simply ignore that, but verify it didn't
	 * create one with not enough blocks and bail out if so.
	 */
	block = obfs_blocks_needed(sbi->s_ninodes, s->s_blocksize);
	if (sbi->s_imap_blocks < block) {
		printk("OBFS: file system does not have enough "
				"imap blocks allocated.  Refusing to mount.\n");
		goto out_no_bitmap;
	}

	block = obfs_blocks_needed(
			(sbi->s_nzones - sbi->s_firstdatazone + 1),
			s->s_blocksize);
	if (sbi->s_zmap_blocks < block) {
		printk("OBFS: file system does not have enough "
				"zmap blocks allocated.  Refusing to mount.\n");
		goto out_no_bitmap;
	}

	/* set up enough so that it can read an inode */
	s->s_op = &obfs_sops;
	root_inode = obfs_iget(s, OBFS_ROOT_INO);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto out_no_root;
	}

	ret = -ENOMEM;
	s->s_root = d_make_root(root_inode);
	if (!s->s_root)
		goto out_no_root;

	if (!sb_rdonly(s)) {
		if (sbi->s_version != OBFS_V3) /* s_state is now out from V3 sb */
			ms->s_state &= ~OBFS_VALID_FS;
		mark_buffer_dirty(bh);
	}
	if (!(sbi->s_mount_state & OBFS_VALID_FS))
		printk("OBFS: mounting unchecked file system, "
			"running fsck is recommended\n");
	else if (sbi->s_mount_state & OBFS_ERROR_FS)
		printk("OBFS: mounting file system with errors, "
			"running fsck is recommended\n");

	return 0;

out_no_root:
	if (!silent)
		printk("OBFS: get root inode failed\n");
	goto out_freemap;

out_no_bitmap:
	printk("OBFS: bad superblock or unable to read bitmaps\n");
out_freemap:
	for (i = 0; i < sbi->s_imap_blocks; i++)
		brelse(sbi->s_imap[i]);
	for (i = 0; i < sbi->s_zmap_blocks; i++)
		brelse(sbi->s_zmap[i]);
	kfree(sbi->s_imap);
	goto out_release;

out_no_map:
	ret = -ENOMEM;
	if (!silent)
		printk("OBFS: can't allocate map\n");
	goto out_release;

out_illegal_sb:
	if (!silent)
		printk("OBFS: bad superblock\n");
	goto out_release;

out_no_fs:
	if (!silent)
		printk("VFS: Can't find a Minix filesystem V1 | V2 | V3 "
		       "on device %s.\n", s->s_id);
out_release:
	brelse(bh);
	goto out;

out_bad_hblock:
	printk("OBFS: blocksize too small for device\n");
	goto out;

out_bad_sb:
	printk("OBFS: unable to read superblock\n");
out:
	s->s_fs_info = NULL;
	kfree(sbi);
	return ret;
}

static int obfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct obfs_sb_info *sbi = obfs_sb(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
	buf->f_type = sb->s_magic;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = (sbi->s_nzones - sbi->s_firstdatazone) << sbi->s_log_zone_size;
	buf->f_bfree = obfs_count_free_blocks(sb);
	buf->f_bavail = buf->f_bfree;
	buf->f_files = sbi->s_ninodes;
	buf->f_ffree = obfs_count_free_inodes(sb);
	buf->f_namelen = sbi->s_namelen;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

static int obfs_get_block(struct inode *inode, sector_t block,
		    struct buffer_head *bh_result, int create)
{

		return V2_obfs_get_block(inode, block, bh_result, create);
}

static int obfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, obfs_get_block, wbc);
}

static int obfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page,obfs_get_block);
}

int obfs_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
	return __block_write_begin(page, pos, len, obfs_get_block);
}

static void obfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		obfs_truncate(inode);
	}
}

static int obfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				obfs_get_block);
	if (unlikely(ret))
		obfs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t obfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,obfs_get_block);
}

static const struct address_space_operations obfs_aops = {
	.readpage = obfs_readpage,
	.writepage = obfs_writepage,
	.write_begin = obfs_write_begin,
	.write_end = generic_write_end,
	.bmap = obfs_bmap
};

static const struct inode_operations obfs_symlink_inode_operations = {
	.get_link	= page_get_link,
	.getattr	= obfs_getattr,
};

void obfs_set_inode(struct inode *inode, dev_t rdev)
{
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &obfs_file_inode_operations;
		inode->i_fop = &obfs_file_operations;
		inode->i_mapping->a_ops = &obfs_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &obfs_dir_inode_operations;
		inode->i_fop = &obfs_dir_operations;
		inode->i_mapping->a_ops = &obfs_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &obfs_symlink_inode_operations;
		inode_nohighmem(inode);
		inode->i_mapping->a_ops = &obfs_aops;
	} else
		init_special_inode(inode, inode->i_mode, rdev);
}


/*
 * The obfs V2 function to read an inode.
 */
static struct inode *V2_obfs_iget(struct inode *inode)
{
	struct buffer_head * bh;
	struct obfs2_inode * raw_inode;
	struct obfs_inode_info *obfs_inode = obfs_i(inode);
	int i;

	raw_inode = obfs_V2_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}
	inode->i_mode = raw_inode->i_mode;
	i_uid_write(inode, raw_inode->i_uid);
	i_gid_write(inode, raw_inode->i_gid);
	set_nlink(inode, raw_inode->i_nlinks);
	inode->i_size = raw_inode->i_size;
	inode->i_mtime.tv_sec = raw_inode->i_mtime;
	inode->i_atime.tv_sec = raw_inode->i_atime;
	inode->i_ctime.tv_sec = raw_inode->i_ctime;
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_blocks = 0;
	for (i = 0; i < 10; i++)
		obfs_inode->u.i2_data[i] = raw_inode->i_zone[i];
	obfs_set_inode(inode, old_decode_dev(raw_inode->i_zone[0]));
	brelse(bh);
	unlock_new_inode(inode);
	return inode;
}

/*
 * The global function to read an inode.
 */
struct inode *obfs_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	return V2_obfs_iget(inode);
}


/*
 * The obfs V2 function to synchronize an inode.
 */
static struct buffer_head * V2_obfs_update_inode(struct inode * inode)
{
	struct buffer_head * bh;
	struct obfs2_inode * raw_inode;
	struct obfs_inode_info *obfs_inode = obfs_i(inode);
	int i;

	raw_inode = obfs_V2_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode)
		return NULL;
	raw_inode->i_mode = inode->i_mode;
	raw_inode->i_uid = fs_high2lowuid(i_uid_read(inode));
	raw_inode->i_gid = fs_high2lowgid(i_gid_read(inode));
	raw_inode->i_nlinks = inode->i_nlink;
	raw_inode->i_size = inode->i_size;
	raw_inode->i_mtime = inode->i_mtime.tv_sec;
	raw_inode->i_atime = inode->i_atime.tv_sec;
	raw_inode->i_ctime = inode->i_ctime.tv_sec;
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		raw_inode->i_zone[0] = old_encode_dev(inode->i_rdev);
	else for (i = 0; i < 10; i++)
		raw_inode->i_zone[i] = obfs_inode->u.i2_data[i];
	mark_buffer_dirty(bh);
	return bh;
}

static int obfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int err = 0;
	struct buffer_head *bh;

	bh = V2_obfs_update_inode(inode);
	if (!bh)
		return -EIO;
	if (wbc->sync_mode == WB_SYNC_ALL && buffer_dirty(bh)) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh)) {
			printk("IO error syncing obfs inode [%s:%08lx]\n",
				inode->i_sb->s_id, inode->i_ino);
			err = -EIO;
		}
	}
	brelse (bh);
	return err;
}

int obfs_getattr(const struct path *path, struct kstat *stat,
		  u32 request_mask, unsigned int flags)
{
	struct super_block *sb = path->dentry->d_sb;
	struct inode *inode = d_inode(path->dentry);

	generic_fillattr(inode, stat);
	stat->blocks = (sb->s_blocksize / 512) * V2_obfs_blocks(stat->size, sb);
	stat->blksize = sb->s_blocksize;
	return 0;
}

/*
 * The function that is called for file truncation.
 */
void obfs_truncate(struct inode * inode)
{
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)))
		return;
	V2_obfs_truncate(inode);
}

static struct dentry *obfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, obfs_fill_super);
}

static struct file_system_type obfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "obfs",
	.mount		= obfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("obfs");

static int __init init_obfs_fs(void)
{
	int err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&obfs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_obfs_fs(void)
{
        unregister_filesystem(&obfs_fs_type);
	destroy_inodecache();
}

module_init(init_obfs_fs)
module_exit(exit_obfs_fs)
MODULE_LICENSE("GPL");


