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
#include <linux/time.h>

static DECLARE_COMPLETION(thread_done);

struct task_struct *kthread;

//static int thread_func(void* data)
//{
//    printk("OBFS: In %s function\n", __func__);
//    return 0;
//}


static int obfs_write_inode(struct inode *inode, struct writeback_control *wbc);
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
	struct obfs_sb_info *sbi = obfs_sb(sb);
	brelse (sbi->s_sbh);
	kfree(sbi->s_map);
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
	

	sync_filesystem(sb);
	
	if ((bool)(*flags & SB_RDONLY) == sb_rdonly(sb))
		return 0;
	if (*flags & SB_RDONLY) {
		if ( !(sbi->s_mount_state & OBFS_VALID_FS))
			return 0;
		/* Mounting a rw partition read-only. */
//		mark_buffer_dirty(sbi->s_sbh);
	} else {
	  	/* Mount a partition which is read-only, read-write. */
		sbi->s_mount_state = OBFS_VALID_FS;
		
//		mark_buffer_dirty(sbi->s_sbh);

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
	struct iofs_bm *map; //struct buffer_head **map;
	struct obfs_dinode *ms;
//	unsigned long i, block;
	struct inode *root_inode;
	struct obfs_sb_info *sbi;
	int ret = -EINVAL;

        printk("OBFS Initializing Superblock\n");

	sbi = kzalloc(sizeof(struct obfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	s->s_fs_info = sbi;

	if (!sb_set_blocksize(s, OBFS_BLOCKSIZE))
		goto out_bad_hblock;

	if (!(bh = sb_bread(s, (OBFS_ROOTINODE/29)-1)))
		goto out_bad_sb;

	ms = (struct obfs_dinode *) bh->b_data;

        if (ms->origin == OBFS_SUPER_MAGIC) {
                s->s_magic = OBFS_SUPER_MAGIC;
                sbi->s_mount_state = OBFS_VALID_FS;
                s->s_max_links = 0;
        } else
                goto out_no_fs;

 	map = kzalloc(sizeof(struct iofs_bm), GFP_KERNEL);
	if (!map)
		goto out_no_map;

	map->s[0]=~(uint32_t)0;
        map->s[1]=~(uint32_t)0;
	sbi->s_map = map;

	s->s_op = &obfs_sops;
	root_inode = obfs_iget(s, OBFS_ROOTINODE);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto out_no_root;
	}

	ret = -ENOMEM;
	s->s_root = d_make_root(root_inode);
	if (!s->s_root)
		goto out_no_root;


//	kthread = kthread_run(thread_func, NULL, "kthread-test");
//	if (IS_ERR(kthread)) {
//	    complete(&thread_done); /* <-- may or may not be required */
//	    ret = PTR_ERR(kthread);
//	    return ret;
//	}

	printk("OBFS: superblock loaded\n");

	return 0;


out_no_root:
	if (!silent)
		printk("OBFS: get root inode failed\n");
	goto out_freemap;

out_freemap:
	kfree(sbi->s_map);
	goto out_release;

out_no_map:
	ret = -ENOMEM;
	if (!silent)
		printk("OBFS: can't allocate map\n");
	goto out_release;

out_no_fs:
	if (!silent)
		printk("OBFS: Can't find an Oberon filesystem"
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
	buf->f_blocks = 65536; //(sbi->s_nzones - sbi->s_firstdatazone) << sbi->s_log_zone_size;
	buf->f_bfree = obfs_count_free_blocks(sb);
	buf->f_bavail = buf->f_bfree;
	buf->f_files = sbi->s_ninodes;
	buf->f_ffree = obfs_count_free_inodes(sb);
	buf->f_namelen = sbi->s_namelen;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

        printk("OBFS stat filesystem\n");

	return 0;
}

static int fn_obfs_get_block(struct inode *inode, sector_t block,
		    struct buffer_head *bh_result, int create)
{

		return obfs_get_block(inode, block, bh_result, create);
}

static int obfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, fn_obfs_get_block, wbc);
}

static struct buffer_head *create_page_buffers(struct page *page, struct inode *inode, unsigned int b_state)
{
	BUG_ON(!PageLocked(page));

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << READ_ONCE(inode->i_blkbits),
				     b_state);
	return page_buffers(page);
}

static inline int block_size_bits(unsigned int blocksize)
{
	return ilog2(blocksize);
}

static void buffer_io_error(struct buffer_head *bh, char *msg)
{
	if (!test_bit(BH_Quiet, &bh->b_state))
		printk_ratelimited(KERN_ERR
			"Buffer I/O error on dev %pg, logical block %llu%s\n",
			bh->b_bdev, (unsigned long long)bh->b_blocknr, msg);
}

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
	unsigned long flags;
	struct buffer_head *first;
	struct buffer_head *tmp;
	struct page *page;
	int page_uptodate = 1;

	BUG_ON(!buffer_async_read(bh));

	page = bh->b_page;
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		clear_buffer_uptodate(bh);
		buffer_io_error(bh, ", async page read");
		SetPageError(page);
	}

	/*
	 * Be _very_ careful from here on. Bad things can happen if
	 * two buffer heads end IO at almost the same time and both
	 * decide that the page is now completely done.
	 */
	first = page_buffers(page);
//	spin_lock_irqsave(&first->b_uptodate_lock, flags);
	clear_buffer_async_read(bh);
	unlock_buffer(bh);
	tmp = bh;
	do {
		if (!buffer_uptodate(tmp))
			page_uptodate = 0;
		if (buffer_async_read(tmp)) {
			BUG_ON(!buffer_locked(tmp));
			goto still_busy;
		}
		tmp = tmp->b_this_page;
	} while (tmp != bh);
//	spin_unlock_irqrestore(&first->b_uptodate_lock, flags);

	/*
	 * If none of the buffers had errors and they are all
	 * uptodate then we can set the page uptodate.
	 */
	if (page_uptodate && !PageError(page))
		SetPageUptodate(page);
	unlock_page(page);
	return;

still_busy:
//	spin_unlock_irqrestore(&first->b_uptodate_lock, flags);
	return;
}

static void end_buffer_async_read_io(struct buffer_head *bh, int uptodate)
{
	/* Decrypt if needed */
//	if (uptodate && IS_ENABLED(CONFIG_FS_ENCRYPTION) &&
//	    IS_ENCRYPTED(bh->b_page->mapping->host) &&
//	    S_ISREG(bh->b_page->mapping->host->i_mode)) {
//		struct decrypt_bh_ctx *ctx = kmalloc(sizeof(*ctx), GFP_ATOMIC);
//
//		if (ctx) {
//			INIT_WORK(&ctx->work, decrypt_bh);
//			ctx->bh = bh;
//			fscrypt_enqueue_decrypt_work(&ctx->work);
//			return;
//		}
//		uptodate = 0;
//	}
	end_buffer_async_read(bh, uptodate);
}

static void mark_buffer_async_read(struct buffer_head *bh)
{
	bh->b_end_io = end_buffer_async_read_io;
	set_buffer_async_read(bh);
}

static int obfs_block_read_full_page(struct page *page, get_block_t * fn_get_block)
{
	struct inode *inode = page->mapping->host;
	sector_t iblock, lblock;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize, bbits;
	int nr, i;
	int fully_mapped = 1;

	head = create_page_buffers(page, inode, 0);
	blocksize = head->b_size;
	bbits = block_size_bits(blocksize);

	iblock = (sector_t)page->index << (PAGE_SHIFT - bbits);
	lblock = (i_size_read(inode)+blocksize-1) >> bbits;
	bh = head;
	nr = 0;
	i = 0;

	do {
		if (buffer_uptodate(bh))
			continue;

		if (!buffer_mapped(bh)) {
			int err = 0;

			fully_mapped = 0;
			if (iblock < lblock) {
				WARN_ON(bh->b_size != blocksize);
				err = fn_get_block(inode, iblock, bh, 0);
				if (err)
					SetPageError(page);
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, i * blocksize, blocksize);
				if (!err)
					set_buffer_uptodate(bh);
				continue;
			}
			/*
			 * fn_get_block() might have updated the buffer
			 * synchronously
			 */
			if (buffer_uptodate(bh))
				continue;
		}
		arr[nr++] = bh;
	} while (i++, iblock++, (bh = bh->b_this_page) != head);

	if (fully_mapped)
		SetPageMappedToDisk(page);

	if (!nr) {
		/*
		 * All buffers are uptodate - we can set the page uptodate
		 * as well. But not if fn_get_block() returned an error.
		 */
		if (!PageError(page))
			SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	/* Stage two: lock the buffers */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		lock_buffer(bh);
		mark_buffer_async_read(bh);
	}

	/*
	 * Stage 3: start the IO.  Check for uptodateness
	 * inside the buffer lock in case another process reading
	 * the underlying blockdev brought it uptodate (the sct fix).
	 */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (buffer_uptodate(bh))
			end_buffer_async_read(bh, 1);
		else
			submit_bh(REQ_OP_READ, 0, bh);
	}
	return 0;
}

static int obfs_readpage(struct file *file, struct page *page)
{
	return obfs_block_read_full_page(page,fn_obfs_get_block);
}

int obfs_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
	return __block_write_begin(page, pos, len, fn_obfs_get_block);
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
				fn_obfs_get_block);
	if (unlikely(ret))
		obfs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t obfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,fn_obfs_get_block);
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
//		inode->i_mapping->a_ops = &obfs_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &obfs_dir_inode_operations;
		inode->i_fop = &obfs_dir_operations;
//		inode->i_mapping->a_ops = &obfs_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &obfs_symlink_inode_operations;
		inode_nohighmem(inode);
//		inode->i_mapping->a_ops = &obfs_aops;
	} else
		init_special_inode(inode, inode->i_mode, rdev);
}


/*
 * The obfs function to read an inode.
 */
static struct inode *do_obfs_iget(struct inode *inode)
{
	struct buffer_head * bh;
	struct obfs_dinode * raw_inode;
	struct obfs_inode_info *obfs_inode = obfs_i(inode);
	int i;
        uint32_t tv;
        time_t t_of_day;



        printk("OBFS: reading inode %08lx\n",inode->i_ino);

	raw_inode = obfs_get_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}

        if (raw_inode->origin == OBFS_DIRMARK) {
          inode->i_mode = 0040777; //octal
        }else{
          inode->i_mode = 0100777; //octal
	  for(i=0;i<OBFS_SECTABSIZE;i++){
		obfs_inode->direct[i]=raw_inode->fhb.sec[i];
	  }
          for(i=0;i<OBFS_EXTABSIZE;i++){
                obfs_inode->indirect[i]=raw_inode->fhb.ext[i];
          }
        }
        tv = raw_inode->fhb.date;
        //                  year        month             day                 
        //                  hour        minute            second
	


        t_of_day = mktime((uint32_t)((tv >> 26) & 0x3FF)+2000,
                 ((tv >> 22) & 0xFF)+1 , ((tv >> 18) & 0x1FF)+1, (tv >> 12) & 0x1FF, ( tv >> 6) & 0x3FF, tv & 0x3FF);



        inode->i_atime.tv_sec = t_of_day;
        inode->i_mtime.tv_sec = t_of_day;
        inode->i_ctime.tv_sec = t_of_day;
        inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;

	inode->i_blocks=0;

        switch (inode->i_mode & S_IFMT) {
                case S_IFDIR:
                        inode->i_op = &obfs_dir_inode_operations;
                        inode->i_fop = &obfs_dir_operations;
                        break;
                case S_IFREG:
                        inode->i_fop = &generic_ro_fops;
                        inode->i_data.a_ops = &obfs_aops;
			inode->i_size = (raw_inode->fhb.aleng * 1024) + raw_inode->fhb.bleng - 352;
                        break;
                case S_IFLNK:
//                        inode->i_op = &page_symlink_inode_operations;
//                        inode_nohighmem(inode);
//                        inode->i_data.a_ops = &obfs_symlink_aops;
//                        break;
                case S_IFCHR:
                case S_IFBLK:
                case S_IFIFO:
//                      init_special_inode(inode, inode->i_mode, device);
//                      break;
                default:
                        pr_warn("unsupported inode mode %o\n", inode->i_mode);
	                return ERR_PTR(-EIO);
        }


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
	if (!(inode->i_state & I_NEW)){
		printk("OBFS: returning cached inode\n");
		return inode;
	}
	return do_obfs_iget(inode);
}


/*
 * The obfs function to synchronize an inode.
 */
static struct buffer_head * V2_obfs_update_inode(struct inode * inode)
{
	struct buffer_head * bh;
	struct obfs_dinode * raw_inode;
//	struct obfs_inode_info *obfs_inode = obfs_i(inode);
//	int i;

	raw_inode = obfs_get_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode)
		return NULL;
/*
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
*/
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
        printk("OBFS Mount Filesystem\n");
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
        printk("OBFS Init\n");

	if (err){
	        printk("OBFS Inodecache Init Failure\n");
		goto out1;
	}
	err = register_filesystem(&obfs_fs_type);
	if (err){
	        printk("OBFS Filesystem Register Failure\n");
		goto out;
	}
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_obfs_fs(void)
{

//        printk("OBFS Wait for Completion\n"); 
//        complete_and_exit(&thread_done, 0);
//	wait_for_completion(&thread_done);
        printk("OBFS Unregister Fileystem\n");
        unregister_filesystem(&obfs_fs_type);
        printk("OBFS Destroy Inodecache\n");
	destroy_inodecache();
        printk("OBFS Exit\n");
}

module_init(init_obfs_fs)
module_exit(exit_obfs_fs)
MODULE_LICENSE("GPL");


