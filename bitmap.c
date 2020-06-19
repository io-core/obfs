// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/obfs/bitmap.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Copyright (C) 2020  Charles Perkins
 *      Project Oberon fs support.
 */


/* bitmap.c contains the code that handles the inode and block bitmaps */

#include "obfs.h"
#include <linux/buffer_head.h>
#include <linux/bitops.h>
#include <linux/sched.h>

static DEFINE_SPINLOCK(bitmap_lock);

/*
 * bitmap consists of 8k of memory filled with 32bit words
 * bit set == busy, bit clear == free
 */
static __u32 count_free(struct iofs_bm *map)
{
        int i,a = 0;
        for(i=0;i<2048;i++){ a += hweight_long(map->s[i]);}
	return 65536-a;
}

void obfs_free_block(struct inode *inode, unsigned long block)
{
	struct super_block *sb = inode->i_sb;
	struct obfs_sb_info *sbi = obfs_sb(sb);
        

        
	if (block < 1 || block > 65535) {
		printk("Trying to free block beyond range of Oberon filesystem\n");
		return;
	}
	spin_lock(&bitmap_lock);
	if (BITCHECK(sbi->s_map->s[block/32],block%32))
                printk("Block already free on dev %s: %ld\n",
                       sb->s_id, (long)block);
	else
          BITCLEAR(sbi->s_map->s[block/32],block%32); 
	spin_unlock(&bitmap_lock);

	return;
}

int obfs_new_block(struct inode * inode)
{
	struct obfs_sb_info *sbi = obfs_sb(inode->i_sb);
	int j;

	spin_lock(&bitmap_lock);
	j = obfs_find_first_zero_bit(sbi->s_map, 65536/8);
	if (j < 65536/8) {
		BITSET(sbi->s_map->s[j/32],j%32);
		spin_unlock(&bitmap_lock);
		return j;
	}
	spin_unlock(&bitmap_lock);
	return 0;
}

unsigned long obfs_count_free_blocks(struct super_block *sb)
{

	struct obfs_sb_info *sbi = obfs_sb(sb);
	return count_free(sbi->s_map);
}


struct obfs_dinode *
obfs_get_raw_inode(struct super_block *sb, ino_t ino, struct buffer_head **bh)
{
	struct obfs_dinode *p;

	*bh = NULL;
	if (!ino || ino % 29 != 0 ) {
		printk("Bad inode number on dev %s: %ld is zero or not divisble by 29\n",
		       sb->s_id, (long)ino);
		return NULL;
	}
	*bh = sb_bread(sb, (ino/29)-1);
	if (!*bh) {
		printk("Unable to read inode block\n");
		return NULL;
	}
	p = (void *)(*bh)->b_data;
	return p; 
}

/* Clear the link count and mode of a deleted inode on disk. */

static void obfs_clear_inode(struct inode *inode)
{
	struct buffer_head *bh = NULL;

	struct obfs_dinode *raw_inode;
	raw_inode = obfs_get_raw_inode(inode->i_sb, inode->i_ino, &bh);
//	if (raw_inode) {
//		raw_inode->i_nlinks = 0;
//		raw_inode->i_mode = 0;
//	}

	if (bh) {
		mark_buffer_dirty(bh);
		brelse (bh);
	}
}

void obfs_free_inode(struct inode * inode)
{
	struct super_block *sb = inode->i_sb;
	struct obfs_sb_info *sbi = obfs_sb(inode->i_sb);
	unsigned long block;

	block = inode->i_ino/29;
	if (block < 1 || block > 65535 || inode->i_ino % 29 != 0) {
		printk("obfs_free_inode: inode 0 or nonexistent inode\n");
		return;
	}

	obfs_clear_inode(inode);	/* clear on-disk copy */

	spin_lock(&bitmap_lock);
        if (BITCHECK(sbi->s_map->s[block/32],block%32))
                printk("Block already free on dev %s: %ld\n",
                       sb->s_id, (long)block);
        else
          BITCLEAR(sbi->s_map->s[block/32],block%32);
	spin_unlock(&bitmap_lock);

}


struct inode *obfs_new_inode(const struct inode *dir, umode_t mode, int *error)
{
	struct super_block *sb = dir->i_sb;
	struct obfs_sb_info *sbi = obfs_sb(sb);
	struct inode *inode = new_inode(sb);
	unsigned long j;
//	int i;

	if (!inode) {
		*error = -ENOMEM;
		return NULL;
	}
	*error = -ENOSPC;

	spin_lock(&bitmap_lock);

        j = obfs_find_first_zero_bit(sbi->s_map, 65536/8);
        if (j < 65536/8) {
                BITSET(sbi->s_map->s[j/32],j%32);
        }else{
		spin_unlock(&bitmap_lock);
		return NULL;
	}
	spin_unlock(&bitmap_lock);

//	TODO: Actually load and initialize the inode on-disk block

	inode_init_owner(inode, dir, mode);
	inode->i_ino = j;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;
	memset(&obfs_i(inode)->direct, 0, sizeof(obfs_i(inode)->direct));
	memset(&obfs_i(inode)->indirect, 0, sizeof(obfs_i(inode)->indirect));
//	memset(&obfs_i(inode)->u, 0, sizeof(obfs_i(inode)->u));
	insert_inode_hash(inode);
	mark_inode_dirty(inode);

	*error = 0;
	return inode;
}

unsigned long obfs_count_free_inodes(struct super_block *sb)
{
        struct obfs_sb_info *sbi = obfs_sb(sb);
        return count_free(sbi->s_map);
}
