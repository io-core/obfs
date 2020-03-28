// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/obfs/bitmap.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Copyright (C) 2020  Charles Perkins
 *      Project Oberon fs support.
 */

/*
 * Modified for 680x0 by Hamish Macdonald
 * Fixed for 680x0 by Andreas Schwab
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
        uint32_t iino;

        iino=block/29;
	if (iino < 1 || iino > 65535) {
		printk("Trying to free block beyond range of Oberon filesystem\n");
		return;
	}
	spin_lock(&bitmap_lock);
	if (BITCHECK(sbi->s_map->s[iino/32],iino%32))
                printk("Block already free on dev %s: %ld\n",
                       sb->s_id, (long)block);
	else
          BITCLEAR(sbi->s_map->s[iino/32],iino%32); 
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
/*
	u32 bits = sbi->s_nzones - sbi->s_firstdatazone + 1;

	return (count_free(sbi->s_zmap, sb->s_blocksize, bits)
		<< sbi->s_log_zone_size);
*/
	return count_free(sbi->s_map);
}


struct obfs_dinode *
obfs_get_raw_inode(struct super_block *sb, ino_t ino, struct buffer_head **bh)
{
//	int block;
//	struct obfs_sb_info *sbi = obfs_sb(sb);
	struct obfs_dinode *p;
//	int obfs2_inodes_per_block = sb->s_blocksize / sizeof(struct obfs2_inode);

	*bh = NULL;
	if (!ino || ino % 29 != 0 ) {
		printk("Bad inode number on dev %s: %ld is zero or not divisble by 29\n",
		       sb->s_id, (long)ino);
		return NULL;
	}
//	ino--;
//	block = 2 + sbi->s_imap_blocks + sbi->s_zmap_blocks +
//		 ino / obfs2_inodes_per_block;
	*bh = sb_bread(sb, (ino/29)-1);
	if (!*bh) {
		printk("Unable to read inode block\n");
		return NULL;
	}
	p = (void *)(*bh)->b_data;
	return p; // + ino % obfs2_inodes_per_block;
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
//	struct buffer_head *bh;
	int k = sb->s_blocksize_bits + 3;
	unsigned long ino, bit;

	ino = inode->i_ino;
	if (ino < 1 || ino > sbi->s_ninodes) {
		printk("obfs_free_inode: inode 0 or nonexistent inode\n");
		return;
	}
	bit = ino & ((1<<k) - 1);
	ino >>= k;
/*
	if (ino >= sbi->s_imap_blocks) {
		printk("obfs_free_inode: nonexistent imap in superblock\n");
		return;
	}
*/
	obfs_clear_inode(inode);	/* clear on-disk copy */
/*
	bh = sbi->s_imap[ino];
	spin_lock(&bitmap_lock);
	if (!obfs_test_and_clear_bit(bit, bh->b_data))
		printk("obfs_free_inode: bit %lu already cleared\n", bit);
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(bh);
*/
}


struct inode *obfs_new_inode(const struct inode *dir, umode_t mode, int *error)
{
	struct super_block *sb = dir->i_sb;
//	struct obfs_sb_info *sbi = obfs_sb(sb);
	struct inode *inode = new_inode(sb);
	struct buffer_head * bh;
	int bits_per_zone = 8 * sb->s_blocksize;
	unsigned long j;
//	int i;

	if (!inode) {
		*error = -ENOMEM;
		return NULL;
	}
	j = bits_per_zone;
	bh = NULL;
	*error = -ENOSPC;
/*
	spin_lock(&bitmap_lock);

	for (i = 0; i < sbi->s_imap_blocks; i++) {
		bh = sbi->s_imap[i];
		j = obfs_find_first_zero_bit(bh->b_data, bits_per_zone);
		if (j < bits_per_zone)
			break;
	}
	if (!bh || j >= bits_per_zone) {
		spin_unlock(&bitmap_lock);
		iput(inode);
		return NULL;
	}
	if (obfs_test_and_set_bit(j, bh->b_data)) {	// shouldn't happen 
		spin_unlock(&bitmap_lock);
		printk("obfs_new_inode: bit already set\n");
		iput(inode);
		return NULL;
	}
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(bh);
	j += i * bits_per_zone;
	if (!j || j > sbi->s_ninodes) {
		iput(inode);
		return NULL;
	}
*/
	inode_init_owner(inode, dir, mode);
	inode->i_ino = j;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;
	memset(&obfs_i(inode)->u, 0, sizeof(obfs_i(inode)->u));
	insert_inode_hash(inode);
	mark_inode_dirty(inode);

	*error = 0;
	return inode;
}

unsigned long obfs_count_free_inodes(struct super_block *sb)
{
//	struct obfs_sb_info *sbi = obfs_sb(sb);
//	u32 bits = sbi->s_ninodes + 1;

//	return count_free(sbi->s_imap, sb->s_blocksize, bits);
	return 0;
}
