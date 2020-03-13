/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FS_MINIX_H
#define FS_MINIX_H

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "xinix_fs.h"

#define INODE_VERSION(inode)	xinix_sb(inode->i_sb)->s_version
#define MINIX_V1		0x0001		/* original xinix fs */
#define MINIX_V2		0x0002		/* xinix V2 fs */
#define MINIX_V3		0x0003		/* xinix V3 fs */

/*
 * xinix fs inode data in memory
 */
struct xinix_inode_info {
	union {
		__u16 i1_data[16];
		__u32 i2_data[16];
	} u;
	struct inode vfs_inode;
};

/*
 * xinix super-block data in memory
 */
struct xinix_sb_info {
	unsigned long s_ninodes;
	unsigned long s_nzones;
	unsigned long s_imap_blocks;
	unsigned long s_zmap_blocks;
	unsigned long s_firstdatazone;
	unsigned long s_log_zone_size;
	unsigned long s_max_size;
	int s_dirsize;
	int s_namelen;
	struct buffer_head ** s_imap;
	struct buffer_head ** s_zmap;
	struct buffer_head * s_sbh;
	struct xinix_super_block * s_ms;
	unsigned short s_mount_state;
	unsigned short s_version;
};

extern struct inode *xinix_iget(struct super_block *, unsigned long);
extern struct xinix_inode * xinix_V1_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct xinix2_inode * xinix_V2_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct inode * xinix_new_inode(const struct inode *, umode_t, int *);
extern void xinix_free_inode(struct inode * inode);
extern unsigned long xinix_count_free_inodes(struct super_block *sb);
extern int xinix_new_block(struct inode * inode);
extern void xinix_free_block(struct inode *inode, unsigned long block);
extern unsigned long xinix_count_free_blocks(struct super_block *sb);
extern int xinix_getattr(const struct path *, struct kstat *, u32, unsigned int);
extern int xinix_prepare_chunk(struct page *page, loff_t pos, unsigned len);

extern void V1_xinix_truncate(struct inode *);
extern void V2_xinix_truncate(struct inode *);
extern void xinix_truncate(struct inode *);
extern void xinix_set_inode(struct inode *, dev_t);
extern int V1_xinix_get_block(struct inode *, long, struct buffer_head *, int);
extern int V2_xinix_get_block(struct inode *, long, struct buffer_head *, int);
extern unsigned V1_xinix_blocks(loff_t, struct super_block *);
extern unsigned V2_xinix_blocks(loff_t, struct super_block *);

extern struct xinix_dir_entry *xinix_find_entry(struct dentry*, struct page**);
extern int xinix_add_link(struct dentry*, struct inode*);
extern int xinix_delete_entry(struct xinix_dir_entry*, struct page*);
extern int xinix_make_empty(struct inode*, struct inode*);
extern int xinix_empty_dir(struct inode*);
extern void xinix_set_link(struct xinix_dir_entry*, struct page*, struct inode*);
extern struct xinix_dir_entry *xinix_dotdot(struct inode*, struct page**);
extern ino_t xinix_inode_by_name(struct dentry*);

extern const struct inode_operations xinix_file_inode_operations;
extern const struct inode_operations xinix_dir_inode_operations;
extern const struct file_operations xinix_file_operations;
extern const struct file_operations xinix_dir_operations;

static inline struct xinix_sb_info *xinix_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct xinix_inode_info *xinix_i(struct inode *inode)
{
	return container_of(inode, struct xinix_inode_info, vfs_inode);
}

static inline unsigned xinix_blocks_needed(unsigned bits, unsigned blocksize)
{
	return DIV_ROUND_UP(bits, blocksize * 8);
}

#if defined(CONFIG_MINIX_FS_NATIVE_ENDIAN) && \
	defined(CONFIG_MINIX_FS_BIG_ENDIAN_16BIT_INDEXED)

#error Minix file system byte order broken

#elif defined(CONFIG_MINIX_FS_NATIVE_ENDIAN)

/*
 * big-endian 32 or 64 bit indexed bitmaps on big-endian system or
 * little-endian bitmaps on little-endian system
 */

#define xinix_test_and_set_bit(nr, addr)	\
	__test_and_set_bit((nr), (unsigned long *)(addr))
#define xinix_set_bit(nr, addr)		\
	__set_bit((nr), (unsigned long *)(addr))
#define xinix_test_and_clear_bit(nr, addr) \
	__test_and_clear_bit((nr), (unsigned long *)(addr))
#define xinix_test_bit(nr, addr)		\
	test_bit((nr), (unsigned long *)(addr))
#define xinix_find_first_zero_bit(addr, size) \
	find_first_zero_bit((unsigned long *)(addr), (size))

#elif defined(CONFIG_MINIX_FS_BIG_ENDIAN_16BIT_INDEXED)

/*
 * big-endian 16bit indexed bitmaps
 */

static inline int xinix_find_first_zero_bit(const void *vaddr, unsigned size)
{
	const unsigned short *p = vaddr, *addr = vaddr;
	unsigned short num;

	if (!size)
		return 0;

	size >>= 4;
	while (*p++ == 0xffff) {
		if (--size == 0)
			return (p - addr) << 4;
	}

	num = *--p;
	return ((p - addr) << 4) + ffz(num);
}

#define xinix_test_and_set_bit(nr, addr)	\
	__test_and_set_bit((nr) ^ 16, (unsigned long *)(addr))
#define xinix_set_bit(nr, addr)	\
	__set_bit((nr) ^ 16, (unsigned long *)(addr))
#define xinix_test_and_clear_bit(nr, addr)	\
	__test_and_clear_bit((nr) ^ 16, (unsigned long *)(addr))

static inline int xinix_test_bit(int nr, const void *vaddr)
{
	const unsigned short *p = vaddr;
	return (p[nr >> 4] & (1U << (nr & 15))) != 0;
}

#else

/*
 * little-endian bitmaps
 */

#define xinix_test_and_set_bit	__test_and_set_bit_le
#define xinix_set_bit		__set_bit_le
#define xinix_test_and_clear_bit	__test_and_clear_bit_le
#define xinix_test_bit	test_bit_le
#define xinix_find_first_zero_bit	find_first_zero_bit_le

#endif

#endif /* FS_MINIX_H */
