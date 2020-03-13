/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OBFS_H
#define OBFS_H

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "obfs_fs.h"

#define INODE_VERSION(inode)	obfs_sb(inode->i_sb)->s_version
#define OBFS_V1		0x0001		/* original obfs fs */
#define OBFS_V2		0x0002		/* obfs V2 fs */
#define OBFS_V3		0x0003		/* obfs V3 fs */

/*
 * obfs fs inode data in memory
 */
struct obfs_inode_info {
	union {
		__u16 i1_data[16];
		__u32 i2_data[16];
	} u;
	struct inode vfs_inode;
};

/*
 * obfs super-block data in memory
 */
struct obfs_sb_info {
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
	struct obfs_super_block * s_ms;
	unsigned short s_mount_state;
	unsigned short s_version;
};

extern struct inode *obfs_iget(struct super_block *, unsigned long);
extern struct obfs_inode * obfs_V1_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct obfs2_inode * obfs_V2_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct inode * obfs_new_inode(const struct inode *, umode_t, int *);
extern void obfs_free_inode(struct inode * inode);
extern unsigned long obfs_count_free_inodes(struct super_block *sb);
extern int obfs_new_block(struct inode * inode);
extern void obfs_free_block(struct inode *inode, unsigned long block);
extern unsigned long obfs_count_free_blocks(struct super_block *sb);
extern int obfs_getattr(const struct path *, struct kstat *, u32, unsigned int);
extern int obfs_prepare_chunk(struct page *page, loff_t pos, unsigned len);

extern void V1_obfs_truncate(struct inode *);
extern void V2_obfs_truncate(struct inode *);
extern void obfs_truncate(struct inode *);
extern void obfs_set_inode(struct inode *, dev_t);
extern int V1_obfs_get_block(struct inode *, long, struct buffer_head *, int);
extern int V2_obfs_get_block(struct inode *, long, struct buffer_head *, int);
extern unsigned V1_obfs_blocks(loff_t, struct super_block *);
extern unsigned V2_obfs_blocks(loff_t, struct super_block *);

extern struct obfs_dir_entry *obfs_find_entry(struct dentry*, struct page**);
extern int obfs_add_link(struct dentry*, struct inode*);
extern int obfs_delete_entry(struct obfs_dir_entry*, struct page*);
extern int obfs_make_empty(struct inode*, struct inode*);
extern int obfs_empty_dir(struct inode*);
extern void obfs_set_link(struct obfs_dir_entry*, struct page*, struct inode*);
extern struct obfs_dir_entry *obfs_dotdot(struct inode*, struct page**);
extern ino_t obfs_inode_by_name(struct dentry*);

extern const struct inode_operations obfs_file_inode_operations;
extern const struct inode_operations obfs_dir_inode_operations;
extern const struct file_operations obfs_file_operations;
extern const struct file_operations obfs_dir_operations;

static inline struct obfs_sb_info *obfs_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct obfs_inode_info *obfs_i(struct inode *inode)
{
	return container_of(inode, struct obfs_inode_info, vfs_inode);
}

static inline unsigned obfs_blocks_needed(unsigned bits, unsigned blocksize)
{
	return DIV_ROUND_UP(bits, blocksize * 8);
}

#if defined(CONFIG_OBFS_FS_NATIVE_ENDIAN) && \
	defined(CONFIG_OBFS_FS_BIG_ENDIAN_16BIT_INDEXED)

#error Minix file system byte order broken

#elif defined(CONFIG_OBFS_FS_NATIVE_ENDIAN)

/*
 * big-endian 32 or 64 bit indexed bitmaps on big-endian system or
 * little-endian bitmaps on little-endian system
 */

#define obfs_test_and_set_bit(nr, addr)	\
	__test_and_set_bit((nr), (unsigned long *)(addr))
#define obfs_set_bit(nr, addr)		\
	__set_bit((nr), (unsigned long *)(addr))
#define obfs_test_and_clear_bit(nr, addr) \
	__test_and_clear_bit((nr), (unsigned long *)(addr))
#define obfs_test_bit(nr, addr)		\
	test_bit((nr), (unsigned long *)(addr))
#define obfs_find_first_zero_bit(addr, size) \
	find_first_zero_bit((unsigned long *)(addr), (size))

#elif defined(CONFIG_OBFS_FS_BIG_ENDIAN_16BIT_INDEXED)

/*
 * big-endian 16bit indexed bitmaps
 */

static inline int obfs_find_first_zero_bit(const void *vaddr, unsigned size)
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

#define obfs_test_and_set_bit(nr, addr)	\
	__test_and_set_bit((nr) ^ 16, (unsigned long *)(addr))
#define obfs_set_bit(nr, addr)	\
	__set_bit((nr) ^ 16, (unsigned long *)(addr))
#define obfs_test_and_clear_bit(nr, addr)	\
	__test_and_clear_bit((nr) ^ 16, (unsigned long *)(addr))

static inline int obfs_test_bit(int nr, const void *vaddr)
{
	const unsigned short *p = vaddr;
	return (p[nr >> 4] & (1U << (nr & 15))) != 0;
}

#else

/*
 * little-endian bitmaps
 */

#define obfs_test_and_set_bit	__test_and_set_bit_le
#define obfs_set_bit		__set_bit_le
#define obfs_test_and_clear_bit	__test_and_clear_bit_le
#define obfs_test_bit	test_bit_le
#define obfs_find_first_zero_bit	find_first_zero_bit_le

#endif

#endif /* OBFS_H */
