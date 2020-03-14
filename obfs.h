/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OBFS_H
#define OBFS_H

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/magic.h>

/*
 * The oberon filesystem constants/structures
 */

#define OBFS_ROOT_INO 1

#define OBFS_VERSION "2013a"
#define OBFS_SUPER_MAGIC 0x9B1EA38D
#define OBFS_DIRMARK 0x9B1EA38D
#define OBFS_HEADERMARK 0x9BA71D86

#define OBFS_ROOTINODE 29
#define OBFS_BITMAPSIZE 8192
#define OBFS_FNLENGTH 32
#define OBFS_SECTABSIZE 64
#define OBFS_EXTABSIZE 12
#define OBFS_SECTORSIZE 1024
#define OBFS_INDEXSIZE (OBFS_SECTORSIZE / 4)
#define OBFS_HEADERSIZE 352
#define OBFS_INDATASIZE (OBFS_SECTORSIZE - OBFS_HEADERSIZE)
#define OBFS_SMALLFILELIMIT (OBFS_SECTORSIZE * OBFS_SECTABSIZE)
#define OBFS_DIRROOTADR 29
#define OBFS_DIRPGSIZE 24
#define OBFS_FILLERSIZE 52
#define OBFS_FILENAME_MAXLEN 63
#define OBFS_BLOCKSIZE_BITS     10
#define OBFS_BLOCKSIZE          (1 << OBFS_BLOCKSIZE_BITS)

#define OBFS_LINK_MAX	65530

#define OBFS_I_MAP_SLOTS	8
#define OBFS_Z_MAP_SLOTS	64
#define OBFS_VALID_FS		0x0001		/* Clean fs. */
#define OBFS_ERROR_FS		0x0002		/* fs has errors. */

struct  obfs_de {  // directory entry B-tree node
    char name[OBFS_FNLENGTH];
    uint32_t  adr;       // sec no of file header
    uint32_t  p;         // sec no of descendant in directory
}__attribute__((packed));

struct obfs_fh {    // file header
    char name[OBFS_FNLENGTH];
    uint32_t aleng;
    uint32_t bleng;
    uint32_t date;
    uint32_t ext[OBFS_EXTABSIZE];                     // ExtensionTable
    uint32_t sec[OBFS_SECTABSIZE];                    // SectorTable;
    char fill[OBFS_SECTORSIZE - OBFS_HEADERSIZE];     // File Data
}__attribute__((packed));

struct obfs_dp {    // directory page
    uint32_t m;
    uint32_t p0;         //sec no of left descendant in directory
    char fill[OBFS_FILLERSIZE];
    struct obfs_de e[24];
}__attribute__((packed));

struct obfs_ep {    // extended page
    uint32_t x[256];
}__attribute__((packed));


struct obfs_dir_record {
    char filename[OBFS_FILENAME_MAXLEN];
    uint64_t inode_no;
}__attribute__((packed));

struct obfs_dinode {
    uint32_t origin;     // magic number on disk, inode type | sector number in memory
    union {
       struct obfs_fh fhb;
       struct obfs_dp dirb;
    };
//    struct inode vfs_inode;
}__attribute__((packed));


/*
 * The new obfs inode has all the time entries, as well as
 * long block numbers and a third indirect block (7+1+1+1
 * instead of 7+1+1). Also, some previously 8-bit values are
 * now 16-bit. The inode is now 64 bytes instead of 32.
 */
struct obfs2_inode {
	__u16 i_mode;
	__u16 i_nlinks;
	__u16 i_uid;
	__u16 i_gid;
	__u32 i_size;
	__u32 i_atime;
	__u32 i_mtime;
	__u32 i_ctime;
	__u32 i_zone[10];
};

/*
 * obfs super-block data on disk
 */
struct obfs_super_block {
	__u16 s_ninodes;
	__u16 s_nzones;
	__u16 s_imap_blocks;
	__u16 s_zmap_blocks;
	__u16 s_firstdatazone;
	__u16 s_log_zone_size;
	__u32 s_max_size;
	__u16 s_magic;
	__u16 s_state;
	__u32 s_zones;
};

/*
 * V3 obfs super-block data on disk
 */
struct obfs3_super_block {
	__u32 s_ninodes;
	__u16 s_pad0;
	__u16 s_imap_blocks;
	__u16 s_zmap_blocks;
	__u16 s_firstdatazone;
	__u16 s_log_zone_size;
	__u16 s_pad1;
	__u32 s_max_size;
	__u32 s_zones;
	__u16 s_magic;
	__u16 s_pad2;
	__u16 s_blocksize;
	__u8  s_disk_version;
};

struct obfs_dir_entry {
	__u16 inode;
	char name[0];
};

struct obfs3_dir_entry {
	__u32 inode;
	char name[0];
};


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

#define BITSET(val,nbit)   ((val) |=  (1<<(nbit)))
#define BITCLEAR(val,nbit) ((val) &= ~(1<<(nbit)))
#define BITFLIP(val,nbit)  ((val) ^=  (1<<(nbit)))
#define BITCHECK(val,nbit) ((val) &   (1<<(nbit)))

extern struct inode *obfs_iget(struct super_block *, unsigned long);
extern struct obfs2_inode * obfs_V2_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct inode * obfs_new_inode(const struct inode *, umode_t, int *);
extern void obfs_free_inode(struct inode * inode);
extern unsigned long obfs_count_free_inodes(struct super_block *sb);
extern int obfs_new_block(struct inode * inode);
extern void obfs_free_block(struct inode *inode, unsigned long block);
extern unsigned long obfs_count_free_blocks(struct super_block *sb);
extern int obfs_getattr(const struct path *, struct kstat *, u32, unsigned int);
extern int obfs_prepare_chunk(struct page *page, loff_t pos, unsigned len);

extern void V2_obfs_truncate(struct inode *);
extern void obfs_truncate(struct inode *);
extern void obfs_set_inode(struct inode *, dev_t);
extern int V2_obfs_get_block(struct inode *, long, struct buffer_head *, int);
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
