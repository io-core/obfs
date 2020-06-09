// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/obfs/dir.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  obfs directory handling functions
 *
 *  Updated to filesystem version 3 by Daniel Aragones
 *
 *  Copyright (C) 2020  Charles Perkins
 *      Project Oberon fs support.
 */

#include "obfs.h"
#include <linux/buffer_head.h>
#include <linux/highmem.h>
#include <linux/swap.h>

typedef struct obfs_dir_entry obfs_dirent;
typedef struct obfs3_dir_entry obfs3_dirent;

static int obfs_readdir(struct file *, struct dir_context *);

const struct file_operations obfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= obfs_readdir,
	.fsync		= generic_file_fsync,
};

static inline void dir_put_page(struct page *page)
{
	kunmap(page);
	put_page(page);
}

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned
obfs_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned last_byte = PAGE_SIZE;

	if (page_nr == (inode->i_size >> PAGE_SHIFT))
		last_byte = inode->i_size & (PAGE_SIZE - 1);
	return last_byte;
}

static int dir_commit_chunk(struct page *page, loff_t pos, unsigned len)
{
	struct address_space *mapping = page->mapping;
	struct inode *dir = mapping->host;
	int err = 0;
	block_write_end(NULL, mapping, pos, len, len, page, NULL);

	if (pos+len > dir->i_size) {
		i_size_write(dir, pos+len);
		mark_inode_dirty(dir);
	}
	if (IS_DIRSYNC(dir))
		err = write_one_page(page);
	else
		unlock_page(page);
	return err;
}

static struct page * dir_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page))
		kmap(page);
	return page;
}

static inline void *obfs_next_entry(void *de, struct obfs_sb_info *sbi)
{
	return (void*)((char*)de + sbi->s_dirsize);
}

static int do_obfs_readdir(struct inode *file, uint64_t ino, struct dir_context *ctx, int start, bool mark)
{

        struct inode *finode = file; //file_inode(file);
        struct buffer_head *bh;

        int                     slot, here, namelen;
        char                    *nameptr;
        struct obfs_dinode      *dinode;
        struct obfs_dinode      dinode_buf;
        struct obfs_de          *dirslot;
//        struct obfs_bm          *bm;

        here = start;

        bh = sb_bread(finode->i_sb, (ino/29)-1);

        if (!bh) {
                pr_err("%s(): failed to read dir inode %llu\n",
                       __func__, ino);
                return 0;
        }

        dinode = &dinode_buf;
        memcpy(dinode,bh->b_data,sizeof(dinode_buf));
        brelse(bh);

        if (le32_to_cpu(dinode->origin) != OBFS_DIRMARK) {
                pr_err("%s(): invalid directory inode %llu\n", __func__,ino);
                return here;
        }
//        bm = SUPER_INFO(finode->i_sb);

//        if (mark) {
//                BITSET(bm->s[(ino/29)/32],(ino/29)%32);
//        }

//      if ((!mark) && (here==0)){
//              if (ctx->pos==0){
//                dir_emit_dot(file, ctx);
//                  ctx->pos++;
//                }
//              here++;
//      }

        if (dinode->dirb.p0 != 0){
                here = do_obfs_readdir( file, dinode->dirb.p0, ctx, here, mark );
        }


        for (slot = 0; slot < dinode->dirb.m && slot < 24; slot++) {
                dirslot  = &dinode->dirb.e[slot];
                namelen  = strnlen(dirslot->name,24);
                nameptr  = dirslot->name;
                if((!mark) && (here >= ctx->pos)) {
                  ctx->pos++;
                  if (!dir_emit(ctx, nameptr, namelen, dirslot->adr, DT_UNKNOWN)) {
                        return here;
                  }
                  if (dirslot->p != 0){
                        here = do_obfs_readdir( file, dirslot->p, ctx, here, mark );
                  }
                }else{

//                  markfile(file,dirslot->adr,bm,true);
//
//                  if (dirslot->p != 0){
//                        here = do_obfs_readdir( file, dirslot->p, ctx, here, mark );
//                  }
                }
                here++;
        }

        return here;

/*
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct obfs_sb_info *sbi = obfs_sb(sb);
	unsigned chunk_size = sbi->s_dirsize;
	unsigned long npages = dir_pages(inode);
	unsigned long pos = ctx->pos;
	unsigned offset;
	unsigned long n;

	ctx->pos = pos = ALIGN(pos, chunk_size);
	if (pos >= inode->i_size)
		return 0;

	offset = pos & ~PAGE_MASK;
	n = pos >> PAGE_SHIFT;

	for ( ; n < npages; n++, offset = 0) {
	offset = 0;
		char *p, *kaddr, *limit;
		struct page *page = dir_get_page(inode, n);

		if (IS_ERR(page))
			continue;
		kaddr = (char *)page_address(page);
		p = kaddr+offset;
		limit = kaddr + obfs_last_byte(inode, n) - chunk_size;
		for ( ; p <= limit; p = obfs_next_entry(p, sbi)) {
			const char *name;
			__u32 inumber;
			if (sbi->s_version == OBFS_V3) {
				obfs3_dirent *de3 = (obfs3_dirent *)p;
				name = de3->name;
				inumber = de3->inode;
	 		} else {
				obfs_dirent *de = (obfs_dirent *)p;
				name = de->name;
				inumber = de->inode;
			}
			if (inumber) {
				unsigned l = strnlen(name, sbi->s_namelen);
				if (!dir_emit(ctx, name, l,
					      inumber, DT_UNKNOWN)) {
					dir_put_page(page);
					return 0;
				}
			}
			ctx->pos += chunk_size;
		}
		dir_put_page(page);
	}
	return 0;
*/


}

static int obfs_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    int ret;
    ret = do_obfs_readdir( file_inode(file), inode->i_ino, ctx, 0, false );
    ctx->pos = INT_MAX;
    return 0;

}


static inline int namecompare(int len, int maxlen,
	const char * name, const char * buffer)
{
	if (len < maxlen && buffer[len])
		return 0;
	return !memcmp(name, buffer, len);
}

/*
 *	obfs_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the cache buffer in which the entry was found, and the entry
 * itself (as a parameter - res_dir). It does NOT read the inode of the
 * entry - you'll have to do that yourself if you want to.
 */
obfs_dirent *obfs_find_entry(struct dentry *dentry, struct page **res_page)
{
	const char * name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct inode * dir = d_inode(dentry->d_parent);
	struct super_block * sb = dir->i_sb;
	struct obfs_sb_info * sbi = obfs_sb(sb);
	unsigned long n;
//	unsigned long npages = dir_pages(dir);
	struct page *page = NULL;
	char *p;

	char *namx;
	__u32 inumber;
	*res_page = NULL;

        int                     slot;
        struct obfs_dinode      *dinode;

//	for (n = 0; n < npages; n++) {
	n = 0;
		char *kaddr, *limit;

		page = dir_get_page(dir, n);
		if (IS_ERR(page)){
			printk("OBFS: dir_get_page error\n");
			dir_put_page(page);
			return NULL;
		}

//		kaddr = (char*)page_address(page);
                dinode = (struct obfs_dinode *)page_address(page);

	        if (dinode->origin != OBFS_DIRMARK) {
	                pr_err("%s(): invalid directory inode \n", __func__);
	                dir_put_page(page);
                        return NULL;

	        }else{
	                pr_err("%s(): good directory inode \n", __func__);
	        }

	for (slot = 0; slot < dinode->dirb.m && slot < 24; slot++) {


	}

//		limit = kaddr + obfs_last_byte(dir, n) - sbi->s_dirsize;
//		for (p = kaddr; p <= limit; p = obfs_next_entry(p, sbi)) {
//			if (sbi->s_version == OBFS_V3) {
//				obfs3_dirent *de3 = (obfs3_dirent *)p;
//				namx = de3->name;
//				inumber = de3->inode;
// 			} else {
//				obfs_dirent *de = (obfs_dirent *)p;
//				namx = de->name;
//				inumber = de->inode;
//			}
//			if (!inumber)
//				continue;
//			if (namecompare(namelen, sbi->s_namelen, name, namx))
//				goto found;
//		}
		dir_put_page(page);
//	}
	return NULL;

found:
	*res_page = page;
	return (obfs_dirent *)p;
}

int obfs_add_link(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = d_inode(dentry->d_parent);
	const char * name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct super_block * sb = dir->i_sb;
	struct obfs_sb_info * sbi = obfs_sb(sb);
	struct page *page = NULL;
	unsigned long npages = dir_pages(dir);
	unsigned long n;
	char *kaddr, *p;
	obfs_dirent *de;
	obfs3_dirent *de3;
	loff_t pos;
	int err;
	char *namx = NULL;
	__u32 inumber;

	/*
	 * We take care of directory expansion in the same loop
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	for (n = 0; n <= npages; n++) {
		char *limit, *dir_end;

		page = dir_get_page(dir, n);
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;
		lock_page(page);
		kaddr = (char*)page_address(page);
		dir_end = kaddr + obfs_last_byte(dir, n);
		limit = kaddr + PAGE_SIZE - sbi->s_dirsize;
		for (p = kaddr; p <= limit; p = obfs_next_entry(p, sbi)) {
			de = (obfs_dirent *)p;
			de3 = (obfs3_dirent *)p;
			if (sbi->s_version == OBFS_V3) {
				namx = de3->name;
				inumber = de3->inode;
		 	} else {
  				namx = de->name;
				inumber = de->inode;
			}
			if (p == dir_end) {
				/* We hit i_size */
				if (sbi->s_version == OBFS_V3)
					de3->inode = 0;
		 		else
					de->inode = 0;
				goto got_it;
			}
			if (!inumber)
				goto got_it;
			err = -EEXIST;
			if (namecompare(namelen, sbi->s_namelen, name, namx))
				goto out_unlock;
		}
		unlock_page(page);
		dir_put_page(page);
	}
	BUG();
	return -EINVAL;

got_it:
	pos = page_offset(page) + p - (char *)page_address(page);
	err = obfs_prepare_chunk(page, pos, sbi->s_dirsize);
	if (err)
		goto out_unlock;
	memcpy (namx, name, namelen);
	if (sbi->s_version == OBFS_V3) {
		memset (namx + namelen, 0, sbi->s_dirsize - namelen - 4);
		de3->inode = inode->i_ino;
	} else {
		memset (namx + namelen, 0, sbi->s_dirsize - namelen - 2);
		de->inode = inode->i_ino;
	}
	err = dir_commit_chunk(page, pos, sbi->s_dirsize);
	dir->i_mtime = dir->i_ctime = current_time(dir);
	mark_inode_dirty(dir);
out_put:
	dir_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

int obfs_delete_entry(struct obfs_dir_entry *de, struct page *page)
{
	struct inode *inode = page->mapping->host;
	char *kaddr = page_address(page);
	loff_t pos = page_offset(page) + (char*)de - kaddr;
	struct obfs_sb_info *sbi = obfs_sb(inode->i_sb);
	unsigned len = sbi->s_dirsize;
	int err;

	lock_page(page);
	err = obfs_prepare_chunk(page, pos, len);
	if (err == 0) {
		if (sbi->s_version == OBFS_V3)
			((obfs3_dirent *) de)->inode = 0;
		else
			de->inode = 0;
		err = dir_commit_chunk(page, pos, len);
	} else {
		unlock_page(page);
	}
	dir_put_page(page);
	inode->i_ctime = inode->i_mtime = current_time(inode);
	mark_inode_dirty(inode);
	return err;
}

int obfs_make_empty(struct inode *inode, struct inode *dir)
{
	struct page *page = grab_cache_page(inode->i_mapping, 0);
	struct obfs_sb_info *sbi = obfs_sb(inode->i_sb);
	char *kaddr;
	int err;

	if (!page)
		return -ENOMEM;
	err = obfs_prepare_chunk(page, 0, 2 * sbi->s_dirsize);
	if (err) {
		unlock_page(page);
		goto fail;
	}

	kaddr = kmap_atomic(page);
	memset(kaddr, 0, PAGE_SIZE);

	if (sbi->s_version == OBFS_V3) {
		obfs3_dirent *de3 = (obfs3_dirent *)kaddr;

		de3->inode = inode->i_ino;
		strcpy(de3->name, ".");
		de3 = obfs_next_entry(de3, sbi);
		de3->inode = dir->i_ino;
		strcpy(de3->name, "..");
	} else {
		obfs_dirent *de = (obfs_dirent *)kaddr;

		de->inode = inode->i_ino;
		strcpy(de->name, ".");
		de = obfs_next_entry(de, sbi);
		de->inode = dir->i_ino;
		strcpy(de->name, "..");
	}
	kunmap_atomic(kaddr);

	err = dir_commit_chunk(page, 0, 2 * sbi->s_dirsize);
fail:
	put_page(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int obfs_empty_dir(struct inode * inode)
{
	struct page *page = NULL;
	unsigned long i, npages = dir_pages(inode);
	struct obfs_sb_info *sbi = obfs_sb(inode->i_sb);
	char *name;
	__u32 inumber;

	for (i = 0; i < npages; i++) {
		char *p, *kaddr, *limit;

		page = dir_get_page(inode, i);
		if (IS_ERR(page))
			continue;

		kaddr = (char *)page_address(page);
		limit = kaddr + obfs_last_byte(inode, i) - sbi->s_dirsize;
		for (p = kaddr; p <= limit; p = obfs_next_entry(p, sbi)) {
			if (sbi->s_version == OBFS_V3) {
				obfs3_dirent *de3 = (obfs3_dirent *)p;
				name = de3->name;
				inumber = de3->inode;
			} else {
				obfs_dirent *de = (obfs_dirent *)p;
				name = de->name;
				inumber = de->inode;
			}

			if (inumber != 0) {
				/* check for . and .. */
				if (name[0] != '.')
					goto not_empty;
				if (!name[1]) {
					if (inumber != inode->i_ino)
						goto not_empty;
				} else if (name[1] != '.')
					goto not_empty;
				else if (name[2])
					goto not_empty;
			}
		}
		dir_put_page(page);
	}
	return 1;

not_empty:
	dir_put_page(page);
	return 0;
}

/* Releases the page */
void obfs_set_link(struct obfs_dir_entry *de, struct page *page,
	struct inode *inode)
{
	struct inode *dir = page->mapping->host;
	struct obfs_sb_info *sbi = obfs_sb(dir->i_sb);
	loff_t pos = page_offset(page) +
			(char *)de-(char*)page_address(page);
	int err;

	lock_page(page);

	err = obfs_prepare_chunk(page, pos, sbi->s_dirsize);
	if (err == 0) {
		if (sbi->s_version == OBFS_V3)
			((obfs3_dirent *) de)->inode = inode->i_ino;
		else
			de->inode = inode->i_ino;
		err = dir_commit_chunk(page, pos, sbi->s_dirsize);
	} else {
		unlock_page(page);
	}
	dir_put_page(page);
	dir->i_mtime = dir->i_ctime = current_time(dir);
	mark_inode_dirty(dir);
}

struct obfs_dir_entry * obfs_dotdot (struct inode *dir, struct page **p)
{
	struct page *page = dir_get_page(dir, 0);
	struct obfs_sb_info *sbi = obfs_sb(dir->i_sb);
	struct obfs_dir_entry *de = NULL;

	if (!IS_ERR(page)) {
		de = obfs_next_entry(page_address(page), sbi);
		*p = page;
	}
	return de;
}

ino_t obfs_inode_by_name(struct dentry *dentry)
{
	struct page *page;
	struct obfs_dir_entry *de = obfs_find_entry(dentry, &page);
	ino_t res = 0;

	if (de) {
		struct address_space *mapping = page->mapping;
		struct inode *inode = mapping->host;
		struct obfs_sb_info *sbi = obfs_sb(inode->i_sb);

		if (sbi->s_version == OBFS_V3)
			res = ((obfs3_dirent *) de)->inode;
		else
			res = de->inode;
		dir_put_page(page);
	}
	return res;
}
