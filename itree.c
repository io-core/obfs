// SPDX-License-Identifier: GPL-2.0
#include <linux/buffer_head.h>
#include "obfs.h"

enum {DIRECT = 7, DEPTH = 4};	/* Have triple indirect */
//enum {DIRECT = 7, DEPTH = 2};   /* Have single indirect */

typedef u32 block_t;	/* 32 bit, host order */

static inline unsigned long block_to_cpu(block_t n)
{
	return n;
}

static inline block_t cpu_to_block(unsigned long n)
{
	return n;
}

//static inline block_t *i_data(struct inode *inode)
//{
//	return (block_t *)obfs_i(inode)->u.i2_data;
//}

//#define OBFS_SECTABSIZE 64
//#define OBFS_EXTABSIZE 12
//#define DIRCOUNT 7
#define DIRCOUNT OBFS_SECTABSIZE
//#define INDIRCOUNT(sb) (1 << ((sb)->s_blocksize_bits - 2))
#define INDIRCOUNT OBFS_EXTABSIZE

static int block_to_path(struct inode * inode, long block, int offsets[DEPTH])
{
	int n = 0;
	struct super_block *sb = inode->i_sb;

	if (block < 0) {
		printk("OBFS: block_to_path: block %ld < 0 on dev %pg\n",
			block, sb->s_bdev);
	} else if ((u64)block * (u64)sb->s_blocksize >=
			obfs_sb(sb)->s_max_size) {
		if (printk_ratelimit())
			printk("OBFS: block_to_path: "
			       "block %ld too big on dev %pg\n",
				block, sb->s_bdev);
	} else if (block < DIRCOUNT) {
		offsets[n++] = block;
	} else { //if ((block -= DIRCOUNT) < INDIRCOUNT(sb)) {
		block -= DIRCOUNT;
		offsets[n++] = DIRCOUNT;
		offsets[n++] = block;
//	} else if ((block -= INDIRCOUNT(sb)) < INDIRCOUNT(sb) * INDIRCOUNT(sb)) {
//		offsets[n++] = DIRCOUNT + 1;
//		offsets[n++] = block / INDIRCOUNT(sb);
//		offsets[n++] = block % INDIRCOUNT(sb);
//	} else {
//		block -= INDIRCOUNT(sb) * INDIRCOUNT(sb);
//		offsets[n++] = DIRCOUNT + 2;
//		offsets[n++] = (block / INDIRCOUNT(sb)) / INDIRCOUNT(sb);
//		offsets[n++] = (block / INDIRCOUNT(sb)) % INDIRCOUNT(sb);
//		offsets[n++] = block % INDIRCOUNT(sb);
	}
	return n;
}

typedef struct {
	block_t	*p;
	block_t	key;
	struct buffer_head *bh;
} Indirect;

static DEFINE_RWLOCK(pointers_lock);

static inline void add_chain(Indirect *p, struct buffer_head *bh, block_t *v)
{
	p->key = *(p->p = v);
	p->bh = bh;
}

static inline int verify_chain(Indirect *from, Indirect *to)
{
	while (from <= to && from->key == *from->p)
		from++;
	return (from > to);
}

static inline block_t *block_end(struct buffer_head *bh)
{
	return (block_t *)((char*)bh->b_data + bh->b_size);
}

static inline Indirect *get_branch(struct inode *inode,
					int depth,
					int *offsets,
					Indirect chain[DEPTH],
					int *err)
{
	struct super_block *sb = inode->i_sb;
	Indirect *p = chain;
	struct buffer_head *bh;

	*err = 0;
	/* i_data is not going away, no lock needed */
//	add_chain (chain, NULL, i_data(inode) + *offsets);
	if (!p->key)
		goto no_block;
	while (--depth) {
		bh = sb_bread(sb, (block_to_cpu(p->key)/29)-1);
		if (!bh)
			goto failure;
		read_lock(&pointers_lock);
		if (!verify_chain(chain, p))
			goto changed;
		add_chain(++p, bh, (block_t *)bh->b_data + *++offsets);
		read_unlock(&pointers_lock);
		if (!p->key)
			goto no_block;
	}
	return NULL;

changed:
	read_unlock(&pointers_lock);
	brelse(bh);
	*err = -EAGAIN;
	goto no_block;
failure:
	*err = -EIO;
no_block:
	return p;
}

static int alloc_branch(struct inode *inode,
			     int num,
			     int *offsets,
			     Indirect *branch)
{
	int n = 0;
	int i;
	int parent = obfs_new_block(inode);

	branch[0].key = cpu_to_block(parent);
	if (parent) for (n = 1; n < num; n++) {
		struct buffer_head *bh;
		/* Allocate the next block */
		int nr = obfs_new_block(inode);
		if (!nr)
			break;
		branch[n].key = cpu_to_block(nr);
		bh = sb_getblk(inode->i_sb, parent);
		lock_buffer(bh);
		memset(bh->b_data, 0, bh->b_size);
		branch[n].bh = bh;
		branch[n].p = (block_t*) bh->b_data + offsets[n];
		*branch[n].p = branch[n].key;
		set_buffer_uptodate(bh);
		unlock_buffer(bh);
		mark_buffer_dirty_inode(bh, inode);
		parent = nr;
	}
	if (n == num)
		return 0;

	/* Allocation failed, free what we already allocated */
	for (i = 1; i < n; i++)
		bforget(branch[i].bh);
	for (i = 0; i < n; i++)
		obfs_free_block(inode, block_to_cpu(branch[i].key));
	return -ENOSPC;
}

static inline int splice_branch(struct inode *inode,
				     Indirect chain[DEPTH],
				     Indirect *where,
				     int num)
{
	int i;

	write_lock(&pointers_lock);

	/* Verify that place we are splicing to is still there and vacant */
	if (!verify_chain(chain, where-1) || *where->p)
		goto changed;

	*where->p = where->key;

	write_unlock(&pointers_lock);

	/* We are done with atomic stuff, now do the rest of housekeeping */

	inode->i_ctime = current_time(inode);

	/* had we spliced it onto indirect block? */
	if (where->bh)
		mark_buffer_dirty_inode(where->bh, inode);

	mark_inode_dirty(inode);
	return 0;

changed:
	write_unlock(&pointers_lock);
	for (i = 1; i < num; i++)
		bforget(where[i].bh);
	for (i = 0; i < num; i++)
		obfs_free_block(inode, block_to_cpu(where[i].key));
	return -EAGAIN;
}

static int get_block(struct inode * inode, sector_t block,
			struct buffer_head *bh, int create)
{
	int err = -EIO;
	int offsets[DEPTH];
	Indirect chain[DEPTH];
	Indirect *partial;
	int left;
	int depth = 1; //block_to_path(inode, block, offsets);

	if (block > OBFS_SECTABSIZE){
		depth=2;
		if ((block - OBFS_SECTABSIZE) > (OBFS_EXTABSIZE * 256)){
	        	printk("OBFS: get_block: sector %lld too large for inode %ld\n", block, inode->i_ino);
			goto out;
		}
	}

        printk("OBFS: get_block: block %lld attempted at sector %d\n",
                block, obfs_i(inode)->direct[block]);

	err=0;
	map_bh(bh, inode->i_sb, (block_to_cpu(obfs_i(inode)->direct[block])/29)-1);//                              chain[depth-1].key));

	goto out;

reread:
	partial = get_branch(inode, depth, offsets, chain, &err);

	/* Simplest case - block found, no allocation needed */
	if (!partial) {
got_it:
		map_bh(bh, inode->i_sb, block_to_cpu(chain[depth-1].key));
		/* Clean up and exit */
		partial = chain+depth-1; /* the whole chain */
		goto cleanup;
	}

	/* Next simple case - plain lookup or failed read of indirect block */
	if (!create || err == -EIO) {
cleanup:
		while (partial > chain) {
			brelse(partial->bh);
			partial--;
		}
out:
		return err;
	}

	/*
	 * Indirect block might be removed by truncate while we were
	 * reading it. Handling of that case (forget what we've got and
	 * reread) is taken out of the main path.
	 */
	if (err == -EAGAIN)
		goto changed;

	left = (chain + depth) - partial;
	err = alloc_branch(inode, left, offsets+(partial-chain), partial);
	if (err)
		goto cleanup;

	if (splice_branch(inode, chain, partial, left) < 0)
		goto changed;

	set_buffer_new(bh);
	goto got_it;

changed:
	while (partial > chain) {
		brelse(partial->bh);
		partial--;
	}
	goto reread;
}

static inline int all_zeroes(block_t *p, block_t *q)
{
	while (p < q)
		if (*p++)
			return 0;
	return 1;
}

static Indirect *find_shared(struct inode *inode,
				int depth,
				int offsets[DEPTH],
				Indirect chain[DEPTH],
				block_t *top)
{
	Indirect *partial, *p;
	int k, err;

	*top = 0;
	for (k = depth; k > 1 && !offsets[k-1]; k--)
		;
	partial = get_branch(inode, k, offsets, chain, &err);

	write_lock(&pointers_lock);
	if (!partial)
		partial = chain + k-1;
	if (!partial->key && *partial->p) {
		write_unlock(&pointers_lock);
		goto no_top;
	}
	for (p=partial;p>chain && all_zeroes((block_t*)p->bh->b_data,p->p);p--)
		;
	if (p == chain + k - 1 && p > chain) {
		p->p--;
	} else {
		*top = *p->p;
		*p->p = 0;
	}
	write_unlock(&pointers_lock);

	while(partial > p)
	{
		brelse(partial->bh);
		partial--;
	}
no_top:
	return partial;
}

static inline void free_data(struct inode *inode, block_t *p, block_t *q)
{
	unsigned long nr;

	for ( ; p < q ; p++) {
		nr = block_to_cpu(*p);
		if (nr) {
			*p = 0;
			obfs_free_block(inode, nr);
		}
	}
}

static void free_branches(struct inode *inode, block_t *p, block_t *q, int depth)
{
	struct buffer_head * bh;
	unsigned long nr;

	if (depth--) {
		for ( ; p < q ; p++) {
			nr = block_to_cpu(*p);
			if (!nr)
				continue;
			*p = 0;
			bh = sb_bread(inode->i_sb, (nr/29)-1);
			if (!bh)
				continue;
			free_branches(inode, (block_t*)bh->b_data,
				      block_end(bh), depth);
			bforget(bh);
			obfs_free_block(inode, nr);
			mark_inode_dirty(inode);
		}
	} else
		free_data(inode, p, q);
}

static inline void truncate (struct inode * inode)
{
	struct super_block *sb = inode->i_sb;
	block_t *idata = 0; //i_data(inode);
	int offsets[DEPTH];
	Indirect chain[DEPTH];
	Indirect *partial;
	block_t nr = 0;
	int n;
	int first_whole;
	long iblock;

	iblock = (inode->i_size + sb->s_blocksize -1) >> sb->s_blocksize_bits;
	block_truncate_page(inode->i_mapping, inode->i_size, get_block);

	n = block_to_path(inode, iblock, offsets);
	if (!n)
		return;

	if (n == 1) {
		free_data(inode, idata+offsets[0], idata + DIRECT);
		first_whole = 0;
		goto do_indirects;
	}

	first_whole = offsets[0] + 1 - DIRECT;
	partial = find_shared(inode, n, offsets, chain, &nr);
	if (nr) {
		if (partial == chain)
			mark_inode_dirty(inode);
		else
			mark_buffer_dirty_inode(partial->bh, inode);
		free_branches(inode, &nr, &nr+1, (chain+n-1) - partial);
	}
	/* Clear the ends of indirect blocks on the shared branch */
	while (partial > chain) {
		free_branches(inode, partial->p + 1, block_end(partial->bh),
				(chain+n-1) - partial);
		mark_buffer_dirty_inode(partial->bh, inode);
		brelse (partial->bh);
		partial--;
	}
do_indirects:
	/* Kill the remaining (whole) subtrees */
	while (first_whole < DEPTH-1) {
		nr = idata[DIRECT+first_whole];
		if (nr) {
			idata[DIRECT+first_whole] = 0;
			mark_inode_dirty(inode);
			free_branches(inode, &nr, &nr+1, first_whole+1);
		}
		first_whole++;
	}
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);
}

static inline unsigned nblocks(loff_t size, struct super_block *sb)
{
	int k = sb->s_blocksize_bits - 10;
	unsigned blocks, res, direct = DIRECT, i = DEPTH;
	blocks = (size + sb->s_blocksize - 1) >> (BLOCK_SIZE_BITS + k);
	res = blocks;
	while (--i && blocks > direct) {
		blocks -= direct;
		blocks += sb->s_blocksize/sizeof(block_t) - 1;
		blocks /= sb->s_blocksize/sizeof(block_t);
		res += blocks;
		direct = 1;
	}
	return res;
}


int V2_obfs_get_block(struct inode * inode, long block,
			struct buffer_head *bh_result, int create)
{
	return get_block(inode, block, bh_result, create);
}

void V2_obfs_truncate(struct inode * inode)
{
	truncate(inode);
}

unsigned V2_obfs_blocks(loff_t size, struct super_block *sb)
{
	return nblocks(size, sb);
}
