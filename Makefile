# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Linux obfs filesystem routines.
#

#obj-$(CONFIG_OBFS_FS) += minix.o







obj-m := obfs.o

obfs-objs := bitmap.o itree_v2.o namei.o inode.o file.o dir.o


#obj-m := iofs.o
#iofs-objs := super.o inode.o namei.o dir.o file.o symlink.o
#CFLAGS_super.o := -DDEBUG
#CFLAGS_inode.o := -DDEBUG
#CFLAGS_namei.o := -DEBUG
#CFLAGS_dir.o := -DDEBUG
#CFLAGS_file.o := -DDEBUG
#CFLAGS_symlink.o := -DDEBUG

all: ko 

ko:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules



clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
