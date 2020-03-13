# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Linux obfs filesystem routines.
#

obj-m := obfs.o

obfs-objs := bitmap.o itree.o namei.o inode.o file.o dir.o

all: ko 

ko:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
