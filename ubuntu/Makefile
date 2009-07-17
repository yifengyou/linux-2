#
# Makefile for the Linux kernel ubuntu supplied third-party device drivers.
#

obj-$(CONFIG_SECURITY_APPARMOR)        += apparmor/

obj-$(CONFIG_AUFS_FS)		+= aufs/
obj-$(CONFIG_BLK_DEV_COMPCACHE)	+= compcache/
obj-$(CONFIG_DM_RAID45)		+= dm-raid4-5/
obj-$(CONFIG_BLK_DEV_DRBD)	+= drbd/
obj-$(CONFIG_SCSI_ISCSITARGET)	+= iscsitarget/

# This is a stupid trick to get kbuild to create ubuntu/built-in.o
obj- += foo.o
