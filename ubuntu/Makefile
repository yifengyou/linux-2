#
# Makefile for the Linux kernel ubuntu supplied third-party device drivers.
#

obj-$(CONFIG_AUFS_FS)		+= aufs/
obj-$(CONFIG_BLK_DEV_COMPCACHE)	+= compcache/
obj-$(CONFIG_DM_RAID45)		+= dm-raid4-5/
obj-$(CONFIG_FSAM7400)		+= fsam7400/
#obj-$(CONFIG_BLK_DEV_DRBD)	+= drbd/
obj-$(CONFIG_LENOVO_SL_LAPTOP)	+= lenovo-sl-laptop/
obj-$(CONFIG_LIRC_DEV)          += lirc/
obj-$(CONFIG_NDISWRAPPER)	+= ndiswrapper/
obj-$(CONFIG_OMNIBOOK)		+= omnibook/
obj-m				+= rfkill/

# This is a stupid trick to get kbuild to create ubuntu/built-in.o
obj- += foo.o
