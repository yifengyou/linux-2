/*      $Id: lirc_sasem.c,v 1.40 2009/02/28 10:27:10 lirc Exp $      */
/*
 * lirc_sasem.c - USB remote support for LIRC
 * Version 0.5
 *
 * Copyright (C) 2004-2005 Oliver Stabel <oliver.stabel@gmx.de>
 *			 Tim Davies <tim@opensystems.net.au>
 *
 * This driver was derived from:
 *   Venky Raju <dev@venky.ws>
 *      "lirc_imon - "LIRC/VFD driver for Ahanix/Soundgraph IMON IR/VFD"
 *   Paul Miller <pmiller9@users.sourceforge.net>'s 2003-2004
 *      "lirc_atiusb - USB remote support for LIRC"
 *   Culver Consulting Services <henry@culcon.com>'s 2003
 *      "Sasem OnAir VFD/IR USB driver"
 *
 *
 * NOTE - The LCDproc iMon driver should work with this module.  More info at
 *	http://www.frogstorm.info/sasem
 */

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 22)
#error "*** Sorry, this driver requires kernel version 2.4.22 or higher"
#endif

#include <linux/autoconf.h>

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
#include <asm/uaccess.h>
#else
#include <linux/uaccess.h>
#endif
#include <linux/usb.h>

#include "../kcompat.h"
#include "../lirc.h"
#include "../lirc_dev/lirc_dev.h"


#define MOD_AUTHOR	"Oliver Stabel <oliver.stabel@gmx.de>, " \
			"Tim Davies <tim@opensystems.net.au>"
#define MOD_DESC	"USB Driver for Sasem Remote Controller V1.1"
#define MOD_NAME	"lirc_sasem"
#define MOD_VERSION	"0.5"

#define VFD_MINOR_BASE	144	/* Same as LCD */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
#define DEVFS_MODE S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
#endif
#define DEVFS_NAME	LIRC_DEVFS_PREFIX "lcd%d"

#define BUF_CHUNK_SIZE	8
#define BUF_SIZE	128

#define IOCTL_LCD_CONTRAST 1

/*** P R O T O T Y P E S ***/

/* USB Callback prototypes */
#ifdef KERNEL_2_5
static int sasem_probe(struct usb_interface *interface,
			const struct usb_device_id *id);
static void sasem_disconnect(struct usb_interface *interface);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void usb_rx_callback(struct urb *urb, struct pt_regs *regs);
static void usb_tx_callback(struct urb *urb, struct pt_regs *regs);
#else
static void usb_rx_callback(struct urb *urb);
static void usb_tx_callback(struct urb *urb);
#endif
#else
static void *sasem_probe(struct usb_device *dev, unsigned int intf,
				const struct usb_device_id *id);
static void sasem_disconnect(struct usb_device *dev, void *data);
static void usb_rx_callback(struct urb *urb);
static void usb_tx_callback(struct urb *urb);
#endif

/* VFD file_operations function prototypes */
static int vfd_open(struct inode *inode, struct file *file);
static int vfd_ioctl(struct inode *inode, struct file *file,
				unsigned cmd, unsigned long arg);
static int vfd_close(struct inode *inode, struct file *file);
static ssize_t vfd_write(struct file *file, const char *buf,
				size_t n_bytes, loff_t *pos);

/* LIRC driver function prototypes */
static int ir_open(void *data);
static void ir_close(void *data);

/* Driver init/exit prototypes */
static int __init sasem_init(void);
static void __exit sasem_exit(void);

/*** G L O B A L S ***/

struct sasem_context {

	struct usb_device *dev;
	int vfd_isopen;			/* VFD port has been opened       */
	unsigned int vfd_contrast;	/* VFD contrast		   */
#if !defined(KERNEL_2_5)
	int subminor;			/* index into minor_table	 */
	devfs_handle_t devfs;
#endif
	int ir_isopen;			/* IR port has been opened	*/
	int dev_present;		/* USB device presence	    */
	struct mutex lock;		/* to lock this object	    */
	wait_queue_head_t remove_ok;	/* For unexpected USB disconnects */

	struct lirc_driver *driver;
	struct usb_endpoint_descriptor *rx_endpoint;
	struct usb_endpoint_descriptor *tx_endpoint;
	struct urb *rx_urb;
	struct urb *tx_urb;
	unsigned char usb_rx_buf[8];
	unsigned char usb_tx_buf[8];

	struct tx_t {
		unsigned char data_buf[32];  /* user data buffer	  */
		struct completion finished;  /* wait for write to finish  */
		atomic_t busy;		     /* write in progress	 */
		int status;		     /* status of tx completion   */
	} tx;

	/* for dealing with repeat codes (wish there was a toggle bit!) */
	struct timeval presstime;
	char lastcode[8];
	int codesaved;
};

/* VFD file operations */
static struct file_operations vfd_fops = {

	.owner		= THIS_MODULE,
	.open		= &vfd_open,
	.write		= &vfd_write,
	.ioctl		= &vfd_ioctl,
	.release	= &vfd_close
};

/* USB Device ID for Sasem USB Control Board */
static struct usb_device_id sasem_usb_id_table [] = {
	/* Sasem USB Control Board */
	{ USB_DEVICE(0x11ba, 0x0101) },
	/* Terminating entry */
	{}
};

/* USB Device data */
static struct usb_driver sasem_driver = {
	LIRC_THIS_MODULE(.owner = THIS_MODULE)
	.name		= MOD_NAME,
	.probe		= sasem_probe,
	.disconnect	= sasem_disconnect,
	.id_table	= sasem_usb_id_table,
#if !defined(KERNEL_2_5)
	.fops		= &vfd_fops,
	.minor		= VFD_MINOR_BASE,
#endif
};

#ifdef KERNEL_2_5
static struct usb_class_driver sasem_class = {
	.name		= DEVFS_NAME,
	.fops		= &vfd_fops,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
	.mode		= DEVFS_MODE,
#endif
	.minor_base	= VFD_MINOR_BASE,
};
#endif

/* to prevent races between open() and disconnect() */
static DEFINE_MUTEX(disconnect_lock);

static int debug;

#if !defined(KERNEL_2_5)

#define MAX_DEVICES	4	/* In case there's more than one Sasem device */
static struct sasem_context *minor_table [MAX_DEVICES];

/* the global usb devfs handle */
extern devfs_handle_t usb_devfs_handle;

#endif

/*** M O D U L E   C O D E ***/

MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
MODULE_LICENSE("GPL");
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Debug messages: 0=no, 1=yes (default: no)");

static void delete_context(struct sasem_context *context)
{
	usb_free_urb(context->tx_urb);  /* VFD */
	usb_free_urb(context->rx_urb);  /* IR */
	lirc_buffer_free(context->driver->rbuf);
	kfree(context->driver->rbuf);
	kfree(context->driver);
	kfree(context);

	if (debug)
		printk(KERN_INFO "%s: context deleted\n", __func__);
}

static void deregister_from_lirc(struct sasem_context *context)
{
	int retval;
	int minor = context->driver->minor;

	retval = lirc_unregister_driver(minor);
	if (retval)
		err("%s: unable to deregister from lirc (%d)",
			__func__, retval);
	else
		printk(KERN_INFO "Deregistered Sasem driver (minor:%d)\n",
		       minor);

}

/**
 * Called when the VFD device (e.g. /dev/usb/lcd)
 * is opened by the application.
 */
static int vfd_open(struct inode *inode, struct file *file)
{
#ifdef KERNEL_2_5
	struct usb_interface *interface;
#endif
	struct sasem_context *context = NULL;
	int subminor;
	int retval = 0;

	/* prevent races with disconnect */
	mutex_lock(&disconnect_lock);

#ifdef KERNEL_2_5
	subminor = iminor(inode);
	interface = usb_find_interface(&sasem_driver, subminor);
	if (!interface) {
		err("%s: could not find interface for minor %d",
		    __func__, subminor);
		retval = -ENODEV;
		goto exit;
	}
	context = usb_get_intfdata(interface);
#else
	subminor = MINOR(inode->i_rdev) - VFD_MINOR_BASE;
	if (subminor < 0 || subminor >= MAX_DEVICES) {
		err("%s: no record of minor %d", __func__, subminor);
		retval = -ENODEV;
		goto exit;
	}
	context = minor_table [subminor];
#endif

	if (!context) {
		err("%s: no context found for minor %d",
					__func__, subminor);
		retval = -ENODEV;
		goto exit;
	}

	mutex_lock(&context->lock);

	if (context->vfd_isopen) {
		err("%s: VFD port is already open", __func__);
		retval = -EBUSY;
	} else {
		MOD_INC_USE_COUNT;
		context->vfd_isopen = 1;
		file->private_data = context;
		printk(KERN_INFO "VFD port opened\n");
	}

	mutex_unlock(&context->lock);

exit:
	mutex_unlock(&disconnect_lock);
	return retval;
}

/**
 * Called when the VFD device (e.g. /dev/usb/lcd)
 * is closed by the application.
 */
static int vfd_ioctl(struct inode *inode, struct file *file,
		     unsigned cmd, unsigned long arg)
{
	struct sasem_context *context = NULL;

	context = (struct sasem_context *) file->private_data;

	if (!context) {
		err("%s: no context for device", __func__);
		return -ENODEV;
	}

	mutex_lock(&context->lock);

	switch (cmd) {
	case IOCTL_LCD_CONTRAST:
		if (arg > 1000)
			arg = 1000;
		context->vfd_contrast = (unsigned int)arg;
		break;
	default:
		printk(KERN_INFO "Unknown IOCTL command\n");
		mutex_unlock(&context->lock);
		return -ENOIOCTLCMD;  /* not supported */
	}

	mutex_unlock(&context->lock);
	return 0;
}

/**
 * Called when the VFD device (e.g. /dev/usb/lcd)
 * is closed by the application.
 */
static int vfd_close(struct inode *inode, struct file *file)
{
	struct sasem_context *context = NULL;
	int retval = 0;

	context = (struct sasem_context *) file->private_data;

	if (!context) {
		err("%s: no context for device", __func__);
		return -ENODEV;
	}

	mutex_lock(&context->lock);

	if (!context->vfd_isopen) {
		err("%s: VFD is not open", __func__);
		retval = -EIO;
	} else {
		context->vfd_isopen = 0;
		MOD_DEC_USE_COUNT;
		printk(KERN_INFO "VFD port closed\n");
		if (!context->dev_present && !context->ir_isopen) {

			/* Device disconnected before close and IR port is
			 * not open. If IR port is open, context will be
			 * deleted by ir_close. */
			mutex_unlock(&context->lock);
			delete_context(context);
			return retval;
		}
	}

	mutex_unlock(&context->lock);
	return retval;
}

/**
 * Sends a packet to the VFD.
 */
static int send_packet(struct sasem_context *context)
{
	unsigned int pipe;
	int interval = 0;
	int retval = 0;

	pipe = usb_sndintpipe(context->dev,
			context->tx_endpoint->bEndpointAddress);
#ifdef KERNEL_2_5
	interval = context->tx_endpoint->bInterval;
#endif	/* Use 0 for 2.4 kernels */

	usb_fill_int_urb(context->tx_urb, context->dev, pipe,
		context->usb_tx_buf, sizeof(context->usb_tx_buf),
		usb_tx_callback, context, interval);

	context->tx_urb->actual_length = 0;

	init_completion(&context->tx.finished);
	atomic_set(&(context->tx.busy), 1);

#ifdef KERNEL_2_5
	retval =  usb_submit_urb(context->tx_urb, GFP_KERNEL);
#else
	retval =  usb_submit_urb(context->tx_urb);
#endif
	if (retval) {
		atomic_set(&(context->tx.busy), 0);
		err("%s: error submitting urb (%d)", __func__, retval);
	} else {
		/* Wait for transmission to complete (or abort) */
		mutex_unlock(&context->lock);
		wait_for_completion(&context->tx.finished);
		mutex_lock(&context->lock);

		retval = context->tx.status;
		if (retval)
			err("%s: packet tx failed (%d)", __func__, retval);
	}

	return retval;
}

/**
 * Writes data to the VFD.  The Sasem VFD is 2x16 characters
 * and requires data in 9 consecutive USB interrupt packets,
 * each packet carrying 8 bytes.
 */
static ssize_t vfd_write(struct file *file, const char *buf,
				size_t n_bytes, loff_t *pos)
{
	int i;
	int retval = 0;
	struct sasem_context *context;

	context = (struct sasem_context *) file->private_data;
	if (!context) {
		err("%s: no context for device", __func__);
		return -ENODEV;
	}

	mutex_lock(&context->lock);

	if (!context->dev_present) {
		err("%s: no Sasem device present", __func__);
		retval = -ENODEV;
		goto exit;
	}

	if (n_bytes <= 0 || n_bytes > 32) {
		err("%s: invalid payload size", __func__);
		retval = -EINVAL;
		goto exit;
	}

	retval = copy_from_user(context->tx.data_buf, buf, n_bytes);
	if (retval < 0)
		goto exit;

	/* Pad with spaces */
	for (i = n_bytes; i < 32; ++i)
		context->tx.data_buf[i] = ' ';

	/* Nine 8 byte packets to be sent */
	/* NOTE: "\x07\x01\0\0\0\0\0\0" or "\x0c\0\0\0\0\0\0\0"
	 *       will clear the VFD */
	for (i = 0; i < 9; i++) {
		switch (i) {
		case 0:
			memcpy(context->usb_tx_buf, "\x07\0\0\0\0\0\0\0", 8);
			context->usb_tx_buf[1] = (context->vfd_contrast) ?
				(0x2B - (context->vfd_contrast - 1) / 250)
				: 0x2B;
			break;
		case 1:
			memcpy(context->usb_tx_buf, "\x09\x01\0\0\0\0\0\0", 8);
			break;
		case 2:
			memcpy(context->usb_tx_buf, "\x0b\x01\0\0\0\0\0\0", 8);
			break;
		case 3:
			memcpy(context->usb_tx_buf, context->tx.data_buf, 8);
			break;
		case 4:
			memcpy(context->usb_tx_buf,
			       context->tx.data_buf + 8, 8);
			break;
		case 5:
			memcpy(context->usb_tx_buf, "\x09\x01\0\0\0\0\0\0", 8);
			break;
		case 6:
			memcpy(context->usb_tx_buf, "\x0b\x02\0\0\0\0\0\0", 8);
			break;
		case 7:
			memcpy(context->usb_tx_buf,
			       context->tx.data_buf + 16, 8);
			break;
		case 8:
			memcpy(context->usb_tx_buf,
			       context->tx.data_buf + 24, 8);
			break;
		}
		retval = send_packet(context);
		if (retval) {

			err("%s: send packet failed for packet #%d",
					__func__, i);
			goto exit;
		}
	}
exit:

	mutex_unlock(&context->lock);

	return (!retval) ? n_bytes : retval;
}

/**
 * Callback function for USB core API: transmit data
 */
#if defined(KERNEL_2_5) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void usb_tx_callback(struct urb *urb, struct pt_regs *regs)
#else
static void usb_tx_callback(struct urb *urb)
#endif
{
	struct sasem_context *context;

	if (!urb)
		return;
	context = (struct sasem_context *) urb->context;
	if (!context)
		return;

	context->tx.status = urb->status;

	/* notify waiters that write has finished */
	atomic_set(&context->tx.busy, 0);
	complete(&context->tx.finished);

	return;
}

/**
 * Called by lirc_dev when the application opens /dev/lirc
 */
static int ir_open(void *data)
{
	int retval = 0;
	struct sasem_context *context;

	/* prevent races with disconnect */
	mutex_lock(&disconnect_lock);

	context = (struct sasem_context *) data;

	mutex_lock(&context->lock);

	if (context->ir_isopen) {
		err("%s: IR port is already open", __func__);
		retval = -EBUSY;
		goto exit;
	}

	usb_fill_int_urb(context->rx_urb, context->dev,
		usb_rcvintpipe(context->dev,
				context->rx_endpoint->bEndpointAddress),
		context->usb_rx_buf, sizeof(context->usb_rx_buf),
		usb_rx_callback, context, context->rx_endpoint->bInterval);

#ifdef KERNEL_2_5
	retval = usb_submit_urb(context->rx_urb, GFP_KERNEL);
#else
	retval = usb_submit_urb(context->rx_urb);
#endif

	if (retval)
		err("%s: usb_submit_urb failed for ir_open (%d)",
		    __func__, retval);
	else {
		MOD_INC_USE_COUNT;
		context->ir_isopen = 1;
		printk(KERN_INFO "IR port opened\n");
	}

exit:
	mutex_unlock(&context->lock);

	mutex_unlock(&disconnect_lock);
	return 0;
}

/**
 * Called by lirc_dev when the application closes /dev/lirc
 */
static void ir_close(void *data)
{
	struct sasem_context *context;

	context = (struct sasem_context *)data;
	if (!context) {
		err("%s: no context for device", __func__);
		return;
	}

	mutex_lock(&context->lock);

	usb_kill_urb(context->rx_urb);
	context->ir_isopen = 0;
	MOD_DEC_USE_COUNT;
	printk(KERN_INFO "IR port closed\n");

	if (!context->dev_present) {

		/*
		 * Device disconnected while IR port was
		 * still open. Driver was not deregistered
		 * at disconnect time, so do it now.
		 */
		deregister_from_lirc(context);

		if (!context->vfd_isopen) {

			mutex_unlock(&context->lock);
			delete_context(context);
			return;
		}
		/* If VFD port is open, context will be deleted by vfd_close */
	}

	mutex_unlock(&context->lock);
	return;
}

/**
 * Process the incoming packet
 */
static void incoming_packet(struct sasem_context *context,
				   struct urb *urb)
{
	int len = urb->actual_length;
	unsigned char *buf = urb->transfer_buffer;
	long ms;
	struct timeval tv;

	if (len != 8) {
		printk(KERN_WARNING "%s: invalid incoming packet size (%d)\n",
		     __func__, len);
		return;
	}

#ifdef DEBUG
	int i;
	for (i = 0; i < 8; ++i)
		printk(KERN_INFO "%02x ", buf [i]);
	printk(KERN_INFO "\n");
#endif

	/*
	 * Lirc could deal with the repeat code, but we really need to block it
	 * if it arrives too late.  Otherwise we could repeat the wrong code.
	 */

	/* get the time since the last button press */
	do_gettimeofday(&tv);
	ms = (tv.tv_sec - context->presstime.tv_sec) * 1000 +
	     (tv.tv_usec - context->presstime.tv_usec) / 1000;

	if (memcmp(buf, "\x08\0\0\0\0\0\0\0", 8) == 0) {
		/*
		 * the repeat code is being sent, so we copy
		 * the old code to LIRC
		 */

		/*
		 * NOTE: Only if the last code was less than 250ms ago
		 * - no one should be able to push another (undetected) button
		 *   in that time and then get a false repeat of the previous
		 *   press but it is long enough for a genuine repeat
		 */
		if ((ms < 250) && (context->codesaved != 0)) {
			memcpy(buf, &context->lastcode, 8);
			context->presstime.tv_sec = tv.tv_sec;
			context->presstime.tv_usec = tv.tv_usec;
		}
	} else {
		/* save the current valid code for repeats */
		memcpy(&context->lastcode, buf, 8);
		/*
		 * set flag to signal a valid code was save;
		 * just for safety reasons
		 */
		context->codesaved = 1;
		context->presstime.tv_sec = tv.tv_sec;
		context->presstime.tv_usec = tv.tv_usec;
	}

	lirc_buffer_write(context->driver->rbuf, buf);
	wake_up(&context->driver->rbuf->wait_poll);
}

/**
 * Callback function for USB core API: receive data
 */
#if defined(KERNEL_2_5) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void usb_rx_callback(struct urb *urb, struct pt_regs *regs)
#else
static void usb_rx_callback(struct urb *urb)
#endif
{
	struct sasem_context *context;

	if (!urb)
		return;
	context = (struct sasem_context *) urb->context;
	if (!context)
		return;

	switch (urb->status) {

	case -ENOENT: 		/* usbcore unlink successful! */
		return;

	case 0:
		if (context->ir_isopen)
			incoming_packet(context, urb);
		break;

	default:
		printk(KERN_WARNING "%s: status (%d): ignored\n",
		       __func__, urb->status);
		break;
	}

#ifdef KERNEL_2_5
	usb_submit_urb(context->rx_urb, GFP_ATOMIC);
#endif
	return;
}



/**
 * Callback function for USB core API: Probe
 */
#ifdef KERNEL_2_5
static int sasem_probe(struct usb_interface *interface,
			const struct usb_device_id *id)
#else
static void *sasem_probe(struct usb_device *dev, unsigned int intf,
			const struct usb_device_id *id)
#endif
{
#ifdef KERNEL_2_5
	struct usb_device *dev = NULL;
	struct usb_host_interface *iface_desc = NULL;
#else
	struct usb_interface *interface = NULL;
	struct usb_interface_descriptor *iface_desc = NULL;
	char name [10];
	int subminor = 0;
#endif
	struct usb_endpoint_descriptor *rx_endpoint = NULL;
	struct usb_endpoint_descriptor *tx_endpoint = NULL;
	struct urb *rx_urb = NULL;
	struct urb *tx_urb = NULL;
	struct lirc_driver *driver = NULL;
	struct lirc_buffer *rbuf = NULL;
	int lirc_minor = 0;
	int num_endpoints;
	int retval = 0;
	int vfd_ep_found;
	int ir_ep_found;
	int alloc_status;
	struct sasem_context *context = NULL;
	int i;

	printk(KERN_INFO "%s: found Sasem device\n", __func__);

#if !defined(KERNEL_2_5)
	for (subminor = 0; subminor < MAX_DEVICES; ++subminor) {
		if (minor_table [subminor] == NULL)
			break;
	}
	if (subminor == MAX_DEVICES) {
		err("%s: allowed number of devices already present",
		    __func__);
		retval = -ENOMEM;
		goto exit;
	}
#endif

#ifdef KERNEL_2_5
	dev = usb_get_dev(interface_to_usbdev(interface));
	iface_desc = interface->cur_altsetting;
	num_endpoints = iface_desc->desc.bNumEndpoints;
#else
	interface = &dev->actconfig->interface [intf];
	iface_desc = &interface->altsetting [interface->act_altsetting];
	num_endpoints = iface_desc->bNumEndpoints;
#endif

	/*
	 * Scan the endpoint list and set:
	 *	first input endpoint = IR endpoint
	 *	first output endpoint = VFD endpoint
	 */

	ir_ep_found = 0;
	vfd_ep_found = 0;

	for (i = 0; i < num_endpoints && !(ir_ep_found && vfd_ep_found); ++i) {

		struct usb_endpoint_descriptor *ep;
		int ep_dir;
		int ep_type;
#ifdef KERNEL_2_5
		ep = &iface_desc->endpoint [i].desc;
#else
		ep = &iface_desc->endpoint [i];
#endif
		ep_dir = ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK;
		ep_type = ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;

		if (!ir_ep_found &&
			ep_dir == USB_DIR_IN &&
			ep_type == USB_ENDPOINT_XFER_INT) {

			rx_endpoint = ep;
			ir_ep_found = 1;
			if (debug)
				printk(KERN_INFO "%s: found IR endpoint\n",
				       __func__);

		} else if (!vfd_ep_found &&
			ep_dir == USB_DIR_OUT &&
			ep_type == USB_ENDPOINT_XFER_INT) {

			tx_endpoint = ep;
			vfd_ep_found = 1;
			if (debug)
				printk(KERN_INFO "%s: found VFD endpoint\n",
				       __func__);
		}
	}

	/* Input endpoint is mandatory */
	if (!ir_ep_found) {

		err("%s: no valid input (IR) endpoint found.", __func__);
		retval = -ENODEV;
		goto exit;
	}

	if (!vfd_ep_found)
		printk(KERN_INFO "%s: no valid output (VFD) endpoint found.\n",
		       __func__);


	/* Allocate memory */
	alloc_status = 0;

	context = kzalloc(sizeof(struct sasem_context), GFP_KERNEL);
	if (!context) {
		err("%s: kzalloc failed for context", __func__);
		alloc_status = 1;
		goto alloc_status_switch;
	}
	driver = kzalloc(sizeof(struct lirc_driver), GFP_KERNEL);
	if (!driver) {
		err("%s: kzalloc failed for lirc_driver", __func__);
		alloc_status = 2;
		goto alloc_status_switch;
	}
	rbuf = kmalloc(sizeof(struct lirc_buffer), GFP_KERNEL);
	if (!rbuf) {
		err("%s: kmalloc failed for lirc_buffer", __func__);
		alloc_status = 3;
		goto alloc_status_switch;
	}
	if (lirc_buffer_init(rbuf, BUF_CHUNK_SIZE, BUF_SIZE)) {
		err("%s: lirc_buffer_init failed", __func__);
		alloc_status = 4;
		goto alloc_status_switch;
	}
#ifdef KERNEL_2_5
	rx_urb = usb_alloc_urb(0, GFP_KERNEL);
#else
	rx_urb = usb_alloc_urb(0);
#endif
	if (!rx_urb) {
		err("%s: usb_alloc_urb failed for IR urb", __func__);
		alloc_status = 5;
		goto alloc_status_switch;
	}
	if (vfd_ep_found) {
#ifdef KERNEL_2_5
		tx_urb = usb_alloc_urb(0, GFP_KERNEL);
#else
		tx_urb = usb_alloc_urb(0);
#endif
		if (!tx_urb) {
			err("%s: usb_alloc_urb failed for VFD urb", __func__);
			alloc_status = 6;
			goto alloc_status_switch;
		}
	}

	mutex_init(&context->lock);

	strcpy(driver->name, MOD_NAME);
	driver->minor = -1;
	driver->code_length = 64;
	driver->sample_rate = 0;
	driver->features = LIRC_CAN_REC_LIRCCODE;
	driver->data = context;
	driver->rbuf = rbuf;
	driver->set_use_inc = ir_open;
	driver->set_use_dec = ir_close;
#ifdef LIRC_HAVE_SYSFS
	driver->dev   = &interface->dev;
#endif
	driver->owner = THIS_MODULE;

	mutex_lock(&context->lock);

	lirc_minor = lirc_register_driver(driver);
	if (lirc_minor < 0) {
		err("%s: lirc_register_driver failed", __func__);
		alloc_status = 7;
		mutex_unlock(&context->lock);
	} else
		printk(KERN_INFO "%s: Registered Sasem driver (minor:%d)\n",
			__func__, lirc_minor);

alloc_status_switch:

	switch (alloc_status) {

	case 7:
		if (vfd_ep_found)
			usb_free_urb(tx_urb);
	case 6:
		usb_free_urb(rx_urb);
	case 5:
		lirc_buffer_free(rbuf);
	case 4:
		kfree(rbuf);
	case 3:
		kfree(driver);
	case 2:
		kfree(context);
		context = NULL;
	case 1:
		retval = -ENOMEM;
		goto exit;
	}

	/* Needed while unregistering! */
	driver->minor = lirc_minor;

	context->dev = dev;
	context->dev_present = 1;
	context->rx_endpoint = rx_endpoint;
	context->rx_urb = rx_urb;
	if (vfd_ep_found) {
		context->tx_endpoint = tx_endpoint;
		context->tx_urb = tx_urb;
		context->vfd_contrast = 1000;   /* range 0 - 1000 */
	}
	context->driver = driver;

#ifdef KERNEL_2_5
	usb_set_intfdata(interface, context);
#else
	minor_table [subminor] = context;
	context->subminor = subminor;
#endif

	if (vfd_ep_found) {

#ifdef KERNEL_2_5
		if (debug)
			printk(KERN_INFO "Registering VFD with sysfs\n");
		if (usb_register_dev(interface, &sasem_class))
			/* Not a fatal error, so ignore */
			printk(KERN_INFO "%s: could not get a minor number "
			       "for VFD\n", __func__);
#else
		if (debug)
			printk(KERN_INFO "Registering VFD with devfs\n");
		sprintf(name, DEVFS_NAME, subminor);
		context->devfs = devfs_register(usb_devfs_handle, name,
				 DEVFS_FL_DEFAULT,
				 USB_MAJOR, VFD_MINOR_BASE + subminor,
				 DEVFS_MODE, &vfd_fops, NULL);
		if (!context->devfs)
			/* not a fatal error so ignore */
			printk(KERN_INFO "%s: devfs register failed for VFD\n",
					__func__);
#endif
	}

	printk(KERN_INFO "%s: Sasem device on usb<%d:%d> initialized\n",
			__func__, dev->bus->busnum, dev->devnum);

	mutex_unlock(&context->lock);
exit:
#ifdef KERNEL_2_5
	return retval;
#else
	return (!retval) ? context : NULL;
#endif
}

/**
 * Callback function for USB core API: disonnect
 */
#ifdef KERNEL_2_5
static void sasem_disconnect(struct usb_interface *interface)
#else
static void sasem_disconnect(struct usb_device *dev, void *data)
#endif
{
	struct sasem_context *context;

	/* prevent races with ir_open()/vfd_open() */
	mutex_lock(&disconnect_lock);

#ifdef KERNEL_2_5
	context = usb_get_intfdata(interface);
#else
	context = (struct sasem_context *)data;
#endif
	mutex_lock(&context->lock);

	printk(KERN_INFO "%s: Sasem device disconnected\n", __func__);

#ifdef KERNEL_2_5
	usb_set_intfdata(interface, NULL);
#else
	minor_table [context->subminor] = NULL;
#endif
	context->dev_present = 0;

	/* Stop reception */
	usb_kill_urb(context->rx_urb);

	/* Abort ongoing write */
	if (atomic_read(&context->tx.busy)) {

		usb_kill_urb(context->tx_urb);
		wait_for_completion(&context->tx.finished);
	}

	/* De-register from lirc_dev if IR port is not open */
	if (!context->ir_isopen)
		deregister_from_lirc(context);

#ifdef KERNEL_2_5
	usb_deregister_dev(interface, &sasem_class);
#else
	if (context->devfs)
		devfs_unregister(context->devfs);
#endif

	mutex_unlock(&context->lock);

	if (!context->ir_isopen && !context->vfd_isopen)
		delete_context(context);

	mutex_unlock(&disconnect_lock);
}

static int __init sasem_init(void)
{
	int rc;

	printk(KERN_INFO MOD_DESC ", v" MOD_VERSION "\n");
	printk(KERN_INFO MOD_AUTHOR "\n");

	rc = usb_register(&sasem_driver);
	if (rc < 0) {
		err("%s: usb register failed (%d)", __func__, rc);
		return -ENODEV;
	}
	return 0;
}

static void __exit sasem_exit(void)
{
	usb_deregister(&sasem_driver);
	printk(KERN_INFO "module removed. Goodbye!\n");
}


module_init(sasem_init);
module_exit(sasem_exit);

#if !defined(KERNEL_2_5)
EXPORT_NO_SYMBOLS;
#endif
