/*
 * lirc_igorplugusb - USB remote support for LIRC
 *
 * Supports the standard homebrew IgorPlugUSB receiver with Igor's firmware.
 * See http://www.cesko.host.sk/IgorPlugUSB/IgorPlug-USB%20(AVR)_eng.htm
 *
 * The device can only record bursts of up to 36 pulses/spaces.
 * Works fine with RC5. Longer commands lead to device buffer overrun.
 * (Maybe a better firmware or a microcontroller with more ram can help?)
 *
 * Version 0.1  [beta status]
 *
 * Copyright (C) 2004 Jan M. Hochstein
 *	<hochstein@algo.informatik.tu-darmstadt.de>
 *
 * This driver was derived from:
 *   Paul Miller <pmiller9@users.sourceforge.net>
 *      "lirc_atiusb" module
 *   Vladimir Dergachev <volodya@minspring.com>'s 2002
 *      "USB ATI Remote support" (input device)
 *   Adrian Dewhurst <sailor-lk@sailorfrag.net>'s 2002
 *      "USB StreamZap remote driver" (LIRC)
 *   Artur Lipowski <alipowski@kki.net.pl>'s 2002
 *      "lirc_dev" and "lirc_gpio" LIRC modules
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 0)
#error "*******************************************************"
#error "Sorry, this driver needs kernel version 2.4.0 or higher"
#error "*******************************************************"
#endif

#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/usb.h>
#include <linux/poll.h>
#include <linux/smp_lock.h>
#include <linux/time.h>

#include "../kcompat.h"
#include "../lirc.h"
#include "../lirc_dev/lirc_dev.h"

#if !defined(KERNEL_2_5)
#define USB_CTRL_GET_TIMEOUT    5
#endif

/* module identification */
#define DRIVER_VERSION		"0.2"
#define DRIVER_AUTHOR		\
	"Jan M. Hochstein <hochstein@algo.informatik.tu-darmstadt.de>"
#define DRIVER_DESC		"USB remote driver for LIRC"
#define DRIVER_NAME		"lirc_igorplugusb"

/* debugging support */
#ifdef CONFIG_USB_DEBUG
static int debug = 1;
#else
static int debug;
#endif

#define dprintk(fmt, args...)					\
	do {							\
		if (debug)					\
			printk(KERN_DEBUG DRIVER_NAME fmt, ## args);	\
	} while (0)

/* One mode2 pulse/space has 4 bytes. */
#define CODE_LENGTH	     sizeof(lirc_t)

/* Igor's firmware cannot record bursts longer than 36. */
#define DEVICE_BUFLEN	   36

/*
 * Header at the beginning of the device's buffer:
 *	unsigned char data_length
 *	unsigned char data_start    (!=0 means ring-buffer overrun)
 *	unsigned char counter       (incremented by each burst)
 */
#define DEVICE_HEADERLEN	3

/* This is for the gap */
#define ADDITIONAL_LIRC_BYTES   2

/* times to poll per second */
#define SAMPLE_RATE	     100
static int sample_rate = SAMPLE_RATE;


/**** Igor's USB Request Codes */

#define SET_INFRABUFFER_EMPTY   1
/**
 * Params: none
 * Answer: empty
 */

#define GET_INFRACODE	   2
/**
 * Params:
 *   wValue: offset to begin reading infra buffer
 *
 * Answer: infra data
 */

#define SET_DATAPORT_DIRECTION  3
/**
 * Params:
 *   wValue: (byte) 1 bit for each data port pin (0=in, 1=out)
 *
 * Answer: empty
 */

#define GET_DATAPORT_DIRECTION  4
/**
 * Params: none
 *
 * Answer: (byte) 1 bit for each data port pin (0=in, 1=out)
 */

#define SET_OUT_DATAPORT	5
/**
 * Params:
 *   wValue: byte to write to output data port
 *
 * Answer: empty
 */

#define GET_OUT_DATAPORT	6
/**
 * Params: none
 *
 * Answer: least significant 3 bits read from output data port
 */

#define GET_IN_DATAPORT	 7
/**
 * Params: none
 *
 * Answer: least significant 3 bits read from input data port
 */

#define READ_EEPROM	     8
/**
 * Params:
 *   wValue: offset to begin reading EEPROM
 *
 * Answer: EEPROM bytes
 */

#define WRITE_EEPROM	    9
/**
 * Params:
 *   wValue: offset to EEPROM byte
 *   wIndex: byte to write
 *
 * Answer: empty
 */

#define SEND_RS232	      10
/**
 * Params:
 *   wValue: byte to send
 *
 * Answer: empty
 */

#define RECV_RS232	      11
/**
 * Params: none
 *
 * Answer: byte received
 */

#define SET_RS232_BAUD	  12
/**
 * Params:
 *   wValue: byte to write to UART bit rate register (UBRR)
 *
 * Answer: empty
 */

#define GET_RS232_BAUD	  13
/**
 * Params: none
 *
 * Answer: byte read from UART bit rate register (UBRR)
 */


/* data structure for each usb remote */
struct igorplug {

	/* usb */
	struct usb_device *usbdev;
	struct urb *urb_in;
	int devnum;

	unsigned char *buf_in;
	unsigned int len_in;
	int in_space;
	struct timeval last_time;

#if defined(KERNEL_2_5)
	dma_addr_t dma_in;
#endif

	/* lirc */
	struct lirc_driver *d;

	/* handle sending (init strings) */
	int send_flags;
};

static int set_use_inc(void *data)
{
	struct igorplug *ir = data;

	if (!ir) {
		printk(KERN_ERR DRIVER_NAME
		       "[?]: set_use_inc called with no context\n");
		return -EIO;
	}
	dprintk("[%d]: set use inc\n", ir->devnum);

	MOD_INC_USE_COUNT;

	if (!ir->usbdev)
		return -ENODEV;

	return 0;
}

static void set_use_dec(void *data)
{
	struct igorplug *ir = data;

	if (!ir) {
		printk(KERN_ERR DRIVER_NAME
		       "[?]: set_use_dec called with no context\n");
		return;
	}
	dprintk("[%d]: set use dec\n", ir->devnum);

	MOD_DEC_USE_COUNT;
}

static void send_fragment(struct igorplug *ir, struct lirc_buffer *buf,
			   int i, int max)
{
	/* MODE2: pulse/space (PULSE_BIT) in 1us units */
	while (i < max) {
		/* 1 Igor-tick = 85.333333 us */
		lirc_t code = (unsigned int)ir->buf_in[i] * 85 +
			(unsigned int)ir->buf_in[i] / 3;
		ir->last_time.tv_usec += code;
		if (ir->in_space)
			code |= PULSE_BIT;
		lirc_buffer_write_n(buf, (unsigned char *)&code, 1);
		/* 1 chunk = CODE_LENGTH bytes */
		ir->in_space ^= 1;
		++i;
	}
}

/**
 * Called in user context.
 * return 0 if data was added to the buffer and
 * -ENODATA if none was available. This should add some number of bits
 * evenly divisible by code_length to the buffer
 */
static int usb_remote_poll(void *data, struct lirc_buffer *buf)
{
	int ret;
	struct igorplug *ir = (struct igorplug *)data;

	if (!ir->usbdev)  /* Has the device been removed? */
		return -ENODEV;

	memset(ir->buf_in, 0, ir->len_in);

	ret = usb_control_msg(
	      ir->usbdev, usb_rcvctrlpipe(ir->usbdev, 0),
	      GET_INFRACODE, USB_TYPE_VENDOR|USB_DIR_IN,
	      0/* offset */, /*unused*/0,
	      ir->buf_in, ir->len_in,
	      /*timeout*/HZ * USB_CTRL_GET_TIMEOUT);
	if (ret > 0) {
		lirc_t code, timediff;
		struct timeval now;

		/* ACK packet has 1 byte --> ignore */
		if (ret < DEVICE_HEADERLEN)
			return -ENODATA;

		dprintk(": Got %d bytes. Header: %02x %02x %02x\n",
			ret, ir->buf_in[0], ir->buf_in[1], ir->buf_in[2]);

		do_gettimeofday(&now);
		timediff = now.tv_sec - ir->last_time.tv_sec;
		if (timediff + 1 > PULSE_MASK / 1000000)
			timediff = PULSE_MASK;
		else {
			timediff *= 1000000;
			timediff += now.tv_usec - ir->last_time.tv_usec;
		}
		ir->last_time.tv_sec = now.tv_sec;
		ir->last_time.tv_usec = now.tv_usec;

		/* create leading gap  */
		code = timediff;
		lirc_buffer_write(buf, (unsigned char *)&code);
		ir->in_space = 1;   /* next comes a pulse */

		if (ir->buf_in[2] == 0)
			send_fragment(ir, buf, DEVICE_HEADERLEN, ret);
		else {
			printk(KERN_WARNING DRIVER_NAME
			       "[%d]: Device buffer overrun.\n", ir->devnum);
			/* HHHNNNNNNNNNNNOOOOOOOO H = header
			      <---[2]--->         N = newer
			   <---------ret--------> O = older */
			ir->buf_in[2] %= ret - DEVICE_HEADERLEN; /* sanitize */
			/* keep even-ness to not desync pulse/pause */
			send_fragment(ir, buf, DEVICE_HEADERLEN +
				      ir->buf_in[2] - (ir->buf_in[2] & 1),
				      ret);
			send_fragment(ir, buf, DEVICE_HEADERLEN,
				      DEVICE_HEADERLEN + ir->buf_in[2]);
		}

		ret = usb_control_msg(
		      ir->usbdev, usb_rcvctrlpipe(ir->usbdev, 0),
		      SET_INFRABUFFER_EMPTY, USB_TYPE_VENDOR|USB_DIR_IN,
		      /*unused*/0, /*unused*/0,
		      /*dummy*/ir->buf_in, /*dummy*/ir->len_in,
		      /*timeout*/HZ * USB_CTRL_GET_TIMEOUT);
		if (ret < 0)
			printk(KERN_WARNING DRIVER_NAME
			       "[%d]: SET_INFRABUFFER_EMPTY: error %d\n",
			       ir->devnum, ret);
		return 0;
	} else
		printk(KERN_WARNING DRIVER_NAME
		       "[%d]: GET_INFRACODE: error %d\n",
			ir->devnum, ret);

	return -ENODATA;
}



#if defined(KERNEL_2_5)
static int usb_remote_probe(struct usb_interface *intf,
				const struct usb_device_id *id)
{
	struct usb_device *dev = NULL;
	struct usb_host_interface *idesc = NULL;
	struct usb_host_endpoint *ep_ctl2;
#else
static void *usb_remote_probe(struct usb_device *dev, unsigned int ifnum,
				const struct usb_device_id *id)
{
	struct usb_interface *intf;
	struct usb_interface_descriptor *idesc;
	struct usb_endpoint_descriptor *ep_ctl2;
#endif
	struct igorplug *ir = NULL;
	struct lirc_driver *driver = NULL;
	int devnum, pipe, maxp;
	int minor = 0;
	char buf[63], name[128] = "";
	int mem_failure = 0;
	int ret;

	dprintk(": usb probe called.\n");

#if defined(KERNEL_2_5)
	dev = interface_to_usbdev(intf);

#  if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 5)
	idesc = &intf->altsetting[intf->act_altsetting];  /* in 2.6.4 */
#  else
	idesc = intf->cur_altsetting;  /* in 2.6.6 */
#  endif

	if (idesc->desc.bNumEndpoints != 1)
		return -ENODEV;
	ep_ctl2 = idesc->endpoint;
	if (((ep_ctl2->desc.bEndpointAddress & USB_ENDPOINT_DIR_MASK)
	    != USB_DIR_IN)
	    || (ep_ctl2->desc.bmAttributes & USB_ENDPOINT_XFERTYPE_MASK)
	    != USB_ENDPOINT_XFER_CONTROL)
		return -ENODEV;
	pipe = usb_rcvctrlpipe(dev, ep_ctl2->desc.bEndpointAddress);
#else
	intf = &dev->actconfig->interface[ifnum];
	idesc = &intf->altsetting[intf->act_altsetting];
	if (idesc->bNumEndpoints != 1)
		return NULL;
	ep_ctl2 = idesc->endpoint;
	if (((ep_ctl2->bEndpointAddress & USB_ENDPOINT_DIR_MASK)
	    != USB_DIR_IN)
	    || (ep_ctl2->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK)
	    != USB_ENDPOINT_XFER_CONTROL)
		return NULL;
	pipe = usb_rcvctrlpipe(dev, ep_ctl2->bEndpointAddress);
#endif
	devnum = dev->devnum;
	maxp = usb_maxpacket(dev, pipe, usb_pipeout(pipe));

	dprintk(DRIVER_NAME "[%d]: bytes_in_key=%d maxp=%d\n",
		devnum, CODE_LENGTH, maxp);


	mem_failure = 0;
	ir = kzalloc(sizeof(struct igorplug), GFP_KERNEL);
	if (!ir) {
		mem_failure = 1;
		goto mem_failure_switch;
	}

	driver = kzalloc(sizeof(struct lirc_driver), GFP_KERNEL);
	if (!driver) {
		mem_failure = 2;
		goto mem_failure_switch;
	}

#if defined(KERNEL_2_5)
	ir->buf_in = usb_buffer_alloc(dev,
			      DEVICE_BUFLEN+DEVICE_HEADERLEN,
			      GFP_ATOMIC, &ir->dma_in);
#else
	ir->buf_in = kmalloc(DEVICE_BUFLEN+DEVICE_HEADERLEN,
			     GFP_KERNEL);
#endif
	if (!ir->buf_in) {
		mem_failure = 3;
		goto mem_failure_switch;
	}

	strcpy(driver->name, DRIVER_NAME " ");
	driver->minor = -1;
	driver->code_length = CODE_LENGTH * 8; /* in bits */
	driver->features = LIRC_CAN_REC_MODE2;
	driver->data = ir;
	driver->buffer_size = DEVICE_BUFLEN + ADDITIONAL_LIRC_BYTES;
	driver->set_use_inc = &set_use_inc;
	driver->set_use_dec = &set_use_dec;
	driver->sample_rate = sample_rate;    /* per second */
	driver->add_to_buf = &usb_remote_poll;
#ifdef LIRC_HAVE_SYSFS
	driver->dev = &intf->dev;
#endif
	driver->owner = THIS_MODULE;

	minor = lirc_register_driver(driver);
	if (minor < 0)
		mem_failure = 9;

mem_failure_switch:

	switch (mem_failure) {
	case 9:
#if defined(KERNEL_2_5)
		usb_buffer_free(dev, DEVICE_BUFLEN+DEVICE_HEADERLEN,
			ir->buf_in, ir->dma_in);
#else
		kfree(ir->buf_in);
#endif
	case 3:
		kfree(driver);
	case 2:
		kfree(ir);
	case 1:
		printk(KERN_ERR DRIVER_NAME "[%d]: out of memory (code=%d)\n",
			devnum, mem_failure);
#if defined(KERNEL_2_5)
		return -ENOMEM;
#else
		return NULL;
#endif
	}

	driver->minor = minor;
	ir->d = driver;
	ir->devnum = devnum;
	ir->usbdev = dev;
	ir->len_in = DEVICE_BUFLEN+DEVICE_HEADERLEN;
	ir->in_space = 1; /* First mode2 event is a space. */
	do_gettimeofday(&ir->last_time);

	if (dev->descriptor.iManufacturer
	    && usb_string(dev, dev->descriptor.iManufacturer,
			  buf, sizeof(buf)) > 0)
		strlcpy(name, buf, sizeof(name));
	if (dev->descriptor.iProduct
	    && usb_string(dev, dev->descriptor.iProduct, buf, sizeof(buf)) > 0)
		snprintf(name + strlen(name), sizeof(name) - strlen(name),
			 " %s", buf);
	printk(KERN_INFO DRIVER_NAME "[%d]: %s on usb%d:%d\n", devnum, name,
	       dev->bus->busnum, devnum);

	/* clear device buffer */
	ret = usb_control_msg(ir->usbdev, usb_rcvctrlpipe(ir->usbdev, 0),
		SET_INFRABUFFER_EMPTY, USB_TYPE_VENDOR|USB_DIR_IN,
		/*unused*/0, /*unused*/0,
		/*dummy*/ir->buf_in, /*dummy*/ir->len_in,
		/*timeout*/HZ * USB_CTRL_GET_TIMEOUT);
	if (ret < 0)
		printk(KERN_WARNING DRIVER_NAME
		       "[%d]: SET_INFRABUFFER_EMPTY: error %d\n",
			devnum, ret);

#if defined(KERNEL_2_5)
	usb_set_intfdata(intf, ir);
	return 0;
#else
	return ir;
#endif
}


#if defined(KERNEL_2_5)
static void usb_remote_disconnect(struct usb_interface *intf)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	struct igorplug *ir = usb_get_intfdata(intf);
#else
static void usb_remote_disconnect(struct usb_device *dev, void *ptr)
{
	struct igorplug *ir = ptr;
#endif

	if (!ir || !ir->d)
		return;

	printk(KERN_INFO DRIVER_NAME
	       "[%d]: usb remote disconnected\n", ir->devnum);

	lirc_unregister_driver(ir->d->minor);

	lirc_buffer_free(ir->d->rbuf);
	kfree(ir->d->rbuf);
	kfree(ir->d);


#if defined(KERNEL_2_5)
	usb_buffer_free(dev, ir->len_in, ir->buf_in, ir->dma_in);
#else
	kfree(ir->buf_in);
#endif

	kfree(ir);
}

static struct usb_device_id usb_remote_id_table [] = {
	/* Igor Plug USB (Atmel's Manufact. ID) */
	{ USB_DEVICE(0x03eb, 0x0002) },
	/* Fit PC2 Infrared Adapter */
	{ USB_DEVICE(0x03eb, 0x21fe) },

	/* Terminating entry */
	{ }
};

static struct usb_driver usb_remote_driver = {
	LIRC_THIS_MODULE(.owner = THIS_MODULE)
	.name =		DRIVER_NAME,
	.probe =	usb_remote_probe,
	.disconnect =	usb_remote_disconnect,
	.id_table =	usb_remote_id_table
};

static int __init usb_remote_init(void)
{
	int i;

	printk(KERN_INFO DRIVER_NAME ": " DRIVER_DESC " v" DRIVER_VERSION "\n");
	printk(KERN_INFO DRIVER_NAME ": " DRIVER_AUTHOR "\n");
	dprintk(": debug mode enabled\n");

	i = usb_register(&usb_remote_driver);
	if (i < 0) {
		printk(KERN_ERR DRIVER_NAME
		       ": usb register failed, result = %d\n", i);
		return -ENODEV;
	}

	return 0;
}

static void __exit usb_remote_exit(void)
{
	usb_deregister(&usb_remote_driver);
}

module_init(usb_remote_init);
module_exit(usb_remote_exit);

#if defined(KERNEL_2_5)
#include <linux/vermagic.h>
MODULE_INFO(vermagic, VERMAGIC_STRING);
#endif

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(usb, usb_remote_id_table);

module_param(sample_rate, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(sample_rate, "Sampling rate in Hz (default: 100)");

EXPORT_NO_SYMBOLS;
