/*      $Id: lirc_streamzap.c,v 1.48 2009/03/15 09:34:00 lirc Exp $      */
/*
 * Streamzap Remote Control driver
 *
 * Copyright (c) 2005 Christoph Bartelmus <lirc@bartelmus.de>
 *
 * This driver was based on the work of Greg Wickham and Adrian
 * Dewhurst. It was substantially rewritten to support correct signal
 * gaps and now maintains a delay buffer, which is used to present
 * consistent timing behaviour to user space applications. Without the
 * delay buffer an ugly hack would be required in lircd, which can
 * cause sluggish signal decoding in certain situations.
 *
 * This driver is based on the USB skeleton driver packaged with the
 * kernel; copyright (C) 2001-2003 Greg Kroah-Hartman (greg@kroah.com)
 *
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 0)
#error "*******************************************************"
#error "Sorry, this driver needs kernel version 2.4.0 or higher"
#error "*******************************************************"
#endif
#include <linux/autoconf.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/completion.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
#include <asm/uaccess.h>
#else
#include <linux/uaccess.h>
#endif
#include <linux/usb.h>

#include "../lirc.h"
#include "../kcompat.h"
#include "../lirc_dev/lirc_dev.h"

#define DRIVER_VERSION	"$Revision: 1.48 $"
#define DRIVER_NAME	"lirc_streamzap"
#define DRIVER_DESC	"Streamzap Remote Control driver"

static int debug;

#define USB_STREAMZAP_VENDOR_ID		0x0e9c
#define USB_STREAMZAP_PRODUCT_ID	0x0000

/* Use our own dbg macro */
#define dprintk(fmt, args...)					\
	do {							\
		if (debug)					\
			printk(KERN_DEBUG DRIVER_NAME "[%d]: "	\
			       fmt "\n", ## args);		\
	} while (0)

/* table of devices that work with this driver */
static struct usb_device_id streamzap_table[] = {
	/* Streamzap Remote Control */
	{ USB_DEVICE(USB_STREAMZAP_VENDOR_ID, USB_STREAMZAP_PRODUCT_ID) },
	/* Terminating entry */
	{ }
};

MODULE_DEVICE_TABLE(usb, streamzap_table);

#define STREAMZAP_PULSE_MASK 0xf0
#define STREAMZAP_SPACE_MASK 0x0f
#define STREAMZAP_RESOLUTION 256

/* number of samples buffered */
#define STREAMZAP_BUFFER_SIZE 128

enum StreamzapDecoderState {
	PulseSpace,
	FullPulse,
	FullSpace,
	IgnorePulse
};

/* Structure to hold all of our device specific stuff
 *
 * some remarks regarding locking:
 * theoretically this struct can be accessed from three threads:
 *
 * - from lirc_dev through set_use_inc/set_use_dec
 *
 * - from the USB layer throuh probe/disconnect/irq
 *
 *   Careful placement of lirc_register_driver/lirc_unregister_driver
 *   calls will prevent conflicts. lirc_dev makes sure that
 *   set_use_inc/set_use_dec are not being executed and will not be
 *   called after lirc_unregister_driver returns.
 *
 * - by the timer callback
 *
 *   The timer is only running when the device is connected and the
 *   LIRC device is open. Making sure the timer is deleted by
 *   set_use_dec will make conflicts impossible.
 */
struct usb_streamzap {

	/* usb */
	/* save off the usb device pointer */
	struct usb_device	*udev;
	/* the interface for this device */
	struct usb_interface	*interface;

	/* buffer & dma */
	unsigned char		*buf_in;
	dma_addr_t		dma_in;
	unsigned int		buf_in_len;

	struct usb_endpoint_descriptor *endpoint;

	/* IRQ */
	struct urb		*urb_in;

	/* lirc */
	struct lirc_driver	driver;
	struct lirc_buffer	delay_buf;
	struct lirc_buffer	lirc_buf;

	/* timer used to support delay buffering */
	struct timer_list	delay_timer;
	int			timer_running;
	spinlock_t		timer_lock;

	/* tracks whether we are currently receiving some signal */
	int			idle;
	/* sum of signal lengths received since signal start */
	unsigned long		sum;
	/* start time of signal; necessary for gap tracking */
	struct timeval		signal_last;
	struct timeval		signal_start;
	enum StreamzapDecoderState decoder_state;
	struct timer_list	flush_timer;
	int			flush;
	int			in_use;
};


/* local function prototypes */
#ifdef KERNEL_2_5
static int streamzap_probe(struct usb_interface *interface,
			   const struct usb_device_id *id);
static void streamzap_disconnect(struct usb_interface *interface);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void usb_streamzap_irq(struct urb *urb, struct pt_regs *regs);
#else
static void usb_streamzap_irq(struct urb *urb);
#endif
#else
static void *streamzap_probe(struct usb_device *udev, unsigned int ifnum,
			     const struct usb_device_id *id);
static void streamzap_disconnect(struct usb_device *dev, void *ptr);
static void usb_streamzap_irq(struct urb *urb);
#endif
static int streamzap_use_inc(void *data);
static void streamzap_use_dec(void *data);
static int streamzap_ioctl(struct inode *node, struct file *filep,
			   unsigned int cmd, unsigned long arg);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
static int streamzap_suspend(struct usb_interface *intf, pm_message_t message);
static int streamzap_resume(struct usb_interface *intf);
#endif

/* usb specific object needed to register this driver with the usb subsystem */

static struct usb_driver streamzap_driver = {
	LIRC_THIS_MODULE(.owner = THIS_MODULE)
	.name =		DRIVER_NAME,
	.probe =	streamzap_probe,
	.disconnect =	streamzap_disconnect,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	.suspend =	streamzap_suspend,
	.resume =	streamzap_resume,
#endif
	.id_table =	streamzap_table,
};

static void stop_timer(struct usb_streamzap *sz)
{
	unsigned long flags;

	spin_lock_irqsave(&sz->timer_lock, flags);
	if (sz->timer_running) {
		sz->timer_running = 0;
		spin_unlock_irqrestore(&sz->timer_lock, flags);
		del_timer_sync(&sz->delay_timer);
	} else {
		spin_unlock_irqrestore(&sz->timer_lock, flags);
	}
}

static void flush_timeout(unsigned long arg)
{
	struct usb_streamzap *sz = (struct usb_streamzap *) arg;

	/* finally start accepting data */
	sz->flush = 0;
}
static void delay_timeout(unsigned long arg)
{
	unsigned long flags;
	/* deliver data every 10 ms */
	static unsigned long timer_inc =
		(10000/(1000000/HZ)) == 0 ? 1 : (10000/(1000000/HZ));
	struct usb_streamzap *sz = (struct usb_streamzap *) arg;
	lirc_t data;

	spin_lock_irqsave(&sz->timer_lock, flags);

	if (!lirc_buffer_empty(&sz->delay_buf) &&
	    !lirc_buffer_full(&sz->lirc_buf)) {
		lirc_buffer_read(&sz->delay_buf, (unsigned char *) &data);
		lirc_buffer_write(&sz->lirc_buf, (unsigned char *) &data);
	}
	if (!lirc_buffer_empty(&sz->delay_buf)) {
		while (lirc_buffer_available(&sz->delay_buf) <
		      STREAMZAP_BUFFER_SIZE/2 &&
		      !lirc_buffer_full(&sz->lirc_buf)) {
			lirc_buffer_read(&sz->delay_buf,
					 (unsigned char *) &data);
			lirc_buffer_write(&sz->lirc_buf,
					  (unsigned char *) &data);
		}
		if (sz->timer_running) {
			sz->delay_timer.expires = jiffies + timer_inc;
			add_timer(&sz->delay_timer);
		}
	} else {
		sz->timer_running = 0;
	}

	if (!lirc_buffer_empty(&sz->lirc_buf))
		wake_up(&sz->lirc_buf.wait_poll);

	spin_unlock_irqrestore(&sz->timer_lock, flags);
}

static void flush_delay_buffer(struct usb_streamzap *sz)
{
	lirc_t data;
	int empty = 1;

	while (!lirc_buffer_empty(&sz->delay_buf)) {
		empty = 0;
		lirc_buffer_read(&sz->delay_buf, (unsigned char *) &data);
		if (!lirc_buffer_full(&sz->lirc_buf)) {
			lirc_buffer_write(&sz->lirc_buf,
					    (unsigned char *) &data);
		} else {
			dprintk("buffer overflow", sz->driver.minor);
		}
	}
	if (!empty)
		wake_up(&sz->lirc_buf.wait_poll);
}

static void push(struct usb_streamzap *sz, unsigned char *data)
{
	unsigned long flags;

	spin_lock_irqsave(&sz->timer_lock, flags);
	if (lirc_buffer_full(&sz->delay_buf)) {
		lirc_t data;

		lirc_buffer_read(&sz->delay_buf, (unsigned char *) &data);
		if (!lirc_buffer_full(&sz->lirc_buf)) {
			lirc_buffer_write(&sz->lirc_buf,
					  (unsigned char *) &data);
		} else {
			dprintk("buffer overflow", sz->driver.minor);
		}
	}

	lirc_buffer_write(&sz->delay_buf, data);

	if (!sz->timer_running) {
		sz->delay_timer.expires = jiffies + HZ/10;
		add_timer(&sz->delay_timer);
		sz->timer_running = 1;
	}

	spin_unlock_irqrestore(&sz->timer_lock, flags);
}

static void push_full_pulse(struct usb_streamzap *sz,
				   unsigned char value)
{
	lirc_t pulse;

	if (sz->idle) {
		long deltv;
		lirc_t tmp;

		sz->signal_last = sz->signal_start;
		do_gettimeofday(&sz->signal_start);

		deltv = sz->signal_start.tv_sec-sz->signal_last.tv_sec;
		if (deltv > 15) {
			tmp = PULSE_MASK; /* really long time */
		} else {
			tmp = (lirc_t) (deltv*1000000+
					sz->signal_start.tv_usec -
					sz->signal_last.tv_usec);
			tmp -= sz->sum;
		}
		dprintk("ls %u", sz->driver.minor, tmp);
		push(sz, (char *)&tmp);

		sz->idle = 0;
		sz->sum = 0;
	}

	pulse = ((lirc_t) value)*STREAMZAP_RESOLUTION;
	pulse += STREAMZAP_RESOLUTION/2;
	sz->sum += pulse;
	pulse |= PULSE_BIT;

	dprintk("p %u", sz->driver.minor, pulse&PULSE_MASK);
	push(sz, (char *)&pulse);
}

static void push_half_pulse(struct usb_streamzap *sz,
				   unsigned char value)
{
	push_full_pulse(sz, (value & STREAMZAP_PULSE_MASK)>>4);
}

static void push_full_space(struct usb_streamzap *sz,
				   unsigned char value)
{
	lirc_t space;

	space = ((lirc_t) value)*STREAMZAP_RESOLUTION;
	space += STREAMZAP_RESOLUTION/2;
	sz->sum += space;
	dprintk("s %u", sz->driver.minor, space);
	push(sz, (char *)&space);
}

static void push_half_space(struct usb_streamzap *sz,
				   unsigned char value)
{
	push_full_space(sz, value & STREAMZAP_SPACE_MASK);
}

/**
 * usb_streamzap_irq - IRQ handler
 *
 * This procedure is invoked on reception of data from
 * the usb remote.
 */
#if defined(KERNEL_2_5) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void usb_streamzap_irq(struct urb *urb, struct pt_regs *regs)
#else
static void usb_streamzap_irq(struct urb *urb)
#endif
{
	struct usb_streamzap *sz;
	int		len;
	unsigned int	i = 0;

	if (!urb)
		return;

	sz = urb->context;
	len = urb->actual_length;

	switch (urb->status) {
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/*
		 * this urb is terminated, clean up.
		 * sz might already be invalid at this point
		 */
		dprintk("urb status: %d", -1, urb->status);
		return;
	default:
		break;
	}

	dprintk("received %d", sz->driver.minor, urb->actual_length);
	if (!sz->flush) {
		for (i = 0; i < urb->actual_length; i++) {
			dprintk("%d: %x", sz->driver.minor,
				i, (unsigned char) sz->buf_in[i]);
			switch (sz->decoder_state) {
			case PulseSpace:
				if ((sz->buf_in[i]&STREAMZAP_PULSE_MASK) ==
				    STREAMZAP_PULSE_MASK) {
					sz->decoder_state = FullPulse;
					continue;
				} else if ((sz->buf_in[i]&STREAMZAP_SPACE_MASK)
					   == STREAMZAP_SPACE_MASK) {
					push_half_pulse(sz, sz->buf_in[i]);
					sz->decoder_state = FullSpace;
					continue;
				} else {
					push_half_pulse(sz, sz->buf_in[i]);
					push_half_space(sz, sz->buf_in[i]);
				}
				break;
			case FullPulse:
				push_full_pulse(sz, sz->buf_in[i]);
				sz->decoder_state = IgnorePulse;
				break;
			case FullSpace:
				if (sz->buf_in[i] == 0xff) {
					sz->idle = 1;
					stop_timer(sz);
					flush_delay_buffer(sz);
				} else
					push_full_space(sz, sz->buf_in[i]);
				sz->decoder_state = PulseSpace;
				break;
			case IgnorePulse:
				if ((sz->buf_in[i]&STREAMZAP_SPACE_MASK) ==
				    STREAMZAP_SPACE_MASK) {
					sz->decoder_state = FullSpace;
					continue;
				}
				push_half_space(sz, sz->buf_in[i]);
				sz->decoder_state = PulseSpace;
				break;
			}
		}
	}

#ifdef KERNEL_2_5
	usb_submit_urb(urb, GFP_ATOMIC);
#endif

	return;
}

static struct file_operations streamzap_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= streamzap_ioctl,
};


/**
 *	streamzap_probe
 *
 *	Called by usb-core to associated with a candidate device
 *	On any failure the return value is the ERROR
 *	On success return 0
 */
#ifdef KERNEL_2_5
static int streamzap_probe(struct usb_interface *interface,
			   const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(interface);
	struct usb_host_interface *iface_host;
#else
static void *streamzap_probe(struct usb_device *udev, unsigned int ifnum,
			     const struct usb_device_id *id)
{
	struct usb_interface *interface = &udev->actconfig->interface[ifnum];
	struct usb_interface_descriptor *iface_host;
#endif
	int retval = -ENOMEM;
	struct usb_streamzap *sz = NULL;
	char buf[63], name[128] = "";

	/* Allocate space for device driver specific data */
	sz = kzalloc(sizeof(struct usb_streamzap), GFP_KERNEL);
	if (sz == NULL)
		goto error;

	sz->udev = udev;
	sz->interface = interface;

	/* Check to ensure endpoint information matches requirements */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 5)
	iface_host = &interface->altsetting[interface->act_altsetting];
#else
	iface_host = interface->cur_altsetting;
#endif

#ifdef KERNEL_2_5
	if (iface_host->desc.bNumEndpoints != 1) {
#else
	if (iface_host->bNumEndpoints != 1) {
#endif
#ifdef KERNEL_2_5
		err("%s: Unexpected desc.bNumEndpoints (%d)", __func__,
		    iface_host->desc.bNumEndpoints);
#else
		err("%s: Unexpected desc.bNumEndpoints (%d)", __func__,
		    iface_host->bNumEndpoints);
#endif
		retval = -ENODEV;
		goto error;
	}

#ifdef KERNEL_2_5
	sz->endpoint = &(iface_host->endpoint[0].desc);
#else
	sz->endpoint = &(iface_host->endpoint[0]);
#endif
	if ((sz->endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK)
	    != USB_DIR_IN) {
		err("%s: endpoint doesn't match input device 02%02x",
		    __func__, sz->endpoint->bEndpointAddress);
		retval = -ENODEV;
		goto error;
	}

	if ((sz->endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK)
	    != USB_ENDPOINT_XFER_INT) {
		err("%s: endpoint attributes don't match xfer 02%02x",
		    __func__, sz->endpoint->bmAttributes);
		retval = -ENODEV;
		goto error;
	}

	if (sz->endpoint->wMaxPacketSize == 0) {
		err("%s: endpoint message size==0? ", __func__);
		retval = -ENODEV;
		goto error;
	}

	/* Allocate the USB buffer and IRQ URB */

	sz->buf_in_len = sz->endpoint->wMaxPacketSize;
#ifdef KERNEL_2_5
	sz->buf_in = usb_buffer_alloc(sz->udev, sz->buf_in_len,
				      GFP_ATOMIC, &sz->dma_in);
#else
	sz->buf_in = kmalloc(sz->buf_in_len, GFP_KERNEL);
#endif
	if (sz->buf_in == NULL)
		goto error;

#ifdef KERNEL_2_5
	sz->urb_in = usb_alloc_urb(0, GFP_KERNEL);
#else

	sz->urb_in = usb_alloc_urb(0);
#endif
	if (sz->urb_in == NULL)
		goto error;

	/* Connect this device to the LIRC sub-system */

	if (lirc_buffer_init(&sz->lirc_buf, sizeof(lirc_t),
			     STREAMZAP_BUFFER_SIZE))
		goto error;

	if (lirc_buffer_init(&sz->delay_buf, sizeof(lirc_t),
			     STREAMZAP_BUFFER_SIZE)) {
		lirc_buffer_free(&sz->lirc_buf);
		goto error;
	}

	strcpy(sz->driver.name, DRIVER_NAME);
	sz->driver.minor = -1;
	sz->driver.sample_rate = 0;
	sz->driver.code_length = sizeof(lirc_t) * 8;
	sz->driver.features = LIRC_CAN_REC_MODE2 | LIRC_CAN_GET_REC_RESOLUTION;
	sz->driver.data = sz;
	sz->driver.rbuf = &sz->lirc_buf;
	sz->driver.set_use_inc = &streamzap_use_inc;
	sz->driver.set_use_dec = &streamzap_use_dec;
	sz->driver.fops = &streamzap_fops;
#ifdef LIRC_HAVE_SYSFS
	sz->driver.dev = &interface->dev;
#endif
	sz->driver.owner = THIS_MODULE;

	sz->idle = 1;
	sz->decoder_state = PulseSpace;
	init_timer(&sz->delay_timer);
	sz->delay_timer.function = delay_timeout;
	sz->delay_timer.data = (unsigned long) sz;
	sz->timer_running = 0;
	spin_lock_init(&sz->timer_lock);

	init_timer(&sz->flush_timer);
	sz->flush_timer.function = flush_timeout;
	sz->flush_timer.data = (unsigned long) sz;
	/* Complete final initialisations */

	usb_fill_int_urb(sz->urb_in, udev,
		usb_rcvintpipe(udev, sz->endpoint->bEndpointAddress),
		sz->buf_in, sz->buf_in_len, usb_streamzap_irq, sz,
		sz->endpoint->bInterval);
#ifdef KERNEL_2_5
	sz->urb_in->transfer_dma = sz->dma_in;
	sz->urb_in->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
#endif

	if (udev->descriptor.iManufacturer
	    && usb_string(udev, udev->descriptor.iManufacturer,
			  buf, sizeof(buf)) > 0)
		strlcpy(name, buf, sizeof(name));

	if (udev->descriptor.iProduct
	    && usb_string(udev,  udev->descriptor.iProduct,
			  buf, sizeof(buf)) > 0)
		snprintf(name + strlen(name), sizeof(name) - strlen(name),
			 " %s", buf);

	printk(KERN_INFO DRIVER_NAME "[%d]: %s on usb%d:%d attached\n",
	       sz->driver.minor, name,
	       udev->bus->busnum, sz->udev->devnum);

#ifdef KERNEL_2_5
	usb_set_intfdata(interface, sz);
#endif

	if (lirc_register_driver(&sz->driver) < 0) {
		lirc_buffer_free(&sz->delay_buf);
		lirc_buffer_free(&sz->lirc_buf);
		goto error;
	}

#ifdef KERNEL_2_5
	return 0;
#else
	return sz;
#endif

error:

	/*
	 * Premise is that a 'goto error' can be invoked from inside the
	 * probe function and all necessary cleanup actions will be taken
	 * including freeing any necessary memory blocks
	 */

	if (retval == -ENOMEM)
		err("Out of memory");

	if (sz) {
		usb_free_urb(sz->urb_in);
#ifdef KERNEL_2_5
		usb_buffer_free(udev, sz->buf_in_len, sz->buf_in, sz->dma_in);
#else
		if (sz->buf_in) {
			kfree(sz->buf_in);
		}
#endif
		kfree(sz);
	}

#ifdef KERNEL_2_5
	return retval;
#else
	return NULL;
#endif
}

static int streamzap_use_inc(void *data)
{
	struct usb_streamzap *sz = data;

	if (!sz) {
		dprintk("%s called with no context", -1, __func__);
		return -EINVAL;
	}
	dprintk("set use inc", sz->driver.minor);
	MOD_INC_USE_COUNT;

	lirc_buffer_clear(&sz->lirc_buf);
	lirc_buffer_clear(&sz->delay_buf);

	sz->flush_timer.expires = jiffies + HZ;
	sz->flush = 1;
	add_timer(&sz->flush_timer);

	sz->urb_in->dev = sz->udev;
#ifdef KERNEL_2_5
	if (usb_submit_urb(sz->urb_in, GFP_ATOMIC)) {
#else
	if (usb_submit_urb(sz->urb_in)) {
#endif
		dprintk("open result = -EIO error submitting urb",
			sz->driver.minor);
		MOD_DEC_USE_COUNT;
		return -EIO;
	}
	sz->in_use++;

	return 0;
}

static void streamzap_use_dec(void *data)
{
	struct usb_streamzap *sz = data;

	if (!sz) {
		dprintk("%s called with no context", -1, __func__);
		return;
	}
	dprintk("set use dec", sz->driver.minor);

	if (sz->flush) {
		sz->flush = 0;
		del_timer_sync(&sz->flush_timer);
	}

	usb_kill_urb(sz->urb_in);

	stop_timer(sz);

	MOD_DEC_USE_COUNT;
	sz->in_use--;
}

static int streamzap_ioctl(struct inode *node, struct file *filep,
			   unsigned int cmd, unsigned long arg)
{
	int result;

	switch (cmd) {
	case LIRC_GET_REC_RESOLUTION:
		result = put_user(STREAMZAP_RESOLUTION, (unsigned int *) arg);
		if (result)
			return result;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return 0;
}

/**
 * streamzap_disconnect
 *
 * Called by the usb core when the device is removed from the system.
 *
 * This routine guarantees that the driver will not submit any more urbs
 * by clearing dev->udev.  It is also supposed to terminate any currently
 * active urbs.  Unfortunately, usb_bulk_msg(), used in streamzap_read(),
 * does not provide any way to do this.
 */
#ifdef KERNEL_2_5
static void streamzap_disconnect(struct usb_interface *interface)
#else
static void streamzap_disconnect(struct usb_device *dev, void *ptr)
#endif
{
	struct usb_streamzap *sz;
	int errnum;
	int minor;

#ifdef KERNEL_2_5
	sz = usb_get_intfdata(interface);
#else
	sz = ptr;
#endif

	/* unregister from the LIRC sub-system */

	errnum = lirc_unregister_driver(sz->driver.minor);
	if (errnum != 0)
		dprintk("error in lirc_unregister: (returned %d)",
			sz->driver.minor, errnum);

	lirc_buffer_free(&sz->delay_buf);
	lirc_buffer_free(&sz->lirc_buf);

	/* unregister from the USB sub-system */

	usb_free_urb(sz->urb_in);

#ifdef KERNEL_2_5
	usb_buffer_free(sz->udev, sz->buf_in_len, sz->buf_in, sz->dma_in);
#else
	kfree(sz->buf_in);
#endif

	minor = sz->driver.minor;
	kfree(sz);

	printk(KERN_INFO DRIVER_NAME "[%d]: disconnected\n", minor);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
static int streamzap_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usb_streamzap *sz = usb_get_intfdata(intf);

	printk(KERN_INFO DRIVER_NAME "[%d]: suspend\n", sz->driver.minor);
	if (sz->in_use) {
		if (sz->flush) {
			sz->flush = 0;
			del_timer_sync(&sz->flush_timer);
		}

		stop_timer(sz);

		usb_kill_urb(sz->urb_in);
	}
	return 0;
}

static int streamzap_resume(struct usb_interface *intf)
{
	struct usb_streamzap *sz = usb_get_intfdata(intf);

	lirc_buffer_clear(&sz->lirc_buf);
	lirc_buffer_clear(&sz->delay_buf);

	if (sz->in_use) {
		sz->flush_timer.expires = jiffies + HZ;
		sz->flush = 1;
		add_timer(&sz->flush_timer);

		sz->urb_in->dev = sz->udev;
#ifdef KERNEL_2_5
		if (usb_submit_urb(sz->urb_in, GFP_ATOMIC)) {
#else
		if (usb_submit_urb(sz->urb_in)) {
#endif
			dprintk("open result = -EIO error submitting urb",
				sz->driver.minor);
			MOD_DEC_USE_COUNT;
			return -EIO;
		}
	}
	return 0;
}
#endif

#ifdef MODULE
/**
 *	usb_streamzap_init
 */
static int __init usb_streamzap_init(void)
{
	int result;

	/* register this driver with the USB subsystem */
	result = usb_register(&streamzap_driver);

	if (result) {
		err("usb_register failed. Error number %d",
		    result);
		return result;
	}

	printk(KERN_INFO DRIVER_NAME " " DRIVER_VERSION " registered\n");
	return 0;
}

/**
 *	usb_streamzap_exit
 */
static void __exit usb_streamzap_exit(void)
{
	usb_deregister(&streamzap_driver);
}


module_init(usb_streamzap_init);
module_exit(usb_streamzap_exit);

MODULE_AUTHOR("Christoph Bartelmus, Greg Wickham, Adrian Dewhurst");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Enable debugging messages");
EXPORT_NO_SYMBOLS;
#endif /* MODULE */
