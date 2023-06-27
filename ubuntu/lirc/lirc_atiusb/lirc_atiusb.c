/*
 * lirc_atiusb - USB remote support for LIRC
 * (currently only supports X10 USB remotes)
 * (supports ATI Remote Wonder and ATI Remote Wonder II, too)
 *
 * Copyright (C) 2003-2004 Paul Miller <pmiller9@users.sourceforge.net>
 *
 * This driver was derived from:
 *   Vladimir Dergachev <volodya@minspring.com>'s 2002
 *      "USB ATI Remote support" (input device)
 *   Adrian Dewhurst <sailor-lk@sailorfrag.net>'s 2002
 *      "USB StreamZap remote driver" (LIRC)
 *   Artur Lipowski <alipowski@kki.net.pl>'s 2002
 *      "lirc_dev" and "lirc_gpio" LIRC modules
 *   Michael Wojciechowski
 *      initial xbox support
 *   Vassilis Virvilis <vasvir@iit.demokritos.gr> 2006
 *      reworked the patch for lirc submission
 *
 * $Id: lirc_atiusb.c,v 1.85 2009/03/11 00:21:46 jarodwilson Exp $
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

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/smp_lock.h>
#include <linux/completion.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
#include <asm/uaccess.h>
#else
#include <linux/uaccess.h>
#endif
#include <linux/usb.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/list.h>

#include "../lirc.h"
#include "../kcompat.h"
#include "../lirc_dev/lirc_dev.h"

#define DRIVER_VERSION		"$Revision: 1.85 $"
#define DRIVER_AUTHOR		"Paul Miller <pmiller9@users.sourceforge.net>"
#define DRIVER_DESC		"USB remote driver for LIRC"
#define DRIVER_NAME		"lirc_atiusb"

#define CODE_LENGTH		(code_length[ir->remote_type])
#define CODE_MIN_LENGTH		(code_min_length[ir->remote_type])
#define DECODE_LENGTH		(decode_length[ir->remote_type])

#define RW2_MODENAV_KEYCODE	0x3F
#define RW2_NULL_MODE		0xFF
/* Fake (virtual) keycode indicating compass mouse usage */
#define RW2_MOUSE_KEYCODE	0xFF
#define RW2_PRESSRELEASE_KEYCODE	0xFE

#define RW2_PRESS_CODE		1
#define RW2_HOLD_CODE		2
#define RW2_RELEASE_CODE	0

/* module parameters */
#ifdef CONFIG_USB_DEBUG
static int debug = 1;
#else
static int debug;
#endif
#define dprintk(fmt, args...)					\
	do {							\
		if (debug)					\
			printk(KERN_DEBUG fmt, ## args);	\
	} while (0)

/* ATI, ATI2, XBOX */
static const int code_length[] = {5, 3, 6};
static const int code_min_length[] = {3, 3, 6};
static const int decode_length[] = {5, 3, 1};
/*
 * USB_BUFF_LEN must be the maximum value of the code_length array.
 * It is used for static arrays.
 */
#define USB_BUFF_LEN 6

static int mask = 0xFFFF;	/* channel acceptance bit mask */
static int unique;		/* enable channel-specific codes */
static int repeat = 10;		/* repeat time in 1/100 sec */
static int emit_updown;		/* send separate press/release codes (rw2) */
static int emit_modekeys;	/* send keycodes for aux1-4, pc, mouse (rw2) */
static unsigned long repeat_jiffies; /* repeat timeout */
static int mdeadzone;		/* mouse sensitivity >= 0 */
static int mgradient = 375;	/* 1000*gradient from cardinal direction */

/* get hi and low bytes of a 16-bits int */
#define HI(a)			((unsigned char)((a) >> 8))
#define LO(a)			((unsigned char)((a) & 0xff))

/* general constants */
#define SEND_FLAG_IN_PROGRESS	1
#define SEND_FLAG_COMPLETE	2
#define FREE_ALL		0xFF

/* endpoints */
#define EP_KEYS			0
#define EP_MOUSE		1
#define EP_MOUSE_ADDR		0x81
#define EP_KEYS_ADDR		0x82

#define VENDOR_ATI1		0x0bc7
#define VENDOR_ATI2		0x0471
#define VENDOR_MS1		0x040b
#define VENDOR_MS2		0x045e
#define VENDOR_MS3		0xFFFF

static struct usb_device_id usb_remote_table[] = {
	/* X10 USB Firecracker Interface */
	{ USB_DEVICE(VENDOR_ATI1, 0x0002) },

	/* X10 VGA Video Sender */
	{ USB_DEVICE(VENDOR_ATI1, 0x0003) },

	/* ATI Wireless Remote Receiver */
	{ USB_DEVICE(VENDOR_ATI1, 0x0004) },

	/* NVIDIA Wireless Remote Receiver */
	{ USB_DEVICE(VENDOR_ATI1, 0x0005) },

	/* ATI Wireless Remote Receiver */
	{ USB_DEVICE(VENDOR_ATI1, 0x0006) },

	/* X10 USB Wireless Transceivers */
	{ USB_DEVICE(VENDOR_ATI1, 0x0007) },
	{ USB_DEVICE(VENDOR_ATI1, 0x0008) },
	{ USB_DEVICE(VENDOR_ATI1, 0x0009) },
	{ USB_DEVICE(VENDOR_ATI1, 0x000A) },
	{ USB_DEVICE(VENDOR_ATI1, 0x000B) },
	{ USB_DEVICE(VENDOR_ATI1, 0x000C) },
	{ USB_DEVICE(VENDOR_ATI1, 0x000D) },
	{ USB_DEVICE(VENDOR_ATI1, 0x000E) },
	{ USB_DEVICE(VENDOR_ATI1, 0x000F) },

	/* ATI Remote Wonder 2: Input Device */
	{ USB_DEVICE(VENDOR_ATI2, 0x0602) },

	/* ATI Remote Wonder 2: Controller (???) */
	{ USB_DEVICE(VENDOR_ATI2, 0x0603) },

	/* Gamester Xbox DVD Movie Playback Kit IR */
	{ USB_DEVICE(VENDOR_MS1, 0x6521) },

	/* Microsoft Xbox DVD Movie Playback Kit IR */
	{ USB_DEVICE(VENDOR_MS2, 0x0284) },

	/*
	 * Some Chinese manufacturer -- conflicts with the joystick from the
	 * same manufacturer
	 */
	{ USB_DEVICE(VENDOR_MS3, 0xFFFF) },

	/* Terminating entry */
	{ }
};


/* init strings */
#define USB_OUTLEN		7

static char init1[] = {0x01, 0x00, 0x20, 0x14};
static char init2[] = {0x01, 0x00, 0x20, 0x14, 0x20, 0x20, 0x20};

struct in_endpt {
	/* inner link in list of endpoints for the remote specified by ir */
	struct list_head iep_list_link;
	struct atirf_dev *ir;
	struct urb *urb;
	struct usb_endpoint_descriptor *ep;
	int type;

	/* buffers and dma */
	unsigned char *buf;
	unsigned int len;
#ifdef KERNEL_2_5
	dma_addr_t dma;
#endif

	/* handle repeats */
	unsigned char old[USB_BUFF_LEN];
	unsigned long old_jiffies;
};

struct out_endpt {
	struct atirf_dev *ir;
	struct urb *urb;
	struct usb_endpoint_descriptor *ep;

	/* buffers and dma */
	unsigned char *buf;
#ifdef KERNEL_2_5
	dma_addr_t dma;
#endif

	/* handle sending (init strings) */
	int send_flags;
	wait_queue_head_t wait;
};


/* data structure for each usb remote */
struct atirf_dev {
	/* inner link in list of all remotes managed by this module */
	struct list_head remote_list_link;
	/* Number of usb interfaces associated with this device */
	int dev_refcount;

	/* usb */
	struct usb_device *usbdev;
	/* Head link to list of all inbound endpoints in this remote */
	struct list_head iep_listhead;
	struct out_endpt *out_init;
	int devnum;

	/* remote type based on usb_device_id tables */
	enum {
		ATI1_COMPATIBLE,
		ATI2_COMPATIBLE,
		XBOX_COMPATIBLE
	} remote_type;

	/* rw2 current mode (mirrors the state of the remote) */
	int mode;

	/* lirc */
	struct lirc_driver *d;
	int connected;

	/* locking */
	struct mutex lock;
};

/* list of all registered devices via the remote_list_link in atirf_dev */
static struct list_head remote_list;

/*
 * Convenience macros to retrieve a pointer to the surrounding struct from
 * the given list_head reference within, pointed at by link.
 */
#define get_iep_from_link(link) \
		list_entry((link), struct in_endpt, iep_list_link);
#define get_irctl_from_link(link) \
		list_entry((link), struct atirf_dev, remote_list_link);

/* send packet - used to initialize remote */
static void send_packet(struct out_endpt *oep, u16 cmd, unsigned char *data)
{
	struct atirf_dev *ir = oep->ir;
	DECLARE_WAITQUEUE(wait, current);
	int timeout = HZ; /* 1 second */
	unsigned char buf[USB_OUTLEN];

	dprintk(DRIVER_NAME "[%d]: send called (%#x)\n", ir->devnum, cmd);

	mutex_lock(&ir->lock);
	oep->urb->transfer_buffer_length = LO(cmd) + 1;
	oep->urb->dev = oep->ir->usbdev;
	oep->send_flags = SEND_FLAG_IN_PROGRESS;

	memcpy(buf+1, data, LO(cmd));
	buf[0] = HI(cmd);
	memcpy(oep->buf, buf, LO(cmd)+1);

	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&oep->wait, &wait);

#ifdef KERNEL_2_5
	if (usb_submit_urb(oep->urb, GFP_ATOMIC)) {
#else
	if (usb_submit_urb(oep->urb)) {
#endif
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&oep->wait, &wait);
		mutex_unlock(&ir->lock);
		return;
	}
	mutex_unlock(&ir->lock);

	while (timeout && (oep->urb->status == -EINPROGRESS)
	       && !(oep->send_flags & SEND_FLAG_COMPLETE)) {
		timeout = schedule_timeout(timeout);
		rmb();
	}

	dprintk(DRIVER_NAME "[%d]: send complete (%#x)\n", ir->devnum, cmd);

	set_current_state(TASK_RUNNING);
	remove_wait_queue(&oep->wait, &wait);
#ifdef KERNEL_2_5
	oep->urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif
	usb_unlink_urb(oep->urb);
}

static int unregister_from_lirc(struct atirf_dev *ir)
{
	struct lirc_driver *d = ir->d;
	int devnum;

	devnum = ir->devnum;
	dprintk(DRIVER_NAME "[%d]: unregister from lirc called\n", devnum);

	lirc_unregister_driver(d->minor);

	printk(DRIVER_NAME "[%d]: usb remote disconnected\n", devnum);
	return 0;
}


static int set_use_inc(void *data)
{
	struct atirf_dev *ir = data;
	struct list_head *pos, *n;
	struct in_endpt *iep;
	int rtn;

	if (!ir) {
		printk(DRIVER_NAME "[?]: set_use_inc called with no context\n");
		return -EIO;
	}
	dprintk(DRIVER_NAME "[%d]: set use inc\n", ir->devnum);

	MOD_INC_USE_COUNT;

	mutex_lock(&ir->lock);
	if (!ir->connected) {
		if (!ir->usbdev) {
			mutex_unlock(&ir->lock);
			dprintk(DRIVER_NAME "[%d]: !ir->usbdev\n", ir->devnum);
			return -ENOENT;
		}

		/* Iterate through the inbound endpoints */
		list_for_each_safe(pos, n, &ir->iep_listhead) {
			/* extract the current in_endpt */
			iep = get_iep_from_link(pos);
			iep->urb->dev = ir->usbdev;
			dprintk(DRIVER_NAME "[%d]: linking iep 0x%02x (%p)\n",
				ir->devnum, iep->ep->bEndpointAddress, iep);
#ifdef KERNEL_2_5
			rtn = usb_submit_urb(iep->urb, GFP_ATOMIC);
#else
			rtn = usb_submit_urb(iep->urb);
#endif
			if (rtn) {
				printk(DRIVER_NAME "[%d]: open result = %d "
				       "error submitting urb\n",
				       ir->devnum, rtn);
				mutex_unlock(&ir->lock);
				MOD_DEC_USE_COUNT;
				return -EIO;
			}
		}
		ir->connected = 1;
	}
	mutex_unlock(&ir->lock);

	return 0;
}

static void set_use_dec(void *data)
{
	struct atirf_dev *ir = data;
	struct list_head *pos, *n;
	struct in_endpt *iep;

	if (!ir) {
		printk(DRIVER_NAME "[?]: set_use_dec called with no context\n");
		return;
	}
	dprintk(DRIVER_NAME "[%d]: set use dec\n", ir->devnum);

	mutex_lock(&ir->lock);
	if (ir->connected) {
		/* Free inbound usb urbs */
		list_for_each_safe(pos, n, &ir->iep_listhead) {
			iep = get_iep_from_link(pos);
			dprintk(DRIVER_NAME "[%d]: unlinking iep 0x%02x (%p)\n",
				ir->devnum, iep->ep->bEndpointAddress, iep);
			usb_kill_urb(iep->urb);
		}
		ir->connected = 0;
	}
	mutex_unlock(&ir->lock);
	MOD_DEC_USE_COUNT;
}

static void print_data(struct in_endpt *iep, char *buf, int len)
{
	const int clen = code_length[iep->ir->remote_type];
	char codes[clen * 3 + 1];
	int i;

	if (len <= 0)
		return;

	for (i = 0; i < len && i < clen; i++)
		snprintf(codes+i*3, 4, "%02x ", buf[i] & 0xFF);
	printk(DRIVER_NAME "[%d]: data received %s (ep=0x%x length=%d)\n",
		iep->ir->devnum, codes, iep->ep->bEndpointAddress, len);
}

static int code_check_ati1(struct in_endpt *iep, int len)
{
	struct atirf_dev *ir = iep->ir;
	int i, chan;

	/* ATI RW1: some remotes emit both 4 and 5 byte length codes. */
	/* ATI RW2: emit 3 byte codes */
	if (len < CODE_MIN_LENGTH || len > CODE_LENGTH)
		return -1;

	/* *** channel not tested with 4/5-byte Dutch remotes *** */
	chan = ((iep->buf[len-1]>>4) & 0x0F);

	/* strip channel code */
	if (!unique) {
		iep->buf[len-1] &= 0x0F;
		iep->buf[len-3] -= (chan<<4);
	}

	if (!((1U<<chan) & mask)) {
		dprintk(DRIVER_NAME "[%d]: ignore channel %d\n",
			ir->devnum, chan+1);
		return -1;
	}
	dprintk(DRIVER_NAME "[%d]: accept channel %d\n", ir->devnum, chan+1);

	if (ir->remote_type == ATI1_COMPATIBLE) {
		for (i = len; i < CODE_LENGTH; i++)
			iep->buf[i] = 0;
		/* check for repeats */
		if (memcmp(iep->old, iep->buf, len) == 0) {
			if (iep->old_jiffies + repeat_jiffies > jiffies)
				return -1;
		} else
			memcpy(iep->old, iep->buf, CODE_LENGTH);
		iep->old_jiffies = jiffies;
	}

	return 0;
}

/*
 * Since the ATI Remote Wonder II has quite a different structure from the
 * prior version, this function was separated out to clarify the sanitization
 * process.
 *
 * Here is a summary of the main differences:
 *
 * a. The rw2 has no sense of a transmission channel.  But, it does have an
 *    auxiliary mode state, which is set by the mode buttons Aux1 through
 *    Aux4 and "PC".  These map respectively to 0-4 in the first byte of the
 *    recv buffer.  Any subsequent button press sends this mode number as its
 *    "channel code."  Annoyingly enough, the mode setting buttons all send
 *    the same key code (0x3f), and can only be distinguished via their mode
 *    byte.
 *
 *    Because of this, old-style "unique"-parameter-enabled channel squashing
 *    kills the functionality of the aux1-aux4 and PC buttons.  However, to
 *    not do so would cause each remote key to send a different code depending
 *    on the active aux.  Further complicating matters, using the mouse norb
 *    also sends an identical code as would pushing the active aux button.  To
 *    handle this we need a separate parameter, like rw2modes, with the
 *    following values and meanings:
 *
 *	0: Don't squash any channel info
 *	1: Only squash channel data for non-mode setting keys
 *	2: Ignore aux keypresses, but don't squash channel
 *	3: Ignore aux keypresses and squash channel data
 *
 *    Option 1 may seem useless since the mouse sends the same code, but one
 *    need only ignore in userspace any press of a mode-setting code that only
 *    reaffirms the current mode.  The 3rd party lirccd should be able to
 *    handle this easily enough, but lircd doesn't keep the state necessary
 *    for this.  TODO We could work around this in the driver by emitting a
 *    single 02 (press) code for a mode key only if that mode is not currently
 *    active.
 *
 *    Option 2 would be useful for those wanting super configurability,
 *    offering the ability to program 5 times the number actions based on the
 *    current mode.
 *
 * b. The rw2 has its own built in repeat handling; the keys endpoint
 *    encodes this in the second byte as 1 for press, 2 for hold, and 0 for
 *    release.  This is generally much more responsive than lirc's built-in
 *    timeout handling.
 *
 *    The problem is that the remote can send the release-receive pair
 *    (0,1) while one is still holding down the same button if the
 *    transmission is momentarily interrupted.  (It seems that the receiver
 *    manages this count instead of the remote.)  By default, this information
 *    is squashed to 2.
 *
 *    In order to expose the built-in repeat code, set the emit_updown
 *    parameter as described below.
 *
 * c. The mouse norb is much more sensitive than on the rw1.  It emulates
 *    a joystick-like controller with the second byte representing the x-axis
 *    and the third, the y-axis.  Treated as signed integers, these axes range
 *    approximately as follows:
 *
 *	x: (left) -46 ... 46 (right) (0xd2..0x2e)
 *	y: (up)   -46 ... 46 (down)  (0xd2..0x2e)
 *
 *    NB these values do not correspond to the pressure with which the mouse
 *    norb is pushed in a given direction, but rather seems to indicate the
 *    duration for which a given direction is held.
 *
 *    These are normalized to 8 cardinal directions for easy configuration via
 *    lircd.conf.  The normalization can be fined tuned with the mdeadzone and
 *    mgradient parameters as described below.
 *
 * d. The interrupt rate of the mouse vs. the normal keys is different.
 *
 *	mouse: ~27Hz (37ms between interrupts)
 *	keys:  ~10Hz (100ms between interrupts)
 *
 *    This means that the normal gap mechanism for lircd won't work as
 *    expected; is emit_updown>0 if you can get away with it.
 */
static int code_check_ati2(struct in_endpt *iep, int len)
{
	struct atirf_dev *ir = iep->ir;
	int mode, i;
	char *buf = iep->buf;

	if (len != CODE_LENGTH) {
		dprintk(DRIVER_NAME
			"[%d]: Huh?  Abnormal length (%d) buffer received.\n",
			ir->devnum, len);
		return -1;
	}
	for (i = len; i < CODE_LENGTH; i++)
		iep->buf[i] = 0;

	mode = buf[0];

	/* Squash the mode indicator if unique wasn't set non-zero */
	if (!unique)
		buf[0] = 0;

	if (iep->ep->bEndpointAddress == EP_KEYS_ADDR) {
		/* ignore mouse nav indicator key and mode-set (aux) keys */
		if (buf[2] == RW2_MODENAV_KEYCODE) {
			if (emit_modekeys >= 2) /* emit raw */
				buf[0] = mode;
			else if (emit_modekeys == 1) {
				/* translate */
				buf[0] = mode;
				if (ir->mode != mode) {
					buf[1] = 0x03;
					ir->mode = mode;
					return 0;
				}
			} else {
				dprintk(DRIVER_NAME
					"[%d]: ignore dummy code 0x%x "
					"(ep=0x%x)\n", ir->devnum,
					buf[2], iep->ep->bEndpointAddress);
				return -1;
			}
		}

		if (buf[1] != 2) {
			/* handle press/release codes */
			if (emit_updown == 0) /* ignore */
				return -1;
			else if (emit_updown == 1) /* normalize keycode */
				 buf[2] = RW2_PRESSRELEASE_KEYCODE;
			/* else emit raw */
		}

	} else {
		int x = (signed char)buf[1];
		int y = (signed char)buf[2];
		int code = 0x00;
		int dir_ew, dir_ns;

		buf[2] = RW2_MOUSE_KEYCODE;

		/* sensitivity threshold (use L2norm^2) */
		if (mdeadzone > (x*x+y*y)) {
			buf[1] = 0x00;
			return 0;
		}

/* Nybble encoding: xy, 2 is -1 (S or W); 1 (N or E) */
#define MOUSE_N		0x01
#define MOUSE_NE	0x11
#define MOUSE_E		0x10
#define MOUSE_SE	0x12
#define MOUSE_S		0x02
#define MOUSE_SW	0x22
#define MOUSE_W		0x20
#define MOUSE_NW	0x21

		/* cardinal leanings: positive x -> E, positive y -> S */
		dir_ew = (x > 0) ? MOUSE_E : MOUSE_W;
		dir_ns = (y > 0) ? MOUSE_S : MOUSE_N;

		/* convert coordinates(angle) into compass direction */
		if (x == 0)
			code = dir_ns;
		else if (y == 0)
			code = dir_ew;
		else {
			if (abs(1000*y/x) > mgradient)
				code = dir_ns;
			if (abs(1000*x/y) > mgradient)
				code |= dir_ew;
		}

		buf[1] = code;
		dprintk(DRIVER_NAME "[%d]: mouse compass=0x%x %s%s (%d,%d)\n",
			ir->devnum, code,
			(code & MOUSE_S ? "S" : (code & MOUSE_N ? "N" : "")),
			(code & MOUSE_E ? "E" : (code & MOUSE_W ? "W" : "")),
			x, y);
	}

	return 0;
}

static int code_check_xbox(struct in_endpt *iep, int len)
{
	struct atirf_dev *ir = iep->ir;
	const int clen = CODE_LENGTH;

	if (len != clen) {
		dprintk(DRIVER_NAME ": We got %d instead of %d bytes from xbox "
			"ir.. ?\n", len, clen);
		return -1;
	}

	/* check for repeats */
	if (memcmp(iep->old, iep->buf, len) == 0) {
		if (iep->old_jiffies + repeat_jiffies > jiffies)
			return -1;
	} else {
		/*
		 * the third byte of xbox ir packet seems to contain key info
		 * the last two bytes are.. some kind of clock?
		 */
		iep->buf[0] = iep->buf[2];
		memset(iep->buf + 1, 0, len - 1);
		memcpy(iep->old, iep->buf, len);
	}
	iep->old_jiffies = jiffies;

	return 0;
}

#if defined(KERNEL_2_5) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void usb_remote_recv(struct urb *urb, struct pt_regs *regs)
#else
static void usb_remote_recv(struct urb *urb)
#endif
{
	struct in_endpt *iep;
	int len, result = -1;

	if (!urb)
		return;
	iep = urb->context;
	if (!iep) {
#ifdef KERNEL_2_5
		urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif
		usb_unlink_urb(urb);
		return;
	}
	if (!iep->ir->usbdev)
		return;

	len = urb->actual_length;
	if (debug)
		print_data(iep, urb->transfer_buffer, len);

	switch (urb->status) {

	case 0:
		switch (iep->ir->remote_type) {
		case XBOX_COMPATIBLE:
			result = code_check_xbox(iep, len);
			break;
		case ATI2_COMPATIBLE:
			result = code_check_ati2(iep, len);
			break;
		case ATI1_COMPATIBLE:
		default:
			result = code_check_ati1(iep, len);
		}
		if (result < 0)
			break;
		lirc_buffer_write(iep->ir->d->rbuf, iep->buf);
		wake_up(&iep->ir->d->rbuf->wait_poll);
		break;

	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
#ifdef KERNEL_2_5
		urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif
		usb_unlink_urb(urb);
		return;

	case -EPIPE:
	default:
		break;
	}

#ifdef KERNEL_2_5
	usb_submit_urb(urb, GFP_ATOMIC);
#endif
}

#if defined(KERNEL_2_5) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void usb_remote_send(struct urb *urb, struct pt_regs *regs)
#else
static void usb_remote_send(struct urb *urb)
#endif
{
	struct out_endpt *oep;

	if (!urb)
		return;
	oep = urb->context;
	if (!oep) {
#ifdef KERNEL_2_5
		urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif
		usb_unlink_urb(urb);
		return;
	}
	if (!oep->ir->usbdev)
		return;

	dprintk(DRIVER_NAME "[%d]: usb out called\n", oep->ir->devnum);

	if (urb->status)
		return;

	oep->send_flags |= SEND_FLAG_COMPLETE;
	wmb();
	if (waitqueue_active(&oep->wait))
		wake_up(&oep->wait);
}


/*
 * Initialization and removal
 */

/*
 * Free iep according to mem_failure which specifies a checkpoint into the
 * initialization sequence for rollback recovery.
 */
static void free_in_endpt(struct in_endpt *iep, int mem_failure)
{
	struct atirf_dev *ir;
	dprintk(DRIVER_NAME ": free_in_endpt(%p, %d)\n", iep, mem_failure);
	if (!iep)
		return;

	ir = iep->ir;
	if (!ir) {
		dprintk(DRIVER_NAME ": free_in_endpt: WARNING! null ir\n");
		return;
	}
	mutex_lock(&ir->lock);
	switch (mem_failure) {
	case FREE_ALL:
	case 5:
		list_del(&iep->iep_list_link);
		dprintk(DRIVER_NAME "[%d]: free_in_endpt removing ep=0x%0x "
			"from list\n", ir->devnum, iep->ep->bEndpointAddress);
	case 4:
		if (iep->urb) {
#ifdef KERNEL_2_5
			iep->urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif
			usb_unlink_urb(iep->urb);
			usb_free_urb(iep->urb);
			iep->urb = 0;
		} else
			dprintk(DRIVER_NAME "[%d]: free_in_endpt null urb!\n",
				ir->devnum);
	case 3:
#ifdef KERNEL_2_5
		usb_buffer_free(iep->ir->usbdev, iep->len, iep->buf, iep->dma);
#else
		kfree(iep->buf);
#endif
		iep->buf = 0;
	case 2:
		kfree(iep);
	}
	mutex_unlock(&ir->lock);
}

/*
 * Construct a new inbound endpoint for this remote, and add it to the list of
 * in_epts in ir.
 */
static struct in_endpt *new_in_endpt(struct atirf_dev *ir,
				     struct usb_endpoint_descriptor *ep)
{
	struct usb_device *dev = ir->usbdev;
	struct in_endpt *iep;
	int pipe, maxp, len, addr;
	int mem_failure;

	addr = ep->bEndpointAddress;
	pipe = usb_rcvintpipe(dev, addr);
	maxp = usb_maxpacket(dev, pipe, usb_pipeout(pipe));

/*	len = (maxp > USB_BUFLEN) ? USB_BUFLEN : maxp;
 *	len -= (len % CODE_LENGTH); */
	len = CODE_LENGTH;

	dprintk(DRIVER_NAME "[%d]: acceptable inbound endpoint (0x%x) found "
		"(maxp=%d len=%d)\n", ir->devnum, addr, maxp, len);

	mem_failure = 0;
	iep = kzalloc(sizeof(*iep), GFP_KERNEL);
	if (!iep) {
		mem_failure = 1;
		goto new_in_endpt_failure_check;
	}
	iep->ir = ir;
	iep->ep = ep;
	iep->len = len;

#ifdef KERNEL_2_5
	iep->buf = usb_buffer_alloc(dev, len, GFP_ATOMIC, &iep->dma);
#else
	iep->buf = kmalloc(len, GFP_KERNEL);
#endif
	if (!iep->buf) {
		mem_failure = 2;
		goto new_in_endpt_failure_check;
	}

#ifdef KERNEL_2_5
	iep->urb = usb_alloc_urb(0, GFP_KERNEL);
#else
	iep->urb = usb_alloc_urb(0);
#endif
	if (!iep->urb)
		mem_failure = 3;

new_in_endpt_failure_check:

	if (mem_failure) {
		free_in_endpt(iep, mem_failure);
		printk(DRIVER_NAME "[%d]: ep=0x%x out of memory (code=%d)\n",
		       ir->devnum, addr, mem_failure);
		return NULL;
	}
	list_add_tail(&iep->iep_list_link, &ir->iep_listhead);
	dprintk(DRIVER_NAME "[%d]: adding ep=0x%0x to list\n",
		ir->devnum, iep->ep->bEndpointAddress);
	return iep;
}

static void free_out_endpt(struct out_endpt *oep, int mem_failure)
{
	struct atirf_dev *ir;
	dprintk(DRIVER_NAME ": free_out_endpt(%p, %d)\n", oep, mem_failure);
	if (!oep)
		return;

	wake_up_all(&oep->wait);

	ir = oep->ir;
	if (!ir) {
		dprintk(DRIVER_NAME ": free_out_endpt: WARNING! null ir\n");
		return;
	}
	mutex_lock(&ir->lock);
	switch (mem_failure) {
	case FREE_ALL:
	case 4:
		if (oep->urb) {
#ifdef KERNEL_2_5
			oep->urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif
			usb_unlink_urb(oep->urb);
			usb_free_urb(oep->urb);
			oep->urb = 0;
		} else {
			dprintk(DRIVER_NAME "[%d]: free_out_endpt: null urb!\n",
				ir->devnum);
		}
	case 3:
#ifdef KERNEL_2_5
		usb_buffer_free(oep->ir->usbdev, USB_OUTLEN,
				oep->buf, oep->dma);
#else
		kfree(oep->buf);
#endif
		oep->buf = 0;
	case 2:
		kfree(oep);
	}
	mutex_unlock(&ir->lock);
}

static struct out_endpt *new_out_endpt(struct atirf_dev *ir,
				       struct usb_endpoint_descriptor *ep)
{
#ifdef KERNEL_2_5
	struct usb_device *dev = ir->usbdev;
#endif
	struct out_endpt *oep;
	int mem_failure;

	dprintk(DRIVER_NAME "[%d]: acceptable outbound endpoint (0x%x) found\n",
		ir->devnum, ep->bEndpointAddress);

	mem_failure = 0;
	oep = kzalloc(sizeof(*oep), GFP_KERNEL);
	if (!oep)
		mem_failure = 1;
	else {
		oep->ir = ir;
		oep->ep = ep;
		init_waitqueue_head(&oep->wait);

#ifdef KERNEL_2_5
		oep->buf = usb_buffer_alloc(dev, USB_OUTLEN,
					    GFP_ATOMIC, &oep->dma);
#else
		oep->buf = kmalloc(USB_OUTLEN, GFP_KERNEL);
#endif
		if (!oep->buf)
			mem_failure = 2;
		else {
#ifdef KERNEL_2_5
			oep->urb = usb_alloc_urb(0, GFP_KERNEL);
#else
			oep->urb = usb_alloc_urb(0);
#endif
			if (!oep->urb)
				mem_failure = 3;
		}
	}
	if (mem_failure) {
		free_out_endpt(oep, mem_failure);
		printk(DRIVER_NAME "[%d]: ep=0x%x out of memory (code=%d)\n",
		       ir->devnum, ep->bEndpointAddress, mem_failure);
		return NULL;
	}
	return oep;
}

static void free_irctl(struct atirf_dev *ir, int mem_failure)
{
	struct list_head *pos, *n;
	struct in_endpt *in;
	dprintk(DRIVER_NAME ": free_irctl(%p, %d)\n", ir, mem_failure);

	if (!ir)
		return;

	list_for_each_safe(pos, n, &ir->iep_listhead) {
		in = get_iep_from_link(pos);
		free_in_endpt(in, FREE_ALL);
	}
	if (ir->out_init) {
		free_out_endpt(ir->out_init, FREE_ALL);
		ir->out_init = NULL;
	}

	mutex_lock(&ir->lock);
	switch (mem_failure) {
	case FREE_ALL:
	case 6:
		if (!--ir->dev_refcount) {
			list_del(&ir->remote_list_link);
			dprintk(DRIVER_NAME "[%d]: free_irctl: removing "
				"remote from list\n", ir->devnum);
		} else {
			dprintk(DRIVER_NAME "[%d]: free_irctl: refcount at %d,"
				"aborting free_irctl\n",
				ir->devnum, ir->dev_refcount);
			mutex_unlock(&ir->lock);
			return;
		}
	case 5:
	case 4:
	case 3:
		if (ir->d) {
			switch (mem_failure) {
			case 5:
				lirc_buffer_free(ir->d->rbuf);
			case 4:
				kfree(ir->d->rbuf);
			case 3:
				kfree(ir->d);
			}
		} else
			printk(DRIVER_NAME "[%d]: ir->d is a null pointer!\n",
			       ir->devnum);
	case 2:
		mutex_unlock(&ir->lock);
		kfree(ir);
		return;
	}
	mutex_unlock(&ir->lock);
}

static struct atirf_dev *new_irctl(struct usb_interface *intf)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	struct atirf_dev *ir;
	struct lirc_driver *driver;
	int type, devnum, dclen;
	int mem_failure;

	devnum = dev->devnum;

	switch (cpu_to_le16(dev->descriptor.idVendor)) {
	case VENDOR_ATI1:
		type = ATI1_COMPATIBLE;
		break;
	case VENDOR_ATI2:
		type = ATI2_COMPATIBLE;
		break;
	case VENDOR_MS1:
	case VENDOR_MS2:
	case VENDOR_MS3:
		type = XBOX_COMPATIBLE;
		break;
	default:
		dprintk(DRIVER_NAME "[%d]: unknown type\n", devnum);
		return NULL;
	}
	dprintk(DRIVER_NAME "[%d]: remote type = %d\n", devnum, type);

	mem_failure = 0;
	ir = kzalloc(sizeof(*ir), GFP_KERNEL);
	if (!ir) {
		mem_failure = 1;
		goto new_irctl_failure_check;
	}

	/*
	 * at this stage we cannot use the macro [DE]CODE_LENGTH: ir
	 * is not yet setup
	 */
	dclen = decode_length[type];
	/*
	 * add this infrared remote struct to remote_list, keeping track
	 * of the number of drivers registered.
	 */
	dprintk(DRIVER_NAME "[%d]: adding remote to list\n", devnum);
	list_add_tail(&ir->remote_list_link, &remote_list);
	ir->dev_refcount = 1;

	driver = kzalloc(sizeof(*driver), GFP_KERNEL);
	if (!driver) {
		mem_failure = 2;
		goto new_irctl_failure_check;
	}

	ir->d = driver;
	driver->rbuf = kmalloc(sizeof(*(driver->rbuf)), GFP_KERNEL);
	if (!driver->rbuf) {
		mem_failure = 3;
		goto new_irctl_failure_check;
	}

	if (lirc_buffer_init(driver->rbuf, dclen, 1)) {
		mem_failure = 4;
		goto new_irctl_failure_check;
	}

	strcpy(driver->name, DRIVER_NAME " ");
	driver->minor = -1;
	driver->code_length = dclen * 8;
	driver->features = LIRC_CAN_REC_LIRCCODE;
	driver->data = ir;
	driver->set_use_inc = &set_use_inc;
	driver->set_use_dec = &set_use_dec;
#ifdef LIRC_HAVE_SYSFS
	driver->dev = &intf->dev;
#endif
	driver->owner = THIS_MODULE;
	ir->usbdev = dev;
	ir->remote_type = type;
	ir->devnum = devnum;
	ir->mode = RW2_NULL_MODE;

	mutex_init(&ir->lock);
	INIT_LIST_HEAD(&ir->iep_listhead);

new_irctl_failure_check:

	if (mem_failure) {
		free_irctl(ir, mem_failure);
		printk(DRIVER_NAME "[%d]: out of memory (code=%d)\n",
		       devnum, mem_failure);
		return NULL;
	}
	return ir;
}


/*
 * Scan the global list of remotes to see if the device listed is one of them.
 * If it is, the corresponding atirf_dev is returned, with its dev_refcount
 * incremented.  Otherwise, returns null.
 */
static struct atirf_dev *get_prior_reg_ir(struct usb_device *dev)
{
	struct list_head *pos;
	struct atirf_dev *ir = NULL;

	dprintk(DRIVER_NAME "[%d]: scanning remote_list...\n", dev->devnum);
	list_for_each(pos, &remote_list) {
		ir = get_irctl_from_link(pos);
		if (ir->usbdev != dev) {
			dprintk(DRIVER_NAME "[%d]: device %d isn't it...",
				dev->devnum, ir->devnum);
		    ir = NULL;
		} else {
			dprintk(DRIVER_NAME "[%d]: prior instance found.\n",
				dev->devnum);
			ir->dev_refcount++;
			break;
		}
	}
	return ir;
}

/*
 * If the USB interface has an out endpoint for control (eg, the first Remote
 * Wonder) send the appropriate initialization packets.
 */
static void send_outbound_init(struct atirf_dev *ir)
{
	if (ir->out_init) {
		struct out_endpt *oep = ir->out_init;
		dprintk(DRIVER_NAME "[%d]: usb_remote_probe: initializing "
			"outbound ep\n", ir->devnum);
		usb_fill_int_urb(oep->urb, ir->usbdev,
			usb_sndintpipe(ir->usbdev, oep->ep->bEndpointAddress),
			oep->buf, USB_OUTLEN, usb_remote_send,
			oep, oep->ep->bInterval);
#ifdef KERNEL_2_5
		oep->urb->transfer_dma = oep->dma;
		oep->urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
#endif

		send_packet(oep, 0x8004, init1);
		send_packet(oep, 0x8007, init2);
	}
}

/* Log driver and usb info */
static void log_usb_dev_info(struct usb_device *dev)
{
	char buf[63], name[128] = "";

	if (dev->descriptor.iManufacturer
	    && usb_string(dev, dev->descriptor.iManufacturer,
			  buf, sizeof(buf)) > 0)
		strlcpy(name, buf, sizeof(name));
	if (dev->descriptor.iProduct
	    && usb_string(dev, dev->descriptor.iProduct, buf, sizeof(buf)) > 0)
		snprintf(name + strlen(name), sizeof(name) - strlen(name),
			 " %s", buf);
	printk(DRIVER_NAME "[%d]: %s on usb%d:%d\n", dev->devnum, name,
	       dev->bus->busnum, dev->devnum);
}


#ifdef KERNEL_2_5
static int usb_remote_probe(struct usb_interface *intf,
				const struct usb_device_id *id)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	struct usb_host_interface *idesc;
#else
static void *usb_remote_probe(struct usb_device *dev, unsigned int ifnum,
				const struct usb_device_id *id)
{
	struct usb_interface *intf = &dev->actconfig->interface[ifnum];
	struct usb_interface_descriptor *idesc;
#endif
	struct usb_endpoint_descriptor *ep;
	struct in_endpt *iep;
	struct atirf_dev *ir;
	int i, type;

	dprintk(DRIVER_NAME "[%d]: usb_remote_probe: dev:%p, intf:%p, id:%p)\n",
		dev->devnum, dev, intf, id);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 5)
	idesc = &intf->altsetting[intf->act_altsetting];
#else
	idesc = intf->cur_altsetting;
#endif

	/* Check if a usb remote has already been registered for this device */
	ir = get_prior_reg_ir(dev);

	if (!ir) {
		ir = new_irctl(intf);
		if (!ir)
#ifdef KERNEL_2_5
			return -ENOMEM;
#else
			return NULL;
#endif
	}
	type = ir->remote_type;

	/*
	 * step through the endpoints to find first in and first out endpoint
	 * of type interrupt transfer
	 */
#ifdef KERNEL_2_5
	for (i = 0; i < idesc->desc.bNumEndpoints; ++i) {
		ep = &idesc->endpoint[i].desc;
#else
	for (i = 0; i < idesc->bNumEndpoints; ++i) {
		ep = &idesc->endpoint[i];
#endif
		dprintk(DRIVER_NAME "[%d]: processing endpoint %d\n",
			dev->devnum, i);
		if (((ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
		     USB_DIR_IN) &&
		     ((ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
		      USB_ENDPOINT_XFER_INT)) {

			iep = new_in_endpt(ir, ep);
			if (iep)
			{
				usb_fill_int_urb(iep->urb, dev,
					usb_rcvintpipe(dev,
						iep->ep->bEndpointAddress),
					iep->buf, iep->len, usb_remote_recv,
					iep, iep->ep->bInterval);
#ifdef KERNEL_2_5
				iep->urb->transfer_dma = iep->dma;
				iep->urb->transfer_flags |=
					URB_NO_TRANSFER_DMA_MAP;
#endif
			}
		}

		if (((ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
		     USB_DIR_OUT) &&
		     ((ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
		      USB_ENDPOINT_XFER_INT) &&
		      (ir->out_init == NULL))
			ir->out_init = new_out_endpt(ir, ep);
	}
	if (list_empty(&ir->iep_listhead)) {
		printk(DRIVER_NAME "[%d]: inbound endpoint not found\n",
		       ir->devnum);
		free_irctl(ir, FREE_ALL);
#ifdef KERNEL_2_5
		return -ENODEV;
#else
		return NULL;
#endif
	}
	if (ir->dev_refcount == 1) {
		ir->d->minor = lirc_register_driver(ir->d);
		if (ir->d->minor < 0) {
			free_irctl(ir, FREE_ALL);
#ifdef KERNEL_2_5
			return -ENODEV;
#else
			return NULL;
#endif
		}

		/* Note new driver registration in kernel logs */
		log_usb_dev_info(dev);

		/* outbound data (initialization) */
		send_outbound_init(ir);
	}

#ifdef KERNEL_2_5
	usb_set_intfdata(intf, ir);
	return 0;
#else
	return ir;
#endif
}

#ifdef KERNEL_2_5
static void usb_remote_disconnect(struct usb_interface *intf)
{
	/* struct usb_device *dev = interface_to_usbdev(intf); */
	struct atirf_dev *ir = usb_get_intfdata(intf);
	usb_set_intfdata(intf, NULL);
#else
static void usb_remote_disconnect(struct usb_device *dev, void *ptr)
{
	struct atirf_dev *ir = ptr;
#endif

	dprintk(DRIVER_NAME ": disconnecting remote %d:\n",
		(ir ? ir->devnum : -1));
	if (!ir || !ir->d)
		return;

	if (ir->usbdev) {
		/* Only unregister once */
		ir->usbdev = NULL;
		unregister_from_lirc(ir);
	}

	/* This also removes the current remote from remote_list */
	free_irctl(ir, FREE_ALL);
}

static struct usb_driver usb_remote_driver = {
	LIRC_THIS_MODULE(.owner = THIS_MODULE)
	.name		= DRIVER_NAME,
	.probe		= usb_remote_probe,
	.disconnect	= usb_remote_disconnect,
	.id_table	= usb_remote_table
};

static int __init usb_remote_init(void)
{
	int i;

	INIT_LIST_HEAD(&remote_list);

	printk(KERN_INFO "\n" DRIVER_NAME ": " DRIVER_DESC " "
	       DRIVER_VERSION "\n");
	printk(DRIVER_NAME ": " DRIVER_AUTHOR "\n");
	dprintk(DRIVER_NAME ": debug mode enabled: "
		"$Id: lirc_atiusb.c,v 1.85 2009/03/11 00:21:46 jarodwilson Exp $\n");

	repeat_jiffies = repeat*HZ/100;

	i = usb_register(&usb_remote_driver);
	if (i) {
		printk(DRIVER_NAME ": usb register failed, result = %d\n", i);
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

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(usb, usb_remote_table);

module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Debug enabled or not (default: 0)");

module_param(mask, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(mask, "Set channel acceptance bit mask (default: 0xFFFF)");

module_param(unique, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(unique, "Enable channel-specific codes (default: 0)");

module_param(repeat, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(repeat, "Repeat timeout (1/100 sec) (default: 10)");

module_param(mdeadzone, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(mdeadzone, "rw2 mouse sensitivity threshold (default: 0)");

/*
 * Enabling this will cause the built-in Remote Wonder II repeat coding to
 * not be squashed.  The second byte of the keys output will then be:
 *
 *	1 initial press (button down)
 *	2 holding (button remains pressed)
 *	0 release (button up)
 *
 * By default, the driver emits 2 for both 1 and 2, and emits nothing for 0.
 * This is good for people having trouble getting their rw2 to send a good
 * consistent signal to the receiver.
 *
 * However, if you have no troubles with the driver outputting up-down pairs
 * at random points while you're still holding a button, then you can enable
 * this parameter to get finer grain repeat control out of your remote:
 *
 *	1 Emit a single (per-channel) virtual code for all up/down events
 *	2 Emit the actual rw2 output
 *
 * 1 is easier to write lircd configs for; 2 allows full control.
 */
module_param(emit_updown, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(emit_updown, "emit press/release codes (rw2): 0:don't "
		 "(default), 1:emit 2 codes only, 2:code for each button");

module_param(emit_modekeys, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(emit_modekeys, "emit keycodes for aux1-aux4, pc, and mouse "
		 "(rw2): 0:don't (default), 1:emit translated codes: one for "
		 "mode switch, one for same mode, 2:raw codes");

module_param(mgradient, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(mgradient, "rw2 mouse: 1000*gradient from E to NE (default: "
		 "500 => .5 => ~27 degrees)");

EXPORT_NO_SYMBOLS;
