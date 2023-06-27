/*      $Id: lirc_i2c.c,v 1.70 2009/08/30 16:59:53 jarodwilson Exp $      */

/*
 * lirc_i2c.c
 *
 * i2c IR driver for the onboard IR port on many TV tuner cards, including:
 *  -Flavors of the Hauppauge PVR-150/250/350
 *  -Hauppauge HVR-1300
 *  -PixelView (BT878P+W/FM)
 *  -KNC ONE TV Station/Anubis Typhoon TView Tuner
 *  -Asus TV-Box and Creative/VisionTek BreakOut-Box
 *  -Leadtek Winfast PVR2000
 *
 * Copyright (c) 2000 Gerd Knorr <kraxel@goldbach.in-berlin.de>
 * modified for PixelView (BT878P+W/FM) by
 *      Michal Kochanowicz <mkochano@pld.org.pl>
 *      Christoph Bartelmus <lirc@bartelmus.de>
 * modified for KNC ONE TV Station/Anubis Typhoon TView Tuner by
 *      Ulrich Mueller <ulrich.mueller42@web.de>
 * modified for Asus TV-Box and Creative/VisionTek BreakOut-Box by
 *      Stefan Jahn <stefan@lkcc.org>
 * modified for inclusion into kernel sources by
 *      Jerome Brock <jbrock@users.sourceforge.net>
 * modified for Leadtek Winfast PVR2000 by
 *      Thomas Reitmayr (treitmayr@yahoo.com)
 * modified for Hauppauge HVR-1300 by
 *      Jan Frey (jfrey@gmx.de)
 *
 * parts are cut&pasted from the old lirc_haup.c driver
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

#include "../kcompat.h"
#include "../lirc_dev/lirc_dev.h"

struct IR {
	struct lirc_driver l;
	struct i2c_client  c;
	int nextkey;
	unsigned char b[3];
	unsigned char bits;
	unsigned char flag;
};

#define DEVICE_NAME "lirc_i2c"

/* module parameters */
static int debug;	/* debug output */
static int minor = -1;	/* minor number */

#define dprintk(fmt, args...)						\
	do {								\
		if (debug)						\
			printk(KERN_DEBUG DEVICE_NAME ": " fmt,		\
			       ## args);				\
	} while (0)

static int reverse(int data, int bits)
{
	int i;
	int c;

	for (c = 0, i = 0; i < bits; i++)
		c |= ((data & (1<<i)) ? 1 : 0) << (bits-1-i);

	return c;
}

static int add_to_buf_adap(void *data, struct lirc_buffer *buf)
{
	struct IR *ir = data;
	unsigned char keybuf[4];

	keybuf[0] = 0x00;
	i2c_master_send(&ir->c, keybuf, 1);
	/* poll IR chip */
	if (i2c_master_recv(&ir->c, keybuf, sizeof(keybuf)) != sizeof(keybuf)) {
		dprintk("read error\n");
		return -EIO;
	}

	dprintk("key (0x%02x%02x%02x%02x)\n",
		keybuf[0], keybuf[1], keybuf[2], keybuf[3]);

	/* key pressed ? */
	if (keybuf[2] == 0xff)
		return -ENODATA;

	/* remove repeat bit */
	keybuf[2] &= 0x7f;
	keybuf[3] |= 0x80;

	lirc_buffer_write(buf, keybuf);
	return 0;
}

static int add_to_buf_pcf8574(void *data, struct lirc_buffer *buf)
{
	struct IR *ir = data;
	int rc;
	unsigned char all, mask;
	unsigned char key;

	/* compute all valid bits (key code + pressed/release flag) */
	all = ir->bits | ir->flag;

	/* save IR writable mask bits */
	mask = i2c_smbus_read_byte(&ir->c) & ~all;

	/* send bit mask */
	rc = i2c_smbus_write_byte(&ir->c, (0xff & all) | mask);

	/* receive scan code */
	rc = i2c_smbus_read_byte(&ir->c);

	if (rc == -1) {
		dprintk("%s read error\n", ir->c.name);
		return -EIO;
	}

	/* drop duplicate polls */
	if (ir->b[0] == (rc & all))
		return -ENODATA;

	ir->b[0] = rc & all;

	dprintk("%s key 0x%02X %s\n", ir->c.name, rc & ir->bits,
		(rc & ir->flag) ? "released" : "pressed");

	/* ignore released buttons */
	if (rc & ir->flag)
		return -ENODATA;

	/* set valid key code */
	key  = rc & ir->bits;
	lirc_buffer_write(buf, &key);
	return 0;
}

/* common for Hauppauge IR receivers */
static int add_to_buf_haup_common(void *data, struct lirc_buffer *buf,
		unsigned char *keybuf, int size, int offset)
{
	struct IR *ir = data;
	__u16 code;
	unsigned char codes[2];
	int ret;

	/* poll IR chip */
	ret = i2c_master_recv(&ir->c, keybuf, size);
	if (ret == size) {
		ir->b[0] = keybuf[offset];
		ir->b[1] = keybuf[offset+1];
		ir->b[2] = keybuf[offset+2];
		if (ir->b[0] != 0x00 && ir->b[1] != 0x00)
			dprintk("key (0x%02x/0x%02x)\n", ir->b[0], ir->b[1]);
	} else {
		dprintk("read error (ret=%d)\n", ret);
		/* keep last successful read buffer */
	}

	/* key pressed ? */
	if ((ir->b[0] & 0x80) == 0)
		return -ENODATA;

	/* look what we have */
	code = (((__u16)ir->b[0]&0x7f)<<6) | (ir->b[1]>>2);

	codes[0] = (code >> 8) & 0xff;
	codes[1] = code & 0xff;

	/* return it */
	dprintk("sending code 0x%02x%02x to lirc\n", codes[0], codes[1]);
	lirc_buffer_write(buf, codes);
	return 0;
}

/* specific for the Hauppauge PVR150 IR receiver */
static int add_to_buf_haup_pvr150(void *data, struct lirc_buffer *buf)
{
	unsigned char keybuf[6];
	/* fetch 6 bytes, first relevant is at offset 3 */
	return add_to_buf_haup_common(data, buf, keybuf, 6, 3);
}

/* used for all Hauppauge IR receivers but the PVR150 */
static int add_to_buf_haup(void *data, struct lirc_buffer *buf)
{
	unsigned char keybuf[3];
	/* fetch 3 bytes, first relevant is at offset 0 */
	return add_to_buf_haup_common(data, buf, keybuf, 3, 0);
}


static int add_to_buf_pvr2000(void *data, struct lirc_buffer *buf)
{
	struct IR *ir = data;
	unsigned char key;
	s32 flags;
	s32 code;

	/* poll IR chip */
	flags = i2c_smbus_read_byte_data(&ir->c, 0x10);
	if (-1 == flags) {
		dprintk("read error\n");
		return -ENODATA;
	}
	/* key pressed ? */
	if (0 == (flags & 0x80))
		return -ENODATA;

	/* read actual key code */
	code = i2c_smbus_read_byte_data(&ir->c, 0x00);
	if (-1 == code) {
		dprintk("read error\n");
		return -ENODATA;
	}

	key = code & 0xFF;

	dprintk("IR Key/Flags: (0x%02x/0x%02x)\n", key, flags & 0xFF);

	/* return it */
	lirc_buffer_write(buf, &key);
	return 0;
}

static int add_to_buf_pixelview(void *data, struct lirc_buffer *buf)
{
	struct IR *ir = data;
	unsigned char key;

	/* poll IR chip */
	if (1 != i2c_master_recv(&ir->c, &key, 1)) {
		dprintk("read error\n");
		return -1;
	}
	dprintk("key %02x\n", key);

	/* return it */
	lirc_buffer_write(buf, &key);
	return 0;
}

static int add_to_buf_pv951(void *data, struct lirc_buffer *buf)
{
	struct IR *ir = data;
	unsigned char key;
	unsigned char codes[4];

	/* poll IR chip */
	if (1 != i2c_master_recv(&ir->c, &key, 1)) {
		dprintk("read error\n");
		return -ENODATA;
	}
	/* ignore 0xaa */
	if (key == 0xaa)
		return -ENODATA;
	dprintk("key %02x\n", key);

	codes[0] = 0x61;
	codes[1] = 0xD6;
	codes[2] = reverse(key, 8);
	codes[3] = (~codes[2])&0xff;

	lirc_buffer_write(buf, codes);
	return 0;
}

static int add_to_buf_knc1(void *data, struct lirc_buffer *buf)
{
	static unsigned char last_key = 0xFF;
	struct IR *ir = data;
	unsigned char key;

	/* poll IR chip */
	if (1 != i2c_master_recv(&ir->c, &key, 1)) {
		dprintk("read error\n");
		return -ENODATA;
	}

	/*
	 * it seems that 0xFE indicates that a button is still held
	 * down, while 0xFF indicates that no button is held
	 * down. 0xFE sequences are sometimes interrupted by 0xFF
	 */

	dprintk("key %02x\n", key);

	if (key == 0xFF)
		return -ENODATA;

	if (key == 0xFE)
		key = last_key;

	last_key = key;
	lirc_buffer_write(buf, &key);

	return 0;
}

static int set_use_inc(void *data)
{
	struct IR *ir = data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	int ret;
#endif

	dprintk("%s called\n", __func__);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	i2c_use_client(&ir->c);
#else
	/* lock bttv in memory while /dev/lirc is in use  */
	ret = i2c_use_client(&ir->c);
	if (ret != 0)
		return ret;
#endif

	MOD_INC_USE_COUNT;
	return 0;
}

static void set_use_dec(void *data)
{
	struct IR *ir = data;

	dprintk("%s called\n", __func__);

	i2c_release_client(&ir->c);
	MOD_DEC_USE_COUNT;
}

static struct lirc_driver lirc_template = {
	.name		= "lirc_i2c",
	.set_use_inc	= set_use_inc,
	.set_use_dec	= set_use_dec,
	.dev		= NULL,
	.owner		= THIS_MODULE,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static int ir_attach(struct i2c_adapter *adap, int addr,
		      unsigned short flags, int kind);
static int ir_probe(struct i2c_adapter *adap);
# else
static int ir_probe(struct i2c_client *client, const struct i2c_device_id *id);
#endif
static int ir_remove(struct i2c_client *client);
static int ir_command(struct i2c_client *client, unsigned int cmd, void *arg);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 30)
static const struct i2c_device_id ir_receiver_id[] = {
	/* Generic entry for any IR receiver */
	{ "ir_video", 0 },
	/* IR device specific entries could be added here */
	{ }
};
#endif

static struct i2c_driver driver = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
	.name		= "i2c ir driver",
	.flags		= I2C_DF_NOTIFY,
#else
	.driver = {
		.owner	= THIS_MODULE,
		.name	= "i2c ir driver",
	},
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	.attach_adapter	= ir_probe,
	.detach_client	= ir_remove,
#else
	.probe		= ir_probe,
	.remove		= ir_remove,
	.id_table	= ir_receiver_id,
#endif
	.command	= ir_command,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static struct i2c_client client_template = {
	.name		= "unset",
	.driver		= &driver
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static int ir_attach(struct i2c_adapter *adap, int addr,
		     unsigned short flags, int kind)
#else
static void pcf_probe(struct i2c_client *client, struct IR *ir)
{
	int ret1, ret2, ret3, ret4;

	ret1 = i2c_smbus_write_byte(client, 0xff);
	ret2 = i2c_smbus_read_byte(client);
	ret3 = i2c_smbus_write_byte(client, 0x00);
	ret4 = i2c_smbus_read_byte(client);

	/* in the Asus TV-Box: bit 1-0 */
	if (((ret2 & 0x03) == 0x03) && ((ret4 & 0x03) == 0x00)) {
		ir->bits = (unsigned char) ~0x07;
		ir->flag = 0x04;
	/* in the Creative/VisionTek BreakOut-Box: bit 7-6 */
	} else if (((ret2 & 0xc0) == 0xc0) && ((ret4 & 0xc0) == 0x00)) {
		ir->bits = (unsigned char) ~0xe0;
		ir->flag = 0x20;
	}

	return;
}

static int ir_probe(struct i2c_client *client, const struct i2c_device_id *id)
#endif
{
	struct IR *ir;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	int err, retval;

	client_template.adapter = adap;
	client_template.addr = addr;
#else
	struct i2c_adapter *adap = client->adapter;
	unsigned short addr = client->addr;
	int retval;
#endif

	ir = kmalloc(sizeof(struct IR), GFP_KERNEL);
	if (!ir)
		return -ENOMEM;
	memcpy(&ir->l, &lirc_template, sizeof(struct lirc_driver));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	memcpy(&ir->c, &client_template, sizeof(struct i2c_client));

	ir->c.adapter = adap;
	ir->c.addr    = addr;
	i2c_set_clientdata(&ir->c, ir);
#else
	memcpy(&ir->c, client, sizeof(struct i2c_client));

	i2c_set_clientdata(client, ir);
#endif
	ir->l.data    = ir;
	ir->l.minor   = minor;
	ir->l.sample_rate = 10;
	ir->l.dev     = &ir->c.dev;
	ir->nextkey   = -1;

	switch (addr) {
	case 0x64:
		strlcpy(ir->c.name, "Pixelview IR", I2C_NAME_SIZE);
		ir->l.code_length = 8;
		ir->l.add_to_buf = add_to_buf_pixelview;
		break;
	case 0x4b:
		strlcpy(ir->c.name, "PV951 IR", I2C_NAME_SIZE);
		ir->l.code_length = 32;
		ir->l.add_to_buf = add_to_buf_pv951;
		break;
	case 0x71:
#ifdef I2C_HW_B_CX2341X
		if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_BT848) ||
		    adap->id == (I2C_ALGO_BIT | I2C_HW_B_CX2341X)) {
#else
		if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_BT848)) {
#endif
			/*
			 * The PVR150 IR receiver uses the same protocol as
			 * other Hauppauge cards, but the data flow is
			 * different, so we need to deal with it by its own.
			 */
			strlcpy(ir->c.name, "Hauppauge PVR150", I2C_NAME_SIZE);
		} else /* I2C_HW_B_CX2388x */
			strlcpy(ir->c.name, "Hauppauge HVR1300", I2C_NAME_SIZE);
		ir->l.code_length = 13;
		ir->l.add_to_buf = add_to_buf_haup_pvr150;
		break;
	case 0x6b:
		strlcpy(ir->c.name, "Adaptec IR", I2C_NAME_SIZE);
		ir->l.code_length = 32;
		ir->l.add_to_buf = add_to_buf_adap;
		break;
	case 0x18:
	case 0x1a:
#ifdef I2C_HW_B_CX2341X
		if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_BT848) ||
		    adap->id == (I2C_ALGO_BIT | I2C_HW_B_CX2341X)) {
#else
		if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_BT848)) {
#endif
			strlcpy(ir->c.name, "Hauppauge IR", I2C_NAME_SIZE);
			ir->l.code_length = 13;
			ir->l.add_to_buf = add_to_buf_haup;
		} else { /* I2C_HW_B_CX2388x */
			strlcpy(ir->c.name, "Leadtek IR", I2C_NAME_SIZE);
			ir->l.code_length = 8;
			ir->l.add_to_buf = add_to_buf_pvr2000;
		}
		break;
	case 0x30:
		strlcpy(ir->c.name, "KNC ONE IR", I2C_NAME_SIZE);
		ir->l.code_length = 8;
		ir->l.add_to_buf = add_to_buf_knc1;
		break;
	case 0x21:
	case 0x23:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
		ir->bits = flags & 0xff;
		ir->flag = (flags >> 8) & 0xff;
#else
		pcf_probe(client, ir);
#endif
		strlcpy(ir->c.name, "TV-Box IR", I2C_NAME_SIZE);
		ir->l.code_length = 8;
		ir->l.add_to_buf = add_to_buf_pcf8574;
		break;
	default:
		/* shouldn't happen */
		printk("lirc_i2c: Huh? unknown i2c address (0x%02x)?\n", addr);
		kfree(ir);
		return -EINVAL;
	}
	printk(KERN_INFO "lirc_i2c: chip 0x%x found @ 0x%02x (%s)\n",
	       adap->id, addr, ir->c.name);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	/* register device */
	err = i2c_attach_client(&ir->c);
	if (err) {
		kfree(ir);
		return err;
	}
#endif

	retval = lirc_register_driver(&ir->l);

	if (retval < 0) {
		printk(KERN_ERR "lirc_i2c: failed to register driver!\n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
		i2c_detach_client(&ir->c);
#endif
		kfree(ir);
		return retval;
	}

	ir->l.minor = retval;

	return 0;
}

static int ir_remove(struct i2c_client *client)
{
	struct IR *ir = i2c_get_clientdata(client);

	/* unregister device */
	lirc_unregister_driver(ir->l.minor);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	i2c_detach_client(&ir->c);
#endif

	/* free memory */
	kfree(ir);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static int ir_probe(struct i2c_adapter *adap)
{
	/*
	 * The external IR receiver is at i2c address 0x34 (0x35 for
	 * reads).  Future Hauppauge cards will have an internal
	 * receiver at 0x30 (0x31 for reads).  In theory, both can be
	 * fitted, and Hauppauge suggest an external overrides an
	 * internal.
	 *
	 * That's why we probe 0x1a (~0x34) first. CB
	 *
	 * The i2c address for the Hauppauge PVR-150 card is 0xe2,
	 * so we need to probe 0x71 as well.
	 */

	static const int probe[] = {
		0x1a, /* Hauppauge IR external */
		0x18, /* Hauppauge IR internal */
		0x71, /* Hauppauge IR (PVR150) */
		0x4b, /* PV951 IR */
		0x64, /* Pixelview IR */
		0x30, /* KNC ONE IR */
		0x6b, /* Adaptec IR */
		-1};

#ifdef I2C_HW_B_CX2388x
	static const int probe_cx88[] = {
		0x18, /* Leadtek Winfast PVR2000 */
		0x71, /* Hauppauge HVR-IR */
		-1};
#endif

	struct i2c_client c;
	char buf;
	int i, rc;

	memset(&c, 0, sizeof(c));
#ifdef I2C_HW_B_CX2341X
	if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_BT848) ||
	    adap->id == (I2C_ALGO_BIT | I2C_HW_B_CX2341X)) {
#else
	if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_BT848)) {
#endif
		c.adapter = adap;
		for (i = 0; -1 != probe[i]; i++) {
			c.addr = probe[i];
			rc = i2c_master_recv(&c, &buf, 1);
			dprintk("probe 0x%02x @ %s: %s\n",
				probe[i], adap->name,
				(1 == rc) ? "yes" : "no");
			if (1 == rc) {
				rc = ir_attach(adap, probe[i], 0, 0);
				if (rc < 0)
					goto attach_fail;
			}
		}
	}

#ifdef I2C_HW_B_CX2388x
	/* Leadtek Winfast PVR2000 or Hauppauge HVR-1300 */
	else if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_CX2388x)) {
		c.adapter = adap;
		for (i = 0; -1 != probe_cx88[i]; i++) {
			c.addr = probe_cx88[i];
			rc = i2c_master_recv(&c, &buf, 1);
			dprintk("probe 0x%02x @ %s: %s\n",
				c.addr, adap->name,
				(1 == rc) ? "yes" : "no");
			if (1 == rc) {
				rc = ir_attach(adap, c.addr, 0, 0);
				if (rc < 0)
					goto attach_fail;
			}
		}
	}
#endif

	/* Asus TV-Box and Creative/VisionTek BreakOut-Box (PCF8574) */
	else if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_RIVA)) {
		/*
		 * addresses to probe;
		 * leave 0x24 and 0x25 because SAA7113H possibly uses it
		 * 0x21 and 0x22 possibly used by SAA7108E
		 * Asus:      0x21 is a correct address (channel 1 of PCF8574)
		 * Creative:  0x23 is a correct address (channel 3 of PCF8574)
		 * VisionTek: 0x23 is a correct address (channel 3 of PCF8574)
		 */
		static const int pcf_probe[] = { 0x20, 0x21, 0x22, 0x23,
						 0x24, 0x25, 0x26, 0x27, -1 };
		int ret1, ret2, ret3, ret4;
		unsigned char bits = 0, flag = 0;

		c.adapter = adap;
		for (i = 0; -1 != pcf_probe[i]; i++) {
			c.addr = pcf_probe[i];
			ret1 = i2c_smbus_write_byte(&c, 0xff);
			ret2 = i2c_smbus_read_byte(&c);
			ret3 = i2c_smbus_write_byte(&c, 0x00);
			ret4 = i2c_smbus_read_byte(&c);

			/* ensure that the writable bitmask works correctly */
			rc = 0;
			if (ret1 != -1 && ret2 != -1 &&
			    ret3 != -1 && ret4 != -1) {
				/* in the Asus TV-Box: bit 1-0 */
				if (((ret2 & 0x03) == 0x03) &&
				    ((ret4 & 0x03) == 0x00)) {
					bits = (unsigned char) ~0x07;
					flag = 0x04;
					rc = 1;
				}
			/* in the Creative/VisionTek BreakOut-Box: bit 7-6 */
				if (((ret2 & 0xc0) == 0xc0) &&
				    ((ret4 & 0xc0) == 0x00)) {
					bits = (unsigned char) ~0xe0;
					flag = 0x20;
					rc = 1;
				}
			}
			dprintk("probe 0x%02x @ %s: %s\n",
				c.addr, adap->name, rc ? "yes" : "no");
			if (rc) {
				rc = ir_attach(adap, pcf_probe[i],
					       bits | (flag << 8), 0);
				if (rc < 0)
					goto attach_fail;
			}
		}
	}

	return 0;

attach_fail:
	printk(KERN_ERR "lirc_i2c: %s: ir_attach failed!\n", __func__);
	return rc;

}
#endif

static int ir_command(struct i2c_client *client, unsigned int cmd, void *arg)
{
	/* nothing */
	return 0;
}

#ifdef MODULE

static int __init lirc_i2c_init(void)
{
	request_module("bttv");
	request_module("rivatv");
	request_module("ivtv");
	request_module("cx8800");
	i2c_add_driver(&driver);
	return 0;
}

static void __exit lirc_i2c_exit(void)
{
	i2c_del_driver(&driver);
}

MODULE_DESCRIPTION("Infrared receiver driver for Hauppauge and "
		   "Pixelview cards (i2c stack)");
MODULE_AUTHOR("Gerd Knorr, Michal Kochanowicz, Christoph Bartelmus, "
	      "Ulrich Mueller, Stefan Jahn, Jerome Brock");
MODULE_LICENSE("GPL");

module_param(minor, int, S_IRUGO);
MODULE_PARM_DESC(minor, "Preferred minor device number");

module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Enable debugging messages");

module_init(lirc_i2c_init);
module_exit(lirc_i2c_exit);
EXPORT_NO_SYMBOLS;

#endif /* MODULE */
