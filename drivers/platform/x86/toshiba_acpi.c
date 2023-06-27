/*
 *  toshiba_acpi.c - Toshiba Laptop ACPI Extras
 *
 *
 *  Copyright (C) 2002-2004 John Belmonte
 *  Copyright (C) 2008 Philip Langdale
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
 *
 *
 *  The devolpment page for this driver is located at
 *  http://memebeam.org/toys/ToshibaAcpiDriver.
 *
 *  Credits:
 *	Jonathan A. Buzzard - Toshiba HCI info, and critical tips on reverse
 *		engineering the Windows drivers
 *	Yasushi Nagato - changes for linux kernel 2.4 -> 2.5
 *	Rob Miller - TV out and hotkeys help
 *      Daniel Silverstone - Punting of hotkeys via acpi using a thread    	
 *
 *  PLEASE NOTE
 *
 *  This is an experimental version of toshiba_acpi which includes emulation
 *  of the original toshiba driver's /proc/toshiba and /dev/toshiba,
 *  allowing Toshiba userspace utilities to work.  The relevant code was
 *  based on toshiba.c (copyright 1996-2001 Jonathan A. Buzzard) and
 *  incorporated into this driver with help from Gintautas Miliauskas,
 *  Charles Schwieters, and Christoph Burger-Scheidlin.
 *
 *  Caveats:
 *      * hotkey status in /proc/toshiba is not implemented
 *      * to make accesses to /dev/toshiba load this driver instead of
 *          the original driver, you will have to modify your module
 *          auto-loading configuration
 *
 *  TODO
 *
 */

#define TOSHIBA_ACPI_VERSION	"0.19-dev-acpikeys"
#define PROC_INTERFACE_VERSION	1

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/miscdevice.h>
#include <linux/toshiba.h>
#include <asm/io.h>
#include <linux/backlight.h>
#include <linux/platform_device.h>
#include <linux/rfkill.h>
#include <linux/input-polldev.h>
#include <linux/freezer.h>

#include <asm/uaccess.h>

#include <acpi/acpi_drivers.h>

MODULE_AUTHOR("John Belmonte");
MODULE_DESCRIPTION("Toshiba Laptop ACPI Extras Driver");
MODULE_LICENSE("GPL");

#define MY_LOGPREFIX "toshiba_acpi: "
#define MY_ERR KERN_ERR MY_LOGPREFIX
#define MY_NOTICE KERN_NOTICE MY_LOGPREFIX
#define MY_INFO KERN_INFO MY_LOGPREFIX

/* Toshiba ACPI method paths */
#define METHOD_LCD_BRIGHTNESS	"\\_SB_.PCI0.VGA_.LCD_._BCM"
#define METHOD_HCI_1		"\\_SB_.VALD.GHCI"
#define METHOD_HCI_2		"\\_SB_.VALZ.GHCI"
#define METHOD_VIDEO_OUT	"\\_SB_.VALX.DSSX"

/* Toshiba HCI interface definitions
 *
 * HCI is Toshiba's "Hardware Control Interface" which is supposed to
 * be uniform across all their models.  Ideally we would just call
 * dedicated ACPI methods instead of using this primitive interface.
 * However the ACPI methods seem to be incomplete in some areas (for
 * example they allow setting, but not reading, the LCD brightness value),
 * so this is still useful.
 */

#define HCI_WORDS			6

/* operations */
#define HCI_SET				0xff00
#define HCI_GET				0xfe00

/* return codes */
#define HCI_SUCCESS			0x0000
#define HCI_FAILURE			0x1000
#define HCI_NOT_SUPPORTED		0x8000
#define HCI_EMPTY			0x8c00

/* registers */
#define HCI_FAN				0x0004
#define HCI_SYSTEM_EVENT		0x0016
#define HCI_VIDEO_OUT			0x001c
#define HCI_HOTKEY_EVENT		0x001e
#define HCI_LCD_BRIGHTNESS		0x002a
#define HCI_WIRELESS			0x0056

/* field definitions */
#define HCI_LCD_BRIGHTNESS_BITS		3
#define HCI_LCD_BRIGHTNESS_SHIFT	(16-HCI_LCD_BRIGHTNESS_BITS)
#define HCI_LCD_BRIGHTNESS_LEVELS	(1 << HCI_LCD_BRIGHTNESS_BITS)
#define HCI_VIDEO_OUT_LCD		0x1
#define HCI_VIDEO_OUT_CRT		0x2
#define HCI_VIDEO_OUT_TV		0x4
#define HCI_WIRELESS_KILL_SWITCH	0x01
#define HCI_WIRELESS_BT_PRESENT		0x0f
#define HCI_WIRELESS_BT_ATTACH		0x40
#define HCI_WIRELESS_BT_POWER		0x80

static const struct acpi_device_id toshiba_device_ids[] = {
	{"TOS6200", 0},
	{"TOS6208", 0},
	{"TOS1900", 0},
	{"", 0},
};
MODULE_DEVICE_TABLE(acpi, toshiba_device_ids);

/* utility
 */

static __inline__ void _set_bit(u32 * word, u32 mask, int value)
{
	*word = (*word & ~mask) | (mask * value);
}

/* acpi interface wrappers
 */

static int is_valid_acpi_path(const char *methodName)
{
	acpi_handle handle;
	acpi_status status;

	status = acpi_get_handle(NULL, (char *)methodName, &handle);
	return !ACPI_FAILURE(status);
}

static int write_acpi_int(const char *methodName, int val)
{
	struct acpi_object_list params;
	union acpi_object in_objs[1];
	acpi_status status;

	params.count = ARRAY_SIZE(in_objs);
	params.pointer = in_objs;
	in_objs[0].type = ACPI_TYPE_INTEGER;
	in_objs[0].integer.value = val;

	status = acpi_evaluate_object(NULL, (char *)methodName, &params, NULL);
	return (status == AE_OK);
}

#if 0
static int read_acpi_int(const char *methodName, int *pVal)
{
	struct acpi_buffer results;
	union acpi_object out_objs[1];
	acpi_status status;

	results.length = sizeof(out_objs);
	results.pointer = out_objs;

	status = acpi_evaluate_object(0, (char *)methodName, 0, &results);
	*pVal = out_objs[0].integer.value;

	return (status == AE_OK) && (out_objs[0].type == ACPI_TYPE_INTEGER);
}
#endif

static const char *method_hci /*= 0*/ ;

/* Perform a raw HCI call.  Here we don't care about input or output buffer
 * format.
 */
static acpi_status hci_raw(const u32 in[HCI_WORDS], u32 out[HCI_WORDS])
{
	struct acpi_object_list params;
	union acpi_object in_objs[HCI_WORDS];
	struct acpi_buffer results;
	union acpi_object out_objs[HCI_WORDS + 1];
	acpi_status status;
	int i;

	params.count = HCI_WORDS;
	params.pointer = in_objs;
	for (i = 0; i < HCI_WORDS; ++i) {
		in_objs[i].type = ACPI_TYPE_INTEGER;
		in_objs[i].integer.value = in[i];
	}

	results.length = sizeof(out_objs);
	results.pointer = out_objs;

	status = acpi_evaluate_object(NULL, (char *)method_hci, &params,
				      &results);
	if ((status == AE_OK) && (out_objs->package.count <= HCI_WORDS)) {
		for (i = 0; i < out_objs->package.count; ++i) {
			out[i] = out_objs->package.elements[i].integer.value;
		}
	}

	return status;
}

/* common hci tasks (get or set one or two value)
 *
 * In addition to the ACPI status, the HCI system returns a result which
 * may be useful (such as "not supported").
 */

static acpi_status hci_write1(u32 reg, u32 in1, u32 * result)
{
	u32 in[HCI_WORDS] = { HCI_SET, reg, in1, 0, 0, 0 };
	u32 out[HCI_WORDS];
	acpi_status status = hci_raw(in, out);
	*result = (status == AE_OK) ? out[0] : HCI_FAILURE;
	return status;
}

static acpi_status hci_read1(u32 reg, u32 * out1, u32 * result)
{
	u32 in[HCI_WORDS] = { HCI_GET, reg, 0, 0, 0, 0 };
	u32 out[HCI_WORDS];
	acpi_status status = hci_raw(in, out);
	*out1 = out[2];
	*result = (status == AE_OK) ? out[0] : HCI_FAILURE;
	return status;
}

static acpi_status hci_write2(u32 reg, u32 in1, u32 in2, u32 *result)
{
	u32 in[HCI_WORDS] = { HCI_SET, reg, in1, in2, 0, 0 };
	u32 out[HCI_WORDS];
	acpi_status status = hci_raw(in, out);
	*result = (status == AE_OK) ? out[0] : HCI_FAILURE;
	return status;
}

static acpi_status hci_read2(u32 reg, u32 *out1, u32 *out2, u32 *result)
{
	u32 in[HCI_WORDS] = { HCI_GET, reg, *out1, *out2, 0, 0 };
	u32 out[HCI_WORDS];
	acpi_status status = hci_raw(in, out);
	*out1 = out[2];
	*out2 = out[3];
	*result = (status == AE_OK) ? out[0] : HCI_FAILURE;
	return status;
}

struct toshiba_acpi_dev {
	struct platform_device *p_dev;
	struct rfkill *bt_rfk;

	const char *bt_name;

	struct mutex mutex;
};

static struct toshiba_acpi_dev toshiba_acpi = {
	.bt_name = "Toshiba Bluetooth",
};

/* Bluetooth rfkill handlers */

static u32 hci_get_bt_present(bool *present)
{
	u32 hci_result;
	u32 value, value2;

	value = 0;
	value2 = 0;
	hci_read2(HCI_WIRELESS, &value, &value2, &hci_result);
	if (hci_result == HCI_SUCCESS)
		*present = (value & HCI_WIRELESS_BT_PRESENT) ? true : false;

	return hci_result;
}

static u32 hci_get_radio_state(bool *radio_state)
{
	u32 hci_result;
	u32 value, value2;

	value = 0;
	value2 = 0x0001;
	hci_read2(HCI_WIRELESS, &value, &value2, &hci_result);

	*radio_state = value & HCI_WIRELESS_KILL_SWITCH;
	return hci_result;
}

static int bt_rfkill_set_block(void *data, bool blocked)
{
	struct toshiba_acpi_dev *dev = data;
	u32 result1, result2;
	u32 value;
	int err;
	bool radio_state;

	value = (blocked == false);

	mutex_lock(&dev->mutex);
	if (hci_get_radio_state(&radio_state) != HCI_SUCCESS) {
		err = -EBUSY;
		goto out;
	}

	if (!radio_state) {
		err = 0;
		goto out;
	}

	hci_write2(HCI_WIRELESS, value, HCI_WIRELESS_BT_POWER, &result1);
	hci_write2(HCI_WIRELESS, value, HCI_WIRELESS_BT_ATTACH, &result2);

	if (result1 != HCI_SUCCESS || result2 != HCI_SUCCESS)
		err = -EBUSY;
	else
		err = 0;
 out:
	mutex_unlock(&dev->mutex);
	return err;
}

static void bt_rfkill_poll(struct rfkill *rfkill, void *data)
{
	bool new_rfk_state;
	bool value;
	u32 hci_result;
	struct toshiba_acpi_dev *dev = data;

	mutex_lock(&dev->mutex);

	hci_result = hci_get_radio_state(&value);
	if (hci_result != HCI_SUCCESS) {
		/* Can't do anything useful */
		mutex_unlock(&dev->mutex);
		return;
	}

	new_rfk_state = value;

	mutex_unlock(&dev->mutex);

	if (rfkill_set_hw_state(rfkill, !new_rfk_state))
		bt_rfkill_set_block(data, true);
}

static const struct rfkill_ops toshiba_rfk_ops = {
	.set_block = bt_rfkill_set_block,
	.poll = bt_rfkill_poll,
};

static struct proc_dir_entry *toshiba_proc_dir /*= 0*/ ;
static struct backlight_device *toshiba_backlight_device;
static int force_fan;
static int last_key_event;
static int key_event_valid;
static int hotkeys_over_acpi = 1;
static int hotkeys_check_per_sec = 2;

module_param(hotkeys_over_acpi, uint, 0400);
module_param(hotkeys_check_per_sec, uint, 0400);

typedef struct _ProcItem {
	const char *name;
	char *(*read_func) (char *);
	unsigned long (*write_func) (const char *, unsigned long);
} ProcItem;

/* proc file handlers
 */

static int
dispatch_read(char *page, char **start, off_t off, int count, int *eof,
	      ProcItem * item)
{
	char *p = page;
	int len;

	if (off == 0)
		p = item->read_func(p);

	/* ISSUE: I don't understand this code */
	len = (p - page);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}

static int
dispatch_write(struct file *file, const char __user * buffer,
	       unsigned long count, ProcItem * item)
{
	int result;
	char *tmp_buffer;

	/* Arg buffer points to userspace memory, which can't be accessed
	 * directly.  Since we're making a copy, zero-terminate the
	 * destination so that sscanf can be used on it safely.
	 */
	tmp_buffer = kmalloc(count + 1, GFP_KERNEL);
	if (!tmp_buffer)
		return -ENOMEM;

	if (copy_from_user(tmp_buffer, buffer, count)) {
		result = -EFAULT;
	} else {
		tmp_buffer[count] = 0;
		result = item->write_func(tmp_buffer, count);
	}
	kfree(tmp_buffer);
	return result;
}

static int get_lcd(struct backlight_device *bd)
{
	u32 hci_result;
	u32 value;

	hci_read1(HCI_LCD_BRIGHTNESS, &value, &hci_result);
	if (hci_result == HCI_SUCCESS) {
		return (value >> HCI_LCD_BRIGHTNESS_SHIFT);
	} else
		return -EFAULT;
}

static char *read_lcd(char *p)
{
	int value = get_lcd(NULL);

	if (value >= 0) {
		p += sprintf(p, "brightness:              %d\n", value);
		p += sprintf(p, "brightness_levels:       %d\n",
			     HCI_LCD_BRIGHTNESS_LEVELS);
	} else {
		printk(MY_ERR "Error reading LCD brightness\n");
	}

	return p;
}

static int set_lcd(int value)
{
	u32 hci_result;

	value = value << HCI_LCD_BRIGHTNESS_SHIFT;
	hci_write1(HCI_LCD_BRIGHTNESS, value, &hci_result);
	if (hci_result != HCI_SUCCESS)
		return -EFAULT;

	return 0;
}

static int set_lcd_status(struct backlight_device *bd)
{
	return set_lcd(bd->props.brightness);
}

static unsigned long write_lcd(const char *buffer, unsigned long count)
{
	int value;
	int ret;

	if (sscanf(buffer, " brightness : %i", &value) == 1 &&
	    value >= 0 && value < HCI_LCD_BRIGHTNESS_LEVELS) {
		ret = set_lcd(value);
		if (ret == 0)
			ret = count;
	} else {
		ret = -EINVAL;
	}
	return ret;
}

static char *read_video(char *p)
{
	u32 hci_result;
	u32 value;

	hci_read1(HCI_VIDEO_OUT, &value, &hci_result);
	if (hci_result == HCI_SUCCESS) {
		int is_lcd = (value & HCI_VIDEO_OUT_LCD) ? 1 : 0;
		int is_crt = (value & HCI_VIDEO_OUT_CRT) ? 1 : 0;
		int is_tv = (value & HCI_VIDEO_OUT_TV) ? 1 : 0;
		p += sprintf(p, "lcd_out:                 %d\n", is_lcd);
		p += sprintf(p, "crt_out:                 %d\n", is_crt);
		p += sprintf(p, "tv_out:                  %d\n", is_tv);
	} else {
		printk(MY_ERR "Error reading video out status\n");
	}

	return p;
}

static unsigned long write_video(const char *buffer, unsigned long count)
{
	int value;
	int remain = count;
	int lcd_out = -1;
	int crt_out = -1;
	int tv_out = -1;
	u32 hci_result;
	u32 video_out;

	/* scan expression.  Multiple expressions may be delimited with ;
	 *
	 *  NOTE: to keep scanning simple, invalid fields are ignored
	 */
	while (remain) {
		if (sscanf(buffer, " lcd_out : %i", &value) == 1)
			lcd_out = value & 1;
		else if (sscanf(buffer, " crt_out : %i", &value) == 1)
			crt_out = value & 1;
		else if (sscanf(buffer, " tv_out : %i", &value) == 1)
			tv_out = value & 1;
		/* advance to one character past the next ; */
		do {
			++buffer;
			--remain;
		}
		while (remain && *(buffer - 1) != ';');
	}

	hci_read1(HCI_VIDEO_OUT, &video_out, &hci_result);
	if (hci_result == HCI_SUCCESS) {
		unsigned int new_video_out = video_out;
		if (lcd_out != -1)
			_set_bit(&new_video_out, HCI_VIDEO_OUT_LCD, lcd_out);
		if (crt_out != -1)
			_set_bit(&new_video_out, HCI_VIDEO_OUT_CRT, crt_out);
		if (tv_out != -1)
			_set_bit(&new_video_out, HCI_VIDEO_OUT_TV, tv_out);
		/* To avoid unnecessary video disruption, only write the new
		 * video setting if something changed. */
		if (new_video_out != video_out)
			write_acpi_int(METHOD_VIDEO_OUT, new_video_out);
	} else {
		return -EFAULT;
	}

	return count;
}

static char *read_fan(char *p)
{
	u32 hci_result;
	u32 value;

	hci_read1(HCI_FAN, &value, &hci_result);
	if (hci_result == HCI_SUCCESS) {
		p += sprintf(p, "running:                 %d\n", (value > 0));
		p += sprintf(p, "force_on:                %d\n", force_fan);
	} else {
		printk(MY_ERR "Error reading fan status\n");
	}

	return p;
}

static unsigned long write_fan(const char *buffer, unsigned long count)
{
	int value;
	u32 hci_result;

	if (sscanf(buffer, " force_on : %i", &value) == 1 &&
	    value >= 0 && value <= 1) {
		hci_write1(HCI_FAN, value, &hci_result);
		if (hci_result != HCI_SUCCESS)
			return -EFAULT;
		else
			force_fan = value;
	} else {
		return -EINVAL;
	}

	return count;
}

static char *read_keys(char *p)
{
	u32 hci_result;
	u32 value;

	if (!hotkeys_over_acpi) {
		if (!key_event_valid) {
			hci_read1(HCI_SYSTEM_EVENT, &value, &hci_result);
			if (hci_result == HCI_SUCCESS) {
				key_event_valid = 1;
				last_key_event = value;
			} else if (hci_result == HCI_EMPTY) {
				/* better luck next time */
			} else if (hci_result == HCI_NOT_SUPPORTED) {
				/* This is a workaround for an
				 * unresolved issue on some machines
				 * where system events sporadically
				 * become disabled. */
				hci_write1(HCI_SYSTEM_EVENT, 1, &hci_result);
				printk(MY_NOTICE "Re-enabled hotkeys\n");
			} else {
				printk(MY_ERR "Error reading hotkey status\n");
				goto end;
			}
		}
	} else {
		key_event_valid = 0;
		last_key_event = 0;
	}

	p += sprintf(p, "hotkey_ready:            %d\n", key_event_valid);
	p += sprintf(p, "hotkey:                  0x%04x\n", last_key_event);
	p += sprintf(p, "hotkeys_via_acpi:        %d\n", hotkeys_over_acpi);

      end:
	return p;
}

static unsigned long write_keys(const char *buffer, unsigned long count)
{
	int value;

	if (sscanf(buffer, " hotkey_ready : %i", &value) == 1 && value == 0) {
		key_event_valid = 0;
	} else {
		return -EINVAL;
	}

	return count;
}

static char *read_version(char *p)
{
	p += sprintf(p, "driver:                  %s\n", TOSHIBA_ACPI_VERSION);
	p += sprintf(p, "proc_interface:          %d\n",
		     PROC_INTERFACE_VERSION);
	return p;
}

/* /dev/toshiba and /proc/toshiba handlers {{{
 *
 * ISSUE: lots of magic numbers and mysterious code
 */

#define TOSH_MINOR_DEV		181
#define OLD_PROC_TOSHIBA	"toshiba"

static int
tosh_acpi_bridge(SMMRegisters* regs)
{
	acpi_status status;

	/* assert(sizeof(SMMRegisters) == sizeof(u32)*HCI_WORDS); */
	status = hci_raw((u32*)regs, (u32*)regs);
	if (status == AE_OK && (regs->eax & 0xff00) == HCI_SUCCESS)
		return 0;

	return -EINVAL;
}

static int
tosh_ioctl(struct inode* ip, struct file* fp, unsigned int cmd,
	unsigned long arg)
{
	SMMRegisters regs;
	unsigned short ax,bx;
	int err;

	if ((!arg) || (cmd != TOSH_SMM))
		return -EINVAL;

	if (copy_from_user(&regs, (SMMRegisters*)arg, sizeof(SMMRegisters)))
		return -EFAULT;

	ax = regs.eax & 0xff00;
	bx = regs.ebx & 0xffff;

	/* block HCI calls to read/write memory & PCI devices */
	if (((ax==HCI_SET) || (ax==HCI_GET)) && (bx>0x0069))
		return -EINVAL;

	err = tosh_acpi_bridge(&regs);

	if (copy_to_user((SMMRegisters*)arg, &regs, sizeof(SMMRegisters)))
		return -EFAULT;

	return err;
}

static int
tosh_get_machine_id(void __iomem *bios)
{
	int id;
	unsigned short bx,cx;
	unsigned long address;

	id = (0x100*(int) readb(bios+0xfffe))+((int) readb(bios+0xfffa));

	/* do we have a SCTTable machine identication number on our hands */
	if (id==0xfc2f) {
		bx = 0xe6f5; /* cheat */
		/* now twiddle with our pointer a bit */
		address = 0x00000000 + bx;
		cx = readw(bios + address);
		address = 0x00000009 + bx + cx;
		cx = readw(bios + address);
		address = 0x0000000a + cx;
		cx = readw(bios + address);
		/* now construct our machine identification number */
		id = ((cx & 0xff)<<8)+((cx & 0xff00)>>8);
	}

	return id;
}

static int tosh_id;
static int tosh_bios;
static int tosh_date;
static int tosh_sci;

static struct file_operations tosh_fops = {
	.owner = THIS_MODULE,
	.ioctl = tosh_ioctl
};

static struct miscdevice tosh_device = {
	TOSH_MINOR_DEV,
	"toshiba",
	&tosh_fops
};

static void
setup_tosh_info(void __iomem *bios)
{
	int major, minor;
	int day, month, year;

	tosh_id = tosh_get_machine_id(bios);

	/* get the BIOS version */
	major = readb(bios + 0xe009)-'0';
	minor = ((readb(bios + 0xe00b)-'0')*10)+(readb(bios + 0xe00c)-'0');
	tosh_bios = (major*0x100)+minor;

	/* get the BIOS date */
	day = ((readb(bios + 0xfff5)-'0')*10)+(readb(bios + 0xfff6)-'0');
	month = ((readb(bios + 0xfff8)-'0')*10)+(readb(bios + 0xfff9)-'0');
	year = ((readb(bios + 0xfffb)-'0')*10)+(readb(bios + 0xfffc)-'0');
	tosh_date = (((year-90) & 0x1f)<<10) | ((month & 0xf)<<6)
		| ((day & 0x1f)<<1);
}

/* /proc/toshiba read handler */
static int
tosh_proc_show(struct seq_file *m, void *v)
{
	/* TODO: tosh_fn_status() */
	int key = 0;

	/* Format:
	 *    0) Linux driver version (this will change if format changes)
	 *    1) Machine ID
	 *    2) SCI version
	 *    3) BIOS version (major, minor)
	 *    4) BIOS date (in SCI date format)
	 *    5) Fn Key status
	 */

	seq_printf(m, "1.1 0x%04x %d.%d %d.%d 0x%04x 0x%02x\n",
		tosh_id,
		(tosh_sci & 0xff00)>>8,
		tosh_sci & 0xff,
		(tosh_bios & 0xff00)>>8,
		tosh_bios & 0xff,
		tosh_date,
		key);

	return 0;
}

static int tosh_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tosh_proc_show, NULL);
}

static const struct file_operations tosh_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= tosh_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init
old_driver_emulation_init(void)
{
	int status;
	void __iomem *bios = ioremap(0xf0000, 0x10000);
	if (!bios)
		return -ENOMEM;

	if ((status = misc_register(&tosh_device))) {
		printk(MY_ERR "failed to register misc device %d (\"%s\")\n",
			tosh_device.minor, tosh_device.name);
		return status;
	}

	setup_tosh_info(bios);
	proc_create(OLD_PROC_TOSHIBA, 0, NULL, &tosh_proc_fops);

	iounmap(bios);

	return 0;
}

static void __exit
old_driver_emulation_exit(void)
{
	remove_proc_entry(OLD_PROC_TOSHIBA, NULL);
	misc_deregister(&tosh_device);
}

/* }}} end of /dev/toshiba and /proc/toshiba handlers */

/* proc and module init
 */

#define PROC_TOSHIBA		"toshiba"

static ProcItem proc_items[] = {
	{"lcd", read_lcd, write_lcd},
	{"video", read_video, write_video},
	{"fan", read_fan, write_fan},
	{"keys", read_keys, write_keys},
	{"version", read_version, NULL},
	{NULL}
};

static acpi_status __init add_device(void)
{
	struct proc_dir_entry *proc;
	ProcItem *item;

	for (item = proc_items; item->name; ++item) {
		proc = create_proc_read_entry(item->name,
					      S_IFREG | S_IRUGO | S_IWUSR,
					      toshiba_proc_dir,
					      (read_proc_t *) dispatch_read,
					      item);
		if (proc && item->write_func)
			proc->write_proc = (write_proc_t *) dispatch_write;
	}

	return AE_OK;
}

static acpi_status remove_device(void)
{
	ProcItem *item;

	for (item = proc_items; item->name; ++item)
		remove_proc_entry(item->name, toshiba_proc_dir);
	return AE_OK;
}

static struct backlight_ops toshiba_backlight_data = {
        .get_brightness = get_lcd,
        .update_status  = set_lcd_status,
};

static struct semaphore thread_sem;
static int thread_should_die;

static struct acpi_device *threaded_device = 0;

static void thread_deliver_button_event(u32 value)
{
	if (!threaded_device) return;
	if( value == 0x0100 ) {
		/* Ignore FN on its own */
	} else if( value & 0x80 ) {
		acpi_bus_generate_proc_event( threaded_device, 1, value & ~0x80 );
	} else {
		acpi_bus_generate_proc_event( threaded_device, 0, value );
	}
}

static int toshiba_acpi_thread(void *data)
{
	int dropped = 0;
	u32 hci_result, value;

	daemonize("ktoshkeyd");
	set_user_nice(current, 4);
	thread_should_die = 0;

	up(&thread_sem);

	do {
		/* In case we get stuck; we can rmmod the module here */
		if (thread_should_die)
			break;

		hci_read1(HCI_SYSTEM_EVENT, &value, &hci_result);
		if (hci_result == HCI_SUCCESS) {
			dropped++;
		} else if (hci_result == HCI_EMPTY) {
                         /* better luck next time */
		} else if (hci_result == HCI_NOT_SUPPORTED) {
			/* This is a workaround for an unresolved issue on
			 * some machines where system events sporadically
			 * become disabled. */
			hci_write1(HCI_SYSTEM_EVENT, 1, &hci_result);
			printk(MY_NOTICE "Re-enabled hotkeys\n");
		}
	} while (hci_result != HCI_EMPTY);

	printk(MY_INFO "Dropped %d keys from the queue on startup\n", dropped);

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ / hotkeys_check_per_sec);

		if (thread_should_die)
			break;

		if (try_to_freeze())
			continue;

		do {
			hci_read1(HCI_SYSTEM_EVENT, &value, &hci_result);
			if (hci_result == HCI_SUCCESS) {
				thread_deliver_button_event(value);
			} else if (hci_result == HCI_EMPTY) {
				/* better luck next time */
			} else if (hci_result == HCI_NOT_SUPPORTED) {
				/* This is a workaround for an
				 * unresolved issue on some machines
				 * where system events sporadically
				 * become disabled. */
				hci_write1(HCI_SYSTEM_EVENT, 1, &hci_result);
				printk(MY_NOTICE "Re-enabled hotkeys\n");
			}
		} while (hci_result == HCI_SUCCESS);
	}
	set_user_nice(current, -20);	/* Become nasty so we are cleaned up
					 * before the module exits making us oops */
	up(&thread_sem);
	return 0;
}

static int acpi_toshkeys_add (struct acpi_device *device)
{
	threaded_device = device;
	strcpy(acpi_device_name(device), "Toshiba laptop hotkeys");
	strcpy(acpi_device_class(device), "hkey");
	return 0;
}

static int acpi_toshkeys_remove (struct acpi_device *device, int type)
{
	if (threaded_device == device)
		threaded_device = 0;
	return 0;
}

static const struct acpi_device_id acpi_toshkeys_ids[] = {
	{ "TOS6200", 0 },
	{ "TOS6207", 0 },
	{ "TOS6208", 0 },
 	{"", 0}
};

static struct acpi_driver acpi_threaded_toshkeys = {
	.name = "Toshiba laptop hotkeys driver",
	.class = "hkey",
	.ids = acpi_toshkeys_ids,
	.ops = {
		.add = acpi_toshkeys_add,
		.remove = acpi_toshkeys_remove,
	},
};

static int __init init_threaded_acpi(void)
{
        acpi_status result = AE_OK;
        result = acpi_bus_register_driver(&acpi_threaded_toshkeys);
        if( result < 0 )
                printk(MY_ERR "Registration of toshkeys acpi device failed\n");
        return result;
}

static void kill_threaded_acpi(void)
{
        acpi_bus_unregister_driver(&acpi_threaded_toshkeys);
}

static void toshiba_acpi_exit(void)
{
	if (toshiba_acpi.bt_rfk) {
		rfkill_unregister(toshiba_acpi.bt_rfk);
		rfkill_destroy(toshiba_acpi.bt_rfk);
	}

	if (toshiba_backlight_device)
		backlight_device_unregister(toshiba_backlight_device);

	if (hotkeys_over_acpi) {
		thread_should_die = 1;
		down(&thread_sem);
		kill_threaded_acpi();
	}

	remove_device();

	if (toshiba_proc_dir)
		remove_proc_entry(PROC_TOSHIBA, acpi_root_dir);

	old_driver_emulation_exit();

	platform_device_unregister(toshiba_acpi.p_dev);

	return;
}

static int __init toshiba_acpi_init(void)
{
	acpi_status status = AE_OK;
	u32 hci_result;
	bool bt_present;
	int ret = 0;

	if (acpi_disabled)
		return -ENODEV;

	/* simple device detection: look for HCI method */
	if (is_valid_acpi_path(METHOD_HCI_1))
		method_hci = METHOD_HCI_1;
	else if (is_valid_acpi_path(METHOD_HCI_2))
		method_hci = METHOD_HCI_2;
	else
		return -ENODEV;

	printk(MY_INFO "Toshiba Laptop ACPI Extras version %s\n",
	       TOSHIBA_ACPI_VERSION);
	printk(MY_INFO "    HCI method: %s\n", method_hci);

	mutex_init(&toshiba_acpi.mutex);

	toshiba_acpi.p_dev = platform_device_register_simple("toshiba_acpi",
							      -1, NULL, 0);
	if (IS_ERR(toshiba_acpi.p_dev)) {
		ret = PTR_ERR(toshiba_acpi.p_dev);
		printk(MY_ERR "unable to register platform device\n");
		toshiba_acpi.p_dev = NULL;
		toshiba_acpi_exit();
		return ret;
	}

	if ((ret = old_driver_emulation_init()))
		return ret;

	force_fan = 0;
	key_event_valid = 0;

	/* enable event fifo */
	hci_write1(HCI_SYSTEM_EVENT, 1, &hci_result);

	toshiba_proc_dir = proc_mkdir(PROC_TOSHIBA, acpi_root_dir);
	if (!toshiba_proc_dir) {
		toshiba_acpi_exit();
		return -ENODEV;
	} else {
		status = add_device();
		if (ACPI_FAILURE(status)) {
			toshiba_acpi_exit();
			return -ENODEV;
		}
	}

	toshiba_backlight_device = backlight_device_register("toshiba",
						&toshiba_acpi.p_dev->dev,
						NULL,
						&toshiba_backlight_data);
        if (IS_ERR(toshiba_backlight_device)) {
		ret = PTR_ERR(toshiba_backlight_device);

		printk(KERN_ERR "Could not register toshiba backlight device\n");
		toshiba_backlight_device = NULL;
		toshiba_acpi_exit();
		return ret;
	}
        toshiba_backlight_device->props.max_brightness = HCI_LCD_BRIGHTNESS_LEVELS - 1;

	if (hotkeys_over_acpi && ACPI_SUCCESS(status)) {
		printk(MY_INFO "Toshiba hotkeys are sent as ACPI events\n");
		if (hotkeys_check_per_sec < 1)
			hotkeys_check_per_sec = 1;
		if (hotkeys_check_per_sec > 10)
			hotkeys_check_per_sec = 10;
		printk(MY_INFO "ktoshkeyd will check %d time%s per second\n",
			hotkeys_check_per_sec, hotkeys_check_per_sec==1?"":"s");
		if (init_threaded_acpi() >= 0) {
			init_MUTEX_LOCKED(&thread_sem);
			kernel_thread(toshiba_acpi_thread, NULL, CLONE_KERNEL);
			down(&thread_sem);
		} else {
			remove_device();
			remove_proc_entry(PROC_TOSHIBA, acpi_root_dir);
			status = AE_ERROR;
			printk(MY_INFO "ktoshkeyd initialisation failed. Refusing to load module\n");
		}
	}

	/* Register rfkill switch for Bluetooth */
	if (hci_get_bt_present(&bt_present) == HCI_SUCCESS && bt_present) {
		toshiba_acpi.bt_rfk = rfkill_alloc(toshiba_acpi.bt_name,
						   &toshiba_acpi.p_dev->dev,
						   RFKILL_TYPE_BLUETOOTH,
						   &toshiba_rfk_ops,
						   &toshiba_acpi);
		if (!toshiba_acpi.bt_rfk) {
			printk(MY_ERR "unable to allocate rfkill device\n");
			toshiba_acpi_exit();
			return -ENOMEM;
		}

		ret = rfkill_register(toshiba_acpi.bt_rfk);
		if (ret) {
			printk(MY_ERR "unable to register rfkill device\n");
			rfkill_destroy(toshiba_acpi.bt_rfk);
			toshiba_acpi_exit();
			return ret;
		}
	}

	return 0;
}

module_init(toshiba_acpi_init);
module_exit(toshiba_acpi_exit);
