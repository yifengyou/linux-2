/*
 *  Driver for Dell laptop extras
 *
 *  Copyright (c) Red Hat <mjg@redhat.com>
 *
 *  Based on documentation in the libsmbios package, Copyright (C) 2005 Dell
 *  Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/backlight.h>
#include <linux/err.h>
#include <linux/dmi.h>
#include <linux/io.h>
#include <linux/rfkill.h>
#include <linux/power_supply.h>
#include <linux/acpi.h>
#include <linux/input.h>
#include "../../firmware/dcdbas.h"

#define BRIGHTNESS_TOKEN 0x7d
#define WLAN_SWITCH_MASK 0
#define BT_SWITCH_MASK 1
#define WWAN_SWITCH_MASK 2
#define HW_SWITCH_SUPPORT 3
#define HW_SWITCH_MASK 16

/* This structure will be modified by the firmware when we enter
 * system management mode, hence the volatiles */

struct calling_interface_buffer {
	u16 class;
	u16 select;
	volatile u32 input[4];
	volatile u32 output[4];
} __packed;

struct calling_interface_token {
	u16 tokenID;
	u16 location;
	union {
		u16 value;
		u16 stringlength;
	};
};

struct calling_interface_structure {
	struct dmi_header header;
	u16 cmdIOAddress;
	u8 cmdIOCode;
	u32 supportedCmds;
	struct calling_interface_token tokens[];
} __packed;

static int da_command_address;
static int da_command_code;
static int da_num_tokens;
static struct calling_interface_token *da_tokens;

static struct backlight_device *dell_backlight_device;
static struct rfkill *wifi_rfkill;
static struct rfkill *bluetooth_rfkill;
static struct rfkill *wwan_rfkill;

/*
 * RFkill status is maintained in software because the BIOS has an annoying
 * habit of emitting a KEY_WLAN key press event before the BIOS state is updated, making
 * dell_send_request() racy.
 */
static int   hw_switch_status;

static const struct dmi_system_id __initdata dell_device_table[] = {
	{
		.ident = "Dell laptop",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_CHASSIS_TYPE, "8"),
		},
	},
	{
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_CHASSIS_TYPE, "9"), /*Laptop*/
		},
	},
	{
		.ident = "Dell Computer Corporation",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Computer Corporation"),
			DMI_MATCH(DMI_CHASSIS_TYPE, "8"),
		},
	},
	{ }
};

static struct dmi_system_id __devinitdata dell_blacklist[] = {
	/* BIOS always returns HW switch disabled */
	{
		.ident = "Dell Vostro 1720",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_PRODUCT_NAME, "Vostro 1720"),
		},
	},
	/* Supported by compal-laptop */
	{
		.ident = "Dell Mini 9",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_PRODUCT_NAME, "Inspiron 910"),
		},
	},
	{
		.ident = "Dell Mini 10",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_PRODUCT_NAME, "Inspiron 1010"),
		},
	},
	{
		.ident = "Dell Mini 10v",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_PRODUCT_NAME, "Inspiron 1011"),
		},
	},
	{
		.ident = "Dell Inspiron 11z",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_PRODUCT_NAME, "Inspiron 1110"),
		},
	},
	{
		.ident = "Dell Mini 12",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
			DMI_MATCH(DMI_PRODUCT_NAME, "Inspiron 1210"),
		},
	},
	{}
};

static void parse_da_table(const struct dmi_header *dm)
{
	/* Final token is a terminator, so we don't want to copy it */
	int tokens = (dm->length-11)/sizeof(struct calling_interface_token)-1;
	struct calling_interface_structure *table =
		container_of(dm, struct calling_interface_structure, header);

	/* 4 bytes of table header, plus 7 bytes of Dell header, plus at least
	   6 bytes of entry */

	if (dm->length < 17)
		return;

	da_command_address = table->cmdIOAddress;
	da_command_code = table->cmdIOCode;

	da_tokens = krealloc(da_tokens, (da_num_tokens + tokens) *
			     sizeof(struct calling_interface_token),
			     GFP_KERNEL);

	if (!da_tokens)
		return;

	memcpy(da_tokens+da_num_tokens, table->tokens,
	       sizeof(struct calling_interface_token) * tokens);

	da_num_tokens += tokens;
}

static void find_tokens(const struct dmi_header *dm, void *dummy)
{
	switch (dm->type) {
	case 0xd4: /* Indexed IO */
		break;
	case 0xd5: /* Protected Area Type 1 */
		break;
	case 0xd6: /* Protected Area Type 2 */
		break;
	case 0xda: /* Calling interface */
		parse_da_table(dm);
		break;
	}
}

static int find_token_location(int tokenid)
{
	int i;
	for (i = 0; i < da_num_tokens; i++) {
		if (da_tokens[i].tokenID == tokenid)
			return da_tokens[i].location;
	}

	return -1;
}

static struct calling_interface_buffer *
dell_send_request(struct calling_interface_buffer *buffer, int class,
		  int select)
{
	struct smi_cmd command;

	command.magic = SMI_CMD_MAGIC;
	command.command_address = da_command_address;
	command.command_code = da_command_code;
	command.ebx = virt_to_phys(buffer);
	command.ecx = 0x42534931;

	buffer->class = class;
	buffer->select = select;

	dcdbas_smi_request(&command);

	return buffer;
}

/* Derived from information in DellWirelessCtl.cpp:
   Class 17, select 11 is radio control. It returns an array of 32-bit values.

   result[0]: return code
   result[1]:
     Bit 0:      Hardware switch supported
     Bit 1:      Wifi locator supported
     Bit 2:      Wifi is supported
     Bit 3:      Bluetooth is supported
     Bit 4:      WWAN is supported
     Bit 5:      Wireless keyboard supported
     Bits 6-7:   Reserved
     Bit 8:      Wifi is installed
     Bit 9:      Bluetooth is installed
     Bit 10:     WWAN is installed
     Bits 11-15: Reserved
     Bit 16:     Hardware switch is on
     Bit 17:     Wifi is blocked
     Bit 18:     Bluetooth is blocked
     Bit 19:     WWAN is blocked
     Bits 20-31: Reserved
   result[2]: NVRAM size in bytes
   result[3]: NVRAM format version number
*/

static int dell_rfkill_set(void *data, bool blocked)
{
	struct calling_interface_buffer buffer;
	int disable = blocked ? 1 : 0;
	unsigned long radio = (unsigned long)data;

	if (!(hw_switch_status & BIT(radio-1)) || !(hw_switch_status & BIT(HW_SWITCH_MASK)) || \
			!(hw_switch_status & BIT(HW_SWITCH_SUPPORT))) {
		memset(&buffer, 0, sizeof(struct calling_interface_buffer));
		buffer.input[0] = (1 | (radio<<8) | (disable << 16));
		dell_send_request(&buffer, 17, 11);
	}
	return 0;
}

static void dell_rfkill_query(struct rfkill *rfkill, void *data)
{
	struct calling_interface_buffer buffer;
	int status;
	int bit = (unsigned long)data - 1;

	memset(&buffer, 0, sizeof(struct calling_interface_buffer));
	dell_send_request(&buffer, 17, 11);
	status = buffer.output[1];

	hw_switch_status |= (status & BIT(0)) << BIT(HW_SWITCH_SUPPORT);
	hw_switch_status |= (status & BIT(HW_SWITCH_MASK)) ^ BIT(HW_SWITCH_MASK);

	/* HW switch control not supported
	   explicitly set it to all 3 as they'll change in unison then */
	if (!(status & BIT(0)))
		hw_switch_status |= BIT(WLAN_SWITCH_MASK) | BIT(BT_SWITCH_MASK) | (WWAN_SWITCH_MASK);
	else {
		/* rerun the query to see what is really supported */
		memset(&buffer, 0, sizeof(struct calling_interface_buffer));
		buffer.input[0] = 2;
		dell_send_request(&buffer, 17, 11);
		status = buffer.output[1];

		hw_switch_status |= status & BIT(bit);
	}

	if (hw_switch_status & BIT(bit))
		rfkill_set_hw_state(rfkill, hw_switch_status & BIT(HW_SWITCH_MASK));
	else
		rfkill_set_hw_state(rfkill, 0);
}

static const struct rfkill_ops dell_rfkill_ops = {
	.set_block = dell_rfkill_set,
	.query = dell_rfkill_query,
};

/*
 * Called for each KEY_WLAN key press event. Note that a physical
 * rf-kill switch change also causes the BIOS to emit a KEY_WLAN.
 *
 * dell_rfkill_set may block, so schedule it on a worker thread.
 */
static void dell_rfkill_update(struct work_struct *work)
{
	hw_switch_status ^= BIT(HW_SWITCH_MASK);
	if (wifi_rfkill && (hw_switch_status & BIT(WLAN_SWITCH_MASK))) {
		rfkill_set_hw_state(wifi_rfkill, hw_switch_status & BIT(HW_SWITCH_MASK));
		dell_rfkill_set((void*)1, rfkill_blocked(wifi_rfkill));
	}

	if (bluetooth_rfkill && (hw_switch_status & BIT(BT_SWITCH_MASK))) {
		rfkill_set_hw_state(bluetooth_rfkill, hw_switch_status & BIT(HW_SWITCH_MASK));
		dell_rfkill_set((void*)2, rfkill_blocked(bluetooth_rfkill));
	}

	if (wwan_rfkill && (hw_switch_status & BIT(WWAN_SWITCH_MASK))) {
		rfkill_set_hw_state(wwan_rfkill, hw_switch_status & BIT(HW_SWITCH_MASK));
		dell_rfkill_set((void*)3, rfkill_blocked(wwan_rfkill));
	}
}
DECLARE_WORK(dell_rfkill_update_work, &dell_rfkill_update);

static int dell_setup_rfkill(void)
{
	struct calling_interface_buffer buffer;
	int status;
	int ret;
	hw_switch_status = 0;

	memset(&buffer, 0, sizeof(struct calling_interface_buffer));
	dell_send_request(&buffer, 17, 11);
	status = buffer.output[1];

	if ((status & (1<<2|1<<8)) == (1<<2|1<<8)) {
		wifi_rfkill = rfkill_alloc("dell-wifi", NULL, RFKILL_TYPE_WLAN,
					   &dell_rfkill_ops, (void *) 1);
		if (!wifi_rfkill) {
			ret = -ENOMEM;
			goto err_wifi;
		}
		ret = rfkill_register(wifi_rfkill);
		if (ret)
			goto err_wifi;
	}

	if ((status & (1<<3|1<<9)) == (1<<3|1<<9)) {
		bluetooth_rfkill = rfkill_alloc("dell-bluetooth", NULL,
						RFKILL_TYPE_BLUETOOTH,
						&dell_rfkill_ops, (void *) 2);
		if (!bluetooth_rfkill) {
			ret = -ENOMEM;
			goto err_bluetooth;
		}
		ret = rfkill_register(bluetooth_rfkill);
		if (ret)
			goto err_bluetooth;
	}

	if ((status & (1<<4|1<<10)) == (1<<4|1<<10)) {
		wwan_rfkill = rfkill_alloc("dell-wwan", NULL, RFKILL_TYPE_WWAN,
					   &dell_rfkill_ops, (void *) 3);
		if (!wwan_rfkill) {
			ret = -ENOMEM;
			goto err_wwan;
		}
		ret = rfkill_register(wwan_rfkill);
		if (ret)
			goto err_wwan;
	}

	return 0;
err_wwan:
	rfkill_destroy(wwan_rfkill);
	if (bluetooth_rfkill)
		rfkill_unregister(bluetooth_rfkill);
err_bluetooth:
	rfkill_destroy(bluetooth_rfkill);
	if (wifi_rfkill)
		rfkill_unregister(wifi_rfkill);
err_wifi:
	rfkill_destroy(wifi_rfkill);

	return ret;
}

static int dell_send_intensity(struct backlight_device *bd)
{
	struct calling_interface_buffer buffer;

	memset(&buffer, 0, sizeof(struct calling_interface_buffer));
	buffer.input[0] = find_token_location(BRIGHTNESS_TOKEN);
	buffer.input[1] = bd->props.brightness;

	if (buffer.input[0] == -1)
		return -ENODEV;

	if (power_supply_is_system_supplied() > 0)
		dell_send_request(&buffer, 1, 2);
	else
		dell_send_request(&buffer, 1, 1);

	return 0;
}

static int dell_get_intensity(struct backlight_device *bd)
{
	struct calling_interface_buffer buffer;

	memset(&buffer, 0, sizeof(struct calling_interface_buffer));
	buffer.input[0] = find_token_location(BRIGHTNESS_TOKEN);

	if (buffer.input[0] == -1)
		return -ENODEV;

	if (power_supply_is_system_supplied() > 0)
		dell_send_request(&buffer, 0, 2);
	else
		dell_send_request(&buffer, 0, 1);

	return buffer.output[1];
}

static struct backlight_ops dell_ops = {
	.get_brightness = dell_get_intensity,
	.update_status  = dell_send_intensity,
};

static const struct input_device_id dell_input_ids[] = {
	{
		.bustype = 0x11,
		.vendor = 0x01,
		.product = 0x01,
		.version = 0xab41,
		.flags = INPUT_DEVICE_ID_MATCH_BUS |
			 INPUT_DEVICE_ID_MATCH_VENDOR |
			 INPUT_DEVICE_ID_MATCH_PRODUCT |
			 INPUT_DEVICE_ID_MATCH_VERSION
	},
	{ },
};

static bool dell_input_filter(struct input_handle *handle, unsigned int type,
			     unsigned int code, int value)
{
	if (type == EV_KEY && code == KEY_WLAN && value == 1) {
		if (!schedule_work(&dell_rfkill_update_work))
			printk(KERN_NOTICE "rfkill switch handling already "
					   "scheduled, dropping this event\n");
		return 1;
	}

	return 0;
}

static void dell_input_event(struct input_handle *handle, unsigned int type,
			     unsigned int code, int value)
{
}

static int dell_input_connect(struct input_handler *handler,
			      struct input_dev *dev,
			      const struct input_device_id *id)
{
	struct input_handle *handle;
	int error;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "dell-laptop";

	error = input_register_handle(handle);
	if (error)
		goto err_free_handle;

	error = input_open_device(handle);
	if (error)
		goto err_unregister_handle;

	error = input_filter_device(handle);
	if (error)
		goto err_close_handle;

	return 0;

err_close_handle:
	input_close_device(handle);
err_unregister_handle:
	input_unregister_handle(handle);
err_free_handle:
	kfree(handle);
	return error;
}

static void dell_input_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static struct input_handler dell_input_handler = {
	.name = "dell-laptop",
	.filter = dell_input_filter,
	.event = dell_input_event,
	.connect = dell_input_connect,
	.disconnect = dell_input_disconnect,
	.id_table = dell_input_ids,
};

static int __init dell_init(void)
{
	struct calling_interface_buffer buffer;
	int max_intensity = 0;
	int ret;

	if (!dmi_check_system(dell_device_table))
		return -ENODEV;

	if (dmi_check_system(dell_blacklist)) {
		printk(KERN_INFO "dell-laptop: Blacklisted hardware detected - "
				"not loading\n");
		return -ENODEV;
	}

	dmi_walk(find_tokens, NULL);

	if (!da_tokens)  {
		printk(KERN_INFO "dell-laptop: Unable to find dmi tokens\n");
		return -ENODEV;
	}

	ret = dell_setup_rfkill();

	if (ret) {
		printk(KERN_WARNING "dell-laptop: Unable to setup rfkill\n");
		goto out;
	}

	if (input_register_handler(&dell_input_handler))
		printk(KERN_INFO
		       "dell-laptop: Could not register input filter\n");

#ifdef CONFIG_ACPI
	/* In the event of an ACPI backlight being available, don't
	 * register the platform controller.
	 */
	if (acpi_video_backlight_support())
		return 0;
#endif

	memset(&buffer, 0, sizeof(struct calling_interface_buffer));
	buffer.input[0] = find_token_location(BRIGHTNESS_TOKEN);

	if (buffer.input[0] != -1) {
		dell_send_request(&buffer, 0, 2);
		max_intensity = buffer.output[3];
	}

	if (max_intensity) {
		dell_backlight_device = backlight_device_register(
			"dell_backlight",
			NULL, NULL,
			&dell_ops);

		if (IS_ERR(dell_backlight_device)) {
			ret = PTR_ERR(dell_backlight_device);
			dell_backlight_device = NULL;
			goto out;
		}

		dell_backlight_device->props.max_brightness = max_intensity;
		dell_backlight_device->props.brightness =
			dell_get_intensity(dell_backlight_device);
		backlight_update_status(dell_backlight_device);
	}

	return 0;
out:
	if (wifi_rfkill)
		rfkill_unregister(wifi_rfkill);
	if (bluetooth_rfkill)
		rfkill_unregister(bluetooth_rfkill);
	if (wwan_rfkill)
		rfkill_unregister(wwan_rfkill);
	kfree(da_tokens);
	return ret;
}

static void __exit dell_exit(void)
{
	backlight_device_unregister(dell_backlight_device);
	if (wifi_rfkill)
		rfkill_unregister(wifi_rfkill);
	if (bluetooth_rfkill)
		rfkill_unregister(bluetooth_rfkill);
	if (wwan_rfkill)
		rfkill_unregister(wwan_rfkill);
	input_unregister_handler(&dell_input_handler);
}

module_init(dell_init);
module_exit(dell_exit);

MODULE_AUTHOR("Matthew Garrett <mjg@redhat.com>");
MODULE_DESCRIPTION("Dell laptop driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("dmi:*svnDellInc.:*:ct8:*");
MODULE_ALIAS("dmi:*svnDellInc.:*:ct9:*");
MODULE_ALIAS("dmi:*svnDellComputerCorporation.:*:ct8:*");
