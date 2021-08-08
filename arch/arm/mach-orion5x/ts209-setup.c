/*
 * QNAP TS-109/TS-209 Board Setup
 *
 * Maintainer: Byron Bradley <byron.bbradley@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/mtd/physmap.h>
#include <linux/mtd/nand.h>
#include <linux/mv643xx_eth.h>
#include <linux/gpio_keys.h>
#include <linux/input.h>
#include <linux/i2c.h>
#include <linux/serial_reg.h>
#include <linux/ata_platform.h>
#include <asm/mach-types.h>
#include <asm/gpio.h>
#include <asm/mach/arch.h>
#include <asm/mach/pci.h>
#include <asm/arch/orion5x.h>
#include "common.h"

#define QNAP_TS209_NOR_BOOT_BASE 0xf4000000
#define QNAP_TS209_NOR_BOOT_SIZE SZ_8M

/****************************************************************************
 * 8MiB NOR flash. The struct mtd_partition is not in the same order as the
 *     partitions on the device because we want to keep compatability with
 *     existing QNAP firmware.
 *
 * Layout as used by QNAP:
 *  [2] 0x00000000-0x00200000 : "Kernel"
 *  [3] 0x00200000-0x00600000 : "RootFS1"
 *  [4] 0x00600000-0x00700000 : "RootFS2"
 *  [6] 0x00700000-0x00760000 : "NAS Config" (read-only)
 *  [5] 0x00760000-0x00780000 : "U-Boot Config"
 *  [1] 0x00780000-0x00800000 : "U-Boot" (read-only)
 ***************************************************************************/
static struct mtd_partition qnap_ts209_partitions[] = {
	{
		.name       = "U-Boot",
		.size       = 0x00080000,
		.offset     = 0x00780000,
		.mask_flags = MTD_WRITEABLE,
	}, {
		.name   = "Kernel",
		.size   = 0x00200000,
		.offset = 0,
	}, {
		.name   = "RootFS1",
		.size   = 0x00400000,
		.offset = 0x00200000,
	}, {
		.name   = "RootFS2",
		.size   = 0x00100000,
		.offset = 0x00600000,
	}, {
		.name   = "U-Boot Config",
		.size   = 0x00020000,
		.offset = 0x00760000,
	}, {
		.name       = "NAS Config",
		.size       = 0x00060000,
		.offset     = 0x00700000,
		.mask_flags = MTD_WRITEABLE,
	}
};

static struct physmap_flash_data qnap_ts209_nor_flash_data = {
	.width    = 1,
	.parts    = qnap_ts209_partitions,
	.nr_parts = ARRAY_SIZE(qnap_ts209_partitions)
};

static struct resource qnap_ts209_nor_flash_resource = {
	.flags = IORESOURCE_MEM,
	.start = QNAP_TS209_NOR_BOOT_BASE,
	.end   = QNAP_TS209_NOR_BOOT_BASE + QNAP_TS209_NOR_BOOT_SIZE - 1,
};

static struct platform_device qnap_ts209_nor_flash = {
	.name          = "physmap-flash",
	.id            = 0,
	.dev           = { .platform_data = &qnap_ts209_nor_flash_data, },
	.resource      = &qnap_ts209_nor_flash_resource,
	.num_resources = 1,
};

/*****************************************************************************
 * PCI
 ****************************************************************************/

#define QNAP_TS209_PCI_SLOT0_OFFS	7
#define QNAP_TS209_PCI_SLOT0_IRQ_PIN	6
#define QNAP_TS209_PCI_SLOT1_IRQ_PIN	7

void __init qnap_ts209_pci_preinit(void)
{
	int pin;

	/*
	 * Configure PCI GPIO IRQ pins
	 */
	pin = QNAP_TS209_PCI_SLOT0_IRQ_PIN;
	if (gpio_request(pin, "PCI Int1") == 0) {
		if (gpio_direction_input(pin) == 0) {
			set_irq_type(gpio_to_irq(pin), IRQT_LOW);
		} else {
			printk(KERN_ERR "qnap_ts209_pci_preinit failed to "
					"set_irq_type pin %d\n", pin);
			gpio_free(pin);
		}
	} else {
		printk(KERN_ERR "qnap_ts209_pci_preinit failed to gpio_request "
				"%d\n", pin);
	}

	pin = QNAP_TS209_PCI_SLOT1_IRQ_PIN;
	if (gpio_request(pin, "PCI Int2") == 0) {
		if (gpio_direction_input(pin) == 0) {
			set_irq_type(gpio_to_irq(pin), IRQT_LOW);
		} else {
			printk(KERN_ERR "qnap_ts209_pci_preinit failed "
					"to set_irq_type pin %d\n", pin);
			gpio_free(pin);
		}
	} else {
		printk(KERN_ERR "qnap_ts209_pci_preinit failed to gpio_request "
				"%d\n", pin);
	}
}

static int __init qnap_ts209_pci_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	int irq;

	/*
	 * Check for devices with hard-wired IRQs.
	 */
	irq = orion5x_pci_map_irq(dev, slot, pin);
	if (irq != -1)
		return irq;

	/*
	 * PCI IRQs are connected via GPIOs.
	 */
	switch (slot - QNAP_TS209_PCI_SLOT0_OFFS) {
	case 0:
		return gpio_to_irq(QNAP_TS209_PCI_SLOT0_IRQ_PIN);
	case 1:
		return gpio_to_irq(QNAP_TS209_PCI_SLOT1_IRQ_PIN);
	default:
		return -1;
	}
}

static struct hw_pci qnap_ts209_pci __initdata = {
	.nr_controllers = 2,
	.preinit        = qnap_ts209_pci_preinit,
	.swizzle        = pci_std_swizzle,
	.setup          = orion5x_pci_sys_setup,
	.scan           = orion5x_pci_sys_scan_bus,
	.map_irq        = qnap_ts209_pci_map_irq,
};

static int __init qnap_ts209_pci_init(void)
{
	if (machine_is_ts_x09())
		pci_common_init(&qnap_ts209_pci);

	return 0;
}

subsys_initcall(qnap_ts209_pci_init);

/*****************************************************************************
 * Ethernet
 ****************************************************************************/

static struct mv643xx_eth_platform_data qnap_ts209_eth_data = {
	.phy_addr       = 8,
	.force_phy_addr = 1,
};

static int __init parse_hex_nibble(char n)
{
	if (n >= '0' && n <= '9')
		return n - '0';

	if (n >= 'A' && n <= 'F')
		return n - 'A' + 10;

	if (n >= 'a' && n <= 'f')
		return n - 'a' + 10;

	return -1;
}

static int __init parse_hex_byte(const char *b)
{
	int hi;
	int lo;

	hi = parse_hex_nibble(b[0]);
	lo = parse_hex_nibble(b[1]);

	if (hi < 0 || lo < 0)
		return -1;

	return (hi << 4) | lo;
}

static int __init check_mac_addr(const char *addr_str)
{
	u_int8_t addr[6];
	int i;

	for (i = 0; i < 6; i++) {
		int byte;

		/*
		 * Enforce "xx:xx:xx:xx:xx:xx\n" format.
		 */
		if (addr_str[(i * 3) + 2] != ((i < 5) ? ':' : '\n'))
			return -1;

		byte = parse_hex_byte(addr_str + (i * 3));
		if (byte < 0)
			return -1;
		addr[i] = byte;
	}

	printk(KERN_INFO "ts209: found ethernet mac address ");
	for (i = 0; i < 6; i++)
		printk("%.2x%s", addr[i], (i < 5) ? ":" : ".\n");

	memcpy(qnap_ts209_eth_data.mac_addr, addr, 6);

	return 0;
}

/*
 * The 'NAS Config' flash partition has an ext2 filesystem which
 * contains a file that has the ethernet MAC address in plain text
 * (format "xx:xx:xx:xx:xx:xx\n".)
 */
static void __init ts209_find_mac_addr(void)
{
	unsigned long addr;

	for (addr = 0x00700000; addr < 0x00760000; addr += 1024) {
		char *nor_page;
		int ret = 0;

		nor_page = ioremap(QNAP_TS209_NOR_BOOT_BASE + addr, 1024);
		if (nor_page != NULL) {
			ret = check_mac_addr(nor_page);
			iounmap(nor_page);
		}

		if (ret == 0)
			break;
	}
}

/*****************************************************************************
 * RTC S35390A on I2C bus
 ****************************************************************************/

#define TS209_RTC_GPIO	3

static struct i2c_board_info __initdata qnap_ts209_i2c_rtc = {
	I2C_BOARD_INFO("s35390a", 0x30),
       .irq         = 0,
};

/****************************************************************************
 * GPIO Attached Keys
 *     Power button is attached to the PIC microcontroller
 ****************************************************************************/

#define QNAP_TS209_GPIO_KEY_MEDIA	1
#define QNAP_TS209_GPIO_KEY_RESET	2

static struct gpio_keys_button qnap_ts209_buttons[] = {
	{
		.code		= KEY_RESTART,
		.gpio		= QNAP_TS209_GPIO_KEY_MEDIA,
		.desc		= "USB Copy Button",
		.active_low	= 1,
	},
	{
		.code		= KEY_POWER,
		.gpio		= QNAP_TS209_GPIO_KEY_RESET,
		.desc		= "Reset Button",
		.active_low	= 1,
	}
};

static struct gpio_keys_platform_data qnap_ts209_button_data = {
	.buttons	= qnap_ts209_buttons,
	.nbuttons       = ARRAY_SIZE(qnap_ts209_buttons),
};

static struct platform_device qnap_ts209_button_device = {
	.name		= "gpio-keys",
	.id		= -1,
	.num_resources	= 0,
	.dev		= { .platform_data  = &qnap_ts209_button_data, },
};

/*****************************************************************************
 * SATA
 ****************************************************************************/
static struct mv_sata_platform_data qnap_ts209_sata_data = {
	.n_ports        = 2,
};

/*****************************************************************************

 * General Setup
 ****************************************************************************/

static struct platform_device *qnap_ts209_devices[] __initdata = {
	&qnap_ts209_nor_flash,
	&qnap_ts209_button_device,
};

/*
 * QNAP TS-[12]09 specific power off method via UART1-attached PIC
 */

#define UART1_REG(x)  (UART1_VIRT_BASE + ((UART_##x) << 2))

static void qnap_ts209_power_off(void)
{
	/* 19200 baud divisor */
	const unsigned divisor = ((ORION5X_TCLK + (8 * 19200)) / (16 * 19200));

	pr_info("%s: triggering power-off...\n", __func__);

	/* hijack uart1 and reset into sane state (19200,8n1) */
	orion5x_write(UART1_REG(LCR), 0x83);
	orion5x_write(UART1_REG(DLL), divisor & 0xff);
	orion5x_write(UART1_REG(DLM), (divisor >> 8) & 0xff);
	orion5x_write(UART1_REG(LCR), 0x03);
	orion5x_write(UART1_REG(IER), 0x00);
	orion5x_write(UART1_REG(FCR), 0x00);
	orion5x_write(UART1_REG(MCR), 0x00);

	/* send the power-off command 'A' to PIC */
	orion5x_write(UART1_REG(TX), 'A');
}

static void __init qnap_ts209_init(void)
{
	/*
	 * Setup basic Orion functions. Need to be called early.
	 */
	orion5x_init();

	/*
	 * Setup flash mapping
	 */
	orion5x_setup_dev_boot_win(QNAP_TS209_NOR_BOOT_BASE,
			    QNAP_TS209_NOR_BOOT_SIZE);

	/*
	 * Open a special address decode windows for the PCIe WA.
	 */
	orion5x_setup_pcie_wa_win(ORION5X_PCIE_WA_PHYS_BASE,
				ORION5X_PCIE_WA_SIZE);

	/*
	 * Setup Multiplexing Pins --
	 * MPP[0] Reserved
	 * MPP[1] USB copy button (0 active)
	 * MPP[2] Load defaults button (0 active)
	 * MPP[3] GPIO RTC
	 * MPP[4-5] Reserved
	 * MPP[6] PCI Int A
	 * MPP[7] PCI Int B
	 * MPP[8-11] Reserved
	 * MPP[12] SATA 0 presence
	 * MPP[13] SATA 1 presence
	 * MPP[14] SATA 0 active
	 * MPP[15] SATA 1 active
	 * MPP[16] UART1 RXD
	 * MPP[17] UART1 TXD
	 * MPP[18] SW_RST (0 active)
	 * MPP[19] Reserved
	 * MPP[20] PCI clock 0
	 * MPP[21] PCI clock 1
	 * MPP[22] USB 0 over current
	 * MPP[23-25] Reserved
	 */
	orion5x_write(MPP_0_7_CTRL, 0x3);
	orion5x_write(MPP_8_15_CTRL, 0x55550000);
	orion5x_write(MPP_16_19_CTRL, 0x5500);
	orion5x_gpio_set_valid_pins(0x3cc0fff);

	/* register ts209 specific power-off method */
	pm_power_off = qnap_ts209_power_off;

	platform_add_devices(qnap_ts209_devices,
				ARRAY_SIZE(qnap_ts209_devices));

	/* Get RTC IRQ and register the chip */
	if (gpio_request(TS209_RTC_GPIO, "rtc") == 0) {
		if (gpio_direction_input(TS209_RTC_GPIO) == 0)
			qnap_ts209_i2c_rtc.irq = gpio_to_irq(TS209_RTC_GPIO);
		else
			gpio_free(TS209_RTC_GPIO);
	}
	if (qnap_ts209_i2c_rtc.irq == 0)
		pr_warning("qnap_ts209_init: failed to get RTC IRQ\n");
	i2c_register_board_info(0, &qnap_ts209_i2c_rtc, 1);

	ts209_find_mac_addr();
	orion5x_eth_init(&qnap_ts209_eth_data);

	orion5x_sata_init(&qnap_ts209_sata_data);
}

MACHINE_START(TS209, "QNAP TS-109/TS-209")
	/* Maintainer:  Byron Bradley <byron.bbradley@gmail.com> */
	.phys_io	= ORION5X_REGS_PHYS_BASE,
	.io_pg_offst	= ((ORION5X_REGS_VIRT_BASE) >> 18) & 0xFFFC,
	.boot_params	= 0x00000100,
	.init_machine	= qnap_ts209_init,
	.map_io		= orion5x_map_io,
	.init_irq	= orion5x_init_irq,
	.timer		= &orion5x_timer,
	.fixup		= tag_fixup_mem32,
MACHINE_END
