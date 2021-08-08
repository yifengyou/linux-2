/*
 * arch/arm/mach-orion5x/common.c
 *
 * Core functions for Marvell Orion 5x SoCs
 *
 * Maintainer: Tzachi Perelstein <tzachi@marvell.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/serial_8250.h>
#include <linux/mbus.h>
#include <linux/mv643xx_eth.h>
#include <linux/mv643xx_i2c.h>
#include <linux/ata_platform.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/timex.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/time.h>
#include <asm/arch/hardware.h>
#include <asm/arch/orion5x.h>
#include <asm/plat-orion/ehci-orion.h>
#include <asm/plat-orion/orion_nand.h>
#include <asm/plat-orion/time.h>
#include "common.h"

/*****************************************************************************
 * I/O Address Mapping
 ****************************************************************************/
static struct map_desc orion5x_io_desc[] __initdata = {
	{
		.virtual	= ORION5X_REGS_VIRT_BASE,
		.pfn		= __phys_to_pfn(ORION5X_REGS_PHYS_BASE),
		.length		= ORION5X_REGS_SIZE,
		.type		= MT_DEVICE
	},
	{
		.virtual	= ORION5X_PCIE_IO_VIRT_BASE,
		.pfn		= __phys_to_pfn(ORION5X_PCIE_IO_PHYS_BASE),
		.length		= ORION5X_PCIE_IO_SIZE,
		.type		= MT_DEVICE
	},
	{
		.virtual	= ORION5X_PCI_IO_VIRT_BASE,
		.pfn		= __phys_to_pfn(ORION5X_PCI_IO_PHYS_BASE),
		.length		= ORION5X_PCI_IO_SIZE,
		.type		= MT_DEVICE
	},
	{
		.virtual	= ORION5X_PCIE_WA_VIRT_BASE,
		.pfn		= __phys_to_pfn(ORION5X_PCIE_WA_PHYS_BASE),
		.length		= ORION5X_PCIE_WA_SIZE,
		.type		= MT_DEVICE
	},
};

void __init orion5x_map_io(void)
{
	iotable_init(orion5x_io_desc, ARRAY_SIZE(orion5x_io_desc));
}

/*****************************************************************************
 * UART
 ****************************************************************************/

static struct resource orion5x_uart_resources[] = {
	{
		.start		= UART0_PHYS_BASE,
		.end		= UART0_PHYS_BASE + 0xff,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= IRQ_ORION5X_UART0,
		.end		= IRQ_ORION5X_UART0,
		.flags		= IORESOURCE_IRQ,
	},
	{
		.start		= UART1_PHYS_BASE,
		.end		= UART1_PHYS_BASE + 0xff,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= IRQ_ORION5X_UART1,
		.end		= IRQ_ORION5X_UART1,
		.flags		= IORESOURCE_IRQ,
	},
};

static struct plat_serial8250_port orion5x_uart_data[] = {
	{
		.mapbase	= UART0_PHYS_BASE,
		.membase	= (char *)UART0_VIRT_BASE,
		.irq		= IRQ_ORION5X_UART0,
		.flags		= UPF_SKIP_TEST | UPF_BOOT_AUTOCONF,
		.iotype		= UPIO_MEM,
		.regshift	= 2,
		.uartclk	= ORION5X_TCLK,
	},
	{
		.mapbase	= UART1_PHYS_BASE,
		.membase	= (char *)UART1_VIRT_BASE,
		.irq		= IRQ_ORION5X_UART1,
		.flags		= UPF_SKIP_TEST | UPF_BOOT_AUTOCONF,
		.iotype		= UPIO_MEM,
		.regshift	= 2,
		.uartclk	= ORION5X_TCLK,
	},
	{ },
};

static struct platform_device orion5x_uart = {
	.name			= "serial8250",
	.id			= PLAT8250_DEV_PLATFORM,
	.dev			= {
		.platform_data	= orion5x_uart_data,
	},
	.resource		= orion5x_uart_resources,
	.num_resources		= ARRAY_SIZE(orion5x_uart_resources),
};

/*******************************************************************************
 * USB Controller - 2 interfaces
 ******************************************************************************/

static struct resource orion5x_ehci0_resources[] = {
	{
		.start	= ORION5X_USB0_PHYS_BASE,
		.end	= ORION5X_USB0_PHYS_BASE + SZ_4K - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= IRQ_ORION5X_USB0_CTRL,
		.end	= IRQ_ORION5X_USB0_CTRL,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct resource orion5x_ehci1_resources[] = {
	{
		.start	= ORION5X_USB1_PHYS_BASE,
		.end	= ORION5X_USB1_PHYS_BASE + SZ_4K - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= IRQ_ORION5X_USB1_CTRL,
		.end	= IRQ_ORION5X_USB1_CTRL,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct orion_ehci_data orion5x_ehci_data = {
	.dram		= &orion5x_mbus_dram_info,
};

static u64 ehci_dmamask = 0xffffffffUL;

static struct platform_device orion5x_ehci0 = {
	.name		= "orion-ehci",
	.id		= 0,
	.dev		= {
		.dma_mask		= &ehci_dmamask,
		.coherent_dma_mask	= 0xffffffff,
		.platform_data		= &orion5x_ehci_data,
	},
	.resource	= orion5x_ehci0_resources,
	.num_resources	= ARRAY_SIZE(orion5x_ehci0_resources),
};

static struct platform_device orion5x_ehci1 = {
	.name		= "orion-ehci",
	.id		= 1,
	.dev		= {
		.dma_mask		= &ehci_dmamask,
		.coherent_dma_mask	= 0xffffffff,
		.platform_data		= &orion5x_ehci_data,
	},
	.resource	= orion5x_ehci1_resources,
	.num_resources	= ARRAY_SIZE(orion5x_ehci1_resources),
};

/*****************************************************************************
 * Gigabit Ethernet port
 * (The Orion and Discovery (MV643xx) families use the same Ethernet driver)
 ****************************************************************************/

struct mv643xx_eth_shared_platform_data orion5x_eth_shared_data = {
	.dram		= &orion5x_mbus_dram_info,
	.t_clk		= ORION5X_TCLK,
};

static struct resource orion5x_eth_shared_resources[] = {
	{
		.start	= ORION5X_ETH_PHYS_BASE + 0x2000,
		.end	= ORION5X_ETH_PHYS_BASE + 0x3fff,
		.flags	= IORESOURCE_MEM,
	},
};

static struct platform_device orion5x_eth_shared = {
	.name		= MV643XX_ETH_SHARED_NAME,
	.id		= 0,
	.dev		= {
		.platform_data	= &orion5x_eth_shared_data,
	},
	.num_resources	= 1,
	.resource	= orion5x_eth_shared_resources,
};

static struct resource orion5x_eth_resources[] = {
	{
		.name	= "eth irq",
		.start	= IRQ_ORION5X_ETH_SUM,
		.end	= IRQ_ORION5X_ETH_SUM,
		.flags	= IORESOURCE_IRQ,
	}
};

static struct platform_device orion5x_eth = {
	.name		= MV643XX_ETH_NAME,
	.id		= 0,
	.num_resources	= 1,
	.resource	= orion5x_eth_resources,
};

void __init orion5x_eth_init(struct mv643xx_eth_platform_data *eth_data)
{
	eth_data->shared = &orion5x_eth_shared;
	orion5x_eth.dev.platform_data = eth_data;

	platform_device_register(&orion5x_eth_shared);
	platform_device_register(&orion5x_eth);
}

/*****************************************************************************
 * I2C controller
 * (The Orion and Discovery (MV643xx) families share the same I2C controller)
 ****************************************************************************/

static struct mv64xxx_i2c_pdata orion5x_i2c_pdata = {
	.freq_m		= 8, /* assumes 166 MHz TCLK */
	.freq_n		= 3,
	.timeout	= 1000, /* Default timeout of 1 second */
};

static struct resource orion5x_i2c_resources[] = {
	{
		.name   = "i2c base",
		.start  = I2C_PHYS_BASE,
		.end    = I2C_PHYS_BASE + 0x20 -1,
		.flags  = IORESOURCE_MEM,
	},
	{
		.name   = "i2c irq",
		.start  = IRQ_ORION5X_I2C,
		.end    = IRQ_ORION5X_I2C,
		.flags  = IORESOURCE_IRQ,
	},
};

static struct platform_device orion5x_i2c = {
	.name		= MV64XXX_I2C_CTLR_NAME,
	.id		= 0,
	.num_resources	= ARRAY_SIZE(orion5x_i2c_resources),
	.resource	= orion5x_i2c_resources,
	.dev		= {
		.platform_data = &orion5x_i2c_pdata,
	},
};

/*****************************************************************************
 * Sata port
 ****************************************************************************/
static struct resource orion5x_sata_resources[] = {
        {
                .name   = "sata base",
                .start  = ORION5X_SATA_PHYS_BASE,
                .end    = ORION5X_SATA_PHYS_BASE + 0x5000 - 1,
                .flags  = IORESOURCE_MEM,
        },
	{
                .name   = "sata irq",
                .start  = IRQ_ORION5X_SATA,
                .end    = IRQ_ORION5X_SATA,
                .flags  = IORESOURCE_IRQ,
        },
};

static struct platform_device orion5x_sata = {
	.name           = "sata_mv",
	.id             = 0,
	.dev		= {
		.coherent_dma_mask	= 0xffffffff,
	},
	.num_resources  = ARRAY_SIZE(orion5x_sata_resources),
	.resource       = orion5x_sata_resources,
};

void __init orion5x_sata_init(struct mv_sata_platform_data *sata_data)
{
	sata_data->dram = &orion5x_mbus_dram_info;
	orion5x_sata.dev.platform_data = sata_data;
	platform_device_register(&orion5x_sata);
}

/*****************************************************************************
 * Time handling
 ****************************************************************************/

static void orion5x_timer_init(void)
{
	orion_time_init(IRQ_ORION5X_BRIDGE, ORION5X_TCLK);
}

struct sys_timer orion5x_timer = {
        .init = orion5x_timer_init,
};

/*****************************************************************************
 * General
 ****************************************************************************/

/*
 * Identify device ID and rev from PCIe configuration header space '0'.
 */
static void __init orion5x_id(u32 *dev, u32 *rev, char **dev_name)
{
	orion5x_pcie_id(dev, rev);

	if (*dev == MV88F5281_DEV_ID) {
		if (*rev == MV88F5281_REV_D2) {
			*dev_name = "MV88F5281-D2";
		} else if (*rev == MV88F5281_REV_D1) {
			*dev_name = "MV88F5281-D1";
		} else {
			*dev_name = "MV88F5281-Rev-Unsupported";
		}
	} else if (*dev == MV88F5182_DEV_ID) {
		if (*rev == MV88F5182_REV_A2) {
			*dev_name = "MV88F5182-A2";
		} else {
			*dev_name = "MV88F5182-Rev-Unsupported";
		}
	} else if (*dev == MV88F5181_DEV_ID) {
		if (*rev == MV88F5181_REV_B1) {
			*dev_name = "MV88F5181-Rev-B1";
		} else {
			*dev_name = "MV88F5181-Rev-Unsupported";
		}
	} else {
		*dev_name = "Device-Unknown";
	}
}

void __init orion5x_init(void)
{
	char *dev_name;
	u32 dev, rev;

	orion5x_id(&dev, &rev, &dev_name);
	printk(KERN_INFO "Orion ID: %s. TCLK=%d.\n", dev_name, ORION5X_TCLK);

	/*
	 * Setup Orion address map
	 */
	orion5x_setup_cpu_mbus_bridge();

	/*
	 * Register devices.
	 */
	platform_device_register(&orion5x_uart);
	platform_device_register(&orion5x_ehci0);
	if (dev == MV88F5182_DEV_ID)
		platform_device_register(&orion5x_ehci1);
	platform_device_register(&orion5x_i2c);
}

/*
 * Many orion-based systems have buggy bootloader implementations.
 * This is a common fixup for bogus memory tags.
 */
void __init tag_fixup_mem32(struct machine_desc *mdesc, struct tag *t,
			    char **from, struct meminfo *meminfo)
{
	for (; t->hdr.size; t = tag_next(t))
		if (t->hdr.tag == ATAG_MEM &&
		    (!t->u.mem.size || t->u.mem.size & ~PAGE_MASK ||
		     t->u.mem.start & ~PAGE_MASK)) {
			printk(KERN_WARNING
			       "Clearing invalid memory bank %dKB@0x%08x\n",
			       t->u.mem.size / 1024, t->u.mem.start);
			t->hdr.tag = 0;
		}
}
