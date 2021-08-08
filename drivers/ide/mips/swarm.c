/*
 * Copyright (C) 2001, 2002, 2003 Broadcom Corporation
 * Copyright (C) 2004 MontaVista Software Inc.
 *	Author:	Manish Lachwani, mlachwani@mvista.com
 * Copyright (C) 2004  MIPS Technologies, Inc.  All rights reserved.
 *	Author: Maciej W. Rozycki <macro@mips.com>
 * Copyright (c) 2006, 2008  Maciej W. Rozycki
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 *  Derived loosely from ide-pmac.c, so:
 *  Copyright (C) 1998 Paul Mackerras.
 *  Copyright (C) 1995-1998 Mark Lord
 */

/*
 * Boards with SiByte processors so far have supported IDE devices via
 * the Generic Bus, PCI bus, and built-in PCMCIA interface.  In all
 * cases, byte-swapping must be avoided for these devices (whereas
 * other PCI devices, for example, will require swapping).  Any
 * SiByte-targetted kernel including IDE support will include this
 * file.  Probing of a Generic Bus for an IDE device is controlled by
 * the definition of "SIBYTE_HAVE_IDE", which is provided by
 * <asm/sibyte/board.h> for Broadcom boards.
 */

#include <linux/ide.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/platform_device.h>

#include <asm/io.h>

#include <asm/sibyte/board.h>
#include <asm/sibyte/sb1250_genbus.h>
#include <asm/sibyte/sb1250_regs.h>

#define DRV_NAME "ide-swarm"

static char swarm_ide_string[] = DRV_NAME;

static struct resource swarm_ide_resource = {
	.name	= "SWARM GenBus IDE",
	.flags	= IORESOURCE_MEM,
};

static struct platform_device *swarm_ide_dev;

/*
 * swarm_ide_probe - if the board header indicates the existence of
 * Generic Bus IDE, allocate a HWIF for it.
 */
static int __devinit swarm_ide_probe(struct device *dev)
{
	ide_hwif_t *hwif;
	u8 __iomem *base;
	phys_t offset, size;
	hw_regs_t hw;
	int i;
	u8 idx[] = { 0xff, 0xff, 0xff, 0xff };

	if (!SIBYTE_HAVE_IDE)
		return -ENODEV;

	hwif = ide_find_port();
	if (hwif == NULL) {
		printk(KERN_ERR DRV_NAME ": no free slot for interface\n");
		return -ENOMEM;
	}

	base = ioremap(A_IO_EXT_BASE, 0x800);
	offset = __raw_readq(base + R_IO_EXT_REG(R_IO_EXT_START_ADDR, IDE_CS));
	size = __raw_readq(base + R_IO_EXT_REG(R_IO_EXT_MULT_SIZE, IDE_CS));
	iounmap(base);

	offset = G_IO_START_ADDR(offset) << S_IO_ADDRBASE;
	size = (G_IO_MULT_SIZE(size) + 1) << S_IO_REGSIZE;
	if (offset < A_PHYS_GENBUS || offset >= A_PHYS_GENBUS_END) {
		printk(KERN_INFO DRV_NAME
		       ": IDE interface at GenBus disabled\n");
		return -EBUSY;
	}

	printk(KERN_INFO DRV_NAME ": IDE interface at GenBus slot %i\n",
	       IDE_CS);

	swarm_ide_resource.start = offset;
	swarm_ide_resource.end = offset + size - 1;
	if (request_resource(&iomem_resource, &swarm_ide_resource)) {
		printk(KERN_ERR DRV_NAME
		       ": can't request I/O memory resource\n");
		return -EBUSY;
	}

	base = ioremap(offset, size);

	/* Setup MMIO ops.  */
	hwif->host_flags = IDE_HFLAG_MMIO;
	default_hwif_mmiops(hwif);

	for (i = 0; i <= 7; i++)
		hw.io_ports_array[i] =
				(unsigned long)(base + ((0x1f0 + i) << 5));
	hw.io_ports.ctl_addr =
				(unsigned long)(base + (0x3f6 << 5));
	hw.irq = K_INT_GB_IDE;
	hw.chipset = ide_generic;

	ide_init_port_hw(hwif, &hw);

	idx[0] = hwif->index;

	ide_device_add(idx, NULL);

	dev_set_drvdata(dev, hwif);

	return 0;
}

static struct device_driver swarm_ide_driver = {
	.name	= swarm_ide_string,
	.bus	= &platform_bus_type,
	.probe	= swarm_ide_probe,
};

static void swarm_ide_platform_release(struct device *device)
{
	struct platform_device *pldev;

	/* free device */
	pldev = to_platform_device(device);
	kfree(pldev);
}

static int __devinit swarm_ide_init_module(void)
{
	struct platform_device *pldev;
	int err;

	printk(KERN_INFO "SWARM IDE driver\n");

	if (driver_register(&swarm_ide_driver)) {
		printk(KERN_ERR "Driver registration failed\n");
		err = -ENODEV;
		goto out;
	}

        if (!(pldev = kzalloc(sizeof (*pldev), GFP_KERNEL))) {
		err = -ENOMEM;
		goto out_unregister_driver;
	}

	pldev->name		= swarm_ide_string;
	pldev->id		= 0;
	pldev->dev.release	= swarm_ide_platform_release;

	if (platform_device_register(pldev)) {
		err = -ENODEV;
		goto out_free_pldev;
	}

        if (!pldev->dev.driver) {
		/*
		 * The driver was not bound to this device, there was
                 * no hardware at this address. Unregister it, as the
		 * release fuction will take care of freeing the
		 * allocated structure
		 */
		platform_device_unregister (pldev);
	}

	swarm_ide_dev = pldev;

	return 0;

out_free_pldev:
	kfree(pldev);

out_unregister_driver:
	driver_unregister(&swarm_ide_driver);
out:
	return err;
}

module_init(swarm_ide_init_module);
