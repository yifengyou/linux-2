/*
 *  This file contains quirk handling code for PnP devices
 *  Some devices do not report all their resources, and need to have extra
 *  resources added. This is most easily accomplished at initialisation time
 *  when building up the resource structure for the first time.
 *
 *  Copyright (c) 2000 Peter Denison <peterd@pnd-pc.demon.co.uk>
 *
 *  Heavily based on PCI quirks handling which is
 *
 *  Copyright (c) 1999 Martin Mares <mj@ucw.cz>
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/pnp.h>
#include <linux/io.h>
#include <linux/kallsyms.h>
#include "base.h"

static void quirk_awe32_resources(struct pnp_dev *dev)
{
	struct pnp_port *port, *port2, *port3;
	struct pnp_option *res = dev->dependent;

	/*
	 * Unfortunately the isapnp_add_port_resource is too tightly bound
	 * into the PnP discovery sequence, and cannot be used. Link in the
	 * two extra ports (at offset 0x400 and 0x800 from the one given) by
	 * hand.
	 */
	for (; res; res = res->next) {
		port2 = pnp_alloc(sizeof(struct pnp_port));
		if (!port2)
			return;
		port3 = pnp_alloc(sizeof(struct pnp_port));
		if (!port3) {
			kfree(port2);
			return;
		}
		port = res->port;
		memcpy(port2, port, sizeof(struct pnp_port));
		memcpy(port3, port, sizeof(struct pnp_port));
		port->next = port2;
		port2->next = port3;
		port2->min += 0x400;
		port2->max += 0x400;
		port3->min += 0x800;
		port3->max += 0x800;
		dev_info(&dev->dev,
			"AWE32 quirk - added ioports 0x%lx and 0x%lx\n",
			(unsigned long)port2->min,
			(unsigned long)port3->min);
	}
}

static void quirk_cmi8330_resources(struct pnp_dev *dev)
{
	struct pnp_option *res = dev->dependent;
	unsigned long tmp;

	for (; res; res = res->next) {

		struct pnp_irq *irq;
		struct pnp_dma *dma;

		for (irq = res->irq; irq; irq = irq->next) {	// Valid irqs are 5, 7, 10
			tmp = 0x04A0;
			bitmap_copy(irq->map, &tmp, 16);	// 0000 0100 1010 0000
		}

		for (dma = res->dma; dma; dma = dma->next)	// Valid 8bit dma channels are 1,3
			if ((dma->flags & IORESOURCE_DMA_TYPE_MASK) ==
			    IORESOURCE_DMA_8BIT)
				dma->map = 0x000A;
	}
	dev_info(&dev->dev, "CMI8330 quirk - forced possible IRQs to 5, 7, 10 "
		"and DMA channels to 1, 3\n");
}

static void quirk_sb16audio_resources(struct pnp_dev *dev)
{
	struct pnp_port *port;
	struct pnp_option *res = dev->dependent;
	int changed = 0;

	/*
	 * The default range on the mpu port for these devices is 0x388-0x388.
	 * Here we increase that range so that two such cards can be
	 * auto-configured.
	 */

	for (; res; res = res->next) {
		port = res->port;
		if (!port)
			continue;
		port = port->next;
		if (!port)
			continue;
		port = port->next;
		if (!port)
			continue;
		if (port->min != port->max)
			continue;
		port->max += 0x70;
		changed = 1;
	}
	if (changed)
		dev_info(&dev->dev, "SB audio device quirk - increased port range\n");
}

static struct pnp_option *quirk_isapnp_mpu_options(struct pnp_dev *dev)
{
	struct pnp_option *head = NULL;
	struct pnp_option *prev = NULL;
	struct pnp_option *res;

	/*
	 * Build a functional IRQ-less variant of each MPU option.
	 */

	for (res = dev->dependent; res; res = res->next) {
		struct pnp_option *curr;
		struct pnp_port *port;
		struct pnp_port *copy;

		port = res->port;
		if (!port || !res->irq)
			continue;

		copy = pnp_alloc(sizeof *copy);
		if (!copy)
			break;

		copy->min = port->min;
		copy->max = port->max;
		copy->align = port->align;
		copy->size = port->size;
		copy->flags = port->flags;

		curr = pnp_build_option(PNP_RES_PRIORITY_FUNCTIONAL);
		if (!curr) {
			kfree(copy);
			break;
		}
		curr->port = copy;

		if (prev)
			prev->next = curr;
		else
			head = curr;
		prev = curr;
	}
	if (head)
		dev_info(&dev->dev, "adding IRQ-less MPU options\n");

	return head;
}

static void quirk_ad1815_mpu_resources(struct pnp_dev *dev)
{
	struct pnp_option *res;
	struct pnp_irq *irq;

	/*
	 * Distribute the independent IRQ over the dependent options
	 */

	res = dev->independent;
	if (!res)
		return;

	irq = res->irq;
	if (!irq || irq->next)
		return;

	res = dev->dependent;
	if (!res)
		return;

	while (1) {
		struct pnp_irq *copy;

		copy = pnp_alloc(sizeof *copy);
		if (!copy)
			break;

		memcpy(copy->map, irq->map, sizeof copy->map);
		copy->flags = irq->flags;

		copy->next = res->irq; /* Yes, this is NULL */
		res->irq = copy;

		if (!res->next)
			break;
		res = res->next;
	}
	kfree(irq);

	res->next = quirk_isapnp_mpu_options(dev);

	res = dev->independent;
	res->irq = NULL;
}

static void quirk_isapnp_mpu_resources(struct pnp_dev *dev)
{
	struct pnp_option *res;

	res = dev->dependent;
	if (!res)
		return;

	while (res->next)
		res = res->next;

	res->next = quirk_isapnp_mpu_options(dev);
}

#include <linux/pci.h>

static void quirk_system_pci_resources(struct pnp_dev *dev)
{
	struct pci_dev *pdev = NULL;
	struct resource *res;
	resource_size_t pnp_start, pnp_end, pci_start, pci_end;
	int i, j;

	/*
	 * Some BIOSes have PNP motherboard devices with resources that
	 * partially overlap PCI BARs.  The PNP system driver claims these
	 * motherboard resources, which prevents the normal PCI driver from
	 * requesting them later.
	 *
	 * This patch disables the PNP resources that conflict with PCI BARs
	 * so they won't be claimed by the PNP system driver.
	 */
	for_each_pci_dev(pdev) {
		for (i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
			if (!(pci_resource_flags(pdev, i) & IORESOURCE_MEM) ||
			    pci_resource_len(pdev, i) == 0)
				continue;

			pci_start = pci_resource_start(pdev, i);
			pci_end = pci_resource_end(pdev, i);
			for (j = 0;
			     (res = pnp_get_resource(dev, IORESOURCE_MEM, j));
			     j++) {
				if (res->flags & IORESOURCE_UNSET ||
				    (res->start == 0 && res->end == 0))
					continue;

				pnp_start = res->start;
				pnp_end = res->end;

				/*
				 * If the PNP region doesn't overlap the PCI
				 * region at all, there's no problem.
				 */
				if (pnp_end < pci_start || pnp_start > pci_end)
					continue;

				/*
				 * If the PNP region completely encloses (or is
				 * at least as large as) the PCI region, that's
				 * also OK.  For example, this happens when the
				 * PNP device describes a bridge with PCI
				 * behind it.
				 */
				if (pnp_start <= pci_start &&
				    pnp_end >= pci_end)
					continue;

				/*
				 * Otherwise, the PNP region overlaps *part* of
				 * the PCI region, and that might prevent a PCI
				 * driver from requesting its resources.
				 */
				dev_warn(&dev->dev, "mem resource "
					"(0x%llx-0x%llx) overlaps %s BAR %d "
					"(0x%llx-0x%llx), disabling\n",
					(unsigned long long) pnp_start,
					(unsigned long long) pnp_end,
					pci_name(pdev), i,
					(unsigned long long) pci_start,
					(unsigned long long) pci_end);
				res->flags |= IORESOURCE_DISABLED;
			}
		}
	}
}

/*
 *  PnP Quirks
 *  Cards or devices that need some tweaking due to incomplete resource info
 */

static struct pnp_fixup pnp_fixups[] = {
	/* Soundblaster awe io port quirk */
	{"CTL0021", quirk_awe32_resources},
	{"CTL0022", quirk_awe32_resources},
	{"CTL0023", quirk_awe32_resources},
	/* CMI 8330 interrupt and dma fix */
	{"@X@0001", quirk_cmi8330_resources},
	/* Soundblaster audio device io port range quirk */
	{"CTL0001", quirk_sb16audio_resources},
	{"CTL0031", quirk_sb16audio_resources},
	{"CTL0041", quirk_sb16audio_resources},
	{"CTL0042", quirk_sb16audio_resources},
	{"CTL0043", quirk_sb16audio_resources},
	{"CTL0044", quirk_sb16audio_resources},
	{"CTL0045", quirk_sb16audio_resources},
	/* Add IRQ-less MPU options */
	{"ADS7151", quirk_ad1815_mpu_resources},
	{"ADS7181", quirk_isapnp_mpu_resources},
	{"AZT0002", quirk_isapnp_mpu_resources},
	/* PnP resources that might overlap PCI BARs */
	{"PNP0c01", quirk_system_pci_resources},
	{"PNP0c02", quirk_system_pci_resources},
	{""}
};

void pnp_fixup_device(struct pnp_dev *dev)
{
	struct pnp_fixup *f;

	for (f = pnp_fixups; *f->id; f++) {
		if (!compare_pnp_id(dev->id, f->id))
			continue;
#ifdef DEBUG
		dev_dbg(&dev->dev, "%s: calling ", f->id);
		print_fn_descriptor_symbol("%s\n", f->quirk_function);
#endif
		f->quirk_function(dev);
	}
}
