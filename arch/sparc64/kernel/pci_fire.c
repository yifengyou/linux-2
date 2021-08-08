/* pci_fire.c: Sun4u platform PCI-E controller support.
 *
 * Copyright (C) 2007 David S. Miller (davem@davemloft.net)
 */
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/msi.h>
#include <linux/irq.h>

#include <asm/oplib.h>
#include <asm/prom.h>
#include <asm/irq.h>

#include "pci_impl.h"

#define fire_read(__reg) \
({	u64 __ret; \
	__asm__ __volatile__("ldxa [%1] %2, %0" \
			     : "=r" (__ret) \
			     : "r" (__reg), "i" (ASI_PHYS_BYPASS_EC_E) \
			     : "memory"); \
	__ret; \
})
#define fire_write(__reg, __val) \
	__asm__ __volatile__("stxa %0, [%1] %2" \
			     : /* no outputs */ \
			     : "r" (__val), "r" (__reg), \
			       "i" (ASI_PHYS_BYPASS_EC_E) \
			     : "memory")

static void __init pci_fire_scan_bus(struct pci_pbm_info *pbm)
{
	pbm->pci_bus = pci_scan_one_pbm(pbm);

	/* XXX register error interrupt handlers XXX */
}

#define FIRE_IOMMU_CONTROL	0x40000UL
#define FIRE_IOMMU_TSBBASE	0x40008UL
#define FIRE_IOMMU_FLUSH	0x40100UL
#define FIRE_IOMMU_FLUSHINV	0x40108UL

static int pci_fire_pbm_iommu_init(struct pci_pbm_info *pbm)
{
	struct iommu *iommu = pbm->iommu;
	u32 vdma[2], dma_mask;
	u64 control;
	int tsbsize, err;

	/* No virtual-dma property on these guys, use largest size.  */
	vdma[0] = 0xc0000000; /* base */
	vdma[1] = 0x40000000; /* size */
	dma_mask = 0xffffffff;
	tsbsize = 128;

	/* Register addresses. */
	iommu->iommu_control  = pbm->pbm_regs + FIRE_IOMMU_CONTROL;
	iommu->iommu_tsbbase  = pbm->pbm_regs + FIRE_IOMMU_TSBBASE;
	iommu->iommu_flush    = pbm->pbm_regs + FIRE_IOMMU_FLUSH;
	iommu->iommu_flushinv = pbm->pbm_regs + FIRE_IOMMU_FLUSHINV;

	/* We use the main control/status register of FIRE as the write
	 * completion register.
	 */
	iommu->write_complete_reg = pbm->controller_regs + 0x410000UL;

	/*
	 * Invalidate TLB Entries.
	 */
	fire_write(iommu->iommu_flushinv, ~(u64)0);

	err = iommu_table_init(iommu, tsbsize * 8 * 1024, vdma[0], dma_mask,
			       pbm->numa_node);
	if (err)
		return err;

	fire_write(iommu->iommu_tsbbase, __pa(iommu->page_table) | 0x7UL);

	control = fire_read(iommu->iommu_control);
	control |= (0x00000400 /* TSB cache snoop enable */	|
		    0x00000300 /* Cache mode */			|
		    0x00000002 /* Bypass enable */		|
		    0x00000001 /* Translation enable */);
	fire_write(iommu->iommu_control, control);

	return 0;
}

#ifdef CONFIG_PCI_MSI
struct pci_msiq_entry {
	u64		word0;
#define MSIQ_WORD0_RESV			0x8000000000000000UL
#define MSIQ_WORD0_FMT_TYPE		0x7f00000000000000UL
#define MSIQ_WORD0_FMT_TYPE_SHIFT	56
#define MSIQ_WORD0_LEN			0x00ffc00000000000UL
#define MSIQ_WORD0_LEN_SHIFT		46
#define MSIQ_WORD0_ADDR0		0x00003fff00000000UL
#define MSIQ_WORD0_ADDR0_SHIFT		32
#define MSIQ_WORD0_RID			0x00000000ffff0000UL
#define MSIQ_WORD0_RID_SHIFT		16
#define MSIQ_WORD0_DATA0		0x000000000000ffffUL
#define MSIQ_WORD0_DATA0_SHIFT		0

#define MSIQ_TYPE_MSG			0x6
#define MSIQ_TYPE_MSI32			0xb
#define MSIQ_TYPE_MSI64			0xf

	u64		word1;
#define MSIQ_WORD1_ADDR1		0xffffffffffff0000UL
#define MSIQ_WORD1_ADDR1_SHIFT		16
#define MSIQ_WORD1_DATA1		0x000000000000ffffUL
#define MSIQ_WORD1_DATA1_SHIFT		0

	u64		resv[6];
};

/* All MSI registers are offset from pbm->pbm_regs */
#define EVENT_QUEUE_BASE_ADDR_REG	0x010000UL
#define  EVENT_QUEUE_BASE_ADDR_ALL_ONES	0xfffc000000000000UL

#define EVENT_QUEUE_CONTROL_SET(EQ)	(0x011000UL + (EQ) * 0x8UL)
#define  EVENT_QUEUE_CONTROL_SET_OFLOW	0x0200000000000000UL
#define  EVENT_QUEUE_CONTROL_SET_EN	0x0000100000000000UL

#define EVENT_QUEUE_CONTROL_CLEAR(EQ)	(0x011200UL + (EQ) * 0x8UL)
#define  EVENT_QUEUE_CONTROL_CLEAR_OF	0x0200000000000000UL
#define  EVENT_QUEUE_CONTROL_CLEAR_E2I	0x0000800000000000UL
#define  EVENT_QUEUE_CONTROL_CLEAR_DIS	0x0000100000000000UL

#define EVENT_QUEUE_STATE(EQ)		(0x011400UL + (EQ) * 0x8UL)
#define  EVENT_QUEUE_STATE_MASK		0x0000000000000007UL
#define  EVENT_QUEUE_STATE_IDLE		0x0000000000000001UL
#define  EVENT_QUEUE_STATE_ACTIVE	0x0000000000000002UL
#define  EVENT_QUEUE_STATE_ERROR	0x0000000000000004UL

#define EVENT_QUEUE_TAIL(EQ)		(0x011600UL + (EQ) * 0x8UL)
#define  EVENT_QUEUE_TAIL_OFLOW		0x0200000000000000UL
#define  EVENT_QUEUE_TAIL_VAL		0x000000000000007fUL

#define EVENT_QUEUE_HEAD(EQ)		(0x011800UL + (EQ) * 0x8UL)
#define  EVENT_QUEUE_HEAD_VAL		0x000000000000007fUL

#define MSI_MAP(MSI)			(0x020000UL + (MSI) * 0x8UL)
#define  MSI_MAP_VALID			0x8000000000000000UL
#define  MSI_MAP_EQWR_N			0x4000000000000000UL
#define  MSI_MAP_EQNUM			0x000000000000003fUL

#define MSI_CLEAR(MSI)			(0x028000UL + (MSI) * 0x8UL)
#define  MSI_CLEAR_EQWR_N		0x4000000000000000UL

#define IMONDO_DATA0			0x02C000UL
#define  IMONDO_DATA0_DATA		0xffffffffffffffc0UL

#define IMONDO_DATA1			0x02C008UL
#define  IMONDO_DATA1_DATA		0xffffffffffffffffUL

#define MSI_32BIT_ADDR			0x034000UL
#define  MSI_32BIT_ADDR_VAL		0x00000000ffff0000UL

#define MSI_64BIT_ADDR			0x034008UL
#define  MSI_64BIT_ADDR_VAL		0xffffffffffff0000UL

static int pci_fire_get_head(struct pci_pbm_info *pbm, unsigned long msiqid,
			     unsigned long *head)
{
	*head = fire_read(pbm->pbm_regs + EVENT_QUEUE_HEAD(msiqid));
	return 0;
}

static int pci_fire_dequeue_msi(struct pci_pbm_info *pbm, unsigned long msiqid,
				unsigned long *head, unsigned long *msi)
{
	unsigned long type_fmt, type, msi_num;
	struct pci_msiq_entry *base, *ep;

	base = (pbm->msi_queues + ((msiqid - pbm->msiq_first) * 8192));
	ep = &base[*head];

	if ((ep->word0 & MSIQ_WORD0_FMT_TYPE) == 0)
		return 0;

	type_fmt = ((ep->word0 & MSIQ_WORD0_FMT_TYPE) >>
		    MSIQ_WORD0_FMT_TYPE_SHIFT);
	type = (type_fmt >> 3);
	if (unlikely(type != MSIQ_TYPE_MSI32 &&
		     type != MSIQ_TYPE_MSI64))
		return -EINVAL;

	*msi = msi_num = ((ep->word0 & MSIQ_WORD0_DATA0) >>
			  MSIQ_WORD0_DATA0_SHIFT);

	fire_write(pbm->pbm_regs + MSI_CLEAR(msi_num),
		   MSI_CLEAR_EQWR_N);

	/* Clear the entry.  */
	ep->word0 &= ~MSIQ_WORD0_FMT_TYPE;

	/* Go to next entry in ring.  */
	(*head)++;
	if (*head >= pbm->msiq_ent_count)
		*head = 0;

	return 1;
}

static int pci_fire_set_head(struct pci_pbm_info *pbm, unsigned long msiqid,
			     unsigned long head)
{
	fire_write(pbm->pbm_regs + EVENT_QUEUE_HEAD(msiqid), head);
	return 0;
}

static int pci_fire_msi_setup(struct pci_pbm_info *pbm, unsigned long msiqid,
			      unsigned long msi, int is_msi64)
{
	u64 val;

	val = fire_read(pbm->pbm_regs + MSI_MAP(msi));
	val &= ~(MSI_MAP_EQNUM);
	val |= msiqid;
	fire_write(pbm->pbm_regs + MSI_MAP(msi), val);

	fire_write(pbm->pbm_regs + MSI_CLEAR(msi),
		   MSI_CLEAR_EQWR_N);

	val = fire_read(pbm->pbm_regs + MSI_MAP(msi));
	val |= MSI_MAP_VALID;
	fire_write(pbm->pbm_regs + MSI_MAP(msi), val);

	return 0;
}

static int pci_fire_msi_teardown(struct pci_pbm_info *pbm, unsigned long msi)
{
	unsigned long msiqid;
	u64 val;

	val = fire_read(pbm->pbm_regs + MSI_MAP(msi));
	msiqid = (val & MSI_MAP_EQNUM);

	val &= ~MSI_MAP_VALID;

	fire_write(pbm->pbm_regs + MSI_MAP(msi), val);

	return 0;
}

static int pci_fire_msiq_alloc(struct pci_pbm_info *pbm)
{
	unsigned long pages, order, i;

	order = get_order(512 * 1024);
	pages = __get_free_pages(GFP_KERNEL | __GFP_COMP, order);
	if (pages == 0UL) {
		printk(KERN_ERR "MSI: Cannot allocate MSI queues (o=%lu).\n",
		       order);
		return -ENOMEM;
	}
	memset((char *)pages, 0, PAGE_SIZE << order);
	pbm->msi_queues = (void *) pages;

	fire_write(pbm->pbm_regs + EVENT_QUEUE_BASE_ADDR_REG,
		   (EVENT_QUEUE_BASE_ADDR_ALL_ONES |
		    __pa(pbm->msi_queues)));

	fire_write(pbm->pbm_regs + IMONDO_DATA0,
		   pbm->portid << 6);
	fire_write(pbm->pbm_regs + IMONDO_DATA1, 0);

	fire_write(pbm->pbm_regs + MSI_32BIT_ADDR,
		   pbm->msi32_start);
	fire_write(pbm->pbm_regs + MSI_64BIT_ADDR,
		   pbm->msi64_start);

	for (i = 0; i < pbm->msiq_num; i++) {
		fire_write(pbm->pbm_regs + EVENT_QUEUE_HEAD(i), 0);
		fire_write(pbm->pbm_regs + EVENT_QUEUE_TAIL(i), 0);
	}

	return 0;
}

static void pci_fire_msiq_free(struct pci_pbm_info *pbm)
{
	unsigned long pages, order;

	order = get_order(512 * 1024);
	pages = (unsigned long) pbm->msi_queues;

	free_pages(pages, order);

	pbm->msi_queues = NULL;
}

static int pci_fire_msiq_build_irq(struct pci_pbm_info *pbm,
				   unsigned long msiqid,
				   unsigned long devino)
{
	unsigned long cregs = (unsigned long) pbm->pbm_regs;
	unsigned long imap_reg, iclr_reg, int_ctrlr;
	unsigned int virt_irq;
	int fixup;
	u64 val;

	imap_reg = cregs + (0x001000UL + (devino * 0x08UL));
	iclr_reg = cregs + (0x001400UL + (devino * 0x08UL));

	/* XXX iterate amongst the 4 IRQ controllers XXX */
	int_ctrlr = (1UL << 6);

	val = fire_read(imap_reg);
	val |= (1UL << 63) | int_ctrlr;
	fire_write(imap_reg, val);

	fixup = ((pbm->portid << 6) | devino) - int_ctrlr;

	virt_irq = build_irq(fixup, iclr_reg, imap_reg);
	if (!virt_irq)
		return -ENOMEM;

	fire_write(pbm->pbm_regs +
		   EVENT_QUEUE_CONTROL_SET(msiqid),
		   EVENT_QUEUE_CONTROL_SET_EN);

	return virt_irq;
}

static const struct sparc64_msiq_ops pci_fire_msiq_ops = {
	.get_head	=	pci_fire_get_head,
	.dequeue_msi	=	pci_fire_dequeue_msi,
	.set_head	=	pci_fire_set_head,
	.msi_setup	=	pci_fire_msi_setup,
	.msi_teardown	=	pci_fire_msi_teardown,
	.msiq_alloc	=	pci_fire_msiq_alloc,
	.msiq_free	=	pci_fire_msiq_free,
	.msiq_build_irq	=	pci_fire_msiq_build_irq,
};

static void pci_fire_msi_init(struct pci_pbm_info *pbm)
{
	sparc64_pbm_msi_init(pbm, &pci_fire_msiq_ops);
}
#else /* CONFIG_PCI_MSI */
static void pci_fire_msi_init(struct pci_pbm_info *pbm)
{
}
#endif /* !(CONFIG_PCI_MSI) */

/* Based at pbm->controller_regs */
#define FIRE_PARITY_CONTROL	0x470010UL
#define  FIRE_PARITY_ENAB	0x8000000000000000UL
#define FIRE_FATAL_RESET_CTL	0x471028UL
#define  FIRE_FATAL_RESET_SPARE	0x0000000004000000UL
#define  FIRE_FATAL_RESET_MB	0x0000000002000000UL
#define  FIRE_FATAL_RESET_CPE	0x0000000000008000UL
#define  FIRE_FATAL_RESET_APE	0x0000000000004000UL
#define  FIRE_FATAL_RESET_PIO	0x0000000000000040UL
#define  FIRE_FATAL_RESET_JW	0x0000000000000004UL
#define  FIRE_FATAL_RESET_JI	0x0000000000000002UL
#define  FIRE_FATAL_RESET_JR	0x0000000000000001UL
#define FIRE_CORE_INTR_ENABLE	0x471800UL

/* Based at pbm->pbm_regs */
#define FIRE_TLU_CTRL		0x80000UL
#define  FIRE_TLU_CTRL_TIM	0x00000000da000000UL
#define  FIRE_TLU_CTRL_QDET	0x0000000000000100UL
#define  FIRE_TLU_CTRL_CFG	0x0000000000000001UL
#define FIRE_TLU_DEV_CTRL	0x90008UL
#define FIRE_TLU_LINK_CTRL	0x90020UL
#define FIRE_TLU_LINK_CTRL_CLK	0x0000000000000040UL
#define FIRE_LPU_RESET		0xe2008UL
#define FIRE_LPU_LLCFG		0xe2200UL
#define  FIRE_LPU_LLCFG_VC0	0x0000000000000100UL
#define FIRE_LPU_FCTRL_UCTRL	0xe2240UL
#define  FIRE_LPU_FCTRL_UCTRL_N	0x0000000000000002UL
#define  FIRE_LPU_FCTRL_UCTRL_P	0x0000000000000001UL
#define FIRE_LPU_TXL_FIFOP	0xe2430UL
#define FIRE_LPU_LTSSM_CFG2	0xe2788UL
#define FIRE_LPU_LTSSM_CFG3	0xe2790UL
#define FIRE_LPU_LTSSM_CFG4	0xe2798UL
#define FIRE_LPU_LTSSM_CFG5	0xe27a0UL
#define FIRE_DMC_IENAB		0x31800UL
#define FIRE_DMC_DBG_SEL_A	0x53000UL
#define FIRE_DMC_DBG_SEL_B	0x53008UL
#define FIRE_PEC_IENAB		0x51800UL

static void pci_fire_hw_init(struct pci_pbm_info *pbm)
{
	u64 val;

	fire_write(pbm->controller_regs + FIRE_PARITY_CONTROL,
		   FIRE_PARITY_ENAB);

	fire_write(pbm->controller_regs + FIRE_FATAL_RESET_CTL,
		   (FIRE_FATAL_RESET_SPARE |
		    FIRE_FATAL_RESET_MB |
		    FIRE_FATAL_RESET_CPE |
		    FIRE_FATAL_RESET_APE |
		    FIRE_FATAL_RESET_PIO |
		    FIRE_FATAL_RESET_JW |
		    FIRE_FATAL_RESET_JI |
		    FIRE_FATAL_RESET_JR));

	fire_write(pbm->controller_regs + FIRE_CORE_INTR_ENABLE, ~(u64)0);

	val = fire_read(pbm->pbm_regs + FIRE_TLU_CTRL);
	val |= (FIRE_TLU_CTRL_TIM |
		FIRE_TLU_CTRL_QDET |
		FIRE_TLU_CTRL_CFG);
	fire_write(pbm->pbm_regs + FIRE_TLU_CTRL, val);
	fire_write(pbm->pbm_regs + FIRE_TLU_DEV_CTRL, 0);
	fire_write(pbm->pbm_regs + FIRE_TLU_LINK_CTRL,
		   FIRE_TLU_LINK_CTRL_CLK);

	fire_write(pbm->pbm_regs + FIRE_LPU_RESET, 0);
	fire_write(pbm->pbm_regs + FIRE_LPU_LLCFG,
		   FIRE_LPU_LLCFG_VC0);
	fire_write(pbm->pbm_regs + FIRE_LPU_FCTRL_UCTRL,
		   (FIRE_LPU_FCTRL_UCTRL_N |
		    FIRE_LPU_FCTRL_UCTRL_P));
	fire_write(pbm->pbm_regs + FIRE_LPU_TXL_FIFOP,
		   ((0xffff << 16) | (0x0000 << 0)));
	fire_write(pbm->pbm_regs + FIRE_LPU_LTSSM_CFG2, 3000000);
	fire_write(pbm->pbm_regs + FIRE_LPU_LTSSM_CFG3, 500000);
	fire_write(pbm->pbm_regs + FIRE_LPU_LTSSM_CFG4,
		   (2 << 16) | (140 << 8));
	fire_write(pbm->pbm_regs + FIRE_LPU_LTSSM_CFG5, 0);

	fire_write(pbm->pbm_regs + FIRE_DMC_IENAB, ~(u64)0);
	fire_write(pbm->pbm_regs + FIRE_DMC_DBG_SEL_A, 0);
	fire_write(pbm->pbm_regs + FIRE_DMC_DBG_SEL_B, 0);

	fire_write(pbm->pbm_regs + FIRE_PEC_IENAB, ~(u64)0);
}

static int __init pci_fire_pbm_init(struct pci_controller_info *p,
				    struct device_node *dp, u32 portid)
{
	const struct linux_prom64_registers *regs;
	struct pci_pbm_info *pbm;
	int err;

	if ((portid & 1) == 0)
		pbm = &p->pbm_A;
	else
		pbm = &p->pbm_B;

	pbm->next = pci_pbm_root;
	pci_pbm_root = pbm;

	pbm->numa_node = -1;

	pbm->scan_bus = pci_fire_scan_bus;
	pbm->pci_ops = &sun4u_pci_ops;
	pbm->config_space_reg_bits = 12;

	pbm->index = pci_num_pbms++;

	pbm->portid = portid;
	pbm->parent = p;
	pbm->prom_node = dp;
	pbm->name = dp->full_name;

	regs = of_get_property(dp, "reg", NULL);
	pbm->pbm_regs = regs[0].phys_addr;
	pbm->controller_regs = regs[1].phys_addr - 0x410000UL;

	printk("%s: SUN4U PCIE Bus Module\n", pbm->name);

	pci_determine_mem_io_space(pbm);

	pci_get_pbm_props(pbm);

	pci_fire_hw_init(pbm);

	err = pci_fire_pbm_iommu_init(pbm);
	if (err)
		return err;

	pci_fire_msi_init(pbm);

	return 0;
}

static inline int portid_compare(u32 x, u32 y)
{
	if (x == (y ^ 1))
		return 1;
	return 0;
}

void __init fire_pci_init(struct device_node *dp, const char *model_name)
{
	struct pci_controller_info *p;
	u32 portid = of_getintprop_default(dp, "portid", 0xff);
	struct iommu *iommu;
	struct pci_pbm_info *pbm;

	for (pbm = pci_pbm_root; pbm; pbm = pbm->next) {
		if (portid_compare(pbm->portid, portid)) {
			if (pci_fire_pbm_init(pbm->parent, dp, portid))
				goto fatal_memory_error;
			return;
		}
	}

	p = kzalloc(sizeof(struct pci_controller_info), GFP_ATOMIC);
	if (!p)
		goto fatal_memory_error;

	iommu = kzalloc(sizeof(struct iommu), GFP_ATOMIC);
	if (!iommu)
		goto fatal_memory_error;

	p->pbm_A.iommu = iommu;

	iommu = kzalloc(sizeof(struct iommu), GFP_ATOMIC);
	if (!iommu)
		goto fatal_memory_error;

	p->pbm_B.iommu = iommu;

	if (pci_fire_pbm_init(p, dp, portid))
		goto fatal_memory_error;

	return;

fatal_memory_error:
	prom_printf("PCI_FIRE: Fatal memory allocation error.\n");
	prom_halt();
}
