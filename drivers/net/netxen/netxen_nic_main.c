/*
 * Copyright (C) 2003 - 2006 NetXen, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA  02111-1307, USA.
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.
 *
 * Contact Information:
 *    info@netxen.com
 * NetXen,
 * 3965 Freedom Circle, Fourth floor,
 * Santa Clara, CA 95054
 *
 *
 *  Main source file for NetXen NIC Driver on Linux
 *
 */

#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include "netxen_nic_hw.h"

#include "netxen_nic.h"
#include "netxen_nic_phan_reg.h"

#include <linux/dma-mapping.h>
#include <net/ip.h>

MODULE_DESCRIPTION("NetXen Multi port (1/10) Gigabit Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(NETXEN_NIC_LINUX_VERSIONID);

char netxen_nic_driver_name[] = "netxen_nic";
static char netxen_nic_driver_string[] = "NetXen Network Driver version "
    NETXEN_NIC_LINUX_VERSIONID;

#define NETXEN_NETDEV_WEIGHT 120
#define NETXEN_ADAPTER_UP_MAGIC 777
#define NETXEN_NIC_PEG_TUNE 0

/* Local functions to NetXen NIC driver */
static int __devinit netxen_nic_probe(struct pci_dev *pdev,
				      const struct pci_device_id *ent);
static void __devexit netxen_nic_remove(struct pci_dev *pdev);
static int netxen_nic_open(struct net_device *netdev);
static int netxen_nic_close(struct net_device *netdev);
static int netxen_nic_xmit_frame(struct sk_buff *, struct net_device *);
static void netxen_tx_timeout(struct net_device *netdev);
static void netxen_tx_timeout_task(struct work_struct *work);
static void netxen_watchdog(unsigned long);
static int netxen_nic_poll(struct napi_struct *napi, int budget);
#ifdef CONFIG_NET_POLL_CONTROLLER
static void netxen_nic_poll_controller(struct net_device *netdev);
#endif
static irqreturn_t netxen_intr(int irq, void *data);
static irqreturn_t netxen_msi_intr(int irq, void *data);

/*  PCI Device ID Table  */
#define ENTRY(device) \
	{PCI_DEVICE(0x4040, (device)), \
	.class = PCI_CLASS_NETWORK_ETHERNET << 8, .class_mask = ~0}

static struct pci_device_id netxen_pci_tbl[] __devinitdata = {
	ENTRY(0x0001),
	ENTRY(0x0002),
	ENTRY(0x0003),
	ENTRY(0x0004),
	ENTRY(0x0005),
	ENTRY(0x0024),
	ENTRY(0x0025),
	{0,}
};

MODULE_DEVICE_TABLE(pci, netxen_pci_tbl);

/*
 * In netxen_nic_down(), we must wait for any pending callback requests into
 * netxen_watchdog_task() to complete; eg otherwise the watchdog_timer could be
 * reenabled right after it is deleted in netxen_nic_down().
 * FLUSH_SCHEDULED_WORK()  does this synchronization.
 *
 * Normally, schedule_work()/flush_scheduled_work() could have worked, but
 * netxen_nic_close() is invoked with kernel rtnl lock held. netif_carrier_off()
 * call in netxen_nic_close() triggers a schedule_work(&linkwatch_work), and a
 * subsequent call to flush_scheduled_work() in netxen_nic_down() would cause
 * linkwatch_event() to be executed which also attempts to acquire the rtnl
 * lock thus causing a deadlock.
 */

static struct workqueue_struct *netxen_workq;
#define SCHEDULE_WORK(tp)	queue_work(netxen_workq, tp)
#define FLUSH_SCHEDULED_WORK()	flush_workqueue(netxen_workq)

static void netxen_watchdog(unsigned long);

static void netxen_nic_update_cmd_producer(struct netxen_adapter *adapter,
					   uint32_t crb_producer)
{
	switch (adapter->portnum) {
		case 0:
			writel(crb_producer, NETXEN_CRB_NORMALIZE
					(adapter, CRB_CMD_PRODUCER_OFFSET));
			return;
		case 1:
			writel(crb_producer, NETXEN_CRB_NORMALIZE
					(adapter, CRB_CMD_PRODUCER_OFFSET_1));
			return;
		case 2:
			writel(crb_producer, NETXEN_CRB_NORMALIZE
					(adapter, CRB_CMD_PRODUCER_OFFSET_2));
			return;
		case 3:
			writel(crb_producer, NETXEN_CRB_NORMALIZE
					(adapter, CRB_CMD_PRODUCER_OFFSET_3));
			return;
		default:
			printk(KERN_WARNING "We tried to update "
					"CRB_CMD_PRODUCER_OFFSET for invalid "
					"PCI function id %d\n",
					adapter->portnum);
			return;
	}
}

static void netxen_nic_update_cmd_consumer(struct netxen_adapter *adapter,
					   u32 crb_consumer)
{
	switch (adapter->portnum) {
		case 0:
			writel(crb_consumer, NETXEN_CRB_NORMALIZE
				(adapter, CRB_CMD_CONSUMER_OFFSET));
			return;
		case 1:
			writel(crb_consumer, NETXEN_CRB_NORMALIZE
				(adapter, CRB_CMD_CONSUMER_OFFSET_1));
			return;
		case 2:
			writel(crb_consumer, NETXEN_CRB_NORMALIZE
				(adapter, CRB_CMD_CONSUMER_OFFSET_2));
			return;
		case 3:
			writel(crb_consumer, NETXEN_CRB_NORMALIZE
				(adapter, CRB_CMD_CONSUMER_OFFSET_3));
			return;
		default:
			printk(KERN_WARNING "We tried to update "
					"CRB_CMD_PRODUCER_OFFSET for invalid "
					"PCI function id %d\n",
					adapter->portnum);
			return;
	}
}

#define	ADAPTER_LIST_SIZE 12

static uint32_t msi_tgt_status[4] = {
	ISR_INT_TARGET_STATUS, ISR_INT_TARGET_STATUS_F1,
	ISR_INT_TARGET_STATUS_F2, ISR_INT_TARGET_STATUS_F3
};

static uint32_t sw_int_mask[4] = {
	CRB_SW_INT_MASK_0, CRB_SW_INT_MASK_1,
	CRB_SW_INT_MASK_2, CRB_SW_INT_MASK_3
};

static void netxen_nic_disable_int(struct netxen_adapter *adapter)
{
	u32 mask = 0x7ff;
	int retries = 32;
	int port = adapter->portnum;
	int pci_fn = adapter->ahw.pci_func;

	if (adapter->msi_mode != MSI_MODE_MULTIFUNC)
		writel(0x0, NETXEN_CRB_NORMALIZE(adapter, sw_int_mask[port]));

	if (adapter->intr_scheme != -1 &&
	    adapter->intr_scheme != INTR_SCHEME_PERPORT)
		writel(mask,PCI_OFFSET_SECOND_RANGE(adapter, ISR_INT_MASK));

	if (!(adapter->flags & NETXEN_NIC_MSI_ENABLED)) {
		do {
			writel(0xffffffff,
			       PCI_OFFSET_SECOND_RANGE(adapter, ISR_INT_TARGET_STATUS));
			mask = readl(pci_base_offset(adapter, ISR_INT_VECTOR));
			if (!(mask & 0x80))
				break;
			udelay(10);
		} while (--retries);

		if (!retries) {
			printk(KERN_NOTICE "%s: Failed to disable interrupt completely\n",
					netxen_nic_driver_name);
		}
	} else {
		if (adapter->msi_mode == MSI_MODE_MULTIFUNC) {
			writel(0xffffffff, PCI_OFFSET_SECOND_RANGE(adapter,
						msi_tgt_status[pci_fn]));
		}
	}
}

static void netxen_nic_enable_int(struct netxen_adapter *adapter)
{
	u32 mask;
	int port = adapter->portnum;

	DPRINTK(1, INFO, "Entered ISR Enable \n");

	if (adapter->intr_scheme != -1 &&
		adapter->intr_scheme != INTR_SCHEME_PERPORT) {
		switch (adapter->ahw.board_type) {
		case NETXEN_NIC_GBE:
			mask  =  0x77b;
			break;
		case NETXEN_NIC_XGBE:
			mask  =  0x77f;
			break;
		default:
			mask  =  0x7ff;
			break;
		}

		writel(mask, PCI_OFFSET_SECOND_RANGE(adapter, ISR_INT_MASK));
	}

	writel(0x1, NETXEN_CRB_NORMALIZE(adapter, sw_int_mask[port]));

	if (!(adapter->flags & NETXEN_NIC_MSI_ENABLED)) {
		mask = 0xbff;
		if (adapter->intr_scheme != -1 &&
			adapter->intr_scheme != INTR_SCHEME_PERPORT) {
			writel(0X0, NETXEN_CRB_NORMALIZE(adapter, CRB_INT_VECTOR));
		}
		writel(mask,
		       PCI_OFFSET_SECOND_RANGE(adapter, ISR_INT_TARGET_MASK));
	}

	DPRINTK(1, INFO, "Done with enable Int\n");
}

/*
 * netxen_nic_probe()
 *
 * The Linux system will invoke this after identifying the vendor ID and
 * device Id in the pci_tbl supported by this module.
 *
 * A quad port card has one operational PCI config space, (function 0),
 * which is used to access all four ports.
 *
 * This routine will initialize the adapter, and setup the global parameters
 * along with the port's specific structure.
 */
static int __devinit
netxen_nic_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *netdev = NULL;
	struct netxen_adapter *adapter = NULL;
	void __iomem *mem_ptr0 = NULL;
	void __iomem *mem_ptr1 = NULL;
	void __iomem *mem_ptr2 = NULL;
	unsigned long first_page_group_end;
	unsigned long first_page_group_start;


	u8 __iomem *db_ptr = NULL;
	unsigned long mem_base, mem_len, db_base, db_len;
	int pci_using_dac, i = 0, err;
	int ring;
	struct netxen_recv_context *recv_ctx = NULL;
	struct netxen_rcv_desc_ctx *rcv_desc = NULL;
	struct netxen_cmd_buffer *cmd_buf_arr = NULL;
	__le64 mac_addr[FLASH_NUM_PORTS + 1];
	int valid_mac = 0;
	u32 val;
	int pci_func_id = PCI_FUNC(pdev->devfn);
	DECLARE_MAC_BUF(mac);

	if (pci_func_id == 0)
		printk(KERN_INFO "%s \n", netxen_nic_driver_string);

	if (pdev->class != 0x020000) {
		printk(KERN_DEBUG "NetXen function %d, class %x will not "
				"be enabled.\n",pci_func_id, pdev->class);
		return -ENODEV;
	}
	if ((err = pci_enable_device(pdev)))
		return err;
	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		err = -ENODEV;
		goto err_out_disable_pdev;
	}

	if ((err = pci_request_regions(pdev, netxen_nic_driver_name)))
		goto err_out_disable_pdev;

	pci_set_master(pdev);
	if (pdev->revision == NX_P2_C1 &&
	    (pci_set_dma_mask(pdev, DMA_35BIT_MASK) == 0) &&
	    (pci_set_consistent_dma_mask(pdev, DMA_35BIT_MASK) == 0)) {
		pci_using_dac = 1;
	} else {
		if ((err = pci_set_dma_mask(pdev, DMA_32BIT_MASK)) ||
		    (err = pci_set_consistent_dma_mask(pdev, DMA_32BIT_MASK)))
			goto err_out_free_res;

		pci_using_dac = 0;
	}


	netdev = alloc_etherdev(sizeof(struct netxen_adapter));
	if(!netdev) {
		printk(KERN_ERR"%s: Failed to allocate memory for the "
				"device block.Check system memory resource"
				" usage.\n", netxen_nic_driver_name);
		goto err_out_free_res;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev->priv;

	adapter->ahw.pdev = pdev;
	adapter->ahw.pci_func  = pci_func_id;

	/* remap phys address */
	mem_base = pci_resource_start(pdev, 0);	/* 0 is for BAR 0 */
	mem_len = pci_resource_len(pdev, 0);

	/* 128 Meg of memory */
	if (mem_len == NETXEN_PCI_128MB_SIZE) {
		mem_ptr0 = ioremap(mem_base, FIRST_PAGE_GROUP_SIZE);
		mem_ptr1 = ioremap(mem_base + SECOND_PAGE_GROUP_START,
				SECOND_PAGE_GROUP_SIZE);
		mem_ptr2 = ioremap(mem_base + THIRD_PAGE_GROUP_START,
				THIRD_PAGE_GROUP_SIZE);
		first_page_group_start = FIRST_PAGE_GROUP_START;
		first_page_group_end   = FIRST_PAGE_GROUP_END;
	} else if (mem_len == NETXEN_PCI_32MB_SIZE) {
		mem_ptr1 = ioremap(mem_base, SECOND_PAGE_GROUP_SIZE);
		mem_ptr2 = ioremap(mem_base + THIRD_PAGE_GROUP_START -
			SECOND_PAGE_GROUP_START, THIRD_PAGE_GROUP_SIZE);
		first_page_group_start = 0;
		first_page_group_end   = 0;
	} else {
		err = -EIO;
		goto err_out_free_netdev;
	}

	if ((!mem_ptr0 && mem_len == NETXEN_PCI_128MB_SIZE) ||
			!mem_ptr1 || !mem_ptr2) {
		DPRINTK(ERR,
			"Cannot remap adapter memory aborting.:"
			"0 -> %p, 1 -> %p, 2 -> %p\n",
			mem_ptr0, mem_ptr1, mem_ptr2);

		err = -EIO;
		goto err_out_iounmap;
	}
	db_base = pci_resource_start(pdev, 4);	/* doorbell is on bar 4 */
	db_len = pci_resource_len(pdev, 4);

	if (db_len == 0) {
		printk(KERN_ERR "%s: doorbell is disabled\n",
		       netxen_nic_driver_name);
		err = -EIO;
		goto err_out_iounmap;
	}
	DPRINTK(INFO, "doorbell ioremap from %lx a size of %lx\n", db_base,
		db_len);

	db_ptr = ioremap(db_base, NETXEN_DB_MAPSIZE_BYTES);
	if (!db_ptr) {
		printk(KERN_ERR "%s: Failed to allocate doorbell map.",
		       netxen_nic_driver_name);
		err = -EIO;
		goto err_out_iounmap;
	}
	DPRINTK(INFO, "doorbell ioremaped at %p\n", db_ptr);

	adapter->ahw.pci_base0 = mem_ptr0;
	adapter->ahw.first_page_group_start = first_page_group_start;
	adapter->ahw.first_page_group_end   = first_page_group_end;
	adapter->ahw.pci_base1 = mem_ptr1;
	adapter->ahw.pci_base2 = mem_ptr2;
	adapter->ahw.db_base = db_ptr;
	adapter->ahw.db_len = db_len;

	adapter->netdev  = netdev;
	adapter->pdev    = pdev;

	netif_napi_add(netdev, &adapter->napi,
		       netxen_nic_poll, NETXEN_NETDEV_WEIGHT);

	/* this will be read from FW later */
	adapter->intr_scheme = -1;
	adapter->msi_mode = -1;

	/* This will be reset for mezz cards  */
	adapter->portnum = pci_func_id;
	adapter->status   &= ~NETXEN_NETDEV_STATUS;
	adapter->rx_csum = 1;

	netdev->open		   = netxen_nic_open;
	netdev->stop		   = netxen_nic_close;
	netdev->hard_start_xmit    = netxen_nic_xmit_frame;
	netdev->get_stats	   = netxen_nic_get_stats;
	netdev->set_multicast_list = netxen_nic_set_multi;
	netdev->set_mac_address    = netxen_nic_set_mac;
	netdev->change_mtu	   = netxen_nic_change_mtu;
	netdev->tx_timeout	   = netxen_tx_timeout;
	netdev->watchdog_timeo     = 2*HZ;

	netxen_nic_change_mtu(netdev, netdev->mtu);

	SET_ETHTOOL_OPS(netdev, &netxen_nic_ethtool_ops);
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = netxen_nic_poll_controller;
#endif
	/* ScatterGather support */
	netdev->features = NETIF_F_SG;
	netdev->features |= NETIF_F_IP_CSUM;
	netdev->features |= NETIF_F_TSO;

	if (pci_using_dac)
		netdev->features |= NETIF_F_HIGHDMA;

	if (pci_enable_msi(pdev))
		adapter->flags &= ~NETXEN_NIC_MSI_ENABLED;
	else
		adapter->flags |= NETXEN_NIC_MSI_ENABLED;

	netdev->irq = pdev->irq;
	INIT_WORK(&adapter->tx_timeout_task, netxen_tx_timeout_task);

	/*
	 * Set the CRB window to invalid. If any register in window 0 is
	 * accessed it should set the window to 0 and then reset it to 1.
	 */
	adapter->curr_window = 255;

	if (netxen_nic_get_board_info(adapter) != 0) {
		printk("%s: Error getting board config info.\n",
		       netxen_nic_driver_name);
		err = -EIO;
		goto err_out_iounmap;
	}

	/*
	 *  Adapter in our case is quad port so initialize it before
	 *  initializing the ports
	 */

	netxen_initialize_adapter_ops(adapter);

	adapter->max_tx_desc_count = MAX_CMD_DESCRIPTORS_HOST;
	if ((adapter->ahw.boardcfg.board_type == NETXEN_BRDTYPE_P2_SB35_4G) ||
			(adapter->ahw.boardcfg.board_type ==
			 NETXEN_BRDTYPE_P2_SB31_2G))
		adapter->max_rx_desc_count = MAX_RCV_DESCRIPTORS_1G;
	else
		adapter->max_rx_desc_count = MAX_RCV_DESCRIPTORS;
	adapter->max_jumbo_rx_desc_count = MAX_JUMBO_RCV_DESCRIPTORS;
	adapter->max_lro_rx_desc_count = MAX_LRO_RCV_DESCRIPTORS;

	cmd_buf_arr = (struct netxen_cmd_buffer *)vmalloc(TX_RINGSIZE);
	if (cmd_buf_arr == NULL) {
		printk(KERN_ERR
		       "%s: Could not allocate cmd_buf_arr memory:%d\n",
		       netxen_nic_driver_name, (int)TX_RINGSIZE);
		err = -ENOMEM;
		goto err_out_free_adapter;
	}
	memset(cmd_buf_arr, 0, TX_RINGSIZE);
	adapter->cmd_buf_arr = cmd_buf_arr;

	for (i = 0; i < MAX_RCV_CTX; ++i) {
		recv_ctx = &adapter->recv_ctx[i];
		for (ring = 0; ring < NUM_RCV_DESC_RINGS; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];
			switch (RCV_DESC_TYPE(ring)) {
			case RCV_DESC_NORMAL:
				rcv_desc->max_rx_desc_count =
				    adapter->max_rx_desc_count;
				rcv_desc->flags = RCV_DESC_NORMAL;
				rcv_desc->dma_size = RX_DMA_MAP_LEN;
				rcv_desc->skb_size = MAX_RX_BUFFER_LENGTH;
				break;

			case RCV_DESC_JUMBO:
				rcv_desc->max_rx_desc_count =
				    adapter->max_jumbo_rx_desc_count;
				rcv_desc->flags = RCV_DESC_JUMBO;
				rcv_desc->dma_size = RX_JUMBO_DMA_MAP_LEN;
				rcv_desc->skb_size = MAX_RX_JUMBO_BUFFER_LENGTH;
				break;

			case RCV_RING_LRO:
				rcv_desc->max_rx_desc_count =
				    adapter->max_lro_rx_desc_count;
				rcv_desc->flags = RCV_DESC_LRO;
				rcv_desc->dma_size = RX_LRO_DMA_MAP_LEN;
				rcv_desc->skb_size = MAX_RX_LRO_BUFFER_LENGTH;
				break;

			}
			rcv_desc->rx_buf_arr = (struct netxen_rx_buffer *)
			    vmalloc(RCV_BUFFSIZE);

			if (rcv_desc->rx_buf_arr == NULL) {
				printk(KERN_ERR "%s: Could not allocate "
				       "rcv_desc->rx_buf_arr memory:%d\n",
				       netxen_nic_driver_name,
				       (int)RCV_BUFFSIZE);
				err = -ENOMEM;
				goto err_out_free_rx_buffer;
			}
			memset(rcv_desc->rx_buf_arr, 0, RCV_BUFFSIZE);
		}

	}

	netxen_initialize_adapter_sw(adapter);	/* initialize the buffers in adapter */

	/* Mezz cards have PCI function 0,2,3 enabled */
	switch (adapter->ahw.boardcfg.board_type) {
	case NETXEN_BRDTYPE_P2_SB31_10G_IMEZ:
	case NETXEN_BRDTYPE_P2_SB31_10G_HMEZ:
		if (pci_func_id >= 2)
			adapter->portnum = pci_func_id - 2;
		break;
	default:
		break;
	}

	init_timer(&adapter->watchdog_timer);
	adapter->ahw.xg_linkup = 0;
	adapter->watchdog_timer.function = &netxen_watchdog;
	adapter->watchdog_timer.data = (unsigned long)adapter;
	INIT_WORK(&adapter->watchdog_task, netxen_watchdog_task);
	adapter->ahw.pdev = pdev;
	adapter->ahw.revision_id = pdev->revision;

	/* make sure Window == 1 */
	netxen_nic_pci_change_crbwindow(adapter, 1);

	netxen_nic_update_cmd_producer(adapter, 0);
	netxen_nic_update_cmd_consumer(adapter, 0);
	writel(0, NETXEN_CRB_NORMALIZE(adapter, CRB_HOST_CMD_ADDR_LO));

	if (netxen_is_flash_supported(adapter) == 0 &&
	    netxen_get_flash_mac_addr(adapter, mac_addr) == 0)
		valid_mac = 1;
	else
		valid_mac = 0;

	if (valid_mac) {
		unsigned char *p = (unsigned char *)&mac_addr[adapter->portnum];
		netdev->dev_addr[0] = *(p + 5);
		netdev->dev_addr[1] = *(p + 4);
		netdev->dev_addr[2] = *(p + 3);
		netdev->dev_addr[3] = *(p + 2);
		netdev->dev_addr[4] = *(p + 1);
		netdev->dev_addr[5] = *(p + 0);

		memcpy(netdev->perm_addr, netdev->dev_addr,
			netdev->addr_len);
		if (!is_valid_ether_addr(netdev->perm_addr)) {
			printk(KERN_ERR "%s: Bad MAC address %s.\n",
			       netxen_nic_driver_name,
			       print_mac(mac, netdev->dev_addr));
		} else {
			if (adapter->macaddr_set)
				adapter->macaddr_set(adapter,
							netdev->dev_addr);
		}
	}

	if (adapter->portnum == 0) {
		err = netxen_initialize_adapter_offload(adapter);
		if (err)
			goto err_out_free_rx_buffer;
		val = readl(NETXEN_CRB_NORMALIZE(adapter,
					NETXEN_CAM_RAM(0x1fc)));
		if (val == 0x55555555) {
		    /* This is the first boot after power up */
		    netxen_nic_read_w0(adapter, NETXEN_PCIE_REG(0x4), &val);
			if (!(val & 0x4)) {
				val |= 0x4;
				netxen_nic_write_w0(adapter, NETXEN_PCIE_REG(0x4), val);
				netxen_nic_read_w0(adapter, NETXEN_PCIE_REG(0x4), &val);
				if (!(val & 0x4))
					printk(KERN_ERR "%s: failed to set MSI bit in PCI-e reg\n",
							netxen_nic_driver_name);
			}
		    val = readl(NETXEN_CRB_NORMALIZE(adapter,
					NETXEN_ROMUSB_GLB_SW_RESET));
		    printk(KERN_INFO"NetXen: read 0x%08x for reset reg.\n",val);
		    if (val != 0x80000f) {
			/* clear the register for future unloads/loads */
				writel(0, NETXEN_CRB_NORMALIZE(adapter,
							NETXEN_CAM_RAM(0x1fc)));
				printk(KERN_ERR "ERROR in NetXen HW init sequence.\n");
				err = -ENODEV;
				goto err_out_free_dev;
		    }
		} else {
			writel(0, NETXEN_CRB_NORMALIZE(adapter,
						CRB_CMDPEG_STATE));
			netxen_pinit_from_rom(adapter, 0);
			msleep(1);
			netxen_load_firmware(adapter);
			netxen_phantom_init(adapter, NETXEN_NIC_PEG_TUNE);
		}

		/* clear the register for future unloads/loads */
		writel(0, NETXEN_CRB_NORMALIZE(adapter, NETXEN_CAM_RAM(0x1fc)));
		dev_info(&pdev->dev, "cmdpeg state: 0x%0x\n",
			readl(NETXEN_CRB_NORMALIZE(adapter, CRB_CMDPEG_STATE)));

		/*
		 * Tell the hardware our version number.
		 */
		i = (_NETXEN_NIC_LINUX_MAJOR << 16)
			| ((_NETXEN_NIC_LINUX_MINOR << 8))
			| (_NETXEN_NIC_LINUX_SUBVERSION);
		writel(i, NETXEN_CRB_NORMALIZE(adapter, CRB_DRIVER_VERSION));

		/* Unlock the HW, prompting the boot sequence */
		writel(1,
			NETXEN_CRB_NORMALIZE(adapter,
				NETXEN_ROMUSB_GLB_PEGTUNE_DONE));
		/* Handshake with the card before we register the devices. */
		netxen_phantom_init(adapter, NETXEN_NIC_PEG_TUNE);
	}

	/*
	 * See if the firmware gave us a virtual-physical port mapping.
	 */
	adapter->physical_port = adapter->portnum;
	i = readl(NETXEN_CRB_NORMALIZE(adapter, CRB_V2P(adapter->portnum)));
	if (i != 0x55555555)
		adapter->physical_port = i;

	netif_carrier_off(netdev);
	netif_stop_queue(netdev);

	if ((err = register_netdev(netdev))) {
		printk(KERN_ERR "%s: register_netdev failed port #%d"
			       " aborting\n", netxen_nic_driver_name,
			       adapter->portnum);
		err = -EIO;
		goto err_out_free_dev;
	}

	netxen_nic_flash_print(adapter);
	pci_set_drvdata(pdev, adapter);

	return 0;

err_out_free_dev:
	if (adapter->portnum == 0)
		netxen_free_adapter_offload(adapter);

err_out_free_rx_buffer:
	for (i = 0; i < MAX_RCV_CTX; ++i) {
		recv_ctx = &adapter->recv_ctx[i];
		for (ring = 0; ring < NUM_RCV_DESC_RINGS; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];
			if (rcv_desc->rx_buf_arr != NULL) {
				vfree(rcv_desc->rx_buf_arr);
				rcv_desc->rx_buf_arr = NULL;
			}
		}
	}
	vfree(cmd_buf_arr);

err_out_free_adapter:
	if (adapter->flags & NETXEN_NIC_MSI_ENABLED)
		pci_disable_msi(pdev);

	pci_set_drvdata(pdev, NULL);

	if (db_ptr)
		iounmap(db_ptr);

err_out_iounmap:
	if (mem_ptr0)
		iounmap(mem_ptr0);
	if (mem_ptr1)
		iounmap(mem_ptr1);
	if (mem_ptr2)
		iounmap(mem_ptr2);

err_out_free_netdev:
	free_netdev(netdev);

err_out_free_res:
	pci_release_regions(pdev);

err_out_disable_pdev:
	pci_disable_device(pdev);
	return err;
}

static void __devexit netxen_nic_remove(struct pci_dev *pdev)
{
	struct netxen_adapter *adapter;
	struct net_device *netdev;
	struct netxen_rx_buffer *buffer;
	struct netxen_recv_context *recv_ctx;
	struct netxen_rcv_desc_ctx *rcv_desc;
	int i, ctxid, ring;
	static int init_firmware_done = 0;

	adapter = pci_get_drvdata(pdev);
	if (adapter == NULL)
		return;

	netdev = adapter->netdev;

	unregister_netdev(netdev);

	if (adapter->is_up == NETXEN_ADAPTER_UP_MAGIC) {
		init_firmware_done++;
		netxen_free_hw_resources(adapter);
	}

	for (ctxid = 0; ctxid < MAX_RCV_CTX; ++ctxid) {
		recv_ctx = &adapter->recv_ctx[ctxid];
		for (ring = 0; ring < NUM_RCV_DESC_RINGS; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];
			for (i = 0; i < rcv_desc->max_rx_desc_count; ++i) {
				buffer = &(rcv_desc->rx_buf_arr[i]);
				if (buffer->state == NETXEN_BUFFER_FREE)
					continue;
				pci_unmap_single(pdev, buffer->dma,
						 rcv_desc->dma_size,
						 PCI_DMA_FROMDEVICE);
				if (buffer->skb != NULL)
					dev_kfree_skb_any(buffer->skb);
			}
			vfree(rcv_desc->rx_buf_arr);
		}
	}

	vfree(adapter->cmd_buf_arr);

	if (adapter->portnum == 0)
		netxen_free_adapter_offload(adapter);

	if (adapter->irq)
		free_irq(adapter->irq, adapter);

	if (adapter->flags & NETXEN_NIC_MSI_ENABLED)
		pci_disable_msi(pdev);

	iounmap(adapter->ahw.db_base);
	iounmap(adapter->ahw.pci_base0);
	iounmap(adapter->ahw.pci_base1);
	iounmap(adapter->ahw.pci_base2);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	free_netdev(netdev);
}

/*
 * Called when a network interface is made active
 * @returns 0 on success, negative value on failure
 */
static int netxen_nic_open(struct net_device *netdev)
{
	struct netxen_adapter *adapter = (struct netxen_adapter *)netdev->priv;
	int err = 0;
	int ctx, ring;
	irq_handler_t handler;
	unsigned long flags = IRQF_SAMPLE_RANDOM;

	if (adapter->driver_mismatch)
		return -EIO;

	if (adapter->is_up != NETXEN_ADAPTER_UP_MAGIC) {
		err = netxen_init_firmware(adapter);
		if (err != 0) {
			printk(KERN_ERR "Failed to init firmware\n");
			return -EIO;
		}

		/* setup all the resources for the Phantom... */
		/* this include the descriptors for rcv, tx, and status */
		netxen_nic_clear_stats(adapter);
		err = netxen_nic_hw_resources(adapter);
		if (err) {
			printk(KERN_ERR "Error in setting hw resources:%d\n",
			       err);
			return err;
		}
		for (ctx = 0; ctx < MAX_RCV_CTX; ++ctx) {
			for (ring = 0; ring < NUM_RCV_DESC_RINGS; ring++)
				netxen_post_rx_buffers(adapter, ctx, ring);
		}
		adapter->irq = adapter->ahw.pdev->irq;
		if (adapter->flags & NETXEN_NIC_MSI_ENABLED)
			handler = netxen_msi_intr;
		else {
			flags |= IRQF_SHARED;
			handler = netxen_intr;
		}
		err = request_irq(adapter->irq, handler,
				  flags, netdev->name, adapter);
		if (err) {
			printk(KERN_ERR "request_irq failed with: %d\n", err);
			netxen_free_hw_resources(adapter);
			return err;
		}

		adapter->is_up = NETXEN_ADAPTER_UP_MAGIC;
	}
	/* Done here again so that even if phantom sw overwrote it,
	 * we set it */
	if (adapter->init_port
	    && adapter->init_port(adapter, adapter->portnum) != 0) {
		printk(KERN_ERR "%s: Failed to initialize port %d\n",
				netxen_nic_driver_name, adapter->portnum);
		return -EIO;
	}
	if (adapter->macaddr_set)
		adapter->macaddr_set(adapter, netdev->dev_addr);

	netxen_nic_set_link_parameters(adapter);

	netxen_nic_set_multi(netdev);
	if (adapter->set_mtu)
		adapter->set_mtu(adapter, netdev->mtu);

	mod_timer(&adapter->watchdog_timer, jiffies);

	napi_enable(&adapter->napi);
	netxen_nic_enable_int(adapter);

	netif_start_queue(netdev);

	return 0;
}

/*
 * netxen_nic_close - Disables a network interface entry point
 */
static int netxen_nic_close(struct net_device *netdev)
{
	struct netxen_adapter *adapter = netdev_priv(netdev);
	int i, j;
	struct netxen_cmd_buffer *cmd_buff;
	struct netxen_skb_frag *buffrag;

	netif_carrier_off(netdev);
	netif_stop_queue(netdev);
	napi_disable(&adapter->napi);

	if (adapter->stop_port)
		adapter->stop_port(adapter);

	netxen_nic_disable_int(adapter);

	cmd_buff = adapter->cmd_buf_arr;
	for (i = 0; i < adapter->max_tx_desc_count; i++) {
		buffrag = cmd_buff->frag_array;
		if (buffrag->dma) {
			pci_unmap_single(adapter->pdev, buffrag->dma,
					 buffrag->length, PCI_DMA_TODEVICE);
			buffrag->dma = 0ULL;
		}
		for (j = 0; j < cmd_buff->frag_count; j++) {
			buffrag++;
			if (buffrag->dma) {
				pci_unmap_page(adapter->pdev, buffrag->dma,
					       buffrag->length,
					       PCI_DMA_TODEVICE);
				buffrag->dma = 0ULL;
			}
		}
		/* Free the skb we received in netxen_nic_xmit_frame */
		if (cmd_buff->skb) {
			dev_kfree_skb_any(cmd_buff->skb);
			cmd_buff->skb = NULL;
		}
		cmd_buff++;
	}
	if (adapter->is_up == NETXEN_ADAPTER_UP_MAGIC) {
		FLUSH_SCHEDULED_WORK();
		del_timer_sync(&adapter->watchdog_timer);
	}

	return 0;
}

static int netxen_nic_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct netxen_adapter *adapter = netdev_priv(netdev);
	struct netxen_hardware_context *hw = &adapter->ahw;
	unsigned int first_seg_len = skb->len - skb->data_len;
	struct netxen_skb_frag *buffrag;
	unsigned int i;

	u32 producer, consumer;
	u32 saved_producer = 0;
	struct cmd_desc_type0 *hwdesc;
	int k;
	struct netxen_cmd_buffer *pbuf = NULL;
	int frag_count;
	int no_of_desc;
	u32 num_txd = adapter->max_tx_desc_count;

	frag_count = skb_shinfo(skb)->nr_frags + 1;

	/* There 4 fragments per descriptor */
	no_of_desc = (frag_count + 3) >> 2;
	if (netdev->features & NETIF_F_TSO) {
		if (skb_shinfo(skb)->gso_size > 0) {

			no_of_desc++;
			if ((ip_hdrlen(skb) + tcp_hdrlen(skb) +
			     sizeof(struct ethhdr)) >
			    (sizeof(struct cmd_desc_type0) - 2)) {
				no_of_desc++;
			}
		}
	}

	producer = adapter->cmd_producer;
	smp_mb();
	consumer = adapter->last_cmd_consumer;
	if ((no_of_desc+2) > find_diff_among(producer, consumer, num_txd)) {
		netif_stop_queue(netdev);
		smp_mb();
		return NETDEV_TX_BUSY;
	}

	/* Copy the descriptors into the hardware    */
	saved_producer = producer;
	hwdesc = &hw->cmd_desc_head[producer];
	memset(hwdesc, 0, sizeof(struct cmd_desc_type0));
	/* Take skb->data itself */
	pbuf = &adapter->cmd_buf_arr[producer];
	if ((netdev->features & NETIF_F_TSO) && skb_shinfo(skb)->gso_size > 0) {
		pbuf->mss = skb_shinfo(skb)->gso_size;
		hwdesc->mss = cpu_to_le16(skb_shinfo(skb)->gso_size);
	} else {
		pbuf->mss = 0;
		hwdesc->mss = 0;
	}
	pbuf->total_length = skb->len;
	pbuf->skb = skb;
	pbuf->cmd = TX_ETHER_PKT;
	pbuf->frag_count = frag_count;
	pbuf->port = adapter->portnum;
	buffrag = &pbuf->frag_array[0];
	buffrag->dma = pci_map_single(adapter->pdev, skb->data, first_seg_len,
				      PCI_DMA_TODEVICE);
	buffrag->length = first_seg_len;
	netxen_set_cmd_desc_totallength(hwdesc, skb->len);
	netxen_set_cmd_desc_num_of_buff(hwdesc, frag_count);
	netxen_set_cmd_desc_opcode(hwdesc, TX_ETHER_PKT);

	netxen_set_cmd_desc_port(hwdesc, adapter->portnum);
	netxen_set_cmd_desc_ctxid(hwdesc, adapter->portnum);
	hwdesc->buffer1_length = cpu_to_le16(first_seg_len);
	hwdesc->addr_buffer1 = cpu_to_le64(buffrag->dma);

	for (i = 1, k = 1; i < frag_count; i++, k++) {
		struct skb_frag_struct *frag;
		int len, temp_len;
		unsigned long offset;
		dma_addr_t temp_dma;

		/* move to next desc. if there is a need */
		if ((i & 0x3) == 0) {
			k = 0;
			producer = get_next_index(producer, num_txd);
			hwdesc = &hw->cmd_desc_head[producer];
			memset(hwdesc, 0, sizeof(struct cmd_desc_type0));
			pbuf = &adapter->cmd_buf_arr[producer];
			pbuf->skb = NULL;
		}
		frag = &skb_shinfo(skb)->frags[i - 1];
		len = frag->size;
		offset = frag->page_offset;

		temp_len = len;
		temp_dma = pci_map_page(adapter->pdev, frag->page, offset,
					len, PCI_DMA_TODEVICE);

		buffrag++;
		buffrag->dma = temp_dma;
		buffrag->length = temp_len;

		switch (k) {
		case 0:
			hwdesc->buffer1_length = cpu_to_le16(temp_len);
			hwdesc->addr_buffer1 = cpu_to_le64(temp_dma);
			break;
		case 1:
			hwdesc->buffer2_length = cpu_to_le16(temp_len);
			hwdesc->addr_buffer2 = cpu_to_le64(temp_dma);
			break;
		case 2:
			hwdesc->buffer3_length = cpu_to_le16(temp_len);
			hwdesc->addr_buffer3 = cpu_to_le64(temp_dma);
			break;
		case 3:
			hwdesc->buffer4_length = cpu_to_le16(temp_len);
			hwdesc->addr_buffer4 = cpu_to_le64(temp_dma);
			break;
		}
		frag++;
	}
	producer = get_next_index(producer, num_txd);

	/* might change opcode to TX_TCP_LSO */
	netxen_tso_check(adapter, &hw->cmd_desc_head[saved_producer], skb);

	/* For LSO, we need to copy the MAC/IP/TCP headers into
	 * the descriptor ring
	 */
	if (netxen_get_cmd_desc_opcode(&hw->cmd_desc_head[saved_producer])
	    == TX_TCP_LSO) {
		int hdr_len, first_hdr_len, more_hdr;
		hdr_len = hw->cmd_desc_head[saved_producer].total_hdr_length;
		if (hdr_len > (sizeof(struct cmd_desc_type0) - 2)) {
			first_hdr_len = sizeof(struct cmd_desc_type0) - 2;
			more_hdr = 1;
		} else {
			first_hdr_len = hdr_len;
			more_hdr = 0;
		}
		/* copy the MAC/IP/TCP headers to the cmd descriptor list */
		hwdesc = &hw->cmd_desc_head[producer];
		pbuf = &adapter->cmd_buf_arr[producer];
		pbuf->skb = NULL;

		/* copy the first 64 bytes */
		memcpy(((void *)hwdesc) + 2,
		       (void *)(skb->data), first_hdr_len);
		producer = get_next_index(producer, num_txd);

		if (more_hdr) {
			hwdesc = &hw->cmd_desc_head[producer];
			pbuf = &adapter->cmd_buf_arr[producer];
			pbuf->skb = NULL;
			/* copy the next 64 bytes - should be enough except
			 * for pathological case
			 */
			skb_copy_from_linear_data_offset(skb, first_hdr_len,
							 hwdesc,
							 (hdr_len -
							  first_hdr_len));
			producer = get_next_index(producer, num_txd);
		}
	}

	adapter->cmd_producer = producer;
	adapter->stats.txbytes += skb->len;

	netxen_nic_update_cmd_producer(adapter, adapter->cmd_producer);

	adapter->stats.xmitcalled++;
	netdev->trans_start = jiffies;

	return NETDEV_TX_OK;
}

static void netxen_watchdog(unsigned long v)
{
	struct netxen_adapter *adapter = (struct netxen_adapter *)v;

	SCHEDULE_WORK(&adapter->watchdog_task);
}

static void netxen_tx_timeout(struct net_device *netdev)
{
	struct netxen_adapter *adapter = (struct netxen_adapter *)
						netdev_priv(netdev);
	SCHEDULE_WORK(&adapter->tx_timeout_task);
}

static void netxen_tx_timeout_task(struct work_struct *work)
{
	struct netxen_adapter *adapter =
		container_of(work, struct netxen_adapter, tx_timeout_task);

	printk(KERN_ERR "%s %s: transmit timeout, resetting.\n",
	       netxen_nic_driver_name, adapter->netdev->name);

	netxen_nic_disable_int(adapter);
	napi_disable(&adapter->napi);

	adapter->netdev->trans_start = jiffies;

	napi_enable(&adapter->napi);
	netxen_nic_enable_int(adapter);
	netif_wake_queue(adapter->netdev);
}

static inline void
netxen_handle_int(struct netxen_adapter *adapter)
{
	netxen_nic_disable_int(adapter);
	napi_schedule(&adapter->napi);
}

irqreturn_t netxen_intr(int irq, void *data)
{
	struct netxen_adapter *adapter = data;
	u32 our_int = 0;

	our_int = readl(NETXEN_CRB_NORMALIZE(adapter, CRB_INT_VECTOR));
	/* not our interrupt */
	if ((our_int & (0x80 << adapter->portnum)) == 0)
		return IRQ_NONE;

	if (adapter->intr_scheme == INTR_SCHEME_PERPORT) {
		/* claim interrupt */
		writel(our_int & ~((u32)(0x80 << adapter->portnum)),
			NETXEN_CRB_NORMALIZE(adapter, CRB_INT_VECTOR));
	}

	netxen_handle_int(adapter);

	return IRQ_HANDLED;
}

irqreturn_t netxen_msi_intr(int irq, void *data)
{
	struct netxen_adapter *adapter = data;

	netxen_handle_int(adapter);
	return IRQ_HANDLED;
}

static int netxen_nic_poll(struct napi_struct *napi, int budget)
{
	struct netxen_adapter *adapter = container_of(napi, struct netxen_adapter, napi);
	int tx_complete;
	int ctx;
	int work_done;

	tx_complete = netxen_process_cmd_ring(adapter);

	work_done = 0;
	for (ctx = 0; ctx < MAX_RCV_CTX; ++ctx) {
		/*
		 * Fairness issue. This will give undue weight to the
		 * receive context 0.
		 */

		/*
		 * To avoid starvation, we give each of our receivers,
		 * a fraction of the quota. Sometimes, it might happen that we
		 * have enough quota to process every packet, but since all the
		 * packets are on one context, it gets only half of the quota,
		 * and ends up not processing it.
		 */
		work_done += netxen_process_rcv_ring(adapter, ctx,
						     budget / MAX_RCV_CTX);
	}

	if ((work_done < budget) && tx_complete) {
		netif_rx_complete(adapter->netdev, &adapter->napi);
		netxen_nic_enable_int(adapter);
	}

	return work_done;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void netxen_nic_poll_controller(struct net_device *netdev)
{
	struct netxen_adapter *adapter = netdev_priv(netdev);
	disable_irq(adapter->irq);
	netxen_intr(adapter->irq, adapter);
	enable_irq(adapter->irq);
}
#endif

static struct pci_driver netxen_driver = {
	.name = netxen_nic_driver_name,
	.id_table = netxen_pci_tbl,
	.probe = netxen_nic_probe,
	.remove = __devexit_p(netxen_nic_remove)
};

/* Driver Registration on NetXen card    */

static int __init netxen_init_module(void)
{
	if ((netxen_workq = create_singlethread_workqueue("netxen")) == NULL)
		return -ENOMEM;

	return pci_register_driver(&netxen_driver);
}

module_init(netxen_init_module);

static void __exit netxen_exit_module(void)
{
	/*
	 * Wait for some time to allow the dma to drain, if any.
	 */
	msleep(100);
	pci_unregister_driver(&netxen_driver);
	destroy_workqueue(netxen_workq);
}

module_exit(netxen_exit_module);
