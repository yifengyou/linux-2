/******************************************************************************
 * Copyright(c) 2008 - 2010 Realtek Corporation. All rights reserved.
 *
 * Based on the r8180 driver, which is:
 * Copyright 2004-2005 Andrea Merello <andreamrl@tiscali.it>, et al.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 * wlanfae <wlanfae@realtek.com>
******************************************************************************/
#include "rtl_debug.h"
#include "rtl_core.h"
#ifdef RTL8192CE
#include "rtl8192c/r8192C_phy.h"
#include "rtl8192c/r8192C_phyreg.h"
#include "rtl8192c/r8192C_rtl6052.h"
#include "rtl8192c/r8192C_Efuse.h"
#elif defined RTL8192SE
#include "rtl8192s/r8192S_phy.h"
#include "rtl8192s/r8192S_phyreg.h"
#include "rtl8192s/r8192S_rtl6052.h"
#include "rtl8192s/r8192S_Efuse.h"
#else
#include "rtl8192e/r8192E_phy.h" 
#include "rtl8192e/r8192E_phyreg.h"
#include "rtl8192e/r8190P_rtl8256.h" /* RTL8225 Radio frontend */
#include "rtl8192e/r8192E_cmdpkt.h"
#endif

#ifdef _RTL8192_EXT_PATCH_
#include "../../mshclass/msh_class.h"
#endif
/* this is only for debugging */
void print_buffer(u32 *buffer, int len)
{
	int i;
	u8 *buf =(u8*)buffer;
	
	printk("ASCII BUFFER DUMP (len: %x):\n",len);
	
	for(i=0;i<len;i++)
		printk("%c",buf[i]);
		
	printk("\nBINARY BUFFER DUMP (len: %x):\n",len);
	
	for(i=0;i<len;i++)
		printk("%x",buf[i]);

	printk("\n");
}

/* this is only for debug */
void dump_eprom(struct net_device *dev)
{
	int i;

	for (i = 0; i < 0xff; i++) {
		RT_TRACE(COMP_INIT, "EEPROM addr %x : %x", i, eprom_read(dev,i));
	}
}

/* this is only for debug */
void rtl8192_dump_reg(struct net_device *dev)
{
	int i;
	int n;
	int max = 0x5ff;

	RT_TRACE(COMP_INIT, "Dumping NIC register map");

	for (n = 0; n <= max; ) {
		printk( "\nD: %2x> ", n);
		for (i = 0; i < 16 && n <= max; i++, n++)
			printk("%2x ", read_nic_byte(dev, n));
	}
	printk("\n");
}

#ifdef RTL8192CE
void rtl8192ce_dump_tx_desc(tx_desc *pDesc)
{	
#if 0
	RTPRINT(FTX, TX_DESC, ("DW 0 =========\r\n"));
	RTPRINT(FTX, TX_DESC, ("Own = %d\n", pDesc->OWN));
	RTPRINT(FTX, TX_DESC, ("GF = %d\n", pDesc->GF));
	RTPRINT(FTX, TX_DESC, ("LINIP = %d\n", pDesc->LINIP));
	RTPRINT(FTX, TX_DESC, ("FS = %d\n", pDesc->FirstSeg));
	RTPRINT(FTX, TX_DESC, ("LS = %d\n", pDesc->LastSeg));
	RTPRINT(FTX, TX_DESC, ("Offset = %d\n", pDesc->Offset));
	RTPRINT(FTX, TX_DESC, ("PktSize = %d\r\n", pDesc->PktSize));

	RTPRINT(FTX, TX_DESC, ("DW 1 ==========\r\n"));
	RTPRINT(FTX, TX_DESC, ("PKTOFFSET = %d\n", pDesc->PktOffset));
	RTPRINT(FTX, TX_DESC, ("HTC = %d\n", pDesc->HTC));
	RTPRINT(FTX, TX_DESC, ("SecType = %d\n", pDesc->SecType));
	RTPRINT(FTX, TX_DESC, ("EnDescID = %d\n", pDesc->EnDescID));
	RTPRINT(FTX, TX_DESC, ("NoACM = %d\n", pDesc->NOACM));
	RTPRINT(FTX, TX_DESC, ("QueueSelect = %d\n", pDesc->QueueSel));
	RTPRINT(FTX, TX_DESC, ("PIFS = %d\n", pDesc->PIFS));
	RTPRINT(FTX, TX_DESC, ("MoreFrag = %d\n", pDesc->MoreFrag));
	RTPRINT(FTX, TX_DESC, ("MacID = %d\r\n", pDesc->MacID));

	RTPRINT(FTX, TX_DESC, ("DW 2 ==========\r\n"));
	RTPRINT(FTX, TX_DESC, ("BK = %d\n", pDesc->Bk));
	RTPRINT(FTX, TX_DESC, ("AGG_EN = %d\n", pDesc->AggEn));
	RTPRINT(FTX, TX_DESC, ("Data Retry CNT = %d\n", pDesc->DATARC));
	RTPRINT(FTX, TX_DESC, ("RTS Retry CNT = %d\n", pDesc->RTSRC));
	RTPRINT(FTX, TX_DESC, ("TSFL = %d\n", pDesc->TSFL));
	RTPRINT(FTX, TX_DESC, ("RetryLmtEn = %d\n", pDesc->RetryLmtEn));
	RTPRINT(FTX, TX_DESC, ("DataRetryLmt = %d\r\n", pDesc->TxRetryLmt));

	RTPRINT(FTX, TX_DESC, ("DW 3 ==========\r\n"));
	RTPRINT(FTX, TX_DESC, ("Seq = %d\n", pDesc->Seq));
	RTPRINT(FTX, TX_DESC, ("TailPage = %d\n", pDesc->TailPage));
	RTPRINT(FTX, TX_DESC, ("NextHeadPage = %d\r\n", pDesc->NextHeadPage));

	RTPRINT(FTX, TX_DESC, ("DW 4 ==========\r\n"));
	RTPRINT(FTX, TX_DESC, ("UserRate = %d\n", pDesc->UserRate));
	RTPRINT(FTX, TX_DESC, ("RTS STBC = %d\n", pDesc->RTSSTBC));
	RTPRINT(FTX, TX_DESC, ("RTSSC = %d\n", pDesc->RTSSC));
	RTPRINT(FTX, TX_DESC, ("STBC = %d\n", pDesc->STBC));
	RTPRINT(FTX, TX_DESC, ("TXSC = %d\n", pDesc->TxSc));
	RTPRINT(FTX, TX_DESC, ("TxBw = %d\n", pDesc->TxBW));
	RTPRINT(FTX, TX_DESC, ("TxShort = %d\n", pDesc->TxShort));
	RTPRINT(FTX, TX_DESC, ("RTSEn = %d\n", pDesc->RTSEn));
	RTPRINT(FTX, TX_DESC, ("CTS2Self = %d\n", pDesc->CTS2Self));
	RTPRINT(FTX, TX_DESC, ("RTSRateFBLmt = %d\n", pDesc->RTSRateFBLmt));
	RTPRINT(FTX, TX_DESC, ("DisRTSFB = %d\n", pDesc->DisRTSFB));
	RTPRINT(FTX, TX_DESC, ("RTSRate = %d\r\n", pDesc->RTSRate));

	RTPRINT(FTX, TX_DESC, ("DW 5 ==========\r\n"));
	RTPRINT(FTX, TX_DESC, ("TxAGC = %d\n", pDesc->TXAGCA));
	RTPRINT(FTX, TX_DESC, ("TxAGC = %d\n", pDesc->TXAGCB));
	RTPRINT(FTX, TX_DESC, ("DataRateFBLmt = %d\n", pDesc->TxRateFBLmt));
	RTPRINT(FTX, TX_DESC, ("Disable Feedback = %d\n", pDesc->DisDataFB));
	RTPRINT(FTX, TX_DESC, ("TX_Rate = %d\n", pDesc->TxRate));
	RTPRINT(FTX, TX_DESC, ("PktID = %d\r\n", pDesc->PktID));

	RTPRINT(FTX, TX_DESC, ("DW 6 ==========\r\n"));

	RTPRINT(FTX, TX_DESC, ("DW 7-9 ==========\r\n"));
	RTPRINT(FTX, TX_DESC, ("TxBufferSize = %d\r\n", pDesc->TxBufferSize));

	RTPRINT(FTX, TX_DESC, ("PhyAddressLow = %08x\n", pDesc->TxBuffAddr));

	RTPRINT(FTX, TX_DESC, ("NextDescAddress= %08X\n", pDesc->NextDescAddress));
#else
	u32* desc = (u32*)pDesc;
	u8 i=0;
	printk("#########################\n");	
	for(i=0;i<=9;i++){
		printk("#########>%x\n", desc[i]);	
	}
	printk("#########################\n\n");	
#endif
}
#endif

#ifdef RTL8192SE
void rtl8192se_dump_tx_desc(tx_desc* pDesc)
{	
    printk("DW 0 =========\r\n");
    printk("Own = %d\n", pDesc->OWN);
    printk("GF = %d\n", pDesc->GF);
    printk("LINIP = %d\n", pDesc->LINIP);
    printk("FS = %d\n", pDesc->FirstSeg);
    printk("LS = %d\n", pDesc->LastSeg);
    printk("Offset = %d\n", pDesc->Offset);
    printk("PktSize = %d\r\n", pDesc->PktSize);

    printk("DW 1 ==========\r\n");
    printk("HWPC = %d\n", pDesc->HWPC);
    printk("PKTOFFSET = %d\n", pDesc->PktOffset);
    printk("WDS = %d\n", pDesc->WDS);
    printk("HTC = %d\n", pDesc->HTC);
    printk("SecType = %d\n", pDesc->SecType);
    printk("EnDescID = %d\n", pDesc->EnDescID);
    printk("PktType = %d\n", pDesc->PktType);
    printk("OUI = %d\n", pDesc->OUI);
    printk("SecKeyId = %d\n", pDesc->KeyID);
    printk("NonQos = %d\n", pDesc->NonQos);
    printk("NoACM = %d\n", pDesc->NoACM);
    printk("AckPolicy = %d\n", pDesc->AckPolicy);
    printk("QueueSelect = %d\n", pDesc->QueueSel);
    printk("PIFS = %d\n", pDesc->PIFS);
    printk("MoreFrag = %d\n", pDesc->MoreFrag);
    printk("MoreData = %d\n", pDesc->MoreData);
    printk("MacID = %d\r\n", pDesc->MacID);

    printk("DW 2 ==========\r\n");
    printk("OwnMAC = %d\n", pDesc->OwnMAC);
    printk("BK = %d\n", pDesc->BK);
    printk("AGG_EN = %d\n", pDesc->AggEn);
    printk("Data Retry CNT = %d\n", pDesc->DATARC);
    printk("RTS Retry CNT = %d\n", pDesc->RTSRC);
    printk("TSFL = %d\n", pDesc->TSFL);
    printk("RetryLmtEn = %d\n", pDesc->RetryLmtEn);
    printk("DataRetryLmt = %d\r\n", pDesc->DataRetryLmt);

    printk("DW 3 ==========\r\n");
    printk("Frag = %d\n", pDesc->Frag);
    printk("Seq = %d\n", pDesc->Seq);
    printk("TailPage = %d\n", pDesc->TailPage);
    printk("NextHeadPage = %d\r\n", pDesc->NextHeadPage);

    printk("DW 4 ==========\r\n");
    printk("UserRate = %d\n", pDesc->UserRate);
    printk("RTS STBC = %d\n", pDesc->RTSSTBC);
    printk("RTSSC = %d\n", pDesc->RTSSC);
    printk("RTSBW = %d\n", pDesc->RTSBW);
    printk("RTSShort = %d\n", pDesc->RTSShort);
    printk("RTSHT = %d\n", pDesc->RTSHT);
    printk("RD = %d\n", pDesc->RD);
    printk("STBC = %d\n", pDesc->STBC);
    printk("TXSC = %d\n", pDesc->TXSC);
    printk("TxBw = %d\n", pDesc->TxBw);
    printk("TxShort = %d\n", pDesc->TxShort);
    printk("TXHT = %d\n", pDesc->TXHT);
    printk("RaBRSRID = %d\n", pDesc->RaBRSRID);
    printk("RTSEn = %d\n", pDesc->RTSEn);
    printk("CTS2Self = %d\n", pDesc->CTS2Self);
    printk("RTSRateFBLmt = %d\n", pDesc->RTSRateFBLmt);
    printk("DisRTSFB = %d\n", pDesc->DisRTSFB);
    printk("RTSRate = %d\r\n", pDesc->RTSRate);

    printk("DW 5 ==========\r\n");
    printk("TxAGC = %d\n", pDesc->TxAGC);
    printk("DataRateFBLmt = %d\n", pDesc->DataRateFBLmt);
    printk("Disable Feedback = %d\n", pDesc->DISFB);
    printk("TX_Rate = %d\n", pDesc->TxRate);
    printk("PktID = %d\r\n", pDesc->PktID);

    printk("DW 6 ==========\r\n");
    printk("TCPChkSum = %d\n", pDesc->TCPChkSum);
    printk("IPChkSum = %d\r\n", pDesc->IPChkSum);

    printk("DW 7-9 ==========\r\n");
    printk("TCPEn = %d\n", pDesc->TCPEn);
    printk("IPHdrOffset = %d\n", pDesc->IPHdrOffset);
    printk("TxBufferSize = %d\r\n", pDesc->TxBufferSize);

    printk("PhyAddressLow = %08x\n", pDesc->TxBuffAddr);

    printk("NextDescAddress= %08X\n", pDesc->NextDescAddress);
}
#endif

#ifdef CONFIG_RTLWIFI_DEBUGFS
/* debugfs related stuff */
static struct dentry *rtl_debugfs_root;
static int rtl_dbgfs_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t rtl_dbgfs_register_write(struct file *file,
		const char __user *user_buf,
		size_t count,
		loff_t *ppos)
{
	struct r8192_priv *priv = (struct r8192_priv *)file->private_data;
	char buf[32];
	int buf_size;
	u32 type, offset;

	memset(buf, 0, sizeof(buf));
	buf_size = min(count, sizeof(buf) -  1);
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;

	if (sscanf(buf, "%x,%x", &type, &offset ) == 2) {
		priv->debug->hw_type = type;
		priv->debug->hw_offset = offset;
	} else {
		priv->debug->hw_type = 0;
		priv->debug->hw_offset = 0;
	}

	return count;
}

void  rtl_hardware_grab(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	int t = 0;
	int timeout = 20; 
	u32 mask = RF_CHANGE_BY_HW|RF_CHANGE_BY_PS|RF_CHANGE_BY_IPS;

	priv->debug->hw_holding = true;
#ifdef ENABLE_IPS
	rtllib_ips_leave_wq(dev);
#endif
	do {
		if ((priv->rtllib->RfOffReason & mask)) {
			msleep(100);
			t++;
		} else {
			return;
		}
	} while (t < timeout);

	return;
}

static ssize_t rtl_dbgfs_register_read(struct file *file,
		char __user *user_buf,
		size_t count,
		loff_t *ppos)
{
	struct r8192_priv *priv = (struct r8192_priv *)file->private_data;
	struct net_device *dev = priv->rtllib->dev;
	ssize_t ret = 0;
	char buf[2048];
	int n,i;
	u32 len = 0;
	u32 max = 0xff;
	u32 page_no, path;

	rtl_hardware_grab(dev);

	if(!priv->debug->hw_type) {
		page_no = (priv->debug->hw_offset > 0x0f)? 0x0f: priv->debug->hw_offset;
#ifdef RTL8192SE 
		if(page_no >= 0x08 ) {
			len += snprintf(buf + len, count - len,
					"\n#################### BB page- %x##################\n ", page_no);
			for(n=0;n<=max;)
			{
				len += snprintf(buf + len, count - len, "\nD:  %2x > ",n);
				for(i=0;i<4 && n<=max;n+=4,i++)
					len += snprintf(buf + len, count - len,
							"%8.8x ",rtl8192_QueryBBReg(dev,(page_no << 8|n), 
								bMaskDWord));
			}

		} else 
#endif		
		{
			len += snprintf(buf + len,count - len,
					"\n#################### MAC page- %x##################\n ", page_no);
			for(n=0;n<=max;) {
				len += snprintf(buf + len, count - len, "\nD:  %2x > ",n);
				for(i=0;i<16 && n<=max;i++,n++)
					len += snprintf(buf + len, count - len,
							"%2.2x ",read_nic_byte(dev,((page_no<<8)|n)));
			}
		}
	} else {
		path = (priv->debug->hw_offset < RF90_PATH_MAX)? priv->debug->hw_offset:(RF90_PATH_MAX - 1);
		len += snprintf(buf + len, count - len,
				"\n#################### RF-PATH-%x ##################\n ", 0x0a+path);
		for(n=0;n<=max;) {
			len += snprintf(buf+ len, count - len, "\nD:  %2x > ",n);
			for(i=0;i<4 && n<=max;n+=4,i++)
				len += snprintf(buf + len, count - len,
					"%8.8x ",rtl8192_phy_QueryRFReg(dev, (RF90_RADIO_PATH_E)path,\
					       	n, bMaskDWord)); 
		}   
	}

	priv->debug->hw_holding = false;

	len += snprintf(buf + len, count - len, "\n");
	ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	return ret;
}

static const struct file_operations rtl_register_debug = {
	.read   = rtl_dbgfs_register_read,
	.write  = rtl_dbgfs_register_write,
	.open   = rtl_dbgfs_open,
	.owner  = THIS_MODULE
};

int rtl_debug_module_init(struct r8192_priv *priv, const char *name)
{
	rtl_fs_debug *debug;
	int ret = 0;

	if (!rtl_debugfs_root)
		return -ENOENT;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13))
	debug = kzalloc(sizeof(rtl_fs_debug), GFP_KERNEL);
#else
	rtl_fs_debug = kmalloc(sizeof(*rtl_fs_debug), GFP_KERNEL);
	memset(rtl_fs_debug,0,sizeof(*rtl_fs_debug));
#endif
	if (!debug) {
		ret = -ENOMEM;
		goto err;
	}
	priv->debug = debug;

	debug->name = name;
	debug->dir_drv = debugfs_create_dir(name, rtl_debugfs_root);
	if (!debug->dir_drv ) {
		ret = -ENOENT;
		goto err;
	}

	debug->debug_register = debugfs_create_file("debug_register", S_IRUGO,
			 debug->dir_drv, priv, &rtl_register_debug);
	if(!debug->debug_register) {
		ret = -ENOENT;
		goto err;
	}

	return 0;
err:
        RT_TRACE(COMP_DBG, "Can't open the debugfs directory\n");
        rtl_debug_module_remove(priv);
        return ret;	

}		

void rtl_debug_module_remove(struct r8192_priv *priv)
{
	if (!priv->debug)
		return;
	debugfs_remove(priv->debug->debug_register);
	debugfs_remove(priv->debug->dir_drv);
	kfree(priv->debug);
	priv->debug = NULL;
}

int rtl_create_debugfs_root(void)
{       
	rtl_debugfs_root = debugfs_create_dir(DRV_NAME, NULL);
	if (!rtl_debugfs_root)
		return -ENOENT;

	return 0;
}

void rtl_remove_debugfs_root(void)
{
	debugfs_remove(rtl_debugfs_root);
	rtl_debugfs_root = NULL;
}
#endif

/****************************************************************************
   -----------------------------PROCFS STUFF-------------------------
*****************************************************************************/
/*This part is related to PROC, which will record some statistics. */
static struct proc_dir_entry *rtl8192_proc = NULL;

static int proc_get_stats_ap(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	struct r8192_priv *priv = (struct r8192_priv *)rtllib_priv(dev);
	struct rtllib_device *ieee = priv->rtllib;
	struct rtllib_network *target;
	
	int len = 0;

        list_for_each_entry(target, &ieee->network_list, list) {

		len += snprintf(page + len, count - len,
                "%s ", target->ssid);

		if(target->wpa_ie_len>0 || target->rsn_ie_len>0){
	                len += snprintf(page + len, count - len,
        	        "WPA\n");
		}
		else{
                        len += snprintf(page + len, count - len,
                        "non_WPA\n");
                }
		 
        }
	
	*eof = 1;
	return len;
}

static int proc_get_registers_0(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0x000;
	
#ifdef RTL8192SE
	/* This dump the current register page */
	if(!IS_BB_REG_OFFSET_92S(page0)){
		len += snprintf(page + len, count - len,
				"\n####################page %x##################\n ", (page0>>8));
		for(n=0;n<=max;)
		{
			len += snprintf(page + len, count - len,
					"\nD:  %2x > ",n);
			for(i=0;i<16 && n<=max;i++,n++)
				len += snprintf(page + len, count - len,
						"%2.2x ",read_nic_byte(dev,(page0|n)));
		}
	}else
#endif
	{
		len += snprintf(page + len, count - len,
				"\n####################page %x##################\n ", (page0>>8));
		for(n=0;n<=max;)
		{
			len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
			for(i=0;i<16 && n<=max;n++,i++)
				len += snprintf(page + len, count - len,
						"%2.2x ",read_nic_byte(dev,(page0|n)));
		}
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;

}
static int proc_get_registers_1(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0x100;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len,
				"\nD:  %2x > ",n);
		for(i=0;i<16 && n<=max;i++,n++)
			len += snprintf(page + len, count - len,
					"%2.2x ",read_nic_byte(dev,(page0|n)));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;

}
static int proc_get_registers_2(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0x200;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len,
				"\nD:  %2x > ",n);
		for(i=0;i<16 && n<=max;i++,n++)
			len += snprintf(page + len, count - len,
					"%2.2x ",read_nic_byte(dev,(page0|n)));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;

}
static int proc_get_registers_3(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0x300;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len,
				"\nD:  %2x > ",n);
		for(i=0;i<16 && n<=max;i++,n++)
			len += snprintf(page + len, count - len,
					"%2.2x ",read_nic_byte(dev,(page0|n)));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;

}
static int proc_get_registers_4(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0x400;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len,
				"\nD:  %2x > ",n);
		for(i=0;i<16 && n<=max;i++,n++)
			len += snprintf(page + len, count - len,
					"%2.2x ",read_nic_byte(dev,(page0|n)));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;

}
static int proc_get_registers_5(char *page, char **start,
                          off_t offset, int count,
                          int *eof, void *data)
{
        struct net_device *dev = data;

        int len = 0;
        int i,n,page0;

        int max=0xff;
        page0 = 0x500;

        /* This dump the current register page */
        len += snprintf(page + len, count - len,
                        "\n####################page %x##################\n ", (page0>>8));
        for(n=0;n<=max;)
        {
                len += snprintf(page + len, count - len,
                                "\nD:  %2x > ",n);
                for(i=0;i<16 && n<=max;i++,n++)
                        len += snprintf(page + len, count - len,
                                        "%2.2x ",read_nic_byte(dev,(page0|n)));
        }
        len += snprintf(page + len, count - len,"\n");
        *eof = 1;
        return len;

}
static int proc_get_registers_6(char *page, char **start,
                          off_t offset, int count,
                          int *eof, void *data)
{
        struct net_device *dev = data;

        int len = 0;
        int i,n,page0;

        int max=0xff;
        page0 = 0x600;

        /* This dump the current register page */
        len += snprintf(page + len, count - len,
                        "\n####################page %x##################\n ", (page0>>8));
        for(n=0;n<=max;)
        {
                len += snprintf(page + len, count - len,
                                "\nD:  %2x > ",n);
                for(i=0;i<16 && n<=max;i++,n++)
                        len += snprintf(page + len, count - len,
                                        "%2.2x ",read_nic_byte(dev,(page0|n)));
        }
        len += snprintf(page + len, count - len,"\n");
        *eof = 1;
        return len;

}
static int proc_get_registers_7(char *page, char **start,
                          off_t offset, int count,
                          int *eof, void *data)
{
        struct net_device *dev = data;

        int len = 0;
        int i,n,page0;

        int max=0xff;
        page0 = 0x700;

        /* This dump the current register page */
        len += snprintf(page + len, count - len,
                        "\n####################page %x##################\n ", (page0>>8));
        for(n=0;n<=max;)
        {
                len += snprintf(page + len, count - len,
                                "\nD:  %2x > ",n);
                for(i=0;i<16 && n<=max;i++,n++)
                        len += snprintf(page + len, count - len,
                                        "%2.2x ",read_nic_byte(dev,(page0|n)));
        }
        len += snprintf(page + len, count - len,"\n");
        *eof = 1;
        return len;

}
static int proc_get_registers_8(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0x800;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_QueryBBReg(dev,(page0|n), bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;

}
static int proc_get_registers_9(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0x900;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_QueryBBReg(dev,(page0|n), bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}
static int proc_get_registers_a(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0xa00;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_QueryBBReg(dev,(page0|n), bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}
static int proc_get_registers_b(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0xb00;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_QueryBBReg(dev,(page0|n), bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}
static int proc_get_registers_c(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0xc00;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_QueryBBReg(dev,(page0|n), bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}
static int proc_get_registers_d(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0xd00;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_QueryBBReg(dev,(page0|n), bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}
static int proc_get_registers_e(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n,page0;
			
	int max=0xff;
	page0 = 0xe00;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n####################page %x##################\n ", (page0>>8));
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_QueryBBReg(dev,(page0|n), bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}

static int proc_get_reg_rf_a(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n;
			
	int max=0xff;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n#################### RF-A ##################\n ");
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_phy_QueryRFReg(dev, (RF90_RADIO_PATH_E)RF90_PATH_A,n, bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}

static int proc_get_reg_rf_b(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n;
			
	int max=0xff;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n#################### RF-B ##################\n ");
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_phy_QueryRFReg(dev, (RF90_RADIO_PATH_E)RF90_PATH_B, n, bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}

static int proc_get_reg_rf_c(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n;
			
	int max=0xff;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n#################### RF-C ##################\n ");
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_phy_QueryRFReg(dev, (RF90_RADIO_PATH_E)RF90_PATH_C, n, bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}

static int proc_get_reg_rf_d(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	
	int len = 0;
	int i,n;
			
	int max=0xff;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
			"\n#################### RF-D ##################\n ");
	for(n=0;n<=max;)
	{
		len += snprintf(page + len, count - len, "\nD:  %2x > ",n);
		for(i=0;i<4 && n<=max;n+=4,i++)
			len += snprintf(page + len, count - len,
					"%8.8x ",rtl8192_phy_QueryRFReg(dev, (RF90_RADIO_PATH_E)RF90_PATH_D, n, bMaskDWord));
	}
	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}

static int proc_get_cam_register(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	u32 target_command=0;
	u32 target_content=0;
	u8 entry_i=0;
	u32 ulStatus;
	int len = 0;
	int i=100, j = 0;

	/* This dump the current register page */
	len += snprintf(page + len, count - len,
				"\n#################### SECURITY CAM ##################\n ");
	for(j=0; j<TOTAL_CAM_ENTRY; j++)
	{
		if((j>6) && (j<31))
			continue;
		len += snprintf(page + len, count - len, "\nD:  %2x > ",j);
	 	for(entry_i=0;entry_i<CAM_CONTENT_COUNT;entry_i++)
	 	{
			target_command= entry_i+CAM_CONTENT_COUNT*j;
			target_command= target_command | BIT31;

			while((i--)>=0)
			{
				ulStatus = read_nic_dword(dev, RWCAM);
				if(ulStatus & BIT31){
					continue;
				}
				else{
					break;
				}
			}
	  		write_nic_dword(dev, RWCAM, target_command);
	  	 	target_content = read_nic_dword(dev, RCAMO);
			len += snprintf(page + len, count - len,"%8.8x ",target_content);
	 	}
	}

	len += snprintf(page + len, count - len,"\n");
	*eof = 1;
	return len;
}

static int proc_get_stats_tx(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	struct r8192_priv *priv = (struct r8192_priv *)rtllib_priv(dev);
	
	int len = 0;
	
	len += snprintf(page + len, count - len,
		"TX VI priority ok int: %lu\n"
		"TX VO priority ok int: %lu\n"
		"TX BE priority ok int: %lu\n"
		"TX BK priority ok int: %lu\n"
		"TX MANAGE priority ok int: %lu\n"
		"TX BEACON priority ok int: %lu\n"
		"TX BEACON priority error int: %lu\n"
		"TX CMDPKT priority ok int: %lu\n"
		"TX queue stopped?: %d\n"
		"TX fifo overflow: %lu\n"
		"TX total data packets %lu\n"		
		"TX total data bytes :%lu\n",
		priv->stats.txviokint,
		priv->stats.txvookint,
		priv->stats.txbeokint,
		priv->stats.txbkokint,
		priv->stats.txmanageokint,
		priv->stats.txbeaconokint,
		priv->stats.txbeaconerr,
		priv->stats.txcmdpktokint,
		netif_queue_stopped(dev),
		priv->stats.txoverflow,
		priv->rtllib->stats.tx_packets,
		priv->rtllib->stats.tx_bytes


		);
			
	*eof = 1;
	return len;
}		



static int proc_get_stats_rx(char *page, char **start,
			  off_t offset, int count,
			  int *eof, void *data)
{
	struct net_device *dev = data;
	struct r8192_priv *priv = (struct r8192_priv *)rtllib_priv(dev);
	
	int len = 0;
	
	len += snprintf(page + len, count - len,
		"RX packets: %lu\n"
		"RX data crc err: %lu\n"
		"RX mgmt crc err: %lu\n"
		"RX desc err: %lu\n"
		"RX rx overflow error: %lu\n",
		priv->stats.rxint,
		priv->stats.rxdatacrcerr,
		priv->stats.rxmgmtcrcerr,
		priv->stats.rxrdu,
		priv->stats.rxoverflow);
			
	*eof = 1;
	return len;
}		

void rtl8192_proc_module_init(void)
{	
	RT_TRACE(COMP_INIT, "Initializing proc filesystem");
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	rtl8192_proc=create_proc_entry(DRV_NAME, S_IFDIR, proc_net);
#else
	rtl8192_proc=create_proc_entry(DRV_NAME, S_IFDIR, init_net.proc_net);
#endif
}


void rtl8192_proc_module_remove(void)
{
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	remove_proc_entry(DRV_NAME, proc_net);
#else
	remove_proc_entry(DRV_NAME, init_net.proc_net);
#endif
}


void rtl8192_proc_remove_one(struct net_device *dev)
{
	struct r8192_priv *priv = (struct r8192_priv *)rtllib_priv(dev);

	printk("dev name %s\n",dev->name);

	if (priv->dir_dev) {
		remove_proc_entry("stats-tx", priv->dir_dev);
		remove_proc_entry("stats-rx", priv->dir_dev);
		remove_proc_entry("stats-ap", priv->dir_dev);
		remove_proc_entry("registers-0", priv->dir_dev);
		remove_proc_entry("registers-1", priv->dir_dev);
		remove_proc_entry("registers-2", priv->dir_dev);
		remove_proc_entry("registers-3", priv->dir_dev);
		remove_proc_entry("registers-4", priv->dir_dev);
		remove_proc_entry("registers-5", priv->dir_dev);
		remove_proc_entry("registers-6", priv->dir_dev);
		remove_proc_entry("registers-7", priv->dir_dev);
		remove_proc_entry("registers-8", priv->dir_dev);
		remove_proc_entry("registers-9", priv->dir_dev);
		remove_proc_entry("registers-a", priv->dir_dev);
		remove_proc_entry("registers-b", priv->dir_dev);
		remove_proc_entry("registers-c", priv->dir_dev);
		remove_proc_entry("registers-d", priv->dir_dev);
		remove_proc_entry("registers-e", priv->dir_dev);
		remove_proc_entry("RF-A", priv->dir_dev);
		remove_proc_entry("RF-B", priv->dir_dev);
		remove_proc_entry("RF-C", priv->dir_dev);
		remove_proc_entry("RF-D", priv->dir_dev);
		remove_proc_entry("SEC-CAM", priv->dir_dev);
#ifdef _RTL8192_EXT_PATCH_
		remove_proc_entry("ra0", rtl8192_proc);
#else
		remove_proc_entry("wlan0", rtl8192_proc);
#endif
		priv->dir_dev = NULL;
	}
}


void rtl8192_proc_init_one(struct net_device *dev)
{
	struct proc_dir_entry *e;
	struct r8192_priv *priv = (struct r8192_priv *)rtllib_priv(dev);
	priv->dir_dev = create_proc_entry(dev->name, 
					  S_IFDIR | S_IRUGO | S_IXUGO, 
					  rtl8192_proc);
	if (!priv->dir_dev) {
		RT_TRACE(COMP_ERR, "Unable to initialize /proc/net/rtl8192/%s\n",
		      dev->name);
		return;
	}
	e = create_proc_read_entry("stats-rx", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_stats_rx, dev);
				   
	if (!e) {
		RT_TRACE(COMP_ERR,"Unable to initialize "
		      "/proc/net/rtl8192/%s/stats-rx\n",
		      dev->name);
	}
	
	
	e = create_proc_read_entry("stats-tx", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_stats_tx, dev);
				   
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/stats-tx\n",
		      dev->name);
	}
	
	e = create_proc_read_entry("stats-ap", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_stats_ap, dev);
				   
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/stats-ap\n",
		      dev->name);
	}
	
	e = create_proc_read_entry("registers-0", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_0, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-0\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-1", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_1, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-1\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-2", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_2, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-2\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-3", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_3, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-3\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-4", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_4, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-4\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-5", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_5, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-5\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-6", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_6, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-6\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-7", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_7, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-7\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-8", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_8, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-8\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-9", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_9, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-9\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-a", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_a, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-a\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-b", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_b, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-b\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-c", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_c, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-c\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-d", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_d, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-d\n",
		      dev->name);
	}
	e = create_proc_read_entry("registers-e", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_registers_e, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/registers-e\n",
		      dev->name);
	}
	e = create_proc_read_entry("RF-A", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_reg_rf_a, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/RF-A\n",
		      dev->name);
	}
	e = create_proc_read_entry("RF-B", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_reg_rf_b, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/RF-B\n",
		      dev->name);
	}
	e = create_proc_read_entry("RF-C", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_reg_rf_c, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/RF-C\n",
		      dev->name);
	}
	e = create_proc_read_entry("RF-D", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_reg_rf_d, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/RF-D\n",
		      dev->name);
	}
	e = create_proc_read_entry("SEC-CAM", S_IFREG | S_IRUGO,
				   priv->dir_dev, proc_get_cam_register, dev);
	if (!e) {
		RT_TRACE(COMP_ERR, "Unable to initialize "
		      "/proc/net/rtl8192/%s/SEC-CAM\n",
		      dev->name);
	}
#ifdef _RTL8192_EXT_PATCH_
        if( priv->mshobj && priv->mshobj->ext_patch_create_proc )
                priv->mshobj->ext_patch_create_proc(priv);
#endif

}

