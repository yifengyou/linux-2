/******************************************************************************
 * Copyright(c) 2008 - 2010 Realtek Corporation. All rights reserved.
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
#ifdef RTL8192SE
#include "rtl_core.h"
#include "rtl_dm.h"
#include "rtl8192s/r8192S_phy.h"
#include "rtl8192s/r8192S_phyreg.h"
#else
#include "rtl_core.h"
#include "rtl_dm.h"
#include "rtl8192e/r8192E_hw.h"
#include "rtl8192e/r8192E_phy.h"
#include "rtl8192e/r8192E_phyreg.h"
#include "rtl8192e/r8190P_rtl8256.h"
#endif
#ifdef _RTL8192_EXT_PATCH_
#include "../../mshclass/msh_class.h"
#endif

/*---------------------------Define Local Constant---------------------------*/
#ifdef  RTL8190P
static u32 edca_setting_DL[HT_IOT_PEER_MAX] = 
{ 0x5e4322, 	
   0x5e4322, 	
   0x5ea44f,	
   0x5e4322,  	
   0x604322, 	
   0xa44f, 		
   0x5e4322,	
   0x5e4322	
 };

static u32 edca_setting_DL_GMode[HT_IOT_PEER_MAX] = 
{ 0x5e4322, 	
   0x5e4322, 	
   0x5e4322, 	
   0x5e4322,  	
   0x604322, 	
   0xa44f, 		
   0x5e4322,	
   0x5e4322	
};
		
static u32 edca_setting_UL[HT_IOT_PEER_MAX] = 
{ 0x5e4322, 	
   0xa44f,   	
   0x5ea44f,	
   0x5e4322,  	 
   0x604322, 	
   0x5e4322, 	
   0x5e4322,	
   0x5e4322	
};

#elif defined RTL8192E
static u32 edca_setting_DL[HT_IOT_PEER_MAX] = 
{ 0x5e4322, 	
   0x5e4322, 	
   0x5ea44f,	
   0x5e4322, 	
   0x604322, 	
   0xa44f, 		
   0x5e4322,	
   0x5e4332	
 };

static u32 edca_setting_DL_GMode[HT_IOT_PEER_MAX] = 
{ 0x5e4322, 	
   0x5e4322, 	
   0x5e4322, 	
   0x5e4322, 	
   0x604322, 	
   0xa44f, 		
   0x5e4322,	
   0x5e4322	
};

static u32 edca_setting_UL[HT_IOT_PEER_MAX] = 
{ 0x5e4322, 	
   0xa44f,	  	
   0x5ea44f,	
   0x5e4322,  	
   0x604322, 	
   0x5e4322, 	
   0x5e4322,	
   0x5e4332	
};

#elif defined(RTL8192SE)
static u32 edca_setting_DL[HT_IOT_PEER_MAX] = 
{ 0xa44f, 		
   0x5ea44f, 	
   0x5ea44f,	
   0xa630, 		
   0xa44f,
   0xa630, 		
   0xa630,		
   0xa42b,
   0x5e4322,	
   0x5e4322	
 };	

static u32 edca_setting_DL_GMode[HT_IOT_PEER_MAX] = 
															
{ 0x4322, 		
   0xa44f, 		
   0x5ea44f,	
   0xa42b, 		
   0x5e4322, 	
   0x4322, 		
   0xa430,		
   0x5ea44f,	
   0x5e4322,	
   0x5e4322	
};

static u32 edca_setting_UL[HT_IOT_PEER_MAX] = 
{ 0x5e4322, 	
   0xa44f,		
   0x5ea44f,	
   0x5ea322, 	
   0x5ea422,
   0x5ea322, 	
   0x3ea44f,	
   0x5ea44f,	
   0x5e4322,	
   0x5e4322	
 };	
#endif

#define RTK_UL_EDCA 0xa44f
#define RTK_DL_EDCA 0x5e4322
/*---------------------------Define Local Constant---------------------------*/


/*------------------------Define global variable-----------------------------*/
dig_t	dm_digtable;
u8		dm_shadow[16][256] = {{0}};
DRxPathSel	DM_RxPathSelTable;
/*------------------------Define global variable-----------------------------*/


/*------------------------Define local variable------------------------------*/
/*------------------------Define local variable------------------------------*/


/*--------------------Define export function prototype-----------------------*/
extern	void	init_hal_dm(struct net_device *dev);
extern	void deinit_hal_dm(struct net_device *dev);

extern void hal_dm_watchdog(struct net_device *dev);


extern	void	init_rate_adaptive(struct net_device *dev);
extern	void	dm_txpower_trackingcallback(void *data);

extern	void	dm_restore_dynamic_mechanism_state(struct net_device *dev);
extern	void	dm_backup_dynamic_mechanism_state(struct net_device *dev);
extern	void	dm_change_dynamic_initgain_thresh(struct net_device *dev,
								u32		dm_type,
								u32		dm_value);
extern	void	DM_ChangeFsyncSetting(struct net_device *dev,
												s32		DM_Type,
												s32		DM_Value);
extern	void dm_force_tx_fw_info(struct net_device *dev,
										u32		force_type,
										u32		force_value);
extern	void	dm_init_edca_turbo(struct net_device *dev);
extern	void	dm_rf_operation_test_callback(unsigned long data);
extern	void	dm_rf_pathcheck_workitemcallback(void *data);
extern	void dm_fsync_timer_callback(unsigned long data);
#if 0
extern	bool	dm_check_lbus_status(struct net_device *dev);
#endif
extern	void dm_check_fsync(struct net_device *dev);
extern	void	dm_shadow_init(struct net_device *dev);
extern	void dm_initialize_txpower_tracking(struct net_device *dev);

#if (defined RTL8192E || defined RTL8192SE)
extern  void    dm_CheckRfCtrlGPIO(void *data);
#endif

#ifdef RTL8192SE
extern	void DM_TXPowerTracking92SDirectCall(struct net_device *dev);
static	void dm_CtrlInitGainByTwoPort(struct net_device *dev);
static	void dm_CtrlInitGainBeforeConnectByRssiAndFalseAlarm(struct net_device *dev);
static	void	dm_initial_gain_STABeforeConnect(struct net_device *dev);

void	dm_InitRateAdaptiveMask(struct net_device *dev);
#if 0
static 	void Adhoc_dm_CheckRateAdaptive(struct net_device * dev);
#endif
void 		Adhoc_InitRateAdaptive(struct net_device *dev,struct sta_info  *pEntry);
#endif

/*--------------------Define export function prototype-----------------------*/


/*---------------------Define local function prototype-----------------------*/
static	void	dm_check_rate_adaptive(struct net_device *dev);

static	void	dm_init_bandwidth_autoswitch(struct net_device *dev);
static	void	dm_bandwidth_autoswitch(	struct net_device *dev);


static	void	dm_check_txpower_tracking(struct net_device *dev);





#if defined(RTL8192E)||defined(RTL8190P)
static	void	dm_bb_initialgain_restore(struct net_device *dev);


static	void	dm_bb_initialgain_backup(struct net_device *dev);
#endif

static	void dm_dig_init(struct net_device *dev);
static	void dm_ctrl_initgain_byrssi(struct net_device *dev);
static	void dm_ctrl_initgain_byrssi_highpwr(struct net_device *dev);
static	void dm_ctrl_initgain_byrssi_by_driverrssi(	struct net_device *dev);
static	void dm_ctrl_initgain_byrssi_by_fwfalse_alarm(struct net_device *dev);
static	void dm_initial_gain(struct net_device *dev);
static	void dm_pd_th(struct net_device *dev);
static	void dm_cs_ratio(struct net_device *dev);

static	void dm_init_ctstoself(struct net_device *dev);
static	void dm_Init_WA_Broadcom_IOT(struct net_device *dev);
#ifdef RTL8192SE
static	void dm_WA_Broadcom_IOT(struct net_device *dev);
#endif

static	void	dm_check_edca_turbo(struct net_device *dev);

#if 0
static	void	dm_check_rfctrl_gpio(struct net_device *dev);
#endif

#ifndef RTL8190P 
#endif
static	void dm_check_pbc_gpio(struct net_device *dev);


static	void dm_check_rx_path_selection(struct net_device *dev);
static 	void dm_init_rxpath_selection(struct net_device *dev);
static	void dm_rxpath_sel_byrssi(struct net_device *dev);


static void dm_init_fsync(struct net_device *dev);
static void dm_deInit_fsync(struct net_device *dev);

static	void dm_check_txrateandretrycount(struct net_device *dev);
static  void dm_check_ac_dc_power(struct net_device *dev);

/*---------------------Define local function prototype-----------------------*/

static	void	dm_init_dynamic_txpower(struct net_device *dev);
static	void	dm_dynamic_txpower(struct net_device *dev);


static	void dm_send_rssi_tofw(struct net_device *dev);
static	void	dm_ctstoself(struct net_device *dev);
#if defined RTL8192SE
static	void dm_RefreshRateAdaptiveMask(struct net_device *dev);
#endif
/*---------------------------Define function prototype------------------------*/

extern	void
init_hal_dm(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	priv->DM_Type = DM_Type_ByDriver;

	priv->undecorated_smoothed_pwdb = -1;	
	
	dm_init_dynamic_txpower(dev);

#ifdef RTL8192SE
	if (IS_HARDWARE_TYPE_8192SE(dev))
		dm_InitRateAdaptiveMask(dev);
	else
#endif
		init_rate_adaptive(dev);

	dm_dig_init(dev);
	dm_init_edca_turbo(dev);
	dm_init_bandwidth_autoswitch(dev);
	dm_init_fsync(dev);
	dm_init_rxpath_selection(dev);
	dm_init_ctstoself(dev);
        if (IS_HARDWARE_TYPE_8192SE(dev))
	dm_Init_WA_Broadcom_IOT(dev);
		
#if (defined RTL8192E || defined RTL8192SE)
	INIT_DELAYED_WORK_RSL(&priv->gpio_change_rf_wq, (void *)dm_CheckRfCtrlGPIO,dev);
#endif

}	

extern void deinit_hal_dm(struct net_device *dev)
{

	dm_deInit_fsync(dev);
	
}


#ifdef USB_RX_AGGREGATION_SUPPORT
void dm_CheckRxAggregation(struct net_device *dev) {
	struct r8192_priv *priv = rtllib_priv((struct net_device *)dev);
	PRT_HIGH_THROUGHPUT	pHTInfo = priv->rtllib->pHTInfo;
	static unsigned long	lastTxOkCnt = 0;
	static unsigned long	lastRxOkCnt = 0;
	unsigned long		curTxOkCnt = 0;
	unsigned long		curRxOkCnt = 0;

	curTxOkCnt = priv->stats.txbytesunicast - lastTxOkCnt;
	curRxOkCnt = priv->stats.rxbytesunicast - lastRxOkCnt;

	if((curTxOkCnt + curRxOkCnt) < 15000000) {
		return;
	}

	if(curTxOkCnt > 4*curRxOkCnt) {
		if (priv->bCurrentRxAggrEnable) {
			write_nic_dword(dev, 0x1a8, 0);
			priv->bCurrentRxAggrEnable = false;
		}
	}else{
		if (!priv->bCurrentRxAggrEnable && !pHTInfo->bCurrentRT2RTAggregation) {
			u32 ulValue;
			ulValue = (pHTInfo->UsbRxFwAggrEn<<24) | (pHTInfo->UsbRxFwAggrPageNum<<16) |
				(pHTInfo->UsbRxFwAggrPacketNum<<8) | (pHTInfo->UsbRxFwAggrTimeout);
			write_nic_dword(dev, 0x1a8, ulValue);
			priv->bCurrentRxAggrEnable = true;
		}
	}

	lastTxOkCnt = priv->stats.txbytesunicast;
	lastRxOkCnt = priv->stats.rxbytesunicast;
}	
#endif	



extern  void    hal_dm_watchdog(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	if(priv->being_init_adapter)
		return;

	dm_check_ac_dc_power(dev);

	dm_check_pbc_gpio(dev);
	dm_check_txrateandretrycount(dev);
	dm_check_edca_turbo(dev);

	if (IS_HARDWARE_TYPE_8192SE(dev)){
#ifdef RTL8192SE
		dm_RefreshRateAdaptiveMask(dev);
		dm_WA_Broadcom_IOT(dev);
		return;
#if 0			
		dm_check_txpower_tracking(dev);
		dm_ctrl_initgain_byrssi(dev);	
		dm_dynamic_txpower(dev);
		dm_RefreshRateAdaptiveMask(dev);
		dm_check_fsync(dev); 
		if(priv->rtllib->iw_mode == IW_MODE_ADHOC)
			Adhoc_dm_CheckRateAdaptive(dev);
		else
			dm_check_rate_adaptive(dev);
#endif		
#endif
	}
	dm_check_rate_adaptive(dev);
	dm_dynamic_txpower(dev);	
	dm_check_txpower_tracking(dev);

	dm_ctrl_initgain_byrssi(dev);
	dm_bandwidth_autoswitch(dev);

	dm_check_rx_path_selection(dev);
	dm_check_fsync(dev); 

	dm_send_rssi_tofw(dev);
	dm_ctstoself(dev);

#ifdef USB_RX_AGGREGATION_SUPPORT
	dm_CheckRxAggregation(dev);
#endif	
}	

void dm_check_ac_dc_power(struct net_device *dev) 
{
	struct r8192_priv *priv = rtllib_priv(dev);
	static char *ac_dc_check_script_path = "/etc/acpi/wireless-rtl-ac-dc-power.sh";
	char *argv[] = {ac_dc_check_script_path,DRV_NAME,NULL};
	static char *envp[] = {"HOME=/", 
			"TERM=linux", 
			"PATH=/usr/bin:/bin", 
			 NULL};

	if(priv->ResetProgress == RESET_TYPE_SILENT)
	{
		RT_TRACE((COMP_INIT | COMP_POWER | COMP_RF), "GPIOChangeRFWorkItemCallBack(): Silent Reseting!!!!!!!\n");
		return;
	}

	if(priv->rtllib->state != RTLLIB_LINKED) {
		return;
	}
	call_usermodehelper(ac_dc_check_script_path,argv,envp,UMH_WAIT_PROC);

	return;
};


extern void init_rate_adaptive(struct net_device * dev)	
{

	struct r8192_priv *priv = rtllib_priv(dev);
	prate_adaptive			pra = (prate_adaptive)&priv->rate_adaptive;
	
	pra->ratr_state = DM_RATR_STA_MAX;
	pra->high2low_rssi_thresh_for_ra = RateAdaptiveTH_High;
	pra->low2high_rssi_thresh_for_ra20M = RateAdaptiveTH_Low_20M+5;
	pra->low2high_rssi_thresh_for_ra40M = RateAdaptiveTH_Low_40M+5;

	pra->high_rssi_thresh_for_ra = RateAdaptiveTH_High+5;
	pra->low_rssi_thresh_for_ra20M = RateAdaptiveTH_Low_20M;
	pra->low_rssi_thresh_for_ra40M = RateAdaptiveTH_Low_40M;
	
	if(priv->CustomerID == RT_CID_819x_Netcore)
		pra->ping_rssi_enable = 1;
	else
		pra->ping_rssi_enable = 0;				
	pra->ping_rssi_thresh_for_ra = 15;
	
	
	if (priv->rf_type == RF_2T4R)
	{
		pra->upper_rssi_threshold_ratr		= 	0x8f0f0000;
		pra->middle_rssi_threshold_ratr		= 	0x8f0ff000;
		pra->low_rssi_threshold_ratr		= 	0x8f0ff001;
		pra->low_rssi_threshold_ratr_40M	= 	0x8f0ff005;
		pra->low_rssi_threshold_ratr_20M	= 	0x8f0ff001;
		pra->ping_rssi_ratr	= 	0x0000000d;
	}
	else if (priv->rf_type == RF_1T2R)
	{
		pra->upper_rssi_threshold_ratr		= 	0x000f0000;		
		pra->middle_rssi_threshold_ratr		= 	0x000ff000;
		pra->low_rssi_threshold_ratr		= 	0x000ff001;
		pra->low_rssi_threshold_ratr_40M	= 	0x000ff005;
		pra->low_rssi_threshold_ratr_20M	= 	0x000ff001;
		pra->ping_rssi_ratr	= 	0x0000000d;
	}
	
}	


static void dm_check_rate_adaptive(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	PRT_HIGH_THROUGHPUT	pHTInfo = priv->rtllib->pHTInfo;
	prate_adaptive			pra = (prate_adaptive)&priv->rate_adaptive;
	u32						currentRATR, targetRATR = 0;
	u32						LowRSSIThreshForRA = 0, HighRSSIThreshForRA = 0;
	bool						bshort_gi_enabled = false;
	static u8					ping_rssi_state=0;

	if(IS_NIC_DOWN(priv)){
		RT_TRACE(COMP_RATE, "<---- dm_check_rate_adaptive(): driver is going to unload\n");
		return;
	}

	if(pra->rate_adaptive_disabled)
		return;

	if( !(priv->rtllib->mode == WIRELESS_MODE_N_24G ||
		 priv->rtllib->mode == WIRELESS_MODE_N_5G))
		 return;
		
	if( priv->rtllib->state == RTLLIB_LINKED )
	{

		bshort_gi_enabled = (pHTInfo->bCurTxBW40MHz && pHTInfo->bCurShortGI40MHz) ||
			(!pHTInfo->bCurTxBW40MHz && pHTInfo->bCurShortGI20MHz);
	

		pra->upper_rssi_threshold_ratr =
				(pra->upper_rssi_threshold_ratr & (~BIT31)) | ((bshort_gi_enabled)? BIT31:0) ;

		pra->middle_rssi_threshold_ratr = 
				(pra->middle_rssi_threshold_ratr & (~BIT31)) | ((bshort_gi_enabled)? BIT31:0) ;

		if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
		{
			pra->low_rssi_threshold_ratr = 
				(pra->low_rssi_threshold_ratr_40M & (~BIT31)) | ((bshort_gi_enabled)? BIT31:0) ;
		}
		else
		{
			pra->low_rssi_threshold_ratr = 
			(pra->low_rssi_threshold_ratr_20M & (~BIT31)) | ((bshort_gi_enabled)? BIT31:0) ;
		}
		pra->ping_rssi_ratr = 
				(pra->ping_rssi_ratr & (~BIT31)) | ((bshort_gi_enabled)? BIT31:0) ;
		
		if (pra->ratr_state == DM_RATR_STA_HIGH)
		{
			HighRSSIThreshForRA 	= pra->high2low_rssi_thresh_for_ra;
			LowRSSIThreshForRA	= (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)?
					(pra->low_rssi_thresh_for_ra40M):(pra->low_rssi_thresh_for_ra20M);
		}
		else if (pra->ratr_state == DM_RATR_STA_LOW)
		{
			HighRSSIThreshForRA	= pra->high_rssi_thresh_for_ra;
			LowRSSIThreshForRA 	= (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)?
					(pra->low2high_rssi_thresh_for_ra40M):(pra->low2high_rssi_thresh_for_ra20M);
		}
		else
		{
			HighRSSIThreshForRA	= pra->high_rssi_thresh_for_ra;
			LowRSSIThreshForRA	= (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)?
					(pra->low_rssi_thresh_for_ra40M):(pra->low_rssi_thresh_for_ra20M);
		}
	
		if(priv->undecorated_smoothed_pwdb >= (long)HighRSSIThreshForRA)
		{
			pra->ratr_state = DM_RATR_STA_HIGH;
			targetRATR = pra->upper_rssi_threshold_ratr;
		}else if(priv->undecorated_smoothed_pwdb >= (long)LowRSSIThreshForRA)
		{
			pra->ratr_state = DM_RATR_STA_MIDDLE;
			targetRATR = pra->middle_rssi_threshold_ratr;
		}else
		{
			pra->ratr_state = DM_RATR_STA_LOW;
			targetRATR = pra->low_rssi_threshold_ratr;
		}

		if(pra->ping_rssi_enable)
		{
			if(priv->undecorated_smoothed_pwdb < (long)(pra->ping_rssi_thresh_for_ra+5))
			{
				if( (priv->undecorated_smoothed_pwdb < (long)pra->ping_rssi_thresh_for_ra) ||
					ping_rssi_state )
				{
					pra->ratr_state = DM_RATR_STA_LOW;
					targetRATR = pra->ping_rssi_ratr;
					ping_rssi_state = 1;
				}
			}
			else
			{
				ping_rssi_state = 0;
			}
		}
		
#if 1		
		if(priv->rtllib->GetHalfNmodeSupportByAPsHandler(dev))
			targetRATR &=  0xf00fffff;
#endif

		currentRATR = read_nic_dword(dev, RATR0);
		if( targetRATR !=  currentRATR )
		{
			u32 ratr_value;
			ratr_value = targetRATR;
			RT_TRACE(COMP_RATE,"currentRATR = %x, targetRATR = %x\n", currentRATR, targetRATR);				
			if(priv->rf_type == RF_1T2R)		
			{
				ratr_value &= ~(RATE_ALL_OFDM_2SS);
			}
			write_nic_dword(dev, RATR0, ratr_value);
			write_nic_byte(dev, UFWP, 1);
			
			pra->last_ratr = targetRATR;
		}
		
	}
	else
	{
		pra->ratr_state = DM_RATR_STA_MAX;
	}

}	

#ifdef RTL8192SE
void dm_InitRateAdaptiveMask(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	prate_adaptive	pRA =  (prate_adaptive)&priv->rate_adaptive;

	pRA->ratr_state = DM_RATR_STA_MAX;
	pRA->PreRATRState = DM_RATR_STA_MAX;

#ifdef _RTL8192_EXT_PATCH_
	if (priv->DM_Type == DM_Type_ByDriver && priv->pFirmware->FirmwareVersion >= 60)
		priv->rtllib->bUseRAMask = true;
	else
#endif		
		priv->rtllib->bUseRAMask = false;

	printk("=========>%s: bUseRAMask=%d\n", __func__, priv->rtllib->bUseRAMask);
	priv->bInformFWDriverControlDM = false;
	
}
#endif

static void dm_init_bandwidth_autoswitch(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	
	priv->rtllib->bandwidth_auto_switch.threshold_20Mhzto40Mhz = BW_AUTO_SWITCH_LOW_HIGH;
	priv->rtllib->bandwidth_auto_switch.threshold_40Mhzto20Mhz = BW_AUTO_SWITCH_HIGH_LOW;
	priv->rtllib->bandwidth_auto_switch.bforced_tx20Mhz = false;
	priv->rtllib->bandwidth_auto_switch.bautoswitch_enable = false;
	
}	


static void dm_bandwidth_autoswitch(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	
	if(priv->CurrentChannelBW == HT_CHANNEL_WIDTH_20 ||!priv->rtllib->bandwidth_auto_switch.bautoswitch_enable){
		return;
	}else{
		if(priv->rtllib->bandwidth_auto_switch.bforced_tx20Mhz == false){
			if(priv->undecorated_smoothed_pwdb <= priv->rtllib->bandwidth_auto_switch.threshold_40Mhzto20Mhz)
				priv->rtllib->bandwidth_auto_switch.bforced_tx20Mhz = true;
		}else{
			if(priv->undecorated_smoothed_pwdb >= priv->rtllib->bandwidth_auto_switch.threshold_20Mhzto40Mhz)
				priv->rtllib->bandwidth_auto_switch.bforced_tx20Mhz = false;
	
		}
	}
}	

#ifdef Rtl8192SE
u32	OFDMSwingTable[OFDM_Table_Length] = {
	0x7f8001fe,	
	0x788001e2,	
	0x71c001c7,	
	0x6b8001ae,	
	0x65400195,	
	0x5fc0017f,	
	0x5a400169,	
	0x55400155,	
	0x50800142,	
	0x4c000130,	
	0x47c0011f,	
	0x43c0010f,	
	0x40000100,	
	0x3c8000f2,	
	0x390000e4,	
	0x35c000d7,	
	0x32c000cb,	
	0x300000c0,	
	0x2d4000b5,	
	0x2ac000ab,	
	0x288000a2,	
	0x26000098,	
	0x24000090,	
	0x22000088,	
	0x20000080,	
	0x1e400079,	
	0x1c800072,	
	0x1b00006c,	
	0x19800066,	
	0x18000060,	
	0x16c0005b,	
	0x15800056,	
	0x14400051,	
	0x1300004c,	
	0x12000048,	
	0x11000044,	
	0x10000040,	
};

u8	CCKSwingTable_Ch1_Ch13[CCK_Table_length][8] = {
	{0x36, 0x35, 0x2e, 0x25, 0x1c, 0x12, 0x09, 0x04},	
	{0x33, 0x32, 0x2b, 0x23, 0x1a, 0x11, 0x08, 0x04},	
	{0x30, 0x2f, 0x29, 0x21, 0x19, 0x10, 0x08, 0x03},	
	{0x2d, 0x2d, 0x27, 0x1f, 0x18, 0x0f, 0x08, 0x03},	
	{0x2b, 0x2a, 0x25, 0x1e, 0x16, 0x0e, 0x07, 0x03},	
	{0x28, 0x28, 0x22, 0x1c, 0x15, 0x0d, 0x07, 0x03},	
	{0x26, 0x25, 0x21, 0x1b, 0x14, 0x0d, 0x06, 0x03},	
	{0x24, 0x23, 0x1f, 0x19, 0x13, 0x0c, 0x06, 0x03},	
	{0x22, 0x21, 0x1d, 0x18, 0x11, 0x0b, 0x06, 0x02},	
	{0x20, 0x20, 0x1b, 0x16, 0x11, 0x08, 0x05, 0x02},	
	{0x1f, 0x1e, 0x1a, 0x15, 0x10, 0x0a, 0x05, 0x02},	
	{0x1d, 0x1c, 0x18, 0x14, 0x0f, 0x0a, 0x05, 0x02},	
	{0x1b, 0x1a, 0x17, 0x13, 0x0e, 0x09, 0x04, 0x02},	
	{0x1a, 0x19, 0x16, 0x12, 0x0d, 0x09, 0x04, 0x02},	
	{0x18, 0x17, 0x15, 0x11, 0x0c, 0x08, 0x04, 0x02},	
	{0x17, 0x16, 0x13, 0x10, 0x0c, 0x08, 0x04, 0x02},	
	{0x16, 0x15, 0x12, 0x0f, 0x0b, 0x07, 0x04, 0x01},	
	{0x14, 0x14, 0x11, 0x0e, 0x0b, 0x07, 0x03, 0x02},	
	{0x13, 0x13, 0x10, 0x0d, 0x0a, 0x06, 0x03, 0x01},	
	{0x12, 0x12, 0x0f, 0x0c, 0x09, 0x06, 0x03, 0x01},	
	{0x11, 0x11, 0x0f, 0x0c, 0x09, 0x06, 0x03, 0x01},	
	{0x10, 0x10, 0x0e, 0x0b, 0x08, 0x05, 0x03, 0x01},	
	{0x0f, 0x0f, 0x0d, 0x0b, 0x08, 0x05, 0x03, 0x01},	
	{0x0e, 0x0e, 0x0c, 0x0a, 0x08, 0x05, 0x02, 0x01},	
	{0x0d, 0x0d, 0x0c, 0x0a, 0x07, 0x05, 0x02, 0x01},	
	{0x0d, 0x0c, 0x0b, 0x09, 0x07, 0x04, 0x02, 0x01},	
	{0x0c, 0x0c, 0x0a, 0x09, 0x06, 0x04, 0x02, 0x01},	
	{0x0b, 0x0b, 0x0a, 0x08, 0x06, 0x04, 0x02, 0x01},	
	{0x0b, 0x0a, 0x09, 0x08, 0x06, 0x04, 0x02, 0x01},	
	{0x0a, 0x0a, 0x09, 0x07, 0x05, 0x03, 0x02, 0x01},	
	{0x0a, 0x09, 0x08, 0x07, 0x05, 0x03, 0x02, 0x01},	
	{0x09, 0x09, 0x08, 0x06, 0x05, 0x03, 0x01, 0x01},	
	{0x09, 0x08, 0x07, 0x06, 0x04, 0x03, 0x01, 0x01}	
};


u8	CCKSwingTable_Ch14[CCK_Table_length][8] = {
	{0x36, 0x35, 0x2e, 0x1b, 0x00, 0x00, 0x00, 0x00},	
	{0x33, 0x32, 0x2b, 0x19, 0x00, 0x00, 0x00, 0x00},	
	{0x30, 0x2f, 0x29, 0x18, 0x00, 0x00, 0x00, 0x00},	
	{0x2d, 0x2d, 0x17, 0x17, 0x00, 0x00, 0x00, 0x00},	
	{0x2b, 0x2a, 0x25, 0x15, 0x00, 0x00, 0x00, 0x00},	
	{0x28, 0x28, 0x24, 0x14, 0x00, 0x00, 0x00, 0x00},	
	{0x26, 0x25, 0x21, 0x13, 0x00, 0x00, 0x00, 0x00},	
	{0x24, 0x23, 0x1f, 0x12, 0x00, 0x00, 0x00, 0x00},	
	{0x22, 0x21, 0x1d, 0x11, 0x00, 0x00, 0x00, 0x00},	
	{0x20, 0x20, 0x1b, 0x10, 0x00, 0x00, 0x00, 0x00},	
	{0x1f, 0x1e, 0x1a, 0x0f, 0x00, 0x00, 0x00, 0x00},	
	{0x1d, 0x1c, 0x18, 0x0e, 0x00, 0x00, 0x00, 0x00},	
	{0x1b, 0x1a, 0x17, 0x0e, 0x00, 0x00, 0x00, 0x00},	
	{0x1a, 0x19, 0x16, 0x0d, 0x00, 0x00, 0x00, 0x00},	
	{0x18, 0x17, 0x15, 0x0c, 0x00, 0x00, 0x00, 0x00},	
	{0x17, 0x16, 0x13, 0x0b, 0x00, 0x00, 0x00, 0x00},	
	{0x16, 0x15, 0x12, 0x0b, 0x00, 0x00, 0x00, 0x00},	
	{0x14, 0x14, 0x11, 0x0a, 0x00, 0x00, 0x00, 0x00},	
	{0x13, 0x13, 0x10, 0x0a, 0x00, 0x00, 0x00, 0x00},	
	{0x12, 0x12, 0x0f, 0x09, 0x00, 0x00, 0x00, 0x00},	
	{0x11, 0x11, 0x0f, 0x09, 0x00, 0x00, 0x00, 0x00},	
	{0x10, 0x10, 0x0e, 0x08, 0x00, 0x00, 0x00, 0x00},	
	{0x0f, 0x0f, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x00},	
	{0x0e, 0x0e, 0x0c, 0x07, 0x00, 0x00, 0x00, 0x00},	
	{0x0d, 0x0d, 0x0c, 0x07, 0x00, 0x00, 0x00, 0x00},	
	{0x0d, 0x0c, 0x0b, 0x06, 0x00, 0x00, 0x00, 0x00},	
	{0x0c, 0x0c, 0x0a, 0x06, 0x00, 0x00, 0x00, 0x00},	
	{0x0b, 0x0b, 0x0a, 0x06, 0x00, 0x00, 0x00, 0x00},	
	{0x0b, 0x0a, 0x09, 0x05, 0x00, 0x00, 0x00, 0x00},	
	{0x0a, 0x0a, 0x09, 0x05, 0x00, 0x00, 0x00, 0x00},	
	{0x0a, 0x09, 0x08, 0x05, 0x00, 0x00, 0x00, 0x00},	
	{0x09, 0x09, 0x08, 0x05, 0x00, 0x00, 0x00, 0x00},	
	{0x09, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00}	
};
#elif defined RTL8192E
static u32 OFDMSwingTable[OFDM_Table_Length] = {
	0x7f8001fe,	
	0x71c001c7,	
	0x65400195,	
	0x5a400169,	
	0x50800142,	
	0x47c0011f,	
	0x40000100,	
	0x390000e4,	
	0x32c000cb,	
	0x2d4000b5,	
	0x288000a2,	
	0x24000090,	
	0x20000080,	
	0x1c800072,	
	0x19800066,	
	0x26c0005b,	
	0x24400051,	
	0x12000048,	
	0x10000040	
};
static u8	CCKSwingTable_Ch1_Ch13[CCK_Table_length][8] = {
	{0x36, 0x35, 0x2e, 0x25, 0x1c, 0x12, 0x09, 0x04},	
	{0x30, 0x2f, 0x29, 0x21, 0x19, 0x10, 0x08, 0x03},	
	{0x2b, 0x2a, 0x25, 0x1e, 0x16, 0x0e, 0x07, 0x03},	
	{0x26, 0x25, 0x21, 0x1b, 0x14, 0x0d, 0x06, 0x03},	
	{0x22, 0x21, 0x1d, 0x18, 0x11, 0x0b, 0x06, 0x02},	
	{0x1f, 0x1e, 0x1a, 0x15, 0x10, 0x0a, 0x05, 0x02},	
	{0x1b, 0x1a, 0x17, 0x13, 0x0e, 0x09, 0x04, 0x02},	
	{0x18, 0x17, 0x15, 0x11, 0x0c, 0x08, 0x04, 0x02},	
	{0x16, 0x15, 0x12, 0x0f, 0x0b, 0x07, 0x04, 0x01},	
	{0x13, 0x13, 0x10, 0x0d, 0x0a, 0x06, 0x03, 0x01},	
	{0x11, 0x11, 0x0f, 0x0c, 0x09, 0x06, 0x03, 0x01},	
	{0x0f, 0x0f, 0x0d, 0x0b, 0x08, 0x05, 0x03, 0x01}	
};

static u8	CCKSwingTable_Ch14[CCK_Table_length][8] = {
	{0x36, 0x35, 0x2e, 0x1b, 0x00, 0x00, 0x00, 0x00},	
	{0x30, 0x2f, 0x29, 0x18, 0x00, 0x00, 0x00, 0x00},	
	{0x2b, 0x2a, 0x25, 0x15, 0x00, 0x00, 0x00, 0x00},	
	{0x26, 0x25, 0x21, 0x13, 0x00, 0x00, 0x00, 0x00},	
	{0x22, 0x21, 0x1d, 0x11, 0x00, 0x00, 0x00, 0x00},	
	{0x1f, 0x1e, 0x1a, 0x0f, 0x00, 0x00, 0x00, 0x00},	
	{0x1b, 0x1a, 0x17, 0x0e, 0x00, 0x00, 0x00, 0x00},	
	{0x18, 0x17, 0x15, 0x0c, 0x00, 0x00, 0x00, 0x00},	
	{0x16, 0x15, 0x12, 0x0b, 0x00, 0x00, 0x00, 0x00},	
	{0x13, 0x13, 0x10, 0x0a, 0x00, 0x00, 0x00, 0x00},	
	{0x11, 0x11, 0x0f, 0x09, 0x00, 0x00, 0x00, 0x00},	
	{0x0f, 0x0f, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x00}	
};
#endif
#define		Pw_Track_Flag				0x11d
#define		Tssi_Mea_Value				0x13c
#define		Tssi_Report_Value1			0x134
#define		Tssi_Report_Value2			0x13e
#define		FW_Busy_Flag				0x13f

#ifndef RTL8192SE
static void dm_TXPowerTrackingCallback_TSSI(struct net_device * dev)
	{
	struct r8192_priv *priv = rtllib_priv(dev);
	bool						bHighpowerstate, viviflag = false;
	DCMD_TXCMD_T			tx_cmd;
	u8					powerlevelOFDM24G;
	int	    				i =0, j = 0, k = 0;
	u8						RF_Type, tmp_report[5]={0, 0, 0, 0, 0};
	u32						Value;
	u8						Pwr_Flag;
	u16					Avg_TSSI_Meas, TSSI_13dBm, Avg_TSSI_Meas_from_driver=0;
#ifdef RTL8192U
	RT_STATUS 				rtStatus = RT_STATUS_SUCCESS;
#endif
	u32						delta=0;
	RT_TRACE(COMP_POWER_TRACKING,"%s()\n",__FUNCTION__);
	write_nic_byte(dev, Pw_Track_Flag, 0);
	write_nic_byte(dev, FW_Busy_Flag, 0);
	priv->rtllib->bdynamic_txpower_enable = false;
	bHighpowerstate = priv->bDynamicTxHighPower;

	powerlevelOFDM24G = (u8)(priv->Pwr_Track>>24); 
	RF_Type = priv->rf_type;
	Value = (RF_Type<<8) | powerlevelOFDM24G;

	RT_TRACE(COMP_POWER_TRACKING, "powerlevelOFDM24G = %x\n", powerlevelOFDM24G);

	
#ifdef RTL8190P
	for(j = 0; j<1; j++)	
#else
	for(j = 0; j<=30; j++)	
#endif
{	

	tx_cmd.Op		= TXCMD_SET_TX_PWR_TRACKING;
	tx_cmd.Length	= 4;
	tx_cmd.Value		= Value;
#ifdef RTL8192U
	rtStatus = SendTxCommandPacket(dev, &tx_cmd, 12);	
	if (rtStatus == RT_STATUS_FAILURE)
	{
		RT_TRACE(COMP_POWER_TRACKING, "Set configuration with tx cmd queue fail!\n");
	}
#else
	cmpk_message_handle_tx(dev, (u8*)&tx_cmd, DESC_PACKET_TYPE_INIT, sizeof(DCMD_TXCMD_T));
#endif
	mdelay(1);
	for(i = 0;i <= 30; i++)
	{
		Pwr_Flag = read_nic_byte(dev, Pw_Track_Flag);
		
		if (Pwr_Flag == 0)
		{	
			mdelay(1);

			if(priv->bResetInProgress)	
			{
				RT_TRACE(COMP_POWER_TRACKING, "we are in slient reset progress, so return\n");		
				write_nic_byte(dev, Pw_Track_Flag, 0);
				write_nic_byte(dev, FW_Busy_Flag, 0);
				return;
			}
#ifdef RTL8192E
			if((priv->rtllib->eRFPowerState != eRfOn))
			{
				RT_TRACE(COMP_POWER_TRACKING, "we are in power save, so return\n");		
				write_nic_byte(dev, Pw_Track_Flag, 0);
				write_nic_byte(dev, FW_Busy_Flag, 0);
				return;
			}

#endif
			continue;
		}

		Avg_TSSI_Meas = read_nic_word(dev, Tssi_Mea_Value);

		if(Avg_TSSI_Meas == 0)
		{
			write_nic_byte(dev, Pw_Track_Flag, 0);
			write_nic_byte(dev, FW_Busy_Flag, 0);
			return;
		}
		
		for(k = 0;k < 5; k++)
		{
			if(k !=4)
				tmp_report[k] = read_nic_byte(dev, Tssi_Report_Value1+k);
			else
				tmp_report[k] = read_nic_byte(dev, Tssi_Report_Value2);

			RT_TRACE(COMP_POWER_TRACKING, "TSSI_report_value = %d\n", tmp_report[k]);

		        {
			       if(tmp_report[k] <= 20)
			       {	
				      viviflag =true;
				      break;
			       }
		        }
		}

		if(viviflag ==true)
		{	
			write_nic_byte(dev, Pw_Track_Flag, 0);
			viviflag = false;
			RT_TRACE(COMP_POWER_TRACKING, "we filted this data\n");
			for(k = 0;k < 5; k++)
				tmp_report[k] = 0;
			break;
		}

		for(k = 0;k < 5; k++)
		{
			Avg_TSSI_Meas_from_driver += tmp_report[k];
		}

		Avg_TSSI_Meas_from_driver = Avg_TSSI_Meas_from_driver*100/5;
		RT_TRACE(COMP_POWER_TRACKING, "Avg_TSSI_Meas_from_driver = %d\n", Avg_TSSI_Meas_from_driver);
		TSSI_13dBm = priv->TSSI_13dBm;
		RT_TRACE(COMP_POWER_TRACKING, "TSSI_13dBm = %d\n", TSSI_13dBm);
		
		if(Avg_TSSI_Meas_from_driver > TSSI_13dBm)
			delta = Avg_TSSI_Meas_from_driver - TSSI_13dBm;
		else
			delta = TSSI_13dBm - Avg_TSSI_Meas_from_driver;

		if(delta <= E_FOR_TX_POWER_TRACK)
		{
			priv->rtllib->bdynamic_txpower_enable = true;
			write_nic_byte(dev, Pw_Track_Flag, 0);
			write_nic_byte(dev, FW_Busy_Flag, 0);
			RT_TRACE(COMP_POWER_TRACKING, "tx power track is done\n");
			RT_TRACE(COMP_POWER_TRACKING, "priv->rfa_txpowertrackingindex = %d\n", priv->rfa_txpowertrackingindex);
			RT_TRACE(COMP_POWER_TRACKING, "priv->rfa_txpowertrackingindex_real = %d\n", priv->rfa_txpowertrackingindex_real);
#ifdef RTL8190P					
			RT_TRACE(COMP_POWER_TRACKING, "priv->rfc_txpowertrackingindex = %d\n", priv->rfc_txpowertrackingindex);
			RT_TRACE(COMP_POWER_TRACKING, "priv->rfc_txpowertrackingindex_real = %d\n", priv->rfc_txpowertrackingindex_real);
#endif
			RT_TRACE(COMP_POWER_TRACKING, "priv->CCKPresentAttentuation_difference = %d\n", priv->CCKPresentAttentuation_difference);
			RT_TRACE(COMP_POWER_TRACKING, "priv->CCKPresentAttentuation = %d\n", priv->CCKPresentAttentuation);
			return;
		}
		else
		{
			if(Avg_TSSI_Meas_from_driver < TSSI_13dBm - E_FOR_TX_POWER_TRACK)
			{
				if (RF_Type == RF_2T4R)
				{
						
						if((priv->rfa_txpowertrackingindex > 0) &&(priv->rfc_txpowertrackingindex > 0))
				{
					priv->rfa_txpowertrackingindex--;
					if(priv->rfa_txpowertrackingindex_real > 4)
					{
						priv->rfa_txpowertrackingindex_real--;
						rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfa_txpowertrackingindex_real].txbbgain_value);
					}

					priv->rfc_txpowertrackingindex--;
					if(priv->rfc_txpowertrackingindex_real > 4)
					{
						priv->rfc_txpowertrackingindex_real--;
						rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfc_txpowertrackingindex_real].txbbgain_value);
					}
						}
						else
						{
								rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[4].txbbgain_value);
								rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[4].txbbgain_value);
				}
			}
			else
			{
						{
#ifdef RTL8190P
								{
						if(priv->rfc_txpowertrackingindex > 0)
						{
							priv->rfc_txpowertrackingindex--;
							if(priv->rfc_txpowertrackingindex_real > 4)
							{
								priv->rfc_txpowertrackingindex_real--;
								rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfc_txpowertrackingindex_real].txbbgain_value);
							}
						}
						else
							rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[4].txbbgain_value);		
				}
#endif
#ifdef RTL8192E
								{
									if(priv->rfa_txpowertrackingindex > 0)
									{
										priv->rfa_txpowertrackingindex--;
										if(priv->rfa_txpowertrackingindex_real > 4)
										{
											priv->rfa_txpowertrackingindex_real--;
											rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfa_txpowertrackingindex_real].txbbgain_value);
										}
									}
									else
											rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[4].txbbgain_value);							
								}
#endif
						}

				}
			}
			else
			{
				if (RF_Type == RF_2T4R)
				{
					if((priv->rfa_txpowertrackingindex < TxBBGainTableLength - 1) &&(priv->rfc_txpowertrackingindex < TxBBGainTableLength - 1))				
				{
					priv->rfa_txpowertrackingindex++;
					priv->rfa_txpowertrackingindex_real++;					
					rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfa_txpowertrackingindex_real].txbbgain_value);
					priv->rfc_txpowertrackingindex++;
					priv->rfc_txpowertrackingindex_real++;					
					rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfc_txpowertrackingindex_real].txbbgain_value);
				}
					else
					{
						rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[TxBBGainTableLength - 1].txbbgain_value);
						rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[TxBBGainTableLength - 1].txbbgain_value);
			}
				}
				else
				{
					{
#ifdef RTL8190P
							{
					if(priv->rfc_txpowertrackingindex < (TxBBGainTableLength - 1))
					{
							priv->rfc_txpowertrackingindex++;
							priv->rfc_txpowertrackingindex_real++;					
							rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfc_txpowertrackingindex_real].txbbgain_value);
					}
					else
							rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[TxBBGainTableLength - 1].txbbgain_value);
				}
#endif
#ifdef RTL8192E
							{
								if(priv->rfa_txpowertrackingindex < (TxBBGainTableLength - 1))
								{
									priv->rfa_txpowertrackingindex++;
									priv->rfa_txpowertrackingindex_real++;					
									rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfa_txpowertrackingindex_real].txbbgain_value);
			}
								else
									rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[TxBBGainTableLength - 1].txbbgain_value);
							}
#endif
					}
				}
			}
			if (RF_Type == RF_2T4R){
			priv->CCKPresentAttentuation_difference
				= priv->rfa_txpowertrackingindex - priv->rfa_txpowertracking_default;
			}else{
				{
#ifdef RTL8190P
				priv->CCKPresentAttentuation_difference
					= priv->rfc_txpowertrackingindex - priv->rfc_txpowertracking_default;
#endif
#ifdef RTL8192E
						priv->CCKPresentAttentuation_difference
							= priv->rfa_txpowertrackingindex_real - priv->rfa_txpowertracking_default;
#endif
				}
			}

			if(priv->CurrentChannelBW == HT_CHANNEL_WIDTH_20)	
				priv->CCKPresentAttentuation 
				= priv->CCKPresentAttentuation_20Mdefault + priv->CCKPresentAttentuation_difference;
			else
				priv->CCKPresentAttentuation 
				= priv->CCKPresentAttentuation_40Mdefault + priv->CCKPresentAttentuation_difference;

			if(priv->CCKPresentAttentuation > (CCKTxBBGainTableLength-1))
					priv->CCKPresentAttentuation = CCKTxBBGainTableLength-1;
			if(priv->CCKPresentAttentuation < 0)
					priv->CCKPresentAttentuation = 0;

			if(priv->CCKPresentAttentuation > -1&&priv->CCKPresentAttentuation < CCKTxBBGainTableLength)
			{
				if(priv->rtllib->current_network.channel == 14 && !priv->bcck_in_ch14)
				{
					priv->bcck_in_ch14 = true;
					dm_cck_txpower_adjust(dev,priv->bcck_in_ch14);
				}
				else if(priv->rtllib->current_network.channel != 14 && priv->bcck_in_ch14)
				{
					priv->bcck_in_ch14 = false;
					dm_cck_txpower_adjust(dev,priv->bcck_in_ch14);
				}
				else
					dm_cck_txpower_adjust(dev,priv->bcck_in_ch14);		
			}
		RT_TRACE(COMP_POWER_TRACKING, "priv->rfa_txpowertrackingindex = %d\n", priv->rfa_txpowertrackingindex);
		RT_TRACE(COMP_POWER_TRACKING, "priv->rfa_txpowertrackingindex_real = %d\n", priv->rfa_txpowertrackingindex_real);
#ifdef RTL8190P
		RT_TRACE(COMP_POWER_TRACKING, "priv->rfc_txpowertrackingindex = %d\n", priv->rfc_txpowertrackingindex);
		RT_TRACE(COMP_POWER_TRACKING, "priv->rfc_txpowertrackingindex_real = %d\n", priv->rfc_txpowertrackingindex_real);
#endif
		RT_TRACE(COMP_POWER_TRACKING, "priv->CCKPresentAttentuation_difference = %d\n", priv->CCKPresentAttentuation_difference);
		RT_TRACE(COMP_POWER_TRACKING, "priv->CCKPresentAttentuation = %d\n", priv->CCKPresentAttentuation);

		if (priv->CCKPresentAttentuation_difference <= -12||priv->CCKPresentAttentuation_difference >= 24)
		{
			priv->rtllib->bdynamic_txpower_enable = true;
			write_nic_byte(dev, Pw_Track_Flag, 0);
			write_nic_byte(dev, FW_Busy_Flag, 0);
			RT_TRACE(COMP_POWER_TRACKING, "tx power track--->limited\n");
			return;
		}

		
	}
		write_nic_byte(dev, Pw_Track_Flag, 0);
		Avg_TSSI_Meas_from_driver = 0;
		for(k = 0;k < 5; k++)
			tmp_report[k] = 0;
		break;
	}
	write_nic_byte(dev, FW_Busy_Flag, 0);
}	
		priv->rtllib->bdynamic_txpower_enable = true;
		write_nic_byte(dev, Pw_Track_Flag, 0);
}
#endif

#ifdef RTL8192E
static void dm_TXPowerTrackingCallback_ThermalMeter(struct net_device * dev)
{
#define ThermalMeterVal	9
	struct r8192_priv *priv = rtllib_priv(dev);
	u32 tmpRegA, TempCCk;
	u8 tmpOFDMindex, tmpCCKindex, tmpCCK20Mindex, tmpCCK40Mindex, tmpval;
	int i =0, CCKSwingNeedUpdate=0;

	if(!priv->btxpower_trackingInit)
	{
		tmpRegA= rtl8192_QueryBBReg(dev, rOFDM0_XATxIQImbalance, bMaskDWord);
		for(i=0; i<OFDM_Table_Length; i++)	
		{
			if(tmpRegA == OFDMSwingTable[i])
			{
				priv->OFDM_index= (u8)i;
				RT_TRACE(COMP_POWER_TRACKING, "Initial reg0x%x = 0x%x, OFDM_index=0x%x\n", 
					rOFDM0_XATxIQImbalance, tmpRegA, priv->OFDM_index);
			}
		}

		TempCCk = rtl8192_QueryBBReg(dev, rCCK0_TxFilter1, bMaskByte2);
		for(i=0 ; i<CCK_Table_length ; i++)
		{
			if(TempCCk == (u32)CCKSwingTable_Ch1_Ch13[i][0])
			{
				priv->CCK_index =(u8) i;
				RT_TRACE(COMP_POWER_TRACKING, "Initial reg0x%x = 0x%x, CCK_index=0x%x\n", 
					rCCK0_TxFilter1, TempCCk, priv->CCK_index);
		break;
	}
}	
		priv->btxpower_trackingInit = true;
		return;
	}

#if 0
{
	UINT32	curr_addr;
	UINT32	reg_value;
	
		for (curr_addr = 0; curr_addr < 0x2d; curr_addr++)	
		{			  
			reg_value = PHY_QueryRFReg(	dev, (RF90_RADIO_PATH_E)RF90_PATH_A, 
										curr_addr, bMaskDWord);
		}

	pHalData->TXPowercount = 0;
	return;
}
#endif

	tmpRegA = rtl8192_phy_QueryRFReg(dev, RF90_PATH_A, 0x12, 0x078);	
	RT_TRACE(COMP_POWER_TRACKING, "Readback ThermalMeterA = %d \n", tmpRegA);
	if(tmpRegA < 3 || tmpRegA > 13)
		return;
	if(tmpRegA >= 12)	
		tmpRegA = 12;
	RT_TRACE(COMP_POWER_TRACKING, "Valid ThermalMeterA = %d \n", tmpRegA);
	priv->ThermalMeter[0] = ThermalMeterVal;	
	priv->ThermalMeter[1] = ThermalMeterVal;	

	if(priv->ThermalMeter[0] >= (u8)tmpRegA)	
	{
		tmpOFDMindex = tmpCCK20Mindex = 6+(priv->ThermalMeter[0]-(u8)tmpRegA);
		tmpCCK40Mindex = tmpCCK20Mindex - 6;
		if(tmpOFDMindex >= OFDM_Table_Length)
			tmpOFDMindex = OFDM_Table_Length-1;
		if(tmpCCK20Mindex >= CCK_Table_length)
			tmpCCK20Mindex = CCK_Table_length-1;
		if(tmpCCK40Mindex >= CCK_Table_length)
			tmpCCK40Mindex = CCK_Table_length-1;
	}
	else
	{		
		tmpval = ((u8)tmpRegA - priv->ThermalMeter[0]);
		if(tmpval >= 6)								
			tmpOFDMindex = tmpCCK20Mindex = 0;		
		else
			tmpOFDMindex = tmpCCK20Mindex = 6 - tmpval;
		tmpCCK40Mindex = 0;
	}
	if(priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)	
		tmpCCKindex = tmpCCK40Mindex;
	else
		tmpCCKindex = tmpCCK20Mindex;

	priv->Record_CCK_20Mindex = tmpCCK20Mindex;
	priv->Record_CCK_40Mindex = tmpCCK40Mindex;
	RT_TRACE(COMP_POWER_TRACKING, "Record_CCK_20Mindex / Record_CCK_40Mindex = %d / %d.\n", 
		priv->Record_CCK_20Mindex, priv->Record_CCK_40Mindex);

	if(priv->rtllib->current_network.channel == 14 && !priv->bcck_in_ch14)
	{
		priv->bcck_in_ch14 = true;
		CCKSwingNeedUpdate = 1;
	}
	else if(priv->rtllib->current_network.channel != 14 && priv->bcck_in_ch14)
	{
		priv->bcck_in_ch14 = false;
		CCKSwingNeedUpdate = 1;
	}

	if(priv->CCK_index != tmpCCKindex)
{
		priv->CCK_index = tmpCCKindex; 
		CCKSwingNeedUpdate = 1;
	}

	if(CCKSwingNeedUpdate)
	{
		dm_cck_txpower_adjust(dev, priv->bcck_in_ch14);
	}
	if(priv->OFDM_index != tmpOFDMindex)
	{
		priv->OFDM_index = tmpOFDMindex;
		rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, OFDMSwingTable[priv->OFDM_index]);		
		RT_TRACE(COMP_POWER_TRACKING, "Update OFDMSwing[%d] = 0x%x\n", 
			priv->OFDM_index, OFDMSwingTable[priv->OFDM_index]);
	}
	priv->txpower_count = 0;
}
#elif defined (RTL8192SE)
static void dm_TXPowerTrackingCallback_ThermalMeter(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
        u8 	ThermalValue=0;
	u32	FwCmdVal=0;

	priv->btxpower_trackingInit = true;

	
	ThermalValue = (u8)rtl8192_phy_QueryRFReg(dev, RF90_PATH_A, RF_T_METER, 0x1f);	
	RT_TRACE(COMP_POWER_TRACKING, "Readback Thermal Meter = 0x%x\n", ThermalValue);
	printk("%s()Readback Thermal Meter = 0x%x\n", __func__,ThermalValue);
	if(ThermalValue)
	{
		priv->ThermalValue = ThermalValue;
		if(priv->pFirmware->FirmwareVersion >= 0x35)
		{
			priv->rtllib->SetFwCmdHandler(dev, FW_CMD_TXPWR_TRACK_THERMAL);	
		}
		else
		{
		FwCmdVal = (FW_TXPWR_TRACK_THERMAL|
		(priv->ThermalMeter[0]<<8)|(ThermalValue<<16));
		RT_TRACE(COMP_POWER_TRACKING, "Write to FW Thermal Val = 0x%x\n", FwCmdVal);
		write_nic_dword(dev, WFM5, FwCmdVal); 
				ChkFwCmdIoDone(dev);
		}
	}

	priv->txpower_count = 0;
}
#endif

void	dm_txpower_trackingcallback(void *data)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
	struct r8192_priv *priv = container_of_dwork_rsl(data,struct r8192_priv,txpower_tracking_wq);
	struct net_device *dev = priv->rtllib->dev;
#else	   
	struct net_device *dev = (struct net_device *)data;
	struct r8192_priv *priv = rtllib_priv(dev);
#endif
	
#ifdef RTL8190P
	dm_TXPowerTrackingCallback_TSSI(dev);
#elif defined(RTL8192E)
	if(priv->IC_Cut >= IC_VersionCut_D)
		dm_TXPowerTrackingCallback_TSSI(dev);
	else
		dm_TXPowerTrackingCallback_ThermalMeter(dev);
#elif defined(RTL8192SE)
	dm_TXPowerTrackingCallback_ThermalMeter(dev);
#endif
}

#ifndef RTL8192SE
static void dm_InitializeTXPowerTracking_TSSI(struct net_device *dev)
{

	struct r8192_priv *priv = rtllib_priv(dev);
	
	priv->txbbgain_table[0].txbb_iq_amplifygain = 	 		12;
	priv->txbbgain_table[0].txbbgain_value=0x7f8001fe;
	priv->txbbgain_table[1].txbb_iq_amplifygain = 	 		11;
	priv->txbbgain_table[1].txbbgain_value=0x788001e2;
	priv->txbbgain_table[2].txbb_iq_amplifygain = 	 		10;
	priv->txbbgain_table[2].txbbgain_value=0x71c001c7;
	priv->txbbgain_table[3].txbb_iq_amplifygain = 	 		9;
	priv->txbbgain_table[3].txbbgain_value=0x6b8001ae;
	priv->txbbgain_table[4].txbb_iq_amplifygain = 		       8;
	priv->txbbgain_table[4].txbbgain_value=0x65400195;
	priv->txbbgain_table[5].txbb_iq_amplifygain = 		       7;
	priv->txbbgain_table[5].txbbgain_value=0x5fc0017f;
	priv->txbbgain_table[6].txbb_iq_amplifygain = 		       6;
	priv->txbbgain_table[6].txbbgain_value=0x5a400169;
	priv->txbbgain_table[7].txbb_iq_amplifygain = 		       5;
	priv->txbbgain_table[7].txbbgain_value=0x55400155;
	priv->txbbgain_table[8].txbb_iq_amplifygain = 		       4;
	priv->txbbgain_table[8].txbbgain_value=0x50800142;
	priv->txbbgain_table[9].txbb_iq_amplifygain = 		       3;
	priv->txbbgain_table[9].txbbgain_value=0x4c000130;
	priv->txbbgain_table[10].txbb_iq_amplifygain = 		       2;
	priv->txbbgain_table[10].txbbgain_value=0x47c0011f;
	priv->txbbgain_table[11].txbb_iq_amplifygain = 		       1;
	priv->txbbgain_table[11].txbbgain_value=0x43c0010f;
	priv->txbbgain_table[12].txbb_iq_amplifygain = 		       0;
	priv->txbbgain_table[12].txbbgain_value=0x40000100;
	priv->txbbgain_table[13].txbb_iq_amplifygain = 		       -1;
	priv->txbbgain_table[13].txbbgain_value=0x3c8000f2;
	priv->txbbgain_table[14].txbb_iq_amplifygain = 		     -2;
	priv->txbbgain_table[14].txbbgain_value=0x390000e4;
	priv->txbbgain_table[15].txbb_iq_amplifygain = 		     -3;
	priv->txbbgain_table[15].txbbgain_value=0x35c000d7;
	priv->txbbgain_table[16].txbb_iq_amplifygain = 		     -4;
	priv->txbbgain_table[16].txbbgain_value=0x32c000cb;
	priv->txbbgain_table[17].txbb_iq_amplifygain = 		     -5;
	priv->txbbgain_table[17].txbbgain_value=0x300000c0;
	priv->txbbgain_table[18].txbb_iq_amplifygain = 		 	    -6;
	priv->txbbgain_table[18].txbbgain_value=0x2d4000b5;
	priv->txbbgain_table[19].txbb_iq_amplifygain = 		     -7;
	priv->txbbgain_table[19].txbbgain_value=0x2ac000ab;
	priv->txbbgain_table[20].txbb_iq_amplifygain = 		     -8;
	priv->txbbgain_table[20].txbbgain_value=0x288000a2;
	priv->txbbgain_table[21].txbb_iq_amplifygain = 		     -9;
	priv->txbbgain_table[21].txbbgain_value=0x26000098;
	priv->txbbgain_table[22].txbb_iq_amplifygain = 		     -10;
	priv->txbbgain_table[22].txbbgain_value=0x24000090;
	priv->txbbgain_table[23].txbb_iq_amplifygain = 		     -11;
	priv->txbbgain_table[23].txbbgain_value=0x22000088;
	priv->txbbgain_table[24].txbb_iq_amplifygain = 		     -12;
	priv->txbbgain_table[24].txbbgain_value=0x20000080;
	priv->txbbgain_table[25].txbb_iq_amplifygain = 		     -13;
	priv->txbbgain_table[25].txbbgain_value=0x1a00006c;
	priv->txbbgain_table[26].txbb_iq_amplifygain = 		     -14;
	priv->txbbgain_table[26].txbbgain_value=0x1c800072;
	priv->txbbgain_table[27].txbb_iq_amplifygain = 		     -15;
	priv->txbbgain_table[27].txbbgain_value=0x18000060;
	priv->txbbgain_table[28].txbb_iq_amplifygain = 		     -16;
	priv->txbbgain_table[28].txbbgain_value=0x19800066;
	priv->txbbgain_table[29].txbb_iq_amplifygain = 		     -17;
	priv->txbbgain_table[29].txbbgain_value=0x15800056;
	priv->txbbgain_table[30].txbb_iq_amplifygain = 		     -18;
	priv->txbbgain_table[30].txbbgain_value=0x26c0005b;
	priv->txbbgain_table[31].txbb_iq_amplifygain = 		     -19;
	priv->txbbgain_table[31].txbbgain_value=0x14400051;
	priv->txbbgain_table[32].txbb_iq_amplifygain = 		     -20;
	priv->txbbgain_table[32].txbbgain_value=0x24400051;
	priv->txbbgain_table[33].txbb_iq_amplifygain = 		     -21;
	priv->txbbgain_table[33].txbbgain_value=0x1300004c;
	priv->txbbgain_table[34].txbb_iq_amplifygain = 		     -22;
	priv->txbbgain_table[34].txbbgain_value=0x12000048;
	priv->txbbgain_table[35].txbb_iq_amplifygain = 		     -23;
	priv->txbbgain_table[35].txbbgain_value=0x11000044;
	priv->txbbgain_table[36].txbb_iq_amplifygain = 		     -24;
	priv->txbbgain_table[36].txbbgain_value=0x10000040;

	priv->cck_txbbgain_table[0].ccktxbb_valuearray[0] = 0x36;
	priv->cck_txbbgain_table[0].ccktxbb_valuearray[1] = 0x35;
	priv->cck_txbbgain_table[0].ccktxbb_valuearray[2] = 0x2e;
	priv->cck_txbbgain_table[0].ccktxbb_valuearray[3] = 0x25;
	priv->cck_txbbgain_table[0].ccktxbb_valuearray[4] = 0x1c;
	priv->cck_txbbgain_table[0].ccktxbb_valuearray[5] = 0x12;
	priv->cck_txbbgain_table[0].ccktxbb_valuearray[6] = 0x09;
	priv->cck_txbbgain_table[0].ccktxbb_valuearray[7] = 0x04;

	priv->cck_txbbgain_table[1].ccktxbb_valuearray[0] = 0x33;
	priv->cck_txbbgain_table[1].ccktxbb_valuearray[1] = 0x32;
	priv->cck_txbbgain_table[1].ccktxbb_valuearray[2] = 0x2b;
	priv->cck_txbbgain_table[1].ccktxbb_valuearray[3] = 0x23;
	priv->cck_txbbgain_table[1].ccktxbb_valuearray[4] = 0x1a;
	priv->cck_txbbgain_table[1].ccktxbb_valuearray[5] = 0x11;
	priv->cck_txbbgain_table[1].ccktxbb_valuearray[6] = 0x08;
	priv->cck_txbbgain_table[1].ccktxbb_valuearray[7] = 0x04;
	
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[0] = 0x30;
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[1] = 0x2f;
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[2] = 0x29;
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[3] = 0x21;
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[4] = 0x19;
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[5] = 0x10;
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[6] = 0x08;
	priv->cck_txbbgain_table[2].ccktxbb_valuearray[7] = 0x03;

	priv->cck_txbbgain_table[3].ccktxbb_valuearray[0] = 0x2d;
	priv->cck_txbbgain_table[3].ccktxbb_valuearray[1] = 0x2d;
	priv->cck_txbbgain_table[3].ccktxbb_valuearray[2] = 0x27;
	priv->cck_txbbgain_table[3].ccktxbb_valuearray[3] = 0x1f;
	priv->cck_txbbgain_table[3].ccktxbb_valuearray[4] = 0x18;
	priv->cck_txbbgain_table[3].ccktxbb_valuearray[5] = 0x0f;
	priv->cck_txbbgain_table[3].ccktxbb_valuearray[6] = 0x08;
	priv->cck_txbbgain_table[3].ccktxbb_valuearray[7] = 0x03;
	
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[0] = 0x2b;
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[1] = 0x2a;
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[2] = 0x25;
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[3] = 0x1e;
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[4] = 0x16;
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[5] = 0x0e;
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[6] = 0x07;
	priv->cck_txbbgain_table[4].ccktxbb_valuearray[7] = 0x03;

	priv->cck_txbbgain_table[5].ccktxbb_valuearray[0] = 0x28;
	priv->cck_txbbgain_table[5].ccktxbb_valuearray[1] = 0x28;
	priv->cck_txbbgain_table[5].ccktxbb_valuearray[2] = 0x22;
	priv->cck_txbbgain_table[5].ccktxbb_valuearray[3] = 0x1c;
	priv->cck_txbbgain_table[5].ccktxbb_valuearray[4] = 0x15;
	priv->cck_txbbgain_table[5].ccktxbb_valuearray[5] = 0x0d;
	priv->cck_txbbgain_table[5].ccktxbb_valuearray[6] = 0x07;
	priv->cck_txbbgain_table[5].ccktxbb_valuearray[7] = 0x03;
	
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[0] = 0x26;
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[1] = 0x25;
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[2] = 0x21;
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[3] = 0x1b;
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[4] = 0x14;
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[5] = 0x0d;
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[6] = 0x06;
	priv->cck_txbbgain_table[6].ccktxbb_valuearray[7] = 0x03;

	priv->cck_txbbgain_table[7].ccktxbb_valuearray[0] = 0x24;
	priv->cck_txbbgain_table[7].ccktxbb_valuearray[1] = 0x23;
	priv->cck_txbbgain_table[7].ccktxbb_valuearray[2] = 0x1f;
	priv->cck_txbbgain_table[7].ccktxbb_valuearray[3] = 0x19;
	priv->cck_txbbgain_table[7].ccktxbb_valuearray[4] = 0x13;
	priv->cck_txbbgain_table[7].ccktxbb_valuearray[5] = 0x0c;
	priv->cck_txbbgain_table[7].ccktxbb_valuearray[6] = 0x06;
	priv->cck_txbbgain_table[7].ccktxbb_valuearray[7] = 0x03;
	
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[0] = 0x22;
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[1] = 0x21;
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[2] = 0x1d;
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[3] = 0x18;
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[4] = 0x11;
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[5] = 0x0b;
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[6] = 0x06;
	priv->cck_txbbgain_table[8].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[9].ccktxbb_valuearray[0] = 0x20;
	priv->cck_txbbgain_table[9].ccktxbb_valuearray[1] = 0x20;
	priv->cck_txbbgain_table[9].ccktxbb_valuearray[2] = 0x1b;
	priv->cck_txbbgain_table[9].ccktxbb_valuearray[3] = 0x16;
	priv->cck_txbbgain_table[9].ccktxbb_valuearray[4] = 0x11;
	priv->cck_txbbgain_table[9].ccktxbb_valuearray[5] = 0x08;
	priv->cck_txbbgain_table[9].ccktxbb_valuearray[6] = 0x05;
	priv->cck_txbbgain_table[9].ccktxbb_valuearray[7] = 0x02;
	
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[0] = 0x1f;
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[1] = 0x1e;
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[2] = 0x1a;
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[3] = 0x15;
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[4] = 0x10;
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[5] = 0x0a;
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[6] = 0x05;
	priv->cck_txbbgain_table[10].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[11].ccktxbb_valuearray[0] = 0x1d;
	priv->cck_txbbgain_table[11].ccktxbb_valuearray[1] = 0x1c;
	priv->cck_txbbgain_table[11].ccktxbb_valuearray[2] = 0x18;
	priv->cck_txbbgain_table[11].ccktxbb_valuearray[3] = 0x14;
	priv->cck_txbbgain_table[11].ccktxbb_valuearray[4] = 0x0f;
	priv->cck_txbbgain_table[11].ccktxbb_valuearray[5] = 0x0a;
	priv->cck_txbbgain_table[11].ccktxbb_valuearray[6] = 0x05;
	priv->cck_txbbgain_table[11].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[12].ccktxbb_valuearray[0] = 0x1b;
	priv->cck_txbbgain_table[12].ccktxbb_valuearray[1] = 0x1a;
	priv->cck_txbbgain_table[12].ccktxbb_valuearray[2] = 0x17;
	priv->cck_txbbgain_table[12].ccktxbb_valuearray[3] = 0x13;
	priv->cck_txbbgain_table[12].ccktxbb_valuearray[4] = 0x0e;
	priv->cck_txbbgain_table[12].ccktxbb_valuearray[5] = 0x09;
	priv->cck_txbbgain_table[12].ccktxbb_valuearray[6] = 0x04;
	priv->cck_txbbgain_table[12].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[13].ccktxbb_valuearray[0] = 0x1a;
	priv->cck_txbbgain_table[13].ccktxbb_valuearray[1] = 0x19;
	priv->cck_txbbgain_table[13].ccktxbb_valuearray[2] = 0x16;
	priv->cck_txbbgain_table[13].ccktxbb_valuearray[3] = 0x12;
	priv->cck_txbbgain_table[13].ccktxbb_valuearray[4] = 0x0d;
	priv->cck_txbbgain_table[13].ccktxbb_valuearray[5] = 0x09;
	priv->cck_txbbgain_table[13].ccktxbb_valuearray[6] = 0x04;
	priv->cck_txbbgain_table[13].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[14].ccktxbb_valuearray[0] = 0x18;
	priv->cck_txbbgain_table[14].ccktxbb_valuearray[1] = 0x17;
	priv->cck_txbbgain_table[14].ccktxbb_valuearray[2] = 0x15;
	priv->cck_txbbgain_table[14].ccktxbb_valuearray[3] = 0x11;
	priv->cck_txbbgain_table[14].ccktxbb_valuearray[4] = 0x0c;
	priv->cck_txbbgain_table[14].ccktxbb_valuearray[5] = 0x08;
	priv->cck_txbbgain_table[14].ccktxbb_valuearray[6] = 0x04;
	priv->cck_txbbgain_table[14].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[15].ccktxbb_valuearray[0] = 0x17;
	priv->cck_txbbgain_table[15].ccktxbb_valuearray[1] = 0x16;
	priv->cck_txbbgain_table[15].ccktxbb_valuearray[2] = 0x13;
	priv->cck_txbbgain_table[15].ccktxbb_valuearray[3] = 0x10;
	priv->cck_txbbgain_table[15].ccktxbb_valuearray[4] = 0x0c;
	priv->cck_txbbgain_table[15].ccktxbb_valuearray[5] = 0x08;
	priv->cck_txbbgain_table[15].ccktxbb_valuearray[6] = 0x04;
	priv->cck_txbbgain_table[15].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[16].ccktxbb_valuearray[0] = 0x16;
	priv->cck_txbbgain_table[16].ccktxbb_valuearray[1] = 0x15;
	priv->cck_txbbgain_table[16].ccktxbb_valuearray[2] = 0x12;
	priv->cck_txbbgain_table[16].ccktxbb_valuearray[3] = 0x0f;
	priv->cck_txbbgain_table[16].ccktxbb_valuearray[4] = 0x0b;
	priv->cck_txbbgain_table[16].ccktxbb_valuearray[5] = 0x07;
	priv->cck_txbbgain_table[16].ccktxbb_valuearray[6] = 0x04;
	priv->cck_txbbgain_table[16].ccktxbb_valuearray[7] = 0x01;

	priv->cck_txbbgain_table[17].ccktxbb_valuearray[0] = 0x14;
	priv->cck_txbbgain_table[17].ccktxbb_valuearray[1] = 0x14;
	priv->cck_txbbgain_table[17].ccktxbb_valuearray[2] = 0x11;
	priv->cck_txbbgain_table[17].ccktxbb_valuearray[3] = 0x0e;
	priv->cck_txbbgain_table[17].ccktxbb_valuearray[4] = 0x0b;
	priv->cck_txbbgain_table[17].ccktxbb_valuearray[5] = 0x07;
	priv->cck_txbbgain_table[17].ccktxbb_valuearray[6] = 0x03;
	priv->cck_txbbgain_table[17].ccktxbb_valuearray[7] = 0x02;

	priv->cck_txbbgain_table[18].ccktxbb_valuearray[0] = 0x13;
	priv->cck_txbbgain_table[18].ccktxbb_valuearray[1] = 0x13;
	priv->cck_txbbgain_table[18].ccktxbb_valuearray[2] = 0x10;
	priv->cck_txbbgain_table[18].ccktxbb_valuearray[3] = 0x0d;
	priv->cck_txbbgain_table[18].ccktxbb_valuearray[4] = 0x0a;
	priv->cck_txbbgain_table[18].ccktxbb_valuearray[5] = 0x06;
	priv->cck_txbbgain_table[18].ccktxbb_valuearray[6] = 0x03;
	priv->cck_txbbgain_table[18].ccktxbb_valuearray[7] = 0x01;

	priv->cck_txbbgain_table[19].ccktxbb_valuearray[0] = 0x12;
	priv->cck_txbbgain_table[19].ccktxbb_valuearray[1] = 0x12;
	priv->cck_txbbgain_table[19].ccktxbb_valuearray[2] = 0x0f;
	priv->cck_txbbgain_table[19].ccktxbb_valuearray[3] = 0x0c;
	priv->cck_txbbgain_table[19].ccktxbb_valuearray[4] = 0x09;
	priv->cck_txbbgain_table[19].ccktxbb_valuearray[5] = 0x06;
	priv->cck_txbbgain_table[19].ccktxbb_valuearray[6] = 0x03;
	priv->cck_txbbgain_table[19].ccktxbb_valuearray[7] = 0x01;

	priv->cck_txbbgain_table[20].ccktxbb_valuearray[0] = 0x11;
	priv->cck_txbbgain_table[20].ccktxbb_valuearray[1] = 0x11;
	priv->cck_txbbgain_table[20].ccktxbb_valuearray[2] = 0x0f;
	priv->cck_txbbgain_table[20].ccktxbb_valuearray[3] = 0x0c;
	priv->cck_txbbgain_table[20].ccktxbb_valuearray[4] = 0x09;
	priv->cck_txbbgain_table[20].ccktxbb_valuearray[5] = 0x06;
	priv->cck_txbbgain_table[20].ccktxbb_valuearray[6] = 0x03;
	priv->cck_txbbgain_table[20].ccktxbb_valuearray[7] = 0x01;

	priv->cck_txbbgain_table[21].ccktxbb_valuearray[0] = 0x10;
	priv->cck_txbbgain_table[21].ccktxbb_valuearray[1] = 0x10;
	priv->cck_txbbgain_table[21].ccktxbb_valuearray[2] = 0x0e;
	priv->cck_txbbgain_table[21].ccktxbb_valuearray[3] = 0x0b;
	priv->cck_txbbgain_table[21].ccktxbb_valuearray[4] = 0x08;
	priv->cck_txbbgain_table[21].ccktxbb_valuearray[5] = 0x05;
	priv->cck_txbbgain_table[21].ccktxbb_valuearray[6] = 0x03;
	priv->cck_txbbgain_table[21].ccktxbb_valuearray[7] = 0x01;

	priv->cck_txbbgain_table[22].ccktxbb_valuearray[0] = 0x0f;
	priv->cck_txbbgain_table[22].ccktxbb_valuearray[1] = 0x0f;
	priv->cck_txbbgain_table[22].ccktxbb_valuearray[2] = 0x0d;
	priv->cck_txbbgain_table[22].ccktxbb_valuearray[3] = 0x0b;
	priv->cck_txbbgain_table[22].ccktxbb_valuearray[4] = 0x08;
	priv->cck_txbbgain_table[22].ccktxbb_valuearray[5] = 0x05;
	priv->cck_txbbgain_table[22].ccktxbb_valuearray[6] = 0x03;
	priv->cck_txbbgain_table[22].ccktxbb_valuearray[7] = 0x01;
	
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[0] = 0x36;
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[1] = 0x35;
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[2] = 0x2e;
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[3] = 0x1b;
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[0].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[0] = 0x33;
	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[1] = 0x32;
	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[2] = 0x2b;
	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[3] = 0x19;
	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[1].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[0] = 0x30;
	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[1] = 0x2f;
	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[2] = 0x29;
	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[3] = 0x18;
	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[2].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[0] = 0x2d;
	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[1] = 0x2d;
	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[2] = 0x27;
	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[3] = 0x17;
	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[3].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[0] = 0x2b;
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[1] = 0x2a;
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[2] = 0x25;
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[3] = 0x15;
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[4].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[0] = 0x28;
	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[1] = 0x28;
	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[2] = 0x22;
	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[3] = 0x14;
	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[5].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[0] = 0x26;
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[1] = 0x25;
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[2] = 0x21;
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[3] = 0x13;
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[6].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[0] = 0x24;
	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[1] = 0x23;
	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[2] = 0x1f;
	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[3] = 0x12;
	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[7].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[0] = 0x22;
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[1] = 0x21;
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[2] = 0x1d;
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[3] = 0x11;
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[8].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[0] = 0x20;
	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[1] = 0x20;
	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[2] = 0x1b;
	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[3] = 0x10;
	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[9].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[0] = 0x1f;
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[1] = 0x1e;
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[2] = 0x1a;
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[3] = 0x0f;
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[10].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[0] = 0x1d;
	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[1] = 0x1c;
	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[2] = 0x18;
	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[3] = 0x0e;
	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[11].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[0] = 0x1b;
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[1] = 0x1a;
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[2] = 0x17;
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[3] = 0x0e;
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[12].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[0] = 0x1a;
	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[1] = 0x19;
	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[2] = 0x16;
	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[3] = 0x0d;
	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[13].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[0] = 0x18;
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[1] = 0x17;
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[2] = 0x15;
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[3] = 0x0c;
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[14].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[0] = 0x17;
	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[1] = 0x16;
	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[2] = 0x13;
	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[3] = 0x0b;
	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[15].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[0] = 0x16;
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[1] = 0x15;
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[2] = 0x12;
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[3] = 0x0b;
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[16].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[0] = 0x14;
	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[1] = 0x14;
	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[2] = 0x11;
	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[3] = 0x0a;
	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[17].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[0] = 0x13;
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[1] = 0x13;
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[2] = 0x10;
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[3] = 0x0a;
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[18].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[0] = 0x12;
	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[1] = 0x12;
	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[2] = 0x0f;
	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[3] = 0x09;
	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[19].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[0] = 0x11;
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[1] = 0x11;
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[2] = 0x0f;
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[3] = 0x09;
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[20].ccktxbb_valuearray[7] = 0x00;

	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[0] = 0x10;
	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[1] = 0x10;
	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[2] = 0x0e;
	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[3] = 0x08;
	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[21].ccktxbb_valuearray[7] = 0x00;
	
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[0] = 0x0f;
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[1] = 0x0f;
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[2] = 0x0d;
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[3] = 0x08;
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[4] = 0x00;
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[5] = 0x00;
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[6] = 0x00;
	priv->cck_txbbgain_ch14_table[22].ccktxbb_valuearray[7] = 0x00;

	priv->btxpower_tracking = true;
	priv->txpower_count       = 0;
	priv->btxpower_trackingInit = false;

}
#endif
#ifndef RTL8190P
static void dm_InitializeTXPowerTracking_ThermalMeter(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);

#ifdef RTL8192SE
		priv->btxpower_tracking = false;
		priv->txpower_count       = 0;
		priv->btxpower_trackingInit = false;
#else

	if(priv->rtllib->FwRWRF)
		priv->btxpower_tracking = true;
	else
		priv->btxpower_tracking = false;
	priv->txpower_count       = 0;
	priv->btxpower_trackingInit = false;
#endif
	RT_TRACE(COMP_POWER_TRACKING, "pMgntInfo->bTXPowerTracking = %d\n", priv->btxpower_tracking);
}
#endif

void dm_initialize_txpower_tracking(struct net_device *dev)
{
#ifdef RTL8192E
	struct r8192_priv *priv = rtllib_priv(dev);
#endif
#ifdef RTL8190P
	dm_InitializeTXPowerTracking_TSSI(dev);
#elif defined RTL8192E
	if(priv->IC_Cut >= IC_VersionCut_D)
		dm_InitializeTXPowerTracking_TSSI(dev);
	else
		dm_InitializeTXPowerTracking_ThermalMeter(dev);
#elif defined RTL8192SE
	dm_InitializeTXPowerTracking_ThermalMeter(dev);
#endif
}	

#if (defined RTL8192E || defined RTL8190P)
static void dm_CheckTXPowerTracking_TSSI(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	static u32 tx_power_track_counter = 0;
	RT_TRACE(COMP_POWER_TRACKING,"%s()\n",__FUNCTION__);
	if(read_nic_byte(dev, 0x11e) ==1)
		return;
	if(!priv->btxpower_tracking)
		return;
	tx_power_track_counter++;
	
	
	 if(tx_power_track_counter >= 180)	
	 	{
		queue_delayed_work_rsl(priv->priv_wq,&priv->txpower_tracking_wq,0);
		tx_power_track_counter =0;
	 	}
	
}	
#endif
#ifndef RTL8190P
static void dm_CheckTXPowerTracking_ThermalMeter(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	static u8 	TM_Trigger=0;
	u8		TxPowerCheckCnt = 0;

	if(IS_HARDWARE_TYPE_8192SE(dev))
		TxPowerCheckCnt = 5;	
	else
		TxPowerCheckCnt = 2;	
        if(!priv->btxpower_tracking){
            return;
        } else {
            if(priv->txpower_count  <= TxPowerCheckCnt) {
			priv->txpower_count++;
			return;
		}
	}	

	if(!TM_Trigger)
	{
#ifdef RTL8192SE
		if(IS_HARDWARE_TYPE_8192SE(dev))
		{
                    rtl8192_phy_SetRFReg(dev, RF90_PATH_A, RF_T_METER, bRFRegOffsetMask, 0x60);
                    RT_TRACE(COMP_POWER_TRACKING, "Trigger 92S Thermal Meter!!\n");
                }
                else
#endif
                {
		rtl8192_phy_SetRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits, 0x4d);
		rtl8192_phy_SetRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits, 0x4f);
		rtl8192_phy_SetRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits, 0x4d);
		rtl8192_phy_SetRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits, 0x4f);
                }
		TM_Trigger = 1;
		return;
	} else {
            printk("===============>Schedule TxPowerTrackingWorkItem\n");
#ifdef RTL8192SE
		DM_TXPowerTracking92SDirectCall(dev); 
#else

		queue_delayed_work_rsl(priv->priv_wq,&priv->txpower_tracking_wq,0);
#endif
		TM_Trigger = 0;
		}

	}	
#endif

#ifdef RTL8192SE
void DM_TXPowerTracking92SDirectCall(struct net_device *dev)
{	
	dm_TXPowerTrackingCallback_ThermalMeter(dev);
	}	
#endif

static void dm_check_txpower_tracking(struct net_device *dev)
{
#ifdef RTL8192E
	struct r8192_priv *priv = rtllib_priv(dev);
#endif	
#ifdef  RTL8190P
	dm_CheckTXPowerTracking_TSSI(dev);
#elif defined RTL8192E
	if(priv->IC_Cut >= IC_VersionCut_D)
		dm_CheckTXPowerTracking_TSSI(dev);
	else
		dm_CheckTXPowerTracking_ThermalMeter(dev);
#elif defined RTL8192SE
	dm_CheckTXPowerTracking_ThermalMeter(dev);
#endif
	
}	

#ifndef RTL8192SE
static void dm_CCKTxPowerAdjust_TSSI(struct net_device *dev, bool  bInCH14)
{
	u32 TempVal;
	struct r8192_priv *priv = rtllib_priv(dev);
	TempVal = 0;
	if(!bInCH14){
		TempVal = 	(u32)(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[0] +
					(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[1]<<8)) ;
	
		rtl8192_setBBreg(dev, rCCK0_TxFilter1,bMaskHWord, TempVal);
		TempVal = 0;
		TempVal = 	(u32)(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[2] +
					(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[3]<<8) +
					(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[4]<<16 )+
					(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[5]<<24));
		rtl8192_setBBreg(dev, rCCK0_TxFilter2,bMaskDWord, TempVal);
		TempVal = 0;
		TempVal = 	(u32)(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[6] +
					(priv->cck_txbbgain_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[7]<<8)) ;
		
		rtl8192_setBBreg(dev, rCCK0_DebugPort,bMaskLWord, TempVal);
	}
	else
	{
		TempVal = 	(u32)(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[0] +
					(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[1]<<8)) ;
	
		rtl8192_setBBreg(dev, rCCK0_TxFilter1,bMaskHWord, TempVal);
		TempVal = 0;
		TempVal = 	(u32)(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[2] +
					(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[3]<<8) +
					(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[4]<<16 )+
					(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[5]<<24));
		rtl8192_setBBreg(dev, rCCK0_TxFilter2,bMaskDWord, TempVal);
		TempVal = 0;
		TempVal = 	(u32)(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[6] +
					(priv->cck_txbbgain_ch14_table[(u8)(priv->CCKPresentAttentuation)].ccktxbb_valuearray[7]<<8)) ;
		
		rtl8192_setBBreg(dev, rCCK0_DebugPort,bMaskLWord, TempVal);
	}
		
	
}
#endif
#ifdef RTL8192E
static void dm_CCKTxPowerAdjust_ThermalMeter(struct net_device *dev,	bool  bInCH14)
{
	u32 TempVal;
	struct r8192_priv *priv = rtllib_priv(dev);

	TempVal = 0;
	if(!bInCH14)
	{
		TempVal = 	CCKSwingTable_Ch1_Ch13[priv->CCK_index][0] +
					(CCKSwingTable_Ch1_Ch13[priv->CCK_index][1]<<8) ;
		rtl8192_setBBreg(dev, rCCK0_TxFilter1, bMaskHWord, TempVal);
		RT_TRACE(COMP_POWER_TRACKING, "CCK not chnl 14, reg 0x%x = 0x%x\n", 
			rCCK0_TxFilter1, TempVal);
		TempVal = 0;
		TempVal = 	CCKSwingTable_Ch1_Ch13[priv->CCK_index][2] +
					(CCKSwingTable_Ch1_Ch13[priv->CCK_index][3]<<8) +
					(CCKSwingTable_Ch1_Ch13[priv->CCK_index][4]<<16 )+
					(CCKSwingTable_Ch1_Ch13[priv->CCK_index][5]<<24);
		rtl8192_setBBreg(dev, rCCK0_TxFilter2, bMaskDWord, TempVal);
		RT_TRACE(COMP_POWER_TRACKING, "CCK not chnl 14, reg 0x%x = 0x%x\n", 
			rCCK0_TxFilter2, TempVal);
		TempVal = 0;
		TempVal = 	CCKSwingTable_Ch1_Ch13[priv->CCK_index][6] +
					(CCKSwingTable_Ch1_Ch13[priv->CCK_index][7]<<8) ;
		
		rtl8192_setBBreg(dev, rCCK0_DebugPort, bMaskLWord, TempVal);
		RT_TRACE(COMP_POWER_TRACKING, "CCK not chnl 14, reg 0x%x = 0x%x\n", 
			rCCK0_DebugPort, TempVal);
	}
	else
	{
		TempVal = 	CCKSwingTable_Ch14[priv->CCK_index][0] +
					(CCKSwingTable_Ch14[priv->CCK_index][1]<<8) ;

		rtl8192_setBBreg(dev, rCCK0_TxFilter1, bMaskHWord, TempVal);
		RT_TRACE(COMP_POWER_TRACKING, "CCK chnl 14, reg 0x%x = 0x%x\n", 
			rCCK0_TxFilter1, TempVal);
		TempVal = 0;
		TempVal = 	CCKSwingTable_Ch14[priv->CCK_index][2] +
					(CCKSwingTable_Ch14[priv->CCK_index][3]<<8) +
					(CCKSwingTable_Ch14[priv->CCK_index][4]<<16 )+
					(CCKSwingTable_Ch14[priv->CCK_index][5]<<24);
		rtl8192_setBBreg(dev, rCCK0_TxFilter2, bMaskDWord, TempVal);
		RT_TRACE(COMP_POWER_TRACKING, "CCK chnl 14, reg 0x%x = 0x%x\n", 
			rCCK0_TxFilter2, TempVal);
		TempVal = 0;
		TempVal = 	CCKSwingTable_Ch14[priv->CCK_index][6] +
					(CCKSwingTable_Ch14[priv->CCK_index][7]<<8) ;

		rtl8192_setBBreg(dev, rCCK0_DebugPort, bMaskLWord, TempVal);
		RT_TRACE(COMP_POWER_TRACKING,"CCK chnl 14, reg 0x%x = 0x%x\n", 
			rCCK0_DebugPort, TempVal);
	}
	}
#endif
	
#ifndef RTL8192SE
extern void dm_cck_txpower_adjust(
	struct net_device *dev,
	bool  binch14
)
{	
#ifndef RTL8190P
	struct r8192_priv *priv = rtllib_priv(dev);
#endif
#ifdef RTL8190P
	dm_CCKTxPowerAdjust_TSSI(dev, binch14);
#else
	if(priv->IC_Cut >= IC_VersionCut_D)
		dm_CCKTxPowerAdjust_TSSI(dev, binch14);
	else
		dm_CCKTxPowerAdjust_ThermalMeter(dev, binch14);
#endif
}
#endif


#if defined(RTL8192E)||defined(RTL8190P)
static void dm_txpower_reset_recovery(
	struct net_device *dev
)
{
	struct r8192_priv *priv = rtllib_priv(dev);

	RT_TRACE(COMP_POWER_TRACKING, "Start Reset Recovery ==>\n");
	rtl8192_setBBreg(dev, rOFDM0_XATxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfa_txpowertrackingindex].txbbgain_value);
	RT_TRACE(COMP_POWER_TRACKING, "Reset Recovery: Fill in 0xc80 is %08x\n",priv->txbbgain_table[priv->rfa_txpowertrackingindex].txbbgain_value);
	RT_TRACE(COMP_POWER_TRACKING, "Reset Recovery: Fill in RFA_txPowerTrackingIndex is %x\n",priv->rfa_txpowertrackingindex);
	RT_TRACE(COMP_POWER_TRACKING, "Reset Recovery : RF A I/Q Amplify Gain is %ld\n",priv->txbbgain_table[priv->rfa_txpowertrackingindex].txbb_iq_amplifygain);
	RT_TRACE(COMP_POWER_TRACKING, "Reset Recovery: CCK Attenuation is %d dB\n",priv->CCKPresentAttentuation);
	dm_cck_txpower_adjust(dev,priv->bcck_in_ch14);		

	rtl8192_setBBreg(dev, rOFDM0_XCTxIQImbalance, bMaskDWord, priv->txbbgain_table[priv->rfc_txpowertrackingindex].txbbgain_value);
	RT_TRACE(COMP_POWER_TRACKING, "Reset Recovery: Fill in 0xc90 is %08x\n",priv->txbbgain_table[priv->rfc_txpowertrackingindex].txbbgain_value);
	RT_TRACE(COMP_POWER_TRACKING, "Reset Recovery: Fill in RFC_txPowerTrackingIndex is %x\n",priv->rfc_txpowertrackingindex);
	RT_TRACE(COMP_POWER_TRACKING, "Reset Recovery : RF C I/Q Amplify Gain is %ld\n",priv->txbbgain_table[priv->rfc_txpowertrackingindex].txbb_iq_amplifygain);

}	

extern void dm_restore_dynamic_mechanism_state(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u32 	reg_ratr = priv->rate_adaptive.last_ratr;

	if(IS_NIC_DOWN(priv)){
		RT_TRACE(COMP_RATE, "<---- dm_restore_dynamic_mechanism_state(): driver is going to unload\n");
		return;
	}

	if(priv->rate_adaptive.rate_adaptive_disabled)
		return;
	if( !(priv->rtllib->mode==WIRELESS_MODE_N_24G ||
		 priv->rtllib->mode==WIRELESS_MODE_N_5G))
		 return;
	{
			u32 ratr_value;
			ratr_value = reg_ratr;
			if(priv->rf_type == RF_1T2R)	
			{
				ratr_value &=~ (RATE_ALL_OFDM_2SS);
			}
			write_nic_dword(dev, RATR0, ratr_value);
			write_nic_byte(dev, UFWP, 1);
#if 0		
			u1Byte index;
			u4Byte input_value;
			index = (u1Byte)((((pu4Byte)(val))[0]) >> 28);
			input_value = (((pu4Byte)(val))[0]) & 0x0fffffff;
			PlatformEFIOWrite4Byte(dev, RATR0+index*4, input_value);
#endif		
	}
	if(priv->btxpower_trackingInit && priv->btxpower_tracking){
		dm_txpower_reset_recovery(dev);	
	}

	dm_bb_initialgain_restore(dev);
	
}	

static void dm_bb_initialgain_restore(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u32 bit_mask = 0x7f; 
	
	if(dm_digtable.dig_algorithm == DIG_ALGO_BY_RSSI)
		return;

	rtl8192_setBBreg(dev, UFWP, bMaskByte1, 0x8);	
	rtl8192_setBBreg(dev, rOFDM0_XAAGCCore1, bit_mask, (u32)priv->initgain_backup.xaagccore1);
	rtl8192_setBBreg(dev, rOFDM0_XBAGCCore1, bit_mask, (u32)priv->initgain_backup.xbagccore1);
	rtl8192_setBBreg(dev, rOFDM0_XCAGCCore1, bit_mask, (u32)priv->initgain_backup.xcagccore1);
	rtl8192_setBBreg(dev, rOFDM0_XDAGCCore1, bit_mask, (u32)priv->initgain_backup.xdagccore1);
	bit_mask  = bMaskByte2;
	rtl8192_setBBreg(dev, rCCK0_CCA, bit_mask, (u32)priv->initgain_backup.cca);

	RT_TRACE(COMP_DIG, "dm_BBInitialGainRestore 0xc50 is %x\n",priv->initgain_backup.xaagccore1);
	RT_TRACE(COMP_DIG, "dm_BBInitialGainRestore 0xc58 is %x\n",priv->initgain_backup.xbagccore1);
	RT_TRACE(COMP_DIG, "dm_BBInitialGainRestore 0xc60 is %x\n",priv->initgain_backup.xcagccore1);
	RT_TRACE(COMP_DIG, "dm_BBInitialGainRestore 0xc68 is %x\n",priv->initgain_backup.xdagccore1);
	RT_TRACE(COMP_DIG, "dm_BBInitialGainRestore 0xa0a is %x\n",priv->initgain_backup.cca);
	rtl8192_setBBreg(dev, UFWP, bMaskByte1, 0x1);	
	
}	


extern void dm_backup_dynamic_mechanism_state(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);

	priv->bswitch_fsync  = false;	
	priv->bfsync_processing = false;
	dm_bb_initialgain_backup(dev);
	
}	


static void dm_bb_initialgain_backup(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u32 bit_mask = bMaskByte0; 

	if(dm_digtable.dig_algorithm == DIG_ALGO_BY_RSSI)
		return;

	rtl8192_setBBreg(dev, UFWP, bMaskByte1, 0x8);	
	priv->initgain_backup.xaagccore1 = (u8)rtl8192_QueryBBReg(dev, rOFDM0_XAAGCCore1, bit_mask);
	priv->initgain_backup.xbagccore1 = (u8)rtl8192_QueryBBReg(dev, rOFDM0_XBAGCCore1, bit_mask);
	priv->initgain_backup.xcagccore1 = (u8)rtl8192_QueryBBReg(dev, rOFDM0_XCAGCCore1, bit_mask);
	priv->initgain_backup.xdagccore1 = (u8)rtl8192_QueryBBReg(dev, rOFDM0_XDAGCCore1, bit_mask);
	bit_mask  = bMaskByte2;
	priv->initgain_backup.cca = (u8)rtl8192_QueryBBReg(dev, rCCK0_CCA, bit_mask);

	RT_TRACE(COMP_DIG, "BBInitialGainBackup 0xc50 is %x\n",priv->initgain_backup.xaagccore1);
	RT_TRACE(COMP_DIG, "BBInitialGainBackup 0xc58 is %x\n",priv->initgain_backup.xbagccore1);
	RT_TRACE(COMP_DIG, "BBInitialGainBackup 0xc60 is %x\n",priv->initgain_backup.xcagccore1);
	RT_TRACE(COMP_DIG, "BBInitialGainBackup 0xc68 is %x\n",priv->initgain_backup.xdagccore1);
	RT_TRACE(COMP_DIG, "BBInitialGainBackup 0xa0a is %x\n",priv->initgain_backup.cca);

}   

#endif
extern void dm_change_dynamic_initgain_thresh(struct net_device *dev,
								u32		dm_type,
								u32		dm_value)
{
#ifdef RTL8192SE
	struct r8192_priv *priv = rtllib_priv(dev);
	if(dm_type == DIG_TYPE_THRESH_HIGHPWR_HIGH)
		priv->MidHighPwrTHR_L2 = (u8)dm_value;
	else if(dm_type == DIG_TYPE_THRESH_HIGHPWR_LOW)
		priv->MidHighPwrTHR_L1 = (u8)dm_value;
	return;
#endif
	if (dm_type == DIG_TYPE_THRESH_HIGH)
	{
		dm_digtable.rssi_high_thresh = dm_value;		
	}
	else if (dm_type == DIG_TYPE_THRESH_LOW)
	{
		dm_digtable.rssi_low_thresh = dm_value;
	}
	else if (dm_type == DIG_TYPE_THRESH_HIGHPWR_HIGH)
	{
		dm_digtable.rssi_high_power_highthresh = dm_value;
	}
	else if (dm_type == DIG_TYPE_THRESH_HIGHPWR_HIGH)
	{
		dm_digtable.rssi_high_power_highthresh = dm_value;
	}
	else if (dm_type == DIG_TYPE_ENABLE)
	{
		dm_digtable.dig_state		= DM_STA_DIG_MAX;
		dm_digtable.dig_enable_flag	= true;
	}
	else if (dm_type == DIG_TYPE_DISABLE)
	{
		dm_digtable.dig_state		= DM_STA_DIG_MAX;
		dm_digtable.dig_enable_flag	= false;
	}
	else if (dm_type == DIG_TYPE_DBG_MODE)
	{
		if(dm_value >= DM_DBG_MAX)
			dm_value = DM_DBG_OFF;
		dm_digtable.dbg_mode		= (u8)dm_value;
	}
	else if (dm_type == DIG_TYPE_RSSI)
	{
		if(dm_value > 100)
			dm_value = 30;
		dm_digtable.rssi_val			= (long)dm_value;
	}
	else if (dm_type == DIG_TYPE_ALGORITHM)
	{
		if (dm_value >= DIG_ALGO_MAX)
			dm_value = DIG_ALGO_BY_FALSE_ALARM;
		if(dm_digtable.dig_algorithm != (u8)dm_value)
			dm_digtable.dig_algorithm_switch = 1;
		dm_digtable.dig_algorithm	= (u8)dm_value;
	}
	else if (dm_type == DIG_TYPE_BACKOFF)
	{
		if(dm_value > 30)
			dm_value = 30;
		dm_digtable.backoff_val		= (u8)dm_value;
	}
	else if(dm_type == DIG_TYPE_RX_GAIN_MIN)
	{
		if(dm_value == 0)
			dm_value = 0x1;
		dm_digtable.rx_gain_range_min = (u8)dm_value;
	}
	else if(dm_type == DIG_TYPE_RX_GAIN_MAX)
	{
		if(dm_value > 0x50)
			dm_value = 0x50;
		dm_digtable.rx_gain_range_max = (u8)dm_value;
	}
}	
extern	void	
dm_change_fsync_setting(
	struct net_device *dev,
	s32		DM_Type,
	s32		DM_Value)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	
	if (DM_Type == 0)	
	{
		if(DM_Value > 1)
			DM_Value = 1;
		priv->framesyncMonitor = (u8)DM_Value;
	}
}

extern void	
dm_change_rxpath_selection_setting(	
	struct net_device *dev,
	s32		DM_Type,
	s32		DM_Value)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	prate_adaptive 	pRA = (prate_adaptive)&(priv->rate_adaptive);


	if(DM_Type == 0)	
	{
		if(DM_Value > 1)
			DM_Value = 1;
		DM_RxPathSelTable.Enable = (u8)DM_Value;
	}
	else if(DM_Type == 1)
	{
		if(DM_Value > 1)
			DM_Value = 1;
		DM_RxPathSelTable.DbgMode = (u8)DM_Value;
	}
	else if(DM_Type == 2)
	{
		if(DM_Value > 40)
			DM_Value = 40;
		DM_RxPathSelTable.SS_TH_low = (u8)DM_Value;
	}
	else if(DM_Type == 3)
	{
		if(DM_Value > 25)
			DM_Value = 25;
		DM_RxPathSelTable.diff_TH = (u8)DM_Value;
	}
	else if(DM_Type == 4)
	{
		if(DM_Value >= CCK_Rx_Version_MAX)
			DM_Value = CCK_Rx_Version_1;
		DM_RxPathSelTable.cck_method= (u8)DM_Value;
	}
	else if(DM_Type == 10)
	{
		if(DM_Value > 100)
			DM_Value = 50;
		DM_RxPathSelTable.rf_rssi[0] = (u8)DM_Value;
	}
	else if(DM_Type == 11)
	{
		if(DM_Value > 100)
			DM_Value = 50;
		DM_RxPathSelTable.rf_rssi[1] = (u8)DM_Value;
	}
	else if(DM_Type == 12)
	{
		if(DM_Value > 100)
			DM_Value = 50;
		DM_RxPathSelTable.rf_rssi[2] = (u8)DM_Value;
	}
	else if(DM_Type == 13)
	{
		if(DM_Value > 100)
			DM_Value = 50;
		DM_RxPathSelTable.rf_rssi[3] = (u8)DM_Value;
	}
	else if(DM_Type == 20)
	{
		if(DM_Value > 1)
			DM_Value = 1;
		pRA->ping_rssi_enable = (u8)DM_Value;
	}
	else if(DM_Type == 21)
	{
		if(DM_Value > 30)
			DM_Value = 30;
		pRA->ping_rssi_thresh_for_ra = DM_Value;
	}
}

#if 0
extern void dm_force_tx_fw_info(struct net_device *dev,
										u32		force_type,
										u32		force_value)
{
	struct r8192_priv *priv = rtllib_priv(dev);

	if (force_type == 0)	
	{
		priv->tx_fwinfo_force_subcarriermode = 0;
	}
	else if(force_type == 1) 
	{
		priv->tx_fwinfo_force_subcarriermode = 1;
		if(force_value > 3)
			force_value = 3;
		priv->tx_fwinfo_force_subcarrierval = (u8)force_value;
	}
}
#endif

static void dm_dig_init(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	dm_digtable.dig_enable_flag	= true;
	dm_digtable.Backoff_Enable_Flag = true;

#ifdef RTL8192SE
	if((priv->DM_Type  == DM_Type_ByDriver) && (priv->pFirmware->FirmwareVersion >= 0x3c))
		dm_digtable.dig_algorithm = DIG_ALGO_BY_TOW_PORT;
	else
		dm_digtable.dig_algorithm = DIG_ALGO_BEFORE_CONNECT_BY_RSSI_AND_ALARM;
#else	
	dm_digtable.dig_algorithm = DIG_ALGO_BY_RSSI;
#endif

	dm_digtable.Dig_TwoPort_Algorithm = DIG_TWO_PORT_ALGO_RSSI;
	dm_digtable.Dig_Ext_Port_Stage = DIG_EXT_PORT_STAGE_MAX;
	dm_digtable.dbg_mode = DM_DBG_OFF;	
	dm_digtable.dig_algorithm_switch = 0;
	
	dm_digtable.dig_state		= DM_STA_DIG_MAX;
	dm_digtable.dig_highpwr_state	= DM_STA_DIG_MAX;
	dm_digtable.CurSTAConnectState = dm_digtable.PreSTAConnectState = DIG_STA_DISCONNECT;
	dm_digtable.CurAPConnectState = dm_digtable.PreAPConnectState = DIG_AP_DISCONNECT;
	dm_digtable.initialgain_lowerbound_state = false;

	dm_digtable.rssi_low_thresh 	= DM_DIG_THRESH_LOW;
	dm_digtable.rssi_high_thresh 	= DM_DIG_THRESH_HIGH;

	dm_digtable.FALowThresh	= DM_FALSEALARM_THRESH_LOW;
	dm_digtable.FAHighThresh	= DM_FALSEALARM_THRESH_HIGH;
	
	dm_digtable.rssi_high_power_lowthresh = DM_DIG_HIGH_PWR_THRESH_LOW;
	dm_digtable.rssi_high_power_highthresh = DM_DIG_HIGH_PWR_THRESH_HIGH;
	
	dm_digtable.rssi_val = 50;	
	dm_digtable.backoff_val = DM_DIG_BACKOFF;
	dm_digtable.rx_gain_range_max = DM_DIG_MAX;
	if(priv->CustomerID == RT_CID_819x_Netcore)
		dm_digtable.rx_gain_range_min = DM_DIG_MIN_Netcore;	
	else
		dm_digtable.rx_gain_range_min = DM_DIG_MIN;
	
	dm_digtable.BackoffVal_range_max = DM_DIG_BACKOFF_MAX;
	dm_digtable.BackoffVal_range_min = DM_DIG_BACKOFF_MIN;
}	

void dm_FalseAlarmCounterStatistics(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u32 ret_value;
	PFALSE_ALARM_STATISTICS FalseAlmCnt = &(priv->FalseAlmCnt);
	
	ret_value = rtl8192_QueryBBReg(dev, rOFDM_PHYCounter1, bMaskDWord);
        FalseAlmCnt->Cnt_Parity_Fail = ((ret_value&0xffff0000)>>16);	

        ret_value = rtl8192_QueryBBReg(dev, rOFDM_PHYCounter2, bMaskDWord);
	FalseAlmCnt->Cnt_Rate_Illegal = (ret_value&0xffff);
	FalseAlmCnt->Cnt_Crc8_fail = ((ret_value&0xffff0000)>>16);
	ret_value = rtl8192_QueryBBReg(dev, rOFDM_PHYCounter3, bMaskDWord);
	FalseAlmCnt->Cnt_Mcs_fail = (ret_value&0xffff);

	FalseAlmCnt->Cnt_Ofdm_fail = FalseAlmCnt->Cnt_Parity_Fail + FalseAlmCnt->Cnt_Rate_Illegal +
							  FalseAlmCnt->Cnt_Crc8_fail + FalseAlmCnt->Cnt_Mcs_fail;

	ret_value = rtl8192_QueryBBReg(dev, 0xc64, bMaskDWord);	
	FalseAlmCnt->Cnt_Cck_fail = (ret_value&0xffff);
	FalseAlmCnt->Cnt_all = (FalseAlmCnt->Cnt_Parity_Fail +
						FalseAlmCnt->Cnt_Rate_Illegal +
						FalseAlmCnt->Cnt_Crc8_fail +
						FalseAlmCnt->Cnt_Mcs_fail +
						FalseAlmCnt->Cnt_Cck_fail);	

	RT_TRACE(COMP_DIG, "Cnt_Ofdm_fail = %d, Cnt_Cck_fail = %d, Cnt_all = %d\n", 
				FalseAlmCnt->Cnt_Ofdm_fail, FalseAlmCnt->Cnt_Cck_fail , FalseAlmCnt->Cnt_all);		
}

#ifdef RTL8192SE
static void dm_CtrlInitGainAPByFalseAlarm(struct net_device *dev)
{
	static u8		binitialized = false;

	{
		binitialized = false;
		dm_digtable.Dig_Ext_Port_Stage = DIG_EXT_PORT_STAGE_MAX;
		return;
	}	
}
#endif

static void dm_ctrl_initgain_byrssi(struct net_device *dev)
{
	
	if (dm_digtable.dig_enable_flag == false)
		return;

	if(dm_digtable.dig_algorithm == DIG_ALGO_BY_FALSE_ALARM)
		dm_ctrl_initgain_byrssi_by_fwfalse_alarm(dev);
	else if(dm_digtable.dig_algorithm == DIG_ALGO_BY_RSSI)
		dm_ctrl_initgain_byrssi_by_driverrssi(dev);
#ifdef RTL8192SE
	else if(dm_digtable.dig_algorithm == DIG_ALGO_BEFORE_CONNECT_BY_RSSI_AND_ALARM)
		dm_CtrlInitGainBeforeConnectByRssiAndFalseAlarm(dev);
	else if(dm_digtable.dig_algorithm == DIG_ALGO_BY_TOW_PORT)
		dm_CtrlInitGainByTwoPort(dev);
#endif
	else
		return;
}

#ifdef RTL8192SE
static void dm_CtrlInitGainByTwoPort(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	
	if(rtllib_act_scanning(priv->rtllib,true) == true)
		return;

	if((priv->rtllib->state > RTLLIB_NOLINK) && (priv->rtllib->state < RTLLIB_LINKED))
		dm_digtable.CurSTAConnectState = DIG_STA_BEFORE_CONNECT;
	else if((priv->rtllib->state == RTLLIB_LINKED) ||(priv->rtllib->state == RTLLIB_LINKED_SCANNING))
		dm_digtable.CurSTAConnectState = DIG_STA_CONNECT;
	else
		dm_digtable.CurSTAConnectState = DIG_STA_DISCONNECT;

	dm_digtable.rssi_val = priv->undecorated_smoothed_pwdb;	
	
	if(dm_digtable.CurSTAConnectState != DIG_STA_DISCONNECT)
	{	
		if(dm_digtable.Dig_TwoPort_Algorithm == DIG_TWO_PORT_ALGO_FALSE_ALARM)
		{
			dm_digtable.Dig_TwoPort_Algorithm = DIG_TWO_PORT_ALGO_RSSI;
			priv->rtllib->SetFwCmdHandler(dev, FW_CMD_DIG_MODE_SS);
		}
	}	
	
	dm_FalseAlarmCounterStatistics(dev);
	dm_initial_gain_STABeforeConnect(dev);	
	dm_CtrlInitGainAPByFalseAlarm(dev);
	
	dm_digtable.PreSTAConnectState = dm_digtable.CurSTAConnectState;
}
#endif

/*-----------------------------------------------------------------------------
 * Function:	dm_CtrlInitGainBeforeConnectByRssiAndFalseAlarm()
 *
 * Overview:	Driver monitor RSSI and False Alarm to change initial gain.
 			Only change initial gain during link in progress.
 *
 * Input:		IN	PADAPTER	pAdapter
 *
 * Output:		NONE
 *
 * Return:		NONE
 *
 * Revised History:
 *	When		Who		Remark
 *	03/04/2009	hpfan	Create Version 0.  
 *
 *---------------------------------------------------------------------------*/
 
#ifdef RTL8192SE
static void dm_CtrlInitGainBeforeConnectByRssiAndFalseAlarm(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);

	if(rtllib_act_scanning(priv->rtllib,true) == true)
		return;

	if((priv->rtllib->state > RTLLIB_NOLINK) && (priv->rtllib->state < RTLLIB_LINKED))
		dm_digtable.CurSTAConnectState = DIG_STA_BEFORE_CONNECT;
	else if((priv->rtllib->state == RTLLIB_LINKED) ||(priv->rtllib->state == RTLLIB_LINKED_SCANNING))
		dm_digtable.CurSTAConnectState = DIG_STA_CONNECT;
	else
		dm_digtable.CurSTAConnectState = DIG_STA_DISCONNECT;

	if(dm_digtable.dbg_mode == DM_DBG_OFF)
		dm_digtable.rssi_val = priv->undecorated_smoothed_pwdb;

	dm_FalseAlarmCounterStatistics(dev);
	dm_initial_gain_STABeforeConnect(dev);
	dm_digtable.PreSTAConnectState = dm_digtable.CurSTAConnectState;

}
#endif
static void dm_ctrl_initgain_byrssi_by_driverrssi(
	struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u8 i;
	static u8 	fw_dig=0;
	
	if (dm_digtable.dig_enable_flag == false)
		return;

	if(dm_digtable.dig_algorithm_switch)	
		fw_dig = 0;
	if(fw_dig <= 3)	
	{
		for(i=0; i<3; i++)
			rtl8192_setBBreg(dev, UFWP, bMaskByte1, 0x8);	
		fw_dig++;
		dm_digtable.dig_state = DM_STA_DIG_OFF;	
	}
		
	if(priv->rtllib->state == RTLLIB_LINKED)
		dm_digtable.CurSTAConnectState = DIG_STA_CONNECT;
	else
		dm_digtable.CurSTAConnectState = DIG_STA_DISCONNECT;


	if(dm_digtable.dbg_mode == DM_DBG_OFF)
		dm_digtable.rssi_val = priv->undecorated_smoothed_pwdb;
	dm_initial_gain(dev);
	dm_pd_th(dev);
	dm_cs_ratio(dev);
	if(dm_digtable.dig_algorithm_switch)
		dm_digtable.dig_algorithm_switch = 0;
	dm_digtable.PreSTAConnectState = dm_digtable.CurSTAConnectState;

}	

static void dm_ctrl_initgain_byrssi_by_fwfalse_alarm(
	struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	static u32 reset_cnt = 0;
	u8 i;
	
	if (dm_digtable.dig_enable_flag == false)
		return;

	if(dm_digtable.dig_algorithm_switch)
	{
		dm_digtable.dig_state = DM_STA_DIG_MAX;
		for(i=0; i<3; i++)
			rtl8192_setBBreg(dev, UFWP, bMaskByte1, 0x1);	
		dm_digtable.dig_algorithm_switch = 0;
	}
		
	if (priv->rtllib->state != RTLLIB_LINKED)
		return;

	if ((priv->undecorated_smoothed_pwdb > dm_digtable.rssi_low_thresh) &&
		(priv->undecorated_smoothed_pwdb < dm_digtable.rssi_high_thresh))
	{
		return;
	}
	if ((priv->undecorated_smoothed_pwdb <= dm_digtable.rssi_low_thresh))
	{		
		if (dm_digtable.dig_state == DM_STA_DIG_OFF && 
			(priv->reset_count == reset_cnt))
		{			
			return;
		}
		else
		{
			reset_cnt = priv->reset_count;
		}
		
		dm_digtable.dig_highpwr_state = DM_STA_DIG_MAX;
		dm_digtable.dig_state = DM_STA_DIG_OFF;

		rtl8192_setBBreg(dev, UFWP, bMaskByte1, 0x8);	

		write_nic_byte(dev, rOFDM0_XAAGCCore1, 0x17);
		write_nic_byte(dev, rOFDM0_XBAGCCore1, 0x17);
		write_nic_byte(dev, rOFDM0_XCAGCCore1, 0x17);
		write_nic_byte(dev, rOFDM0_XDAGCCore1, 0x17);

		if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
		{
			#ifdef RTL8190P
			write_nic_byte(dev, rOFDM0_RxDetector1, 0x40);
			#else 
				write_nic_byte(dev, (rOFDM0_XATxAFE+3), 0x00);
				#endif
			/*else if (priv->card_8192 == HARDWARE_TYPE_RTL8190P)
				write_nic_byte(pAdapter, rOFDM0_RxDetector1, 0x40);
			*/
			
				
		}
		else
			write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);

		write_nic_byte(dev, 0xa0a, 0x08);
		
		return;
		
	}
	
	if ((priv->undecorated_smoothed_pwdb >= dm_digtable.rssi_high_thresh) )
	{
		u8 reset_flag = 0;
		
		if (dm_digtable.dig_state == DM_STA_DIG_ON && 
			(priv->reset_count == reset_cnt))
		{
			dm_ctrl_initgain_byrssi_highpwr(dev);
			return;
		}
		else
		{
			if (priv->reset_count != reset_cnt)
				reset_flag = 1;

			reset_cnt = priv->reset_count;
		}
		
		dm_digtable.dig_state = DM_STA_DIG_ON;
		
		if (reset_flag == 1)
		{
			write_nic_byte(dev, rOFDM0_XAAGCCore1, 0x2c);
			write_nic_byte(dev, rOFDM0_XBAGCCore1, 0x2c);
			write_nic_byte(dev, rOFDM0_XCAGCCore1, 0x2c);
			write_nic_byte(dev, rOFDM0_XDAGCCore1, 0x2c);
		}
		else
		{
		write_nic_byte(dev, rOFDM0_XAAGCCore1, 0x20);
		write_nic_byte(dev, rOFDM0_XBAGCCore1, 0x20);
		write_nic_byte(dev, rOFDM0_XCAGCCore1, 0x20);
		write_nic_byte(dev, rOFDM0_XDAGCCore1, 0x20);
		}

		if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
		{
			#ifdef RTL8190P
			write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);
			#else
				write_nic_byte(dev, (rOFDM0_XATxAFE+3), 0x20);
				#endif
			/*
			else if (priv->card_8192 == HARDWARE_TYPE_RTL8190P)
				write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);
			*/
			
		}
		else
			write_nic_byte(dev, rOFDM0_RxDetector1, 0x44);

		write_nic_byte(dev, 0xa0a, 0xcd);

		
		rtl8192_setBBreg(dev, UFWP, bMaskByte1, 0x1);	
		
	}

	dm_ctrl_initgain_byrssi_highpwr(dev);

}	


static void dm_ctrl_initgain_byrssi_highpwr(
	struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	static u32 reset_cnt_highpwr = 0;
	
	if ((priv->undecorated_smoothed_pwdb > dm_digtable.rssi_high_power_lowthresh) &&
		(priv->undecorated_smoothed_pwdb < dm_digtable.rssi_high_power_highthresh))
	{
		return;
	}
	
	if (priv->undecorated_smoothed_pwdb >= dm_digtable.rssi_high_power_highthresh) 
	{
		if (dm_digtable.dig_highpwr_state == DM_STA_DIG_ON && 
			(priv->reset_count == reset_cnt_highpwr))
			return;
		else
			dm_digtable.dig_highpwr_state = DM_STA_DIG_ON;

		if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
		{			
			#ifdef RTL8190P
			write_nic_byte(dev, rOFDM0_RxDetector1, 0x41);
			#else
				write_nic_byte(dev, (rOFDM0_XATxAFE+3), 0x10);
				#endif
			
			/*else if (priv->card_8192 == HARDWARE_TYPE_RTL8190P)
				write_nic_byte(dev, rOFDM0_RxDetector1, 0x41);
			*/

		}
		else
			write_nic_byte(dev, rOFDM0_RxDetector1, 0x43);
	}
	else
	{
		if (dm_digtable.dig_highpwr_state == DM_STA_DIG_OFF&& 
			(priv->reset_count == reset_cnt_highpwr))		
			return;
		else
			dm_digtable.dig_highpwr_state = DM_STA_DIG_OFF;
		
		if (priv->undecorated_smoothed_pwdb < dm_digtable.rssi_high_power_lowthresh &&
			 priv->undecorated_smoothed_pwdb >= dm_digtable.rssi_high_thresh)
		{
			if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
			{				
				#ifdef RTL8190P
				write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);
				#else
					write_nic_byte(dev, (rOFDM0_XATxAFE+3), 0x20);
					#endif
				/*else if (priv->card_8192 == HARDWARE_TYPE_RTL8190P)
					write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);
				*/

			}
			else
				write_nic_byte(dev, rOFDM0_RxDetector1, 0x44);
		}
	}

	reset_cnt_highpwr = priv->reset_count;

}	


static void dm_initial_gain(
	struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u8					initial_gain=0;
	static u8				initialized=0, force_write=0;
	static u32			reset_cnt=0;

	if(dm_digtable.dig_algorithm_switch)
	{
		initialized = 0;
		reset_cnt = 0;
	}
	
	if(rtllib_act_scanning(priv->rtllib,true) == true)
	{
		force_write = 1;
		return;
	}
	
	if(dm_digtable.PreSTAConnectState == dm_digtable.CurSTAConnectState)
	{
		if(dm_digtable.CurSTAConnectState == DIG_STA_CONNECT)
		{
			if((dm_digtable.rssi_val+10-dm_digtable.backoff_val) > dm_digtable.rx_gain_range_max)
				dm_digtable.cur_ig_value = dm_digtable.rx_gain_range_max;
			else if((dm_digtable.rssi_val+10-dm_digtable.backoff_val) < dm_digtable.rx_gain_range_min)
				dm_digtable.cur_ig_value = dm_digtable.rx_gain_range_min;
			else
				dm_digtable.cur_ig_value = dm_digtable.rssi_val+10-dm_digtable.backoff_val;
		}
		else		
		{
			if(dm_digtable.cur_ig_value == 0)
				dm_digtable.cur_ig_value = priv->DefaultInitialGain[0];
			else
				dm_digtable.cur_ig_value = dm_digtable.pre_ig_value;
		}
	}
	else	
	{
		dm_digtable.cur_ig_value = priv->DefaultInitialGain[0];
		dm_digtable.pre_ig_value = 0;
	}

	if(priv->reset_count != reset_cnt)
	{
		force_write = 1;
		reset_cnt = priv->reset_count;
	}
	
	if(dm_digtable.pre_ig_value != read_nic_byte(dev, rOFDM0_XAAGCCore1))
		force_write = 1;
	
	{
		if((dm_digtable.pre_ig_value != dm_digtable.cur_ig_value) 
			|| !initialized || force_write)
		{
			initial_gain = (u8)dm_digtable.cur_ig_value;
			write_nic_byte(dev, rOFDM0_XAAGCCore1, initial_gain);
			write_nic_byte(dev, rOFDM0_XBAGCCore1, initial_gain);
			write_nic_byte(dev, rOFDM0_XCAGCCore1, initial_gain);
			write_nic_byte(dev, rOFDM0_XDAGCCore1, initial_gain);
			dm_digtable.pre_ig_value = dm_digtable.cur_ig_value;
			initialized = 1;
			force_write = 0;
		}
	}
}

void dm_initial_gain_STABeforeConnect(
	struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u8			initial_gain=0;
	static u8		initialized=0, force_write=0;

	RT_TRACE(COMP_DIG, "PreSTAConnectState = %x, CurSTAConnectState = %x\n", 
				dm_digtable.PreSTAConnectState, dm_digtable.CurSTAConnectState);


	if((dm_digtable.PreSTAConnectState == dm_digtable.CurSTAConnectState) ||
		(dm_digtable.CurSTAConnectState == DIG_STA_BEFORE_CONNECT))
	{
		if(dm_digtable.CurSTAConnectState == DIG_STA_BEFORE_CONNECT)
		{
			if(priv->rtllib->eRFPowerState != eRfOn)
				return;
			
			if(dm_digtable.Backoff_Enable_Flag == true)
			{
				if(priv->FalseAlmCnt.Cnt_all > dm_digtable.FAHighThresh)
				{
					if((dm_digtable.backoff_val -6) < dm_digtable.BackoffVal_range_min)
						dm_digtable.backoff_val = dm_digtable.BackoffVal_range_min;
					else
						dm_digtable.backoff_val -= 6; 
				}	
				else if(priv->FalseAlmCnt.Cnt_all < dm_digtable.FALowThresh)
				{
					if((dm_digtable.backoff_val+6) > dm_digtable.BackoffVal_range_max)
						dm_digtable.backoff_val = dm_digtable.BackoffVal_range_max;
					else
						dm_digtable.backoff_val +=6;
				}
			}
			else
				dm_digtable.backoff_val =DM_DIG_BACKOFF;
		
			if((dm_digtable.rssi_val+10-dm_digtable.backoff_val) > dm_digtable.rx_gain_range_max)
				dm_digtable.cur_ig_value = dm_digtable.rx_gain_range_max;
			else if((dm_digtable.rssi_val+10-dm_digtable.backoff_val) < dm_digtable.rx_gain_range_min)
				dm_digtable.cur_ig_value = dm_digtable.rx_gain_range_min;
			else
				dm_digtable.cur_ig_value = dm_digtable.rssi_val+10-dm_digtable.backoff_val;

			if(priv->FalseAlmCnt.Cnt_all > 10000)
				dm_digtable.cur_ig_value = (dm_digtable.cur_ig_value>0x33)?dm_digtable.cur_ig_value:0x33;

			if(priv->FalseAlmCnt.Cnt_all > 16000)
				dm_digtable.cur_ig_value = dm_digtable.rx_gain_range_max;

		}
		else 
		{
			return;	
		}
	}
	else	
	{		
		dm_digtable.Dig_Ext_Port_Stage = DIG_EXT_PORT_STAGE_MAX;
		priv->rtllib->SetFwCmdHandler(dev, FW_CMD_DIG_ENABLE);

		dm_digtable.backoff_val = DM_DIG_BACKOFF;
		dm_digtable.cur_ig_value = priv->DefaultInitialGain[0];
		dm_digtable.pre_ig_value = 0;
		return;
	}
		
	if(dm_digtable.pre_ig_value != rtl8192_QueryBBReg(dev, rOFDM0_XAAGCCore1, bMaskByte0))
		force_write = 1;
	
	if((dm_digtable.pre_ig_value != dm_digtable.cur_ig_value) || !initialized || force_write)
	{
		priv->rtllib->SetFwCmdHandler(dev, FW_CMD_DIG_DISABLE);	

		initial_gain = (u8)dm_digtable.cur_ig_value;

		rtl8192_setBBreg(dev, rOFDM0_XAAGCCore1, bMaskByte0, initial_gain);
		rtl8192_setBBreg(dev, rOFDM0_XBAGCCore1, bMaskByte0, initial_gain);
		dm_digtable.pre_ig_value = dm_digtable.cur_ig_value;
		initialized = 1;
		force_write = 0;
	}
	
	RT_TRACE(COMP_DIG, "CurIGValue = 0x%x, pre_ig_value = 0x%x, backoff_val = %d\n", 
				dm_digtable.cur_ig_value, dm_digtable.pre_ig_value, dm_digtable.backoff_val);

}

static void dm_pd_th(	
	struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	static u8				initialized=0, force_write=0;
	static u32			reset_cnt = 0;

	if(dm_digtable.dig_algorithm_switch)
	{
		initialized = 0;
		reset_cnt = 0;
	}
	
	if(dm_digtable.PreSTAConnectState == dm_digtable.CurSTAConnectState)
	{
		if(dm_digtable.CurSTAConnectState == DIG_STA_CONNECT)
		{
			if (dm_digtable.rssi_val >= dm_digtable.rssi_high_power_highthresh)
				dm_digtable.curpd_thstate = DIG_PD_AT_HIGH_POWER;
			else if ((dm_digtable.rssi_val <= dm_digtable.rssi_low_thresh))
				dm_digtable.curpd_thstate = DIG_PD_AT_LOW_POWER;
			else if ((dm_digtable.rssi_val >= dm_digtable.rssi_high_thresh) &&
					(dm_digtable.rssi_val < dm_digtable.rssi_high_power_lowthresh))
				dm_digtable.curpd_thstate = DIG_PD_AT_NORMAL_POWER;
			else
				dm_digtable.curpd_thstate = dm_digtable.prepd_thstate;
		}
		else
		{
			dm_digtable.curpd_thstate = DIG_PD_AT_LOW_POWER;
		}
	}
	else	
	{
		dm_digtable.curpd_thstate = DIG_PD_AT_LOW_POWER;
	}

	if(priv->reset_count != reset_cnt)
	{
		force_write = 1;
		reset_cnt = priv->reset_count;
	}
		
	{
		if((dm_digtable.prepd_thstate != dm_digtable.curpd_thstate) || 
			(initialized<=3) || force_write)
		{
			if(dm_digtable.curpd_thstate == DIG_PD_AT_LOW_POWER)
			{
				if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
				{
					#ifdef RTL8190P
					write_nic_byte(dev, rOFDM0_RxDetector1, 0x40);
					#else
						write_nic_byte(dev, (rOFDM0_XATxAFE+3), 0x00);
						#endif
					/*else if (priv->card_8192 == HARDWARE_TYPE_RTL8190P)
						write_nic_byte(dev, rOFDM0_RxDetector1, 0x40);
					*/
				}
				else
					write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);
			}
			else if(dm_digtable.curpd_thstate == DIG_PD_AT_NORMAL_POWER)
			{
				if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
				{
					#ifdef RTL8190P
					write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);	
					#else
						write_nic_byte(dev, (rOFDM0_XATxAFE+3), 0x20);
						#endif
					/*else if (priv->card_8192 == HARDWARE_TYPE_RTL8190P)
						write_nic_byte(dev, rOFDM0_RxDetector1, 0x42);		
					*/
				}
				else
					write_nic_byte(dev, rOFDM0_RxDetector1, 0x44);
			}
			else if(dm_digtable.curpd_thstate == DIG_PD_AT_HIGH_POWER)
			{
				if (priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)
				{			
					#ifdef RTL8190P
					write_nic_byte(dev, rOFDM0_RxDetector1, 0x41);
					#else
						write_nic_byte(dev, (rOFDM0_XATxAFE+3), 0x10);
						#endif
					/*else if (priv->card_8192 == HARDWARE_TYPE_RTL8190P)
						write_nic_byte(dev, rOFDM0_RxDetector1, 0x41);
					*/
				}
				else
					write_nic_byte(dev, rOFDM0_RxDetector1, 0x43);
			}	
			dm_digtable.prepd_thstate = dm_digtable.curpd_thstate;
			if(initialized <= 3)
				initialized++;
			force_write = 0;
		}
	}
}

static	void dm_cs_ratio(
	struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	static u8				initialized=0,force_write=0;
	static u32			reset_cnt = 0;

	if(dm_digtable.dig_algorithm_switch)
	{
		initialized = 0;
		reset_cnt = 0;
	}
	
	if(dm_digtable.PreSTAConnectState == dm_digtable.CurSTAConnectState)
	{
		if(dm_digtable.CurSTAConnectState == DIG_STA_CONNECT)
		{
			if ((dm_digtable.rssi_val <= dm_digtable.rssi_low_thresh))
				dm_digtable.curcs_ratio_state = DIG_CS_RATIO_LOWER;
			else if ((dm_digtable.rssi_val >= dm_digtable.rssi_high_thresh) )
				dm_digtable.curcs_ratio_state = DIG_CS_RATIO_HIGHER;
			else
				dm_digtable.curcs_ratio_state = dm_digtable.precs_ratio_state;
		}
		else
		{
			dm_digtable.curcs_ratio_state = DIG_CS_RATIO_LOWER;
		}
	}
	else	
	{
		dm_digtable.curcs_ratio_state = DIG_CS_RATIO_LOWER;
	}

	if(priv->reset_count != reset_cnt)
	{
		force_write = 1;
		reset_cnt = priv->reset_count;
	}

	
	{
		if((dm_digtable.precs_ratio_state != dm_digtable.curcs_ratio_state) || 
			!initialized || force_write)
		{
			if(dm_digtable.curcs_ratio_state == DIG_CS_RATIO_LOWER)
			{
				write_nic_byte(dev, 0xa0a, 0x08);
			}
			else if(dm_digtable.curcs_ratio_state == DIG_CS_RATIO_HIGHER)
			{
				write_nic_byte(dev, 0xa0a, 0xcd);
			}	
			dm_digtable.precs_ratio_state = dm_digtable.curcs_ratio_state;
			initialized = 1;
			force_write = 0;
		}
	}
}

extern void dm_init_edca_turbo(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);

	priv->bcurrent_turbo_EDCA = false;
	priv->rtllib->bis_any_nonbepkts = false;
	priv->bis_cur_rdlstate = false;
}	

#if 1
static void dm_check_edca_turbo(
	struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	PRT_HIGH_THROUGHPUT	pHTInfo = priv->rtllib->pHTInfo;
	
	static unsigned long			lastTxOkCnt = 0;
	static unsigned long			lastRxOkCnt = 0;
	unsigned long				curTxOkCnt = 0;
	unsigned long				curRxOkCnt = 0;	

	if(priv->rtllib->iw_mode == IW_MODE_ADHOC)
	{
		goto dm_CheckEdcaTurbo_EXIT;
	}
	if(priv->rtllib->state != RTLLIB_LINKED)
	{
		goto dm_CheckEdcaTurbo_EXIT;
	}
	if(priv->rtllib->pHTInfo->IOTAction & HT_IOT_ACT_DISABLE_EDCA_TURBO)
	{
		goto dm_CheckEdcaTurbo_EXIT;
	}
	
	{
		u8* peername[11] = {"unknown", "realtek_90", "realtek_92se","broadcom", "ralink", "atheros", "cisco", "marvell", "92u_softap", "self_softap"};
		static int wb_tmp = 0;
		if (wb_tmp == 0){
			printk("%s():iot peer is %s, bssid:"MAC_FMT"\n",__FUNCTION__,peername[pHTInfo->IOTPeer], MAC_ARG(priv->rtllib->current_network.bssid));
			wb_tmp = 1;
		}
	}
	if(!priv->rtllib->bis_any_nonbepkts)
	{
		curTxOkCnt = priv->stats.txbytesunicast - lastTxOkCnt;
		curRxOkCnt = priv->stats.rxbytesunicast - lastRxOkCnt;
		if(pHTInfo->IOTAction & HT_IOT_ACT_EDCA_BIAS_ON_RX)
		{
			if(curTxOkCnt > 4*curRxOkCnt)
			{
				if(priv->bis_cur_rdlstate || !priv->bcurrent_turbo_EDCA)
				{
					write_nic_dword(dev, EDCAPARA_BE, edca_setting_UL[pHTInfo->IOTPeer]);
					priv->bis_cur_rdlstate = false;
				}
			}
			else
			{
				if(!priv->bis_cur_rdlstate || !priv->bcurrent_turbo_EDCA)
				{
					if(priv->rtllib->mode == WIRELESS_MODE_G)
						write_nic_dword(dev, EDCAPARA_BE, edca_setting_DL_GMode[pHTInfo->IOTPeer]);
					else
						write_nic_dword(dev, EDCAPARA_BE, edca_setting_DL[pHTInfo->IOTPeer]);
					priv->bis_cur_rdlstate = true;
				}
			}
			priv->bcurrent_turbo_EDCA = true;
		}
		else
		{
		if(curRxOkCnt > 4*curTxOkCnt)
		{
			if(!priv->bis_cur_rdlstate || !priv->bcurrent_turbo_EDCA)
			{
				if(priv->rtllib->mode == WIRELESS_MODE_G)
					write_nic_dword(dev, EDCAPARA_BE, edca_setting_DL_GMode[pHTInfo->IOTPeer]);
				else
				write_nic_dword(dev, EDCAPARA_BE, edca_setting_DL[pHTInfo->IOTPeer]);
				priv->bis_cur_rdlstate = true;
			}
		}
		else
		{
			if(priv->bis_cur_rdlstate || !priv->bcurrent_turbo_EDCA)
			{
				write_nic_dword(dev, EDCAPARA_BE, edca_setting_UL[pHTInfo->IOTPeer]);
				priv->bis_cur_rdlstate = false;
			}

		}

		priv->bcurrent_turbo_EDCA = true;
	}
	}
	else
	{
		 if(priv->bcurrent_turbo_EDCA)
		{

			{
				u8		u1bAIFS;
				u32		u4bAcParam;
				struct rtllib_qos_parameters *qos_parameters = &priv->rtllib->current_network.qos_data.parameters;
				u8 mode = priv->rtllib->mode;

				dm_init_edca_turbo(dev);
				u1bAIFS = qos_parameters->aifs[0] * ((mode&(IEEE_G|IEEE_N_24G)) ?9:20) + aSifsTime; 
				u4bAcParam = ((((u32)(qos_parameters->tx_op_limit[0]))<< AC_PARAM_TXOP_LIMIT_OFFSET)|
					(((u32)(qos_parameters->cw_max[0]))<< AC_PARAM_ECW_MAX_OFFSET)|
					(((u32)(qos_parameters->cw_min[0]))<< AC_PARAM_ECW_MIN_OFFSET)|
					((u32)u1bAIFS << AC_PARAM_AIFS_OFFSET));
				write_nic_dword(dev, EDCAPARA_BE,  u4bAcParam);
			
				{

					PACI_AIFSN	pAciAifsn = (PACI_AIFSN)&(qos_parameters->aifs[0]);
					u8		AcmCtrl = read_nic_byte( dev, AcmHwCtrl );
					if( pAciAifsn->f.ACM )
					{ 
						AcmCtrl |= AcmHw_BeqEn;
					}
					else
					{ 
						AcmCtrl &= (~AcmHw_BeqEn);
					}

					RT_TRACE( COMP_QOS,"SetHwReg8190pci(): [HW_VAR_ACM_CTRL] Write 0x%X\n", AcmCtrl ) ;
					write_nic_byte(dev, AcmHwCtrl, AcmCtrl );
				}
			}
			priv->bcurrent_turbo_EDCA = false;
		}
	}
	
		
dm_CheckEdcaTurbo_EXIT:
	priv->rtllib->bis_any_nonbepkts = false;
	lastTxOkCnt = priv->stats.txbytesunicast;
	lastRxOkCnt = priv->stats.rxbytesunicast;
}	
#endif

extern void DM_CTSToSelfSetting(struct net_device * dev,u32 DM_Type, u32 DM_Value)
{
	struct r8192_priv *priv = rtllib_priv((struct net_device *)dev);
	
	if (DM_Type == 0)	
	{
		if(DM_Value > 1)
			DM_Value = 1;
		priv->rtllib->bCTSToSelfEnable = (bool)DM_Value;
	}
	else if(DM_Type == 1) 
	{
		if(DM_Value >= 50)
			DM_Value = 50;
		priv->rtllib->CTSToSelfTH = (u8)DM_Value;
	}
}

static void dm_init_ctstoself(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv((struct net_device *)dev);
	
	priv->rtllib->bCTSToSelfEnable = true;
	priv->rtllib->CTSToSelfTH = CTSToSelfTHVal;
}

static void dm_ctstoself(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv((struct net_device *)dev);
	PRT_HIGH_THROUGHPUT	pHTInfo = priv->rtllib->pHTInfo;
	static unsigned long				lastTxOkCnt = 0;
	static unsigned long				lastRxOkCnt = 0;
	unsigned long						curTxOkCnt = 0;
	unsigned long						curRxOkCnt = 0;

	if(priv->rtllib->bCTSToSelfEnable != true)
	{
		pHTInfo->IOTAction &= ~HT_IOT_ACT_FORCED_CTS2SELF;
		return;
	}
	if(pHTInfo->IOTPeer == HT_IOT_PEER_BROADCOM)
	{
		curTxOkCnt = priv->stats.txbytesunicast - lastTxOkCnt;
		curRxOkCnt = priv->stats.rxbytesunicast - lastRxOkCnt;
		if(curRxOkCnt > 4*curTxOkCnt)	
		{
			pHTInfo->IOTAction &= ~HT_IOT_ACT_FORCED_CTS2SELF;
		}
		else	
		{
		#if 1
			pHTInfo->IOTAction |= HT_IOT_ACT_FORCED_CTS2SELF;
		#else
			if(priv->undecorated_smoothed_pwdb < priv->rtllib->CTSToSelfTH)	
			{
				pHTInfo->IOTAction &= ~HT_IOT_ACT_FORCED_CTS2SELF;
			}
			else if(priv->undecorated_smoothed_pwdb >= (priv->rtllib->CTSToSelfTH+5))	
			{
				pHTInfo->IOTAction |= HT_IOT_ACT_FORCED_CTS2SELF;
			}
		#endif
		}

		lastTxOkCnt = priv->stats.txbytesunicast;
		lastRxOkCnt = priv->stats.rxbytesunicast;
	}
}


static	void 
dm_Init_WA_Broadcom_IOT(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv((struct net_device *)dev);
	PRT_HIGH_THROUGHPUT	pHTInfo = priv->rtllib->pHTInfo;
	
	pHTInfo->bWAIotBroadcom = false;
	pHTInfo->WAIotTH = WAIotTHVal;
}

#ifdef RTL8192SE
static	void
dm_WA_Broadcom_IOT(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv((struct net_device *)dev);
	PRT_HIGH_THROUGHPUT	pHTInfo = priv->rtllib->pHTInfo;
	u8					update=0;
	static enum rtllib_state connectState = RTLLIB_NOLINK;

	if( (pHTInfo->bWAIotBroadcom != true) ||
		(priv->rtllib->mode == WIRELESS_MODE_B) ||
		(pHTInfo->bCurBW40MHz))
	{
		if(pHTInfo->IOTAction & HT_IOT_ACT_WA_IOT_Broadcom)
		{	
			pHTInfo->IOTAction &= ~HT_IOT_ACT_WA_IOT_Broadcom;
			update = 1;
			printk(" dm_WA_Broadcom_IOT(), disable HT_IOT_ACT_WA_IOT_Broadcom\n");
		}
		else
			return;
	}

	if(connectState == RTLLIB_LINKED && priv->rtllib->state == RTLLIB_LINKED)	
	{
		if(pHTInfo->IOTAction & HT_IOT_ACT_WA_IOT_Broadcom)
		{	
			pHTInfo->IOTAction &= ~HT_IOT_ACT_WA_IOT_Broadcom;
			update = 1;
			pHTInfo->bWAIotBroadcom = false;
			printk("dm_WA_Broadcom_IOT(), from connect to disconnected, disable HT_IOT_ACT_WA_IOT_Broadcom\n");
		}
	}
	connectState = priv->rtllib->state;
		
	if(!update && pHTInfo->IOTPeer == HT_IOT_PEER_BROADCOM)
	{
		if(priv->undecorated_smoothed_pwdb < pHTInfo->WAIotTH)
		{
			if(pHTInfo->IOTAction & HT_IOT_ACT_WA_IOT_Broadcom)
			{	
				pHTInfo->IOTAction &= ~HT_IOT_ACT_WA_IOT_Broadcom;
				update = 1;
				printk("dm_WA_Broadcom_IOT() ==> WA_IOT enable cck rates\n");
			}
		}
		else if(priv->undecorated_smoothed_pwdb >= (priv->rtllib->CTSToSelfTH+5))	
		{
			if((pHTInfo->IOTAction & HT_IOT_ACT_WA_IOT_Broadcom) == 0)
			{
				pHTInfo->IOTAction |= HT_IOT_ACT_WA_IOT_Broadcom;
				update = 1;
				printk("dm_WA_Broadcom_IOT() ==> WA_IOT disable cck rates\n");
			}
		}
	}

	if(update){
		if(priv->rtllib->bUseRAMask){
			priv->rtllib->UpdateHalRAMaskHandler(
										dev,
										false,
										0,
										priv->rtllib->pHTInfo->PeerMimoPs,
										priv->rtllib->mode,
										priv->rtllib->pHTInfo->bCurTxBW40MHz,
										0);
		}else{
			priv->ops->update_ratr_table(dev, priv->rtllib->dot11HTOperationalRateSet, NULL);
		}
		priv->rtllib->SetHwRegHandler( dev, HW_VAR_BASIC_RATE, (u8*)(&priv->basic_rate));
	}
}
#endif


#if 0
extern void dm_rf_operation_test_callback(unsigned long dev)
{
	u8 erfpath;
		
		
	for(erfpath=0; erfpath<4; erfpath++) 
	{
		udelay(100); 
	} 

	{
	}
	
	{
#if 0
		for(i=0; i<50; i++) 
		{ 
			PHY_SetRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits, 0x4d);
			PHY_SetRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits, 0x4f);
			PHY_SetRFReg(dev, RF90_PATH_C, 0x02, bMask12Bits, 0x4d);
			PHY_SetRFReg(dev, RF90_PATH_C, 0x02, bMask12Bits, 0x4f);

#if 0
			PHY_QueryRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits);
			PHY_QueryRFReg(dev, RF90_PATH_A, 0x02, bMask12Bits);
			PHY_QueryRFReg(dev, RF90_PATH_A, 0x12, bMask12Bits);
			PHY_QueryRFReg(dev, RF90_PATH_A, 0x12, bMask12Bits);
			PHY_QueryRFReg(dev, RF90_PATH_A, 0x21, bMask12Bits);
			PHY_QueryRFReg(dev, RF90_PATH_A, 0x21, bMask12Bits);
#endif
		} 
#endif
	}
	
}	
#endif

#if 0
static void dm_check_rfctrl_gpio(struct net_device * dev)
{
#ifdef RTL8192E
	struct r8192_priv *priv = rtllib_priv(dev);
#endif

	
#ifdef RTL8190P
	return;
#endif
#ifdef RTL8192U
	return;
#endif
#ifdef RTL8192E
	queue_delayed_work_rsl(priv->priv_wq,&priv->gpio_change_rf_wq,0);
#endif

}	

#endif
static	void	dm_check_pbc_gpio(struct net_device *dev)
{
#ifdef RTL8192U
	struct r8192_priv *priv = rtllib_priv(dev);
	u8 tmp1byte;

	
	tmp1byte = read_nic_byte(dev,GPI);
	if(tmp1byte == 0xff)
	return;

	if (tmp1byte&BIT6 || tmp1byte&BIT0)
	{
		RT_TRACE(COMP_IO, "CheckPbcGPIO - PBC is pressed\n");
		priv->bpbc_pressed = true;
	}
#endif
	
}

#ifdef RTL8192E 

extern	void	dm_CheckRfCtrlGPIO(void *data)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
       struct r8192_priv *priv = container_of_dwork_rsl(data,struct r8192_priv,gpio_change_rf_wq);
       struct net_device *dev = priv->rtllib->dev;
#else
	struct r8192_priv *priv = rtllib_priv((struct net_device *)data);
	struct net_device *dev = priv->rtllib->dev;
#endif
	u8 tmp1byte;
	RT_RF_POWER_STATE	eRfPowerStateToSet;
	bool bActuallySet = false;

	char *argv[3];
	static char *RadioPowerPath = "/etc/acpi/events/RadioPower.sh";
	static char *envp[] = {"HOME=/", "TERM=linux", "PATH=/usr/bin:/bin", NULL};

	bActuallySet=false;

	if((priv->up_first_time == 1) || (priv->being_init_adapter))
	{
		return;
	}

	if(priv->bfirst_after_down){
		priv->bfirst_after_down = 1;
		return;
	}



	{
		tmp1byte = read_nic_byte(dev,GPI);

		eRfPowerStateToSet = (tmp1byte&BIT1) ?  eRfOn : eRfOff;

		if( (priv->bHwRadioOff == true) && (eRfPowerStateToSet == eRfOn))
		{
			RT_TRACE(COMP_RF, "gpiochangeRF  - HW Radio ON\n");
			printk("gpiochangeRF  - HW Radio ON\n");
			priv->bHwRadioOff = false;
			bActuallySet = true;
		}
		else if ( (priv->bHwRadioOff == false) && (eRfPowerStateToSet == eRfOff))
		{
			RT_TRACE(COMP_RF, "gpiochangeRF  - HW Radio OFF\n");
			printk("gpiochangeRF  - HW Radio OFF\n");
			priv->bHwRadioOff = true;
			bActuallySet = true;
		}

		if(bActuallySet)
		{
			mdelay(1000); 
			priv->bHwRfOffAction = 1;
			MgntActSet_RF_State(dev, eRfPowerStateToSet, RF_CHANGE_BY_HW);
			{
				if(priv->bHwRadioOff == true)
					argv[1] = "RFOFF";
				else
					argv[1] = "RFON";

				argv[0] = RadioPowerPath;
				argv[2] = NULL;
				call_usermodehelper(RadioPowerPath,argv,envp,UMH_WAIT_PROC);
			}

		}
#if 0 
		else
		{
			msleep(2000);
		}
#endif

	}

}	
#elif defined RTL8192SE
extern void Power_DomainInit92SE(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u8				tmpU1b;
	u16				tmpU2b;

	
	
	priv->PwrDomainProtect = true;

	tmpU1b = read_nic_byte(dev, (SYS_CLKR + 1));
	if(tmpU1b & BIT7)
	{
		tmpU1b &= ~(BIT6 | BIT7);
		if(!HalSetSysClk8192SE(dev, tmpU1b)){
			priv->PwrDomainProtect = false;
			return; 
	}
	}
	
	write_nic_byte(dev, AFE_PLL_CTRL, 0x0);
	write_nic_byte(dev, LDOA15_CTRL, 0x34);
	
#if 0
	tmpU2b = read_nic_word(dev, SYS_CLKR);
	if (tmpU2b & BIT15)	
	{
		tmpU2b &= ~(BIT14|BIT15);
		RT_TRACE(COMP_INIT, DBG_LOUD, ("Return to HW CTRL\n"));
		write_nic_word(dev, SYS_CLKR, tmpU2b);
	}
	udelay(200);
#endif

	tmpU1b = read_nic_byte(dev, SYS_FUNC_EN+1);
	if (priv->rtllib->RfOffReason & (RF_CHANGE_BY_IPS | RF_CHANGE_BY_HW)) {
		tmpU1b &= 0xFB;
	} else {
		tmpU1b &= 0x73;
	}
	
	write_nic_byte(dev, SYS_FUNC_EN+1, tmpU1b);
	udelay(1000);
	
	write_nic_byte(dev, CMDR, 0);
	write_nic_byte(dev, TCR, 0);

	tmpU1b = read_nic_byte(dev, 0x562);
	tmpU1b |= 0x08;
	write_nic_byte(dev, 0x562, tmpU1b);
	tmpU1b &= ~(BIT3);
	write_nic_byte(dev, 0x562, tmpU1b);

	tmpU1b = read_nic_byte(dev, AFE_XTAL_CTRL);	
	write_nic_byte(dev, AFE_XTAL_CTRL, (tmpU1b|0x01));
	udelay(1500);	
	tmpU1b = read_nic_byte(dev, AFE_XTAL_CTRL+1);	
	write_nic_byte(dev, AFE_XTAL_CTRL+1, (tmpU1b&0xfb));


	tmpU1b = read_nic_byte(dev, AFE_MISC);	
	write_nic_byte(dev, AFE_MISC, (tmpU1b|BIT0));
	udelay(1000);

	tmpU1b = read_nic_byte(dev, AFE_MISC);	
	write_nic_byte(dev, AFE_MISC, (tmpU1b|0x02));
	udelay(1000);
	
	tmpU1b = read_nic_byte(dev, LDOA15_CTRL);	
	write_nic_byte(dev, LDOA15_CTRL, (tmpU1b|BIT0));

	tmpU2b = read_nic_word(dev, SYS_ISO_CTRL);	
	write_nic_word(dev, SYS_ISO_CTRL, (tmpU2b|BIT11));


	tmpU2b = read_nic_word(dev, SYS_FUNC_EN);
	write_nic_word(dev, SYS_FUNC_EN, (tmpU2b |BIT13));

	write_nic_byte(dev, SYS_ISO_CTRL+1, 0x68);

	tmpU1b = read_nic_byte(dev, AFE_PLL_CTRL);	
	write_nic_byte(dev, AFE_PLL_CTRL, (tmpU1b|BIT0|BIT4));
	tmpU1b = read_nic_byte(dev, AFE_PLL_CTRL+1);	
	write_nic_byte(dev, AFE_PLL_CTRL+1, (tmpU1b|BIT0));
	udelay(1000);

	write_nic_byte(dev, SYS_ISO_CTRL, 0xA6);

	tmpU2b = read_nic_word(dev, SYS_CLKR);	
	write_nic_word(dev, SYS_CLKR, (tmpU2b|BIT12|BIT11));

	tmpU2b = read_nic_word(dev, SYS_FUNC_EN);	
	write_nic_word(dev, SYS_FUNC_EN, (tmpU2b|BIT11));
	write_nic_word(dev, SYS_FUNC_EN, (tmpU2b|BIT11|BIT15));

	 tmpU2b = read_nic_word(dev, SYS_CLKR);	
	write_nic_word(dev, SYS_CLKR, (tmpU2b&(~BIT2)));
	
	tmpU1b = read_nic_byte(dev, (SYS_CLKR + 1));
	tmpU1b = ((tmpU1b | BIT7) & (~BIT6));
	if(!HalSetSysClk8192SE(dev, tmpU1b))
	{
		priv->PwrDomainProtect = false;
		return; 
	}
#if 0
	tmpU2b = read_nic_word(dev, SYS_CLKR);	
	write_nic_word(dev, SYS_CLKR, ((tmpU2b|BIT15)&(~BIT14)));
#endif

	write_nic_word(dev, CMDR, 0x37FC);	

	gen_RefreshLedState(dev);

	priv->PwrDomainProtect = false;

}	

void	SET_RTL8192SE_RF_HALT(struct net_device *dev)							
{ 																	
	u8		u1bTmp;												
	struct r8192_priv *priv = rtllib_priv(dev);
	
	if(priv->rtllib->RfOffReason == RF_CHANGE_BY_IPS && priv->LedStrategy == SW_LED_MODE8)	
	{
		SET_RTL8192SE_RF_SLEEP(dev);
		return;
	}
	
	u1bTmp = read_nic_byte(dev, LDOV12D_CTRL);		
	u1bTmp |= BIT0; 												
	write_nic_byte(dev, LDOV12D_CTRL, u1bTmp);		
	write_nic_byte(dev, SPS1_CTRL, 0x0);				
	write_nic_byte(dev, TXPAUSE, 0xFF);				
	write_nic_word(dev, CMDR, 0x57FC);				
	udelay(100);													
	write_nic_word(dev, CMDR, 0x77FC);				
	write_nic_byte(dev, PHY_CCA, 0x0);				
	udelay(10);													
	write_nic_word(dev, CMDR, 0x37FC);				
	udelay(10);													
	write_nic_word(dev, CMDR, 0x77FC);				
	udelay(10);													
	write_nic_word(dev, CMDR, 0x57FC);				
	write_nic_word(dev, CMDR, 0x0000);				
	u1bTmp = read_nic_byte(dev, (SYS_CLKR + 1));		
	if(u1bTmp & BIT7)												
	{																
		u1bTmp &= ~(BIT6 | BIT7);									
		if(!HalSetSysClk8192SE(dev, u1bTmp))					
			return;													
	}	
	if(priv->rtllib->RfOffReason==RF_CHANGE_BY_IPS )
	{
		write_nic_byte(dev, 0x03, 0xF9);
	}
	else		
	{
		write_nic_byte(dev, 0x03, 0x71);
	}
	write_nic_byte(dev, SYS_CLKR+1, 0x70);					
	write_nic_byte(dev, AFE_PLL_CTRL+1, 0x68);					
	write_nic_byte(dev, AFE_PLL_CTRL, 0x00);					
	write_nic_byte(dev, LDOA15_CTRL, 0x34);
	write_nic_byte(dev, AFE_XTAL_CTRL, 0x0E);					
															
}

u8 RfOnOffDetect(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u8	u1Tmp;
	u8	retval=eRfOn;

	if(priv->pwrdown)
	{
		u1Tmp = read_nic_byte(dev, 0x06);
		dev_dbg(&dev->dev, "pwrdown, 0x6(BIT6)=%02x\n", u1Tmp);
		retval = (u1Tmp & BIT6) ? eRfOn: eRfOff;
	}
	else
	{
#ifdef CONFIG_BT_COEXIST
		if(pHalData->bt_coexist.BluetoothCoexist)
		{
			if(pHalData->bt_coexist.BT_CoexistType == BT_2Wire)
			{
				PlatformEFIOWrite1Byte(pAdapter, MAC_PINMUX_CFG, 0xa);
				u1Tmp = PlatformEFIORead1Byte(pAdapter, GPIO_IO_SEL);
				delay_us(100);
				u1Tmp = PlatformEFIORead1Byte(pAdapter, GPIO_IN);
				RTPRINT(FPWR, PWRHW, ("GPIO_IN=%02x\n", u1Tmp));
				retval = (u1Tmp & HAL_8192S_HW_GPIO_OFF_BIT) ? eRfOn : eRfOff;
			}
			else if( (pHalData->bt_coexist.BT_CoexistType == BT_ISSC_3Wire) ||
					(pHalData->bt_coexist.BT_CoexistType == BT_Accel) ||
					(pHalData->bt_coexist.BT_CoexistType == BT_CSR) )
			{
				u4tmp = PHY_QueryBBReg(pAdapter, 0x87c, bMaskDWord);
				if((u4tmp & BIT17) != 0)
				{
					PHY_SetBBReg(pAdapter, 0x87c, bMaskDWord, u4tmp & ~BIT17);
					delay_us(50);
					RTPRINT(FBT, BT_RFPoll, ("BT write 0x87c (~BIT17) = 0x%x\n", u4tmp &~BIT17));
				}
				u4tmp = PHY_QueryBBReg(pAdapter, 0x8e0, bMaskDWord);
				RTPRINT(FBT, BT_RFPoll, ("BT read 0x8e0 (BIT24)= 0x%x\n", u4tmp));
				retval = (u4tmp & BIT24) ? eRfOn : eRfOff;
				RTPRINT(FBT, BT_RFPoll, ("BT check RF state to %s\n", (retval==eRfOn)? "ON":"OFF"));
			}
		}
		else
#endif
		{
			write_nic_byte(dev, MAC_PINMUX_CFG, (GPIOMUX_EN | GPIOSEL_GPIO));
			u1Tmp = read_nic_byte(dev, GPIO_IO_SEL);

			u1Tmp &= HAL_8192S_HW_GPIO_OFF_MASK;
			write_nic_byte(dev, GPIO_IO_SEL, u1Tmp);

			mdelay(10);

			u1Tmp = read_nic_byte(dev, GPIO_IN);
			retval = (u1Tmp & HAL_8192S_HW_GPIO_OFF_BIT) ? eRfOn : eRfOff;
		}
	}

	return retval;
}

extern void dm_CheckRfCtrlGPIO(void *data)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
	struct r8192_priv *priv = container_of_dwork_rsl(data,struct r8192_priv,gpio_change_rf_wq);
	struct net_device *dev = priv->rtllib->dev;
#else
	struct net_device *dev = (struct net_device *)data;
	struct r8192_priv *priv = rtllib_priv(dev);
#endif

	RT_RF_POWER_STATE	eRfPowerStateToSet, CurRfState;
	bool					bActuallySet = false;
	PRT_POWER_SAVE_CONTROL		pPSC = (PRT_POWER_SAVE_CONTROL)(&(priv->rtllib->PowerSaveControl));
	unsigned long flag = 0;
	bool			turnonbypowerdomain = false;


#ifdef CONFIG_RTL_RFKILL
	return;
#endif	
	if((priv->up_first_time == 1) || (priv->being_init_adapter))
	{
		;
		return;
	}

	if(priv->ResetProgress == RESET_TYPE_SILENT)
	{
		RT_TRACE((COMP_INIT | COMP_POWER | COMP_RF), "GPIOChangeRFWorkItemCallBack(): Silent Reseting!!!!!!!\n");
		return;
	}


	if (pPSC->bSwRfProcessing) 
	{
		RT_TRACE(COMP_SCAN, "GPIOChangeRFWorkItemCallBack(): Rf is in switching state.\n");
		return;
	}

	RT_TRACE(COMP_RF, "GPIOChangeRFWorkItemCallBack() ---------> \n");

	spin_lock_irqsave(&priv->rf_ps_lock,flag);
	if (priv->RFChangeInProgress) {
		spin_unlock_irqrestore(&priv->rf_ps_lock,flag);
		RT_TRACE(COMP_RF, "GPIOChangeRFWorkItemCallBack(): RF Change in progress! \n");
		return;
	} else {
		priv->RFChangeInProgress = true;
		spin_unlock_irqrestore(&priv->rf_ps_lock,flag);
	}
	CurRfState = priv->rtllib->eRFPowerState;
#ifdef CONFIG_ASPM_OR_D3
	if((pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_ASPM) && RT_IN_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_ASPM))
	{
		RT_DISABLE_ASPM(dev);
		RT_CLEAR_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_ASPM);
	}
	else if((pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_PCI_D3) && RT_IN_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_PCI_D3))
	{
#ifdef TODO		
		RT_LEAVE_D3(dev, false);
		RT_CLEAR_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_PCI_D3);
#endif		
	}

#endif
	if(RT_IN_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_HALT_NIC))
	{
		Power_DomainInit92SE(dev);
		turnonbypowerdomain = true;
	}

	eRfPowerStateToSet = RfOnOffDetect(dev);
	if (priv->bResetInProgress) {
		spin_lock_irqsave(&priv->rf_ps_lock,flag);
		priv->RFChangeInProgress = false;
		spin_unlock_irqrestore(&priv->rf_ps_lock,flag);
		return;
	}

	if( (priv->bHwRadioOff == true) && \
	   (((eRfPowerStateToSet == eRfOn)&&(priv->sw_radio_on == true))
#ifdef CONFIG_RTLWIFI_DEBUGFS	    
	    ||priv->debug->hw_holding
#endif	    
	    ))
	{
		RT_TRACE(COMP_RF, "GPIOChangeRF  - HW Radio ON, RF ON\n");
		printk("GPIOChangeRF  - HW Radio ON, RF ON\n");
                eRfPowerStateToSet = eRfOn;
		bActuallySet = true;
	} else if ((priv->bHwRadioOff == false) && 
		 ((eRfPowerStateToSet == eRfOff) || (priv->sw_radio_on == false)))
	{
		RT_TRACE(COMP_RF, "GPIOChangeRF  - HW Radio OFF\n");
		printk("GPIOChangeRF  - HW Radio OFF\n");
                eRfPowerStateToSet = eRfOff;
		bActuallySet = true;
	}

	if (bActuallySet) {
		priv->bHwRfOffAction = 1;
#ifdef CONFIG_ASPM_OR_D3
		if(eRfPowerStateToSet == eRfOn)
		{
			if((pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_ASPM) && RT_IN_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_ASPM))
			{
				RT_DISABLE_ASPM(dev);
				RT_CLEAR_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_ASPM);
			}
#ifdef TODO			
			else if((pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_PCI_D3) && RT_IN_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_PCI_D3))
			{
				RT_LEAVE_D3(dev, false);
				RT_CLEAR_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_PCI_D3);
			}
#endif			
		}
#endif
		spin_lock_irqsave(&priv->rf_ps_lock,flag);
		priv->RFChangeInProgress = false;
		spin_unlock_irqrestore(&priv->rf_ps_lock,flag);
		MgntActSet_RF_State(dev, eRfPowerStateToSet, RF_CHANGE_BY_HW);

		{
#ifdef CONFIG_CFG_80211			
			struct wireless_dev *wdev = &priv->rtllib->wdev;
			wiphy_rfkill_set_hw_state(wdev->wiphy, priv->bHwRadioOff);
#else
			char *argv[3];
			static char *RadioPowerPath = "/etc/acpi/events/RadioPower.sh";
			static char *envp[] = {"HOME=/", "TERM=linux", "PATH=/usr/bin:/bin", NULL};

			if(priv->bHwRadioOff == true)
				argv[1] = "RFOFF";
			else
				argv[1] = "RFON";

			argv[0] = RadioPowerPath;
			argv[2] = NULL;
			call_usermodehelper(RadioPowerPath,argv,envp,UMH_WAIT_PROC);

#endif			
		}

		if(eRfPowerStateToSet == eRfOff)
		{
			if(priv->pwrdown){

				write_nic_byte(dev, SYS_FUNC_EN+1, 0x31);
			}
#ifdef CONFIG_ASPM_OR_D3
			if(pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_ASPM)
			{
				RT_ENABLE_ASPM(dev);
				RT_SET_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_ASPM);
			}
#ifdef TODO			
			else if(pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_PCI_D3)
			{
				RT_ENTER_D3(dev, false);
				RT_SET_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_PCI_D3);
			}
#endif			
#endif
		}
	}
	else if(eRfPowerStateToSet == eRfOff || CurRfState == eRfOff || priv->bDriverIsGoingToUnload)
	{

		if(pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_HALT_NIC && turnonbypowerdomain)
		{ 
			PHY_SetRtl8192seRfHalt(dev);
			RT_SET_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_HALT_NIC);
		}
#ifdef CONFIG_ASPM_OR_D3
		if(pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_ASPM)
		{
			RT_ENABLE_ASPM(dev);
			RT_SET_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_ASPM);
		}
#ifdef TODO		
		else if(pPSC->RegRfPsLevel & RT_RF_OFF_LEVL_PCI_D3)
		{
			RT_ENTER_D3(dev, false);
			RT_SET_PS_LEVEL(pPSC, RT_RF_OFF_LEVL_PCI_D3);
		}
#endif		
#endif
		spin_lock_irqsave(&priv->rf_ps_lock,flag);
		priv->RFChangeInProgress = false;
		spin_unlock_irqrestore(&priv->rf_ps_lock,flag);
	}
	else
	{
		spin_lock_irqsave(&priv->rf_ps_lock,flag);
		priv->RFChangeInProgress = false;
		spin_unlock_irqrestore(&priv->rf_ps_lock,flag);
	}
	RT_TRACE(COMP_RF, "GPIOChangeRFWorkItemCallBack() <--------- \n");
}
#endif
void	dm_rf_pathcheck_workitemcallback(void *data)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20))
	struct r8192_priv *priv = container_of_dwork_rsl(data,struct r8192_priv,rfpath_check_wq);
	struct net_device *dev =priv->rtllib->dev;
#else
	struct net_device *dev = (struct net_device *)data;
	struct r8192_priv *priv = rtllib_priv(dev);
#endif
	u8 rfpath = 0, i;
	
		
	rfpath = read_nic_byte(dev, 0xc04);
	
	for (i = 0; i < RF90_PATH_MAX; i++)
	{
		if (rfpath & (0x01<<i))		
			priv->brfpath_rxenable[i] = 1;
		else
			priv->brfpath_rxenable[i] = 0;
	}
	if(!DM_RxPathSelTable.Enable)
		return;

	dm_rxpath_sel_byrssi(dev);
}	

static void dm_init_rxpath_selection(struct net_device * dev)
{
	u8 i;
	struct r8192_priv *priv = rtllib_priv(dev);
	DM_RxPathSelTable.Enable = 1;	
	DM_RxPathSelTable.SS_TH_low = RxPathSelection_SS_TH_low;
	DM_RxPathSelTable.diff_TH = RxPathSelection_diff_TH;
	if(priv->CustomerID == RT_CID_819x_Netcore)
		DM_RxPathSelTable.cck_method = CCK_Rx_Version_2;
	else	
		DM_RxPathSelTable.cck_method = CCK_Rx_Version_1;
	DM_RxPathSelTable.DbgMode = DM_DBG_OFF;
	DM_RxPathSelTable.disabledRF = 0;
	for(i=0; i<4; i++)
	{
		DM_RxPathSelTable.rf_rssi[i] = 50;
		DM_RxPathSelTable.cck_pwdb_sta[i] = -64;
		DM_RxPathSelTable.rf_enable_rssi_th[i] = 100;
	}
}

static void dm_rxpath_sel_byrssi(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u8				i, max_rssi_index=0, min_rssi_index=0, sec_rssi_index=0, rf_num=0;
	u8				tmp_max_rssi=0, tmp_min_rssi=0, tmp_sec_rssi=0;
	u8				cck_default_Rx=0x2;	
	u8				cck_optional_Rx=0x3;
	long				tmp_cck_max_pwdb=0, tmp_cck_min_pwdb=0, tmp_cck_sec_pwdb=0;
	u8				cck_rx_ver2_max_index=0, cck_rx_ver2_min_index=0, cck_rx_ver2_sec_index=0;
	u8				cur_rf_rssi;
	long				cur_cck_pwdb;
	static u8			disabled_rf_cnt=0, cck_Rx_Path_initialized=0;
	u8				update_cck_rx_path;

	if(priv->rf_type != RF_2T4R)
		return;

	if(!cck_Rx_Path_initialized)
	{
		DM_RxPathSelTable.cck_Rx_path = (read_nic_byte(dev, 0xa07)&0xf);
		cck_Rx_Path_initialized = 1;
	}
	
	DM_RxPathSelTable.disabledRF = 0xf;
	DM_RxPathSelTable.disabledRF &=~ (read_nic_byte(dev, 0xc04));

	if(priv->rtllib->mode == WIRELESS_MODE_B)
	{
		DM_RxPathSelTable.cck_method = CCK_Rx_Version_2;	
	}

	for (i=0; i<RF90_PATH_MAX; i++)
	{
		if(!DM_RxPathSelTable.DbgMode)
			DM_RxPathSelTable.rf_rssi[i] = priv->stats.rx_rssi_percentage[i];

		if(priv->brfpath_rxenable[i])
		{
			rf_num++;
			cur_rf_rssi = DM_RxPathSelTable.rf_rssi[i];
			
			if(rf_num == 1)	
			{	
				max_rssi_index = min_rssi_index = sec_rssi_index = i;
				tmp_max_rssi = tmp_min_rssi = tmp_sec_rssi = cur_rf_rssi;
			}
			else if(rf_num == 2)
			{	
				if(cur_rf_rssi >= tmp_max_rssi)
				{
					tmp_max_rssi = cur_rf_rssi;
					max_rssi_index = i;
				}
				else
				{
					tmp_sec_rssi = tmp_min_rssi = cur_rf_rssi;
					sec_rssi_index = min_rssi_index = i;					
				}
			}
			else
			{
				if(cur_rf_rssi > tmp_max_rssi)
				{
					tmp_sec_rssi = tmp_max_rssi;
					sec_rssi_index = max_rssi_index;
					tmp_max_rssi = cur_rf_rssi;
					max_rssi_index = i;
				}
				else if(cur_rf_rssi == tmp_max_rssi)
				{	
					tmp_sec_rssi = cur_rf_rssi;
					sec_rssi_index = i;
				}
				else if((cur_rf_rssi < tmp_max_rssi) &&(cur_rf_rssi > tmp_sec_rssi))
				{
					tmp_sec_rssi = cur_rf_rssi;
					sec_rssi_index = i;
				}
				else if(cur_rf_rssi == tmp_sec_rssi)
				{
					if(tmp_sec_rssi == tmp_min_rssi)
					{	
						tmp_sec_rssi = cur_rf_rssi;
						sec_rssi_index = i;
					}
					else
					{
					}
				}
				else if((cur_rf_rssi < tmp_sec_rssi) && (cur_rf_rssi > tmp_min_rssi))
				{
				}
				else if(cur_rf_rssi == tmp_min_rssi)
				{
					if(tmp_sec_rssi == tmp_min_rssi)
					{	
						tmp_min_rssi = cur_rf_rssi;
						min_rssi_index = i;
					}
					else
					{
					}
				}
				else if(cur_rf_rssi < tmp_min_rssi)
				{
					tmp_min_rssi = cur_rf_rssi;
					min_rssi_index = i;
				}
			}
		}
	}

	rf_num = 0;
	if(DM_RxPathSelTable.cck_method == CCK_Rx_Version_2)
	{
		for (i=0; i<RF90_PATH_MAX; i++)
		{
			if(priv->brfpath_rxenable[i])
			{
				rf_num++;
				cur_cck_pwdb =  DM_RxPathSelTable.cck_pwdb_sta[i];
				
				if(rf_num == 1)	
				{	
					cck_rx_ver2_max_index = cck_rx_ver2_min_index = cck_rx_ver2_sec_index = i;
					tmp_cck_max_pwdb = tmp_cck_min_pwdb = tmp_cck_sec_pwdb = cur_cck_pwdb;
				}
				else if(rf_num == 2)
				{	
					if(cur_cck_pwdb >= tmp_cck_max_pwdb)
					{
						tmp_cck_max_pwdb = cur_cck_pwdb;
						cck_rx_ver2_max_index = i;
					}
					else
					{
						tmp_cck_sec_pwdb = tmp_cck_min_pwdb = cur_cck_pwdb;
						cck_rx_ver2_sec_index = cck_rx_ver2_min_index = i;					
					}
				}
				else
				{
					if(cur_cck_pwdb > tmp_cck_max_pwdb)
					{
						tmp_cck_sec_pwdb = tmp_cck_max_pwdb;
						cck_rx_ver2_sec_index = cck_rx_ver2_max_index;
						tmp_cck_max_pwdb = cur_cck_pwdb;
						cck_rx_ver2_max_index = i;
					}
					else if(cur_cck_pwdb == tmp_cck_max_pwdb)
					{	
						tmp_cck_sec_pwdb = cur_cck_pwdb;
						cck_rx_ver2_sec_index = i;
					}
					else if((cur_cck_pwdb < tmp_cck_max_pwdb) &&(cur_cck_pwdb > tmp_cck_sec_pwdb))
					{
						tmp_cck_sec_pwdb = cur_cck_pwdb;
						cck_rx_ver2_sec_index = i;
					}
					else if(cur_cck_pwdb == tmp_cck_sec_pwdb)
					{
						if(tmp_cck_sec_pwdb == tmp_cck_min_pwdb)
						{	
							tmp_cck_sec_pwdb = cur_cck_pwdb;
							cck_rx_ver2_sec_index = i;
						}
						else
						{
						}
					}
					else if((cur_cck_pwdb < tmp_cck_sec_pwdb) && (cur_cck_pwdb > tmp_cck_min_pwdb))
					{
					}
					else if(cur_cck_pwdb == tmp_cck_min_pwdb)
					{
						if(tmp_cck_sec_pwdb == tmp_cck_min_pwdb)
						{	
							tmp_cck_min_pwdb = cur_cck_pwdb;
							cck_rx_ver2_min_index = i;
						}
						else
						{
						}
					}
					else if(cur_cck_pwdb < tmp_cck_min_pwdb)
					{
						tmp_cck_min_pwdb = cur_cck_pwdb;
						cck_rx_ver2_min_index = i;
					}
				}
			
			}
		}
	}


	update_cck_rx_path = 0;
	if(DM_RxPathSelTable.cck_method == CCK_Rx_Version_2)
	{
		cck_default_Rx = cck_rx_ver2_max_index;
		cck_optional_Rx = cck_rx_ver2_sec_index;
		if(tmp_cck_max_pwdb != -64)
			update_cck_rx_path = 1;
	}

	if(tmp_min_rssi < DM_RxPathSelTable.SS_TH_low && disabled_rf_cnt < 2)
	{
		if((tmp_max_rssi - tmp_min_rssi) >= DM_RxPathSelTable.diff_TH)
		{
			DM_RxPathSelTable.rf_enable_rssi_th[min_rssi_index] = tmp_max_rssi+5;
			rtl8192_setBBreg(dev, rOFDM0_TRxPathEnable, 0x1<<min_rssi_index, 0x0);	
			rtl8192_setBBreg(dev, rOFDM1_TRxPathEnable, 0x1<<min_rssi_index, 0x0);	
			disabled_rf_cnt++;
		}
		if(DM_RxPathSelTable.cck_method == CCK_Rx_Version_1)
		{
			cck_default_Rx = max_rssi_index;
			cck_optional_Rx = sec_rssi_index;
			if(tmp_max_rssi)
				update_cck_rx_path = 1;
		}
	}

	if(update_cck_rx_path)
	{
		DM_RxPathSelTable.cck_Rx_path = (cck_default_Rx<<2)|(cck_optional_Rx);
		rtl8192_setBBreg(dev, rCCK0_AFESetting, 0x0f000000, DM_RxPathSelTable.cck_Rx_path);
	}
	
	if(DM_RxPathSelTable.disabledRF)
	{
		for(i=0; i<4; i++)
		{
			if((DM_RxPathSelTable.disabledRF>>i) & 0x1)	
			{
				if(tmp_max_rssi >= DM_RxPathSelTable.rf_enable_rssi_th[i])
				{
					rtl8192_setBBreg(dev, rOFDM0_TRxPathEnable, 0x1<<i, 0x1);	
					rtl8192_setBBreg(dev, rOFDM1_TRxPathEnable, 0x1<<i, 0x1);	
					DM_RxPathSelTable.rf_enable_rssi_th[i] = 100;
					disabled_rf_cnt--;
				}
			}
		}
	}
}

static	void	dm_check_rx_path_selection(struct net_device *dev)
{	
	struct r8192_priv *priv = rtllib_priv(dev);
	queue_delayed_work_rsl(priv->priv_wq,&priv->rfpath_check_wq,0);
}	


static void dm_init_fsync (struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);

	priv->rtllib->fsync_time_interval = 500;
	priv->rtllib->fsync_rate_bitmap = 0x0f000800;
	priv->rtllib->fsync_rssi_threshold = 30;
#ifdef RTL8190P
	priv->rtllib->bfsync_enable = true;
#elif defined RTL8192E || defined RTL8192SE
	priv->rtllib->bfsync_enable = false;
#endif
	priv->rtllib->fsync_multiple_timeinterval = 3;
	priv->rtllib->fsync_firstdiff_ratethreshold= 100;
	priv->rtllib->fsync_seconddiff_ratethreshold= 200;
	priv->rtllib->fsync_state = Default_Fsync;

#ifdef RTL8192SE
	priv->framesyncMonitor = 0;	
#elif defined RTL8192E || defined RTL8190P
	priv->framesyncMonitor = 1;	
#endif

	setup_timer(&priv->fsync_timer, dm_fsync_timer_callback,(unsigned long) dev);
}


static void dm_deInit_fsync(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	del_timer_sync(&priv->fsync_timer);
}

extern void dm_fsync_timer_callback(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct r8192_priv *priv = rtllib_priv((struct net_device *)data);
	u32 rate_index, rate_count = 0, rate_count_diff=0;
	bool		bSwitchFromCountDiff = false;
	bool		bDoubleTimeInterval = false;
	
	if(	priv->rtllib->state == RTLLIB_LINKED && 
		priv->rtllib->bfsync_enable &&
		(priv->rtllib->pHTInfo->IOTAction & HT_IOT_ACT_CDD_FSYNC))
	{	
		u32 rate_bitmap;
		for(rate_index = 0; rate_index <= 27; rate_index++)
		{
			rate_bitmap  = 1 << rate_index;
			if(priv->rtllib->fsync_rate_bitmap &  rate_bitmap)
		 		rate_count+= priv->stats.received_rate_histogram[1][rate_index];
		}	

		if(rate_count < priv->rate_record)
			rate_count_diff = 0xffffffff - rate_count + priv->rate_record;
		else	
			rate_count_diff = rate_count - priv->rate_record;
		if(rate_count_diff < priv->rateCountDiffRecord)
		{
			
			u32 DiffNum = priv->rateCountDiffRecord - rate_count_diff;
			if(DiffNum >= priv->rtllib->fsync_seconddiff_ratethreshold)
				priv->ContiuneDiffCount++;
			else
				priv->ContiuneDiffCount = 0;	
			
			if(priv->ContiuneDiffCount >=2)
			{
				bSwitchFromCountDiff = true;
				priv->ContiuneDiffCount = 0;					
			}				
		}	
		else
		{
			priv->ContiuneDiffCount = 0;
		}	

		if(rate_count_diff <= priv->rtllib->fsync_firstdiff_ratethreshold)
		{
			bSwitchFromCountDiff = true;
			priv->ContiuneDiffCount = 0;
		}	
		priv->rate_record = rate_count;
		priv->rateCountDiffRecord = rate_count_diff;
		RT_TRACE(COMP_HALDM, "rateRecord %d rateCount %d, rateCountdiff %d bSwitchFsync %d\n", priv->rate_record, rate_count, rate_count_diff , priv->bswitch_fsync);
		if(priv->undecorated_smoothed_pwdb > priv->rtllib->fsync_rssi_threshold && bSwitchFromCountDiff)
		{
			bDoubleTimeInterval = true;
			priv->bswitch_fsync = !priv->bswitch_fsync;
			if(priv->bswitch_fsync)
			{		
			#ifdef RTL8190P
				write_nic_byte(dev,0xC36, 0x00);
#elif defined RTL8192E
				write_nic_byte(dev,0xC36, 0x1c);
			#endif
				write_nic_byte(dev, 0xC3e, 0x90);
			}	
			else
			{
			#ifdef RTL8190P
				write_nic_byte(dev, 0xC36, 0x40);
			#else
				write_nic_byte(dev, 0xC36, 0x5c);
			#endif
				write_nic_byte(dev, 0xC3e, 0x96);
			}	
		}
		else if(priv->undecorated_smoothed_pwdb <= priv->rtllib->fsync_rssi_threshold)
		{
			if(priv->bswitch_fsync)
			{
				priv->bswitch_fsync  = false;		
			#ifdef RTL8190P
				write_nic_byte(dev, 0xC36, 0x40);
#elif defined RTL8192E
				write_nic_byte(dev, 0xC36, 0x5c);
			#endif
				write_nic_byte(dev, 0xC3e, 0x96);			
			}	
		}
		if(bDoubleTimeInterval){
			if(timer_pending(&priv->fsync_timer))
				del_timer_sync(&priv->fsync_timer);
			priv->fsync_timer.expires = jiffies + MSECS(priv->rtllib->fsync_time_interval*priv->rtllib->fsync_multiple_timeinterval);
			add_timer(&priv->fsync_timer);
		}
		else{
			if(timer_pending(&priv->fsync_timer))
				del_timer_sync(&priv->fsync_timer);
			priv->fsync_timer.expires = jiffies + MSECS(priv->rtllib->fsync_time_interval);
			add_timer(&priv->fsync_timer);
		}
	}	
	else
	{
		if(priv->bswitch_fsync)
		{
			priv->bswitch_fsync  = false;
		#ifdef RTL8190P
			write_nic_byte(dev, 0xC36, 0x40);
#elif defined RTL8192E
			write_nic_byte(dev, 0xC36, 0x5c);
		#endif
			write_nic_byte(dev, 0xC3e, 0x96);
		}	
		priv->ContiuneDiffCount = 0;
	#ifdef RTL8190P
		write_nic_dword(dev, rOFDM0_RxDetector2, 0x164052cd);
#elif defined RTL8192E
		write_nic_dword(dev, rOFDM0_RxDetector2, 0x465c52cd);
	#endif
	}
	RT_TRACE(COMP_HALDM, "ContiuneDiffCount %d\n", priv->ContiuneDiffCount);
	RT_TRACE(COMP_HALDM, "rateRecord %d rateCount %d, rateCountdiff %d bSwitchFsync %d\n", priv->rate_record, rate_count, rate_count_diff , priv->bswitch_fsync);
}

static void dm_StartHWFsync(struct net_device *dev)
{
	RT_TRACE(COMP_HALDM, "%s\n", __FUNCTION__);
#if defined RTL8192E 
	write_nic_dword(dev, rOFDM0_RxDetector2, 0x465c12cf);
	write_nic_byte(dev, 0xc3b, 0x41);
#elif defined RTL8192SE
	write_nic_byte(dev, rOFDM0_RxDetector3, 0x96);
#endif
}

static void dm_EndHWFsync(struct net_device *dev)
{
	RT_TRACE(COMP_HALDM,"%s\n", __FUNCTION__);
#if defined RTL8192E 
	write_nic_dword(dev, rOFDM0_RxDetector2, 0x465c52cd);
	write_nic_byte(dev, 0xc3b, 0x49);
#elif defined RTL8192SE
	write_nic_byte(dev, rOFDM0_RxDetector3, 0x94);
#endif
	
}

static void dm_EndSWFsync(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);

	RT_TRACE(COMP_HALDM, "%s\n", __FUNCTION__);
	del_timer_sync(&(priv->fsync_timer));

	if(priv->bswitch_fsync)
	{
		priv->bswitch_fsync  = false;

		#ifdef RTL8190P
			write_nic_byte(dev, 0xC36, 0x40);
#elif defined RTL8192E
		write_nic_byte(dev, 0xC36, 0x5c);
#endif

		write_nic_byte(dev, 0xC3e, 0x96);				
	}		
				
	priv->ContiuneDiffCount = 0;
#ifdef RTL8192E
	write_nic_dword(dev, rOFDM0_RxDetector2, 0x465c52cd);
#endif

}

static void dm_StartSWFsync(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	u32 			rateIndex;
	u32 			rateBitmap;	

	RT_TRACE(COMP_HALDM,"%s\n", __FUNCTION__);
	priv->rate_record = 0;
	priv->ContiuneDiffCount = 0;
	priv->rateCountDiffRecord = 0;
	priv->bswitch_fsync  = false;

	if(priv->rtllib->mode == WIRELESS_MODE_N_24G)
	{
		priv->rtllib->fsync_firstdiff_ratethreshold= 600;
		priv->rtllib->fsync_seconddiff_ratethreshold = 0xffff;
	}	
	else
	{
		priv->rtllib->fsync_firstdiff_ratethreshold= 200;
		priv->rtllib->fsync_seconddiff_ratethreshold = 200;
	}	
	for(rateIndex = 0; rateIndex <= 27; rateIndex++)
	{
		rateBitmap  = 1 << rateIndex;
		if(priv->rtllib->fsync_rate_bitmap &  rateBitmap)
			priv->rate_record += priv->stats.received_rate_histogram[1][rateIndex];
	}	
	if(timer_pending(&priv->fsync_timer))
		del_timer_sync(&priv->fsync_timer);
	priv->fsync_timer.expires = jiffies + MSECS(priv->rtllib->fsync_time_interval);
	add_timer(&priv->fsync_timer);
	
#ifdef RTL8192E
	write_nic_dword(dev, rOFDM0_RxDetector2, 0x465c12cd);		
#endif

}

void dm_check_fsync(struct net_device *dev)
{
#define	RegC38_Default				0
#define	RegC38_NonFsync_Other_AP	1
#define	RegC38_Fsync_AP_BCM		2
	struct r8192_priv *priv = rtllib_priv(dev);
	static u8		reg_c38_State=RegC38_Default;
	static u32	reset_cnt=0;
	
	RT_TRACE(COMP_HALDM, "RSSI %d TimeInterval %d MultipleTimeInterval %d\n", priv->rtllib->fsync_rssi_threshold, priv->rtllib->fsync_time_interval, priv->rtllib->fsync_multiple_timeinterval);	
	RT_TRACE(COMP_HALDM, "RateBitmap 0x%x FirstDiffRateThreshold %d SecondDiffRateThreshold %d\n", priv->rtllib->fsync_rate_bitmap, priv->rtllib->fsync_firstdiff_ratethreshold, priv->rtllib->fsync_seconddiff_ratethreshold);	
	
	if(	priv->rtllib->state == RTLLIB_LINKED && 
		(priv->rtllib->pHTInfo->IOTAction & HT_IOT_ACT_CDD_FSYNC))
	{
		if(priv->rtllib->bfsync_enable == 0)
		{
			switch(priv->rtllib->fsync_state)
			{
				case Default_Fsync:
					dm_StartHWFsync(dev);
					priv->rtllib->fsync_state = HW_Fsync;
					break;
				case SW_Fsync:
					dm_EndSWFsync(dev);
					dm_StartHWFsync(dev);
					priv->rtllib->fsync_state = HW_Fsync;
					break;
				case HW_Fsync:
				default:
					break;
			}	
		}
		else
		{
			switch(priv->rtllib->fsync_state)
			{
				case Default_Fsync:
					dm_StartSWFsync(dev);
					priv->rtllib->fsync_state = SW_Fsync;
					break;
				case HW_Fsync:
					dm_EndHWFsync(dev);
					dm_StartSWFsync(dev);
					priv->rtllib->fsync_state = SW_Fsync;
					break;
				case SW_Fsync:
				default:
					break;

			}	
		}
		if(priv->framesyncMonitor)
		{
			if(reg_c38_State != RegC38_Fsync_AP_BCM)
			{	
				#ifdef RTL8190P
					write_nic_byte(dev, rOFDM0_RxDetector3, 0x15);
				#else
					write_nic_byte(dev, rOFDM0_RxDetector3, 0x95);
				#endif
				
				reg_c38_State = RegC38_Fsync_AP_BCM;
			}
		}
	}
	else
	{
		switch(priv->rtllib->fsync_state)
		{
			case HW_Fsync:
				dm_EndHWFsync(dev);
				priv->rtllib->fsync_state = Default_Fsync;
				break;
			case SW_Fsync:
				dm_EndSWFsync(dev);
				priv->rtllib->fsync_state = Default_Fsync;
				break;
			case Default_Fsync:
			default:
				break;
		}
		
		if(priv->framesyncMonitor)
		{
			if(priv->rtllib->state == RTLLIB_LINKED)
			{
				if(priv->undecorated_smoothed_pwdb <= RegC38_TH)
				{
					if(reg_c38_State != RegC38_NonFsync_Other_AP)
					{
						#ifdef RTL8190P
							write_nic_byte(dev, rOFDM0_RxDetector3, 0x10);
						#else
							write_nic_byte(dev, rOFDM0_RxDetector3, 0x90);
						#endif
						
						reg_c38_State = RegC38_NonFsync_Other_AP;
					#if 0
						if (dev->HardwareType == HARDWARE_TYPE_RTL8190P)
							DbgPrint("Fsync is idle, rssi<=35, write 0xc38 = 0x%x \n", 0x10);
						else
							DbgPrint("Fsync is idle, rssi<=35, write 0xc38 = 0x%x \n", 0x90);
					#endif
					}
				}
				else if(priv->undecorated_smoothed_pwdb >= (RegC38_TH+5))
				{
					if(reg_c38_State)
					{
						write_nic_byte(dev, rOFDM0_RxDetector3, priv->framesync);
						reg_c38_State = RegC38_Default;
					}	
				}
			}
			else
			{
				if(reg_c38_State)
				{
					write_nic_byte(dev, rOFDM0_RxDetector3, priv->framesync);
					reg_c38_State = RegC38_Default;
				}
			}
		}
	}	
	if(priv->framesyncMonitor)
	{
		if(priv->reset_count != reset_cnt)
		{	
			write_nic_byte(dev, rOFDM0_RxDetector3, priv->framesync);
			reg_c38_State = RegC38_Default;
			reset_cnt = priv->reset_count;
		}
	}
	else
	{
		if(reg_c38_State)
		{
			write_nic_byte(dev, rOFDM0_RxDetector3, priv->framesync);
			reg_c38_State = RegC38_Default;
		}
	}		
}

#if 0
extern	s1Byte	DM_CheckLBusStatus(IN	PADAPTER	dev)
{
	PMGNT_INFO	pMgntInfo=&dev->MgntInfo;

#if (HAL_CODE_BASE & RTL819X)
	
#if (HAL_CODE_BASE == RTL8192)

#if( DEV_BUS_TYPE==PCI_INTERFACE)
	return true;
#endif

#if( DEV_BUS_TYPE==USB_INTERFACE)
	return true;
#endif

#endif	

#if (HAL_CODE_BASE == RTL8190)
	return true;
#endif	

#endif	
}	

#endif

extern void dm_shadow_init(struct net_device *dev)
{
	u8	page;
	u16	offset;

	for (page = 0; page < 5; page++)
		for (offset = 0; offset < 256; offset++)
		{
			dm_shadow[page][offset] = read_nic_byte(dev, offset+page*256);
		}

	for (page = 8; page < 11; page++)
		for (offset = 0; offset < 256; offset++)
			dm_shadow[page][offset] = read_nic_byte(dev, offset+page*256);

	for (page = 12; page < 15; page++)
		for (offset = 0; offset < 256; offset++)
			dm_shadow[page][offset] = read_nic_byte(dev, offset+page*256);

}   

/*---------------------------Define function prototype------------------------*/
static void dm_init_dynamic_txpower(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	
#ifdef RTL8192SE
	if(((priv->pFirmware->FirmwareVersion) >= 60) && 
		(priv->DM_Type == DM_Type_ByDriver)){
		priv->rtllib->bdynamic_txpower_enable = true; 
		RT_TRACE(COMP_INIT, "Dynamic Tx Power is enabled by Driver \n");
	} else {
		priv->rtllib->bdynamic_txpower_enable = false; 
		RT_TRACE(COMP_INIT, "Dynamic Tx Power is enabled by FW \n");
	}
	
	priv->LastDTPLvl = TxHighPwrLevel_Normal;
	priv->DynamicTxHighPowerLvl = TxHighPwrLevel_Normal;
	
#elif defined RTL8190P || defined RTL8192E
	priv->rtllib->bdynamic_txpower_enable = true;    
	priv->bLastDTPFlag_High = false;
	priv->bLastDTPFlag_Low = false;
	priv->bDynamicTxHighPower = false;
	priv->bDynamicTxLowPower = false;
#endif
}

#if defined RTL8190P || defined RTL8192E
static void dm_dynamic_txpower(struct net_device *dev)
{	
	struct r8192_priv *priv = rtllib_priv(dev);
	unsigned int txhipower_threshhold=0;	
        unsigned int txlowpower_threshold=0;
	if(priv->rtllib->bdynamic_txpower_enable != true)
	{
		priv->bDynamicTxHighPower = false;
		priv->bDynamicTxLowPower = false;
		return;
	}
        if((priv->rtllib->pHTInfo->IOTPeer == HT_IOT_PEER_ATHEROS) && (priv->rtllib->mode == IEEE_G)){
		txhipower_threshhold = TX_POWER_ATHEROAP_THRESH_HIGH;
		txlowpower_threshold = TX_POWER_ATHEROAP_THRESH_LOW;
	}
	else
	{
		txhipower_threshhold = TX_POWER_NEAR_FIELD_THRESH_HIGH;
		txlowpower_threshold = TX_POWER_NEAR_FIELD_THRESH_LOW; 
	}


	RT_TRACE(COMP_TXAGC,"priv->undecorated_smoothed_pwdb = %ld \n" , priv->undecorated_smoothed_pwdb);

	if(priv->rtllib->state == RTLLIB_LINKED)
	{
		if(priv->undecorated_smoothed_pwdb >= txhipower_threshhold)
		{
			priv->bDynamicTxHighPower = true;
			priv->bDynamicTxLowPower = false;
		}
		else
		{
			if(priv->undecorated_smoothed_pwdb < txlowpower_threshold && priv->bDynamicTxHighPower == true)
			{
				priv->bDynamicTxHighPower = false;
			}
			if(priv->undecorated_smoothed_pwdb < 35)
			{
				priv->bDynamicTxLowPower = true;
			}
			else if(priv->undecorated_smoothed_pwdb >= 40)
			{
				priv->bDynamicTxLowPower = false;
			}
		}
	}
	else
	{
		priv->bDynamicTxHighPower = false;
		priv->bDynamicTxLowPower = false;
	}

	if( (priv->bDynamicTxHighPower != priv->bLastDTPFlag_High ) ||
		(priv->bDynamicTxLowPower != priv->bLastDTPFlag_Low ) )
	{
		RT_TRACE(COMP_TXAGC,"SetTxPowerLevel8190()  channel = %d \n" , priv->rtllib->current_network.channel);
		
		rtl8192_phy_setTxPower(dev,priv->rtllib->current_network.channel); 
	}
	priv->bLastDTPFlag_High = priv->bDynamicTxHighPower;
	priv->bLastDTPFlag_Low = priv->bDynamicTxLowPower;

}	
#elif defined RTL8192SE
static void dm_dynamic_txpower(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	long				UndecoratedSmoothedPWDB;

	if( (priv->rtllib->bdynamic_txpower_enable != true) ||
			(priv->DMFlag & HAL_DM_HIPWR_DISABLE) ||
			priv->rtllib->pHTInfo->IOTAction & HT_IOT_ACT_DISABLE_HIGH_POWER) {
		priv->DynamicTxHighPowerLvl = TxHighPwrLevel_Normal;
		return;
	}

	if((!priv->rtllib->state != RTLLIB_LINKED) &&	
		(priv->EntryMinUndecoratedSmoothedPWDB == 0)) {
		RT_TRACE(COMP_POWER, "Not connected to any \n");
		priv->DynamicTxHighPowerLvl = TxHighPwrLevel_Normal;
		return;
	}
	
	if(priv->rtllib->state == RTLLIB_LINKED) {
		if(priv->OpMode == RT_OP_MODE_IBSS) {
			UndecoratedSmoothedPWDB = priv->EntryMinUndecoratedSmoothedPWDB;
			RT_TRACE(COMP_POWER, "AP Client PWDB = %ld \n", UndecoratedSmoothedPWDB);
		} else {
			UndecoratedSmoothedPWDB = priv->undecorated_smoothed_pwdb;
			RT_TRACE(COMP_POWER, "STA Default Port PWDB = %ld \n", UndecoratedSmoothedPWDB);
		}
	} else {
		UndecoratedSmoothedPWDB = priv->EntryMinUndecoratedSmoothedPWDB;
		RT_TRACE(COMP_POWER, "AP Ext Port PWDB = %ld \n", UndecoratedSmoothedPWDB);
	}
		
	if(UndecoratedSmoothedPWDB >= TX_POWER_NEAR_FIELD_THRESH_LVL2)	{
		priv->DynamicTxHighPowerLvl = TxHighPwrLevel_Level2;
		RT_TRACE(COMP_POWER, "TxHighPwrLevel_Level2 (TxPwr=0x0)\n");
	} else if((UndecoratedSmoothedPWDB < (TX_POWER_NEAR_FIELD_THRESH_LVL2-3)) &&
		(UndecoratedSmoothedPWDB >= TX_POWER_NEAR_FIELD_THRESH_LVL1) ) {
		priv->DynamicTxHighPowerLvl = TxHighPwrLevel_Level1;
		RT_TRACE(COMP_POWER, "TxHighPwrLevel_Level1 (TxPwr=0x10)\n");
	} else if(UndecoratedSmoothedPWDB < (TX_POWER_NEAR_FIELD_THRESH_LVL1-3)) {
		priv->DynamicTxHighPowerLvl = TxHighPwrLevel_Normal;
		RT_TRACE(COMP_POWER, "TxHighPwrLevel_Normal\n");
	}

	if( (priv->DynamicTxHighPowerLvl != priv->LastDTPLvl) ) {
		RT_TRACE(COMP_POWER, "PHY_SetTxPowerLevel8192S() Channel = %d \n" , priv->rtllib->current_network.channel);
		rtl8192_phy_setTxPower(dev, priv->rtllib->current_network.channel);
	}
	priv->LastDTPLvl = priv->DynamicTxHighPowerLvl;
}	
#endif

static void dm_check_txrateandretrycount(struct net_device * dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	struct rtllib_device* ieee = priv->rtllib;
	
#ifdef RTL8192SE
	static u8 LegacyRateSet[12] = {0x02 , 0x04 , 0x0b , 0x16 , 0x0c , 0x12 , 0x18 , 0x24 , 0x30 , 0x48 , 0x60 , 0x6c};
	u8 RateIdx = 0;
	RateIdx = read_nic_byte(dev, TX_RATE_REG);
	
	if(ieee->softmac_stats.CurrentShowTxate < 76)
		ieee->softmac_stats.CurrentShowTxate = (RateIdx<12)?(LegacyRateSet[RateIdx]):((RateIdx-12)|0x80);
	else
		ieee->softmac_stats.CurrentShowTxate = 0;
#else
	ieee->softmac_stats.CurrentShowTxate = read_nic_byte(dev, Current_Tx_Rate_Reg);
#endif

	ieee->softmac_stats.last_packet_rate = read_nic_byte(dev ,Initial_Tx_Rate_Reg);	

	ieee->softmac_stats.txretrycount = read_nic_dword(dev, Tx_Retry_Count_Reg);	
}

static void dm_send_rssi_tofw(struct net_device *dev)
{
#ifndef RTL8192SE
	DCMD_TXCMD_T			tx_cmd;
	struct r8192_priv *priv = rtllib_priv(dev);
	
	write_nic_byte(dev, DRIVER_RSSI, (u8)priv->undecorated_smoothed_pwdb);
	return;
	tx_cmd.Op		= TXCMD_SET_RX_RSSI;
	tx_cmd.Length	= 4;
	tx_cmd.Value		= priv->undecorated_smoothed_pwdb;

	cmpk_message_handle_tx(dev, (u8*)&tx_cmd, 
								DESC_PACKET_TYPE_INIT, sizeof(DCMD_TXCMD_T));
#endif
}

#if defined RTL8192SE
/*-----------------------------------------------------------------------------
 * Function:	dm_RefreshRateAdaptiveMask()
 *
 * Overview:	Update rate table mask according to rssi
 *
 * Input:		NONE
 *
 * Output:		NONE
 *
 * Return:		NONE
 *
 * Revised History:
 *	When		Who		Remark
 *	05/27/2009	hpfan	Create Version 0.  
 *
 *---------------------------------------------------------------------------*/
static void dm_RefreshRateAdaptiveMask(struct net_device *dev)
{
	struct r8192_priv *priv = rtllib_priv(dev);
	prate_adaptive	pRA = (prate_adaptive)&priv->rate_adaptive;
	u32	LowRSSIThreshForRA = 0, HighRSSIThreshForRA = 0;
	u8	rssi_level;
	
	if(IS_NIC_DOWN(priv)){
		RT_TRACE(COMP_RATE,"<---- dm_RefreshRateAdaptiveMask(): driver is going to unload\n");
		return;
	}

	if(!priv->rtllib->bUseRAMask){
		return;
	}

	if(priv->pFirmware->FirmwareVersion >= 61 && !priv->bInformFWDriverControlDM){
		RT_TRACE(COMP_RATE, "<---- dm_RefreshRateAdaptiveMask(): inform fw driver control dm\n");
		priv->rtllib->SetFwCmdHandler(dev, FW_CMD_CTRL_DM_BY_DRIVER);
		priv->bInformFWDriverControlDM = true;
	}
		
	if((priv->rtllib->state == RTLLIB_LINKED && (priv->rtllib->iw_mode == IW_MODE_INFRA)) 
#ifdef _RTL8192_EXT_PATCH_			
		|| ((priv->rtllib->state == RTLLIB_LINKED) && (priv->rtllib->iw_mode == IW_MODE_MESH) && (priv->rtllib->only_mesh == 0))
#endif		
		)
	{
		
		switch (pRA->PreRATRState){
			case DM_RATR_STA_HIGH:
				HighRSSIThreshForRA = 50;
				LowRSSIThreshForRA = 20;
				break;
			case DM_RATR_STA_MIDDLE:
				HighRSSIThreshForRA = 55;
				LowRSSIThreshForRA = 20;
				break;
			case DM_RATR_STA_LOW:
				HighRSSIThreshForRA = 50;
				LowRSSIThreshForRA = 25;
				break;
			default:
				HighRSSIThreshForRA = 50;
				LowRSSIThreshForRA = 20;
				break;
		}

		if(priv->undecorated_smoothed_pwdb > (long)HighRSSIThreshForRA){
			pRA->ratr_state = DM_RATR_STA_HIGH;
			rssi_level = 1;
		}
		else if(priv->undecorated_smoothed_pwdb > (long)LowRSSIThreshForRA){
			pRA->ratr_state = DM_RATR_STA_MIDDLE;
			rssi_level = 2;
		}else{
			pRA->ratr_state = DM_RATR_STA_LOW;
			rssi_level = 3;
		}
		if((pRA->PreRATRState != pRA->ratr_state) || ((pRA->PreRATRState == pRA->ratr_state) && (rssi_level != priv->rssi_level)))
		{
			RT_TRACE(COMP_RATE, "Target AP addr : "MAC_FMT"\n", MAC_ARG(priv->rtllib->current_network.bssid));
			RT_TRACE(COMP_RATE, "RSSI = %ld\n", priv->undecorated_smoothed_pwdb);
			RT_TRACE(COMP_RATE, "RSSI_LEVEL = %d\n", rssi_level);
			RT_TRACE(COMP_RATE, "PreState = %d, CurState = %d\n", pRA->PreRATRState, pRA->ratr_state);
			priv->rtllib->UpdateHalRAMaskHandler(
									dev,
									false,
									0,
									priv->rtllib->pHTInfo->PeerMimoPs,
									priv->rtllib->mode,
									priv->rtllib->pHTInfo->bCurTxBW40MHz,
									rssi_level);
			priv->rssi_level = rssi_level;
			pRA->PreRATRState = pRA->ratr_state;
		}
	}
	if((priv->rtllib->state == RTLLIB_LINKED) && (priv->rtllib->iw_mode == IW_MODE_ADHOC)){
		int	i;
		struct sta_info *pEntry;

		for(i = 0; i < PEER_MAX_ASSOC; i++){
			pEntry = priv->rtllib->peer_assoc_list[i];
			if(NULL != pEntry){
				pRA = &pEntry->rate_adaptive;
				switch (pRA->PreRATRState){
					case DM_RATR_STA_HIGH:
						HighRSSIThreshForRA = 50;
						LowRSSIThreshForRA = 20;
						break;
					case DM_RATR_STA_MIDDLE:
						HighRSSIThreshForRA = 55;
						LowRSSIThreshForRA = 20;
						break;
					case DM_RATR_STA_LOW:
						HighRSSIThreshForRA = 50;
						LowRSSIThreshForRA = 25;
						break;
					default:
						HighRSSIThreshForRA = 50;
						LowRSSIThreshForRA = 20;
						break;
				}

				if(pEntry->rssi_stat.UndecoratedSmoothedPWDB > HighRSSIThreshForRA){
					pRA->ratr_state = DM_RATR_STA_HIGH;
					rssi_level = 1;
				}else if(pEntry->rssi_stat.UndecoratedSmoothedPWDB > LowRSSIThreshForRA){
					pRA->ratr_state = DM_RATR_STA_MIDDLE;
					rssi_level = 2;
				}else{
					pRA->ratr_state = DM_RATR_STA_LOW;
					rssi_level = 3;
				}

				if(pRA->PreRATRState != pRA->ratr_state){
					RT_TRACE(COMP_RATE, "AsocEntry addr : "MAC_FMT"\n", MAC_ARG(pEntry->macaddr));
					RT_TRACE(COMP_RATE, "RSSI = %ld\n", pEntry->rssi_stat.UndecoratedSmoothedPWDB);
					RT_TRACE(COMP_RATE, "RSSI_LEVEL = %d\n", rssi_level);
					RT_TRACE(COMP_RATE, "PreState = %d, CurState = %d\n", pRA->PreRATRState, pRA->ratr_state);
					priv->rtllib->UpdateHalRAMaskHandler(
											dev,
											false,
											pEntry->aid+1,
											pEntry->htinfo.MimoPs,
											pEntry->wireless_mode,
											pEntry->htinfo.bCurTxBW40MHz,
											rssi_level);
					pRA->PreRATRState = pRA->ratr_state;
				}

			}
		}
	}
#ifdef _RTL8192_EXT_PATCH_			
	if(priv->rtllib->iw_mode == IW_MODE_MESH)
	{
		if(priv->mshobj->ext_refresh_rate_adaptive_mask)
			priv->mshobj->ext_refresh_rate_adaptive_mask(priv);
	}
#endif
}

void Adhoc_InitRateAdaptive(struct net_device *dev,struct sta_info  *pEntry)
{
	prate_adaptive	pRA = (prate_adaptive)&pEntry->rate_adaptive;
	struct r8192_priv *priv = rtllib_priv(dev);

	pRA->ratr_state = DM_RATR_STA_MAX;
	pRA->high2low_rssi_thresh_for_ra = RateAdaptiveTH_High;
	pRA->low2high_rssi_thresh_for_ra20M = RateAdaptiveTH_Low_20M+5;
	pRA->low2high_rssi_thresh_for_ra40M = RateAdaptiveTH_Low_40M+5;

	pRA->high_rssi_thresh_for_ra = RateAdaptiveTH_High+5;
	pRA->low_rssi_thresh_for_ra20M = RateAdaptiveTH_Low_20M;
	pRA->low_rssi_thresh_for_ra40M = RateAdaptiveTH_Low_40M;
	
	if (priv->rf_type == RF_2T4R)
	{
		/* 2008/01/11 MH Modify 2T RATR table for different RSSI. */
		pRA->upper_rssi_threshold_ratr		= 	0x8f0f0000;
		pRA->middle_rssi_threshold_ratr		= 	0x8d0ff000;
		pRA->low_rssi_threshold_ratr		= 	0x8f0ff003;
		pRA->low_rssi_threshold_ratr_40M	= 	0x8f0ff007;
		pRA->low_rssi_threshold_ratr_20M	= 	0x8f0ff003;
	}
	else if (priv->rf_type == RF_1T2R)
	{
		pRA->upper_rssi_threshold_ratr		= 	0x000f0000;		
		pRA->middle_rssi_threshold_ratr		= 	0x000ff000;
		pRA->low_rssi_threshold_ratr		= 	0x000ff003;
		pRA->low_rssi_threshold_ratr_40M	= 	0x000ff007;
		pRA->low_rssi_threshold_ratr_20M	= 	0x000ff003;
	}
	
}	


void Adhoc_InitRateAdaptiveState(struct net_device *dev,struct sta_info  *pEntry)
{
	prate_adaptive	pRA = (prate_adaptive)&pEntry->rate_adaptive;

	pRA->ratr_state = DM_RATR_STA_MAX;
	pRA->PreRATRState = DM_RATR_STA_MAX;
}

#if 0
static void Adhoc_dm_CheckRateAdaptive(struct net_device * dev)
{
	struct r8192_priv 			*priv = rtllib_priv(dev);
	struct rtllib_device 	*ieee = priv->rtllib;
	prate_adaptive			pRA;
	u32						currentRATR, targetRATR = 0;
	u32						LowRSSIThreshForRA = 0, HighRSSIThreshForRA = 0;
	bool						bShortGIEnabled = false;
	u8 						i = 0;
	struct sta_info 			*pEntry = NULL;
	
	if(!priv->up)
	{
		RT_TRACE(COMP_RATE, "<---- AP_dm_CheckRateAdaptive(): driver is going to unload\n");
		return;
	}

	for(i=0;i<PEER_MAX_ASSOC; i++)
	{
		pEntry = ieee->peer_assoc_list[i];
		if(NULL != pEntry)
		{
			pRA = (prate_adaptive)&pEntry->rate_adaptive;
			if(pRA->rate_adaptive_disabled)
				continue;			
			if((pEntry->wireless_mode!=WIRELESS_MODE_N_24G) && (pEntry->wireless_mode != WIRELESS_MODE_N_5G))
				continue;
			bShortGIEnabled = (pEntry->htinfo.bCurTxBW40MHz && priv->rtllib->pHTInfo->bCurShortGI40MHz && pEntry->htinfo.bCurShortGI40MHz) |
				(!pEntry->htinfo.bCurTxBW40MHz && priv->rtllib->pHTInfo->bCurShortGI20MHz && pEntry->htinfo.bCurShortGI20MHz);
			pRA->upper_rssi_threshold_ratr =
				(pRA->upper_rssi_threshold_ratr & (~BIT31)) | ((bShortGIEnabled)? BIT31:0) ;

			pRA->middle_rssi_threshold_ratr = 
				(pRA->middle_rssi_threshold_ratr & (~BIT31)) | ((bShortGIEnabled)? BIT31:0) ;
			

			if (pEntry->htinfo.bBw40MHz)
			{
				pRA->low_rssi_threshold_ratr = 
					(pRA->low_rssi_threshold_ratr_40M & (~BIT31)) | ((bShortGIEnabled)? BIT31:0) ;
			}
			else
			{
				pRA->low_rssi_threshold_ratr = 
					(pRA->low_rssi_threshold_ratr_20M & (~BIT31)) | ((bShortGIEnabled)? BIT31:0) ;
			}
			if (pRA->ratr_state == DM_RATR_STA_HIGH)
			{
				HighRSSIThreshForRA 	= pRA->high2low_rssi_thresh_for_ra;
				LowRSSIThreshForRA	= 
					(priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)?
					(pRA->low_rssi_thresh_for_ra40M):(pRA->low_rssi_thresh_for_ra20M);
			}
			else if (pRA->ratr_state == DM_RATR_STA_LOW)
			{
				HighRSSIThreshForRA	= pRA->high_rssi_thresh_for_ra;
				LowRSSIThreshForRA 	= 
					(priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)?
					(pRA->low2high_rssi_thresh_for_ra40M):(pRA->low2high_rssi_thresh_for_ra20M);
			}
			else
			{
				HighRSSIThreshForRA	= pRA->high_rssi_thresh_for_ra;
				LowRSSIThreshForRA	= 
					(priv->CurrentChannelBW != HT_CHANNEL_WIDTH_20)?
					(pRA->low_rssi_thresh_for_ra40M):(pRA->low_rssi_thresh_for_ra20M);
			}
			if(priv->undecorated_smoothed_pwdb >= (int)HighRSSIThreshForRA)
			{
				pRA->ratr_state = DM_RATR_STA_HIGH;
				targetRATR = pRA->upper_rssi_threshold_ratr;
			}
			else if(priv->undecorated_smoothed_pwdb >= (int)LowRSSIThreshForRA)
			{
				pRA->ratr_state = DM_RATR_STA_MIDDLE;
				targetRATR = pRA->middle_rssi_threshold_ratr;
			}
			else
			{
				pRA->ratr_state = DM_RATR_STA_LOW;
				targetRATR = pRA->low_rssi_threshold_ratr;
			}
			currentRATR = read_nic_dword(dev, pEntry->ratr_index*4 + RATR0);
			if( targetRATR !=  currentRATR )
			{
				if(priv->rf_type == RF_1T2R)	
				{	
					targetRATR &=~ (RATE_ALL_OFDM_2SS);
				}
				printk("<<<<<<<<<<<currentRATR = %x, targetRATR = %x\n", currentRATR, targetRATR);				
				write_nic_dword(dev, RATR0+pEntry->ratr_index*4, targetRATR);
				write_nic_byte(dev, UFWP, 1);
				pRA->last_ratr = targetRATR;
			}
		}
	}
	
}	
#endif

#endif
/*---------------------------Define function prototype------------------------*/

