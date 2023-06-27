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
#include "rtllib.h"
#include "rtl819x_HT.h"
u8 MCS_FILTER_ALL[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

u8 MCS_FILTER_1SS[16] = {0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

u16 MCS_DATA_RATE[2][2][77] = 
	{	{	{13, 26, 39, 52, 78, 104, 117, 130, 26, 52, 78 ,104, 156, 208, 234, 260,
			39, 78, 117, 234, 312, 351, 390, 52, 104, 156, 208, 312, 416, 468, 520, 
			0, 78, 104, 130, 117, 156, 195, 104, 130, 130, 156, 182, 182, 208, 156, 195,
			195, 234, 273, 273, 312, 130, 156, 181, 156, 181, 208, 234, 208, 234, 260, 260, 
			286, 195, 234, 273, 234, 273, 312, 351, 312, 351, 390, 390, 429},			
			{14, 29, 43, 58, 87, 116, 130, 144, 29, 58, 87, 116, 173, 231, 260, 289, 
			43, 87, 130, 173, 260, 347, 390, 433, 58, 116, 173, 231, 347, 462, 520, 578, 
			0, 87, 116, 144, 130, 173, 217, 116, 144, 144, 173, 202, 202, 231, 173, 217, 
			217, 260, 303, 303, 347, 144, 173, 202, 173, 202, 231, 260, 231, 260, 289, 289, 
			318, 217, 260, 303, 260, 303, 347, 390, 347, 390, 433, 433, 477}	},		
		{	{27, 54, 81, 108, 162, 216, 243, 270, 54, 108, 162, 216, 324, 432, 486, 540, 
			81, 162, 243, 324, 486, 648, 729, 810, 108, 216, 324, 432, 648, 864, 972, 1080, 
			12, 162, 216, 270, 243, 324, 405, 216, 270, 270, 324, 378, 378, 432, 324, 405, 
			405, 486, 567, 567, 648, 270, 324, 378, 324, 378, 432, 486, 432, 486, 540, 540, 
			594, 405, 486, 567, 486, 567, 648, 729, 648, 729, 810, 810, 891}, 	
			{30, 60, 90, 120, 180, 240, 270, 300, 60, 120, 180, 240, 360, 480, 540, 600, 
			90, 180, 270, 360, 540, 720, 810, 900, 120, 240, 360, 480, 720, 960, 1080, 1200, 
			13, 180, 240, 300, 270, 360, 450, 240, 300, 300, 360, 420, 420, 480, 360, 450, 
			450, 540, 630, 630, 720, 300, 360, 420, 360, 420, 480, 540, 480, 540, 600, 600, 
			660, 450, 540, 630, 540, 630, 720, 810, 720, 810, 900, 900, 990}	}	
	};

static u8 UNKNOWN_BORADCOM[3] = {0x00, 0x14, 0xbf};
static u8 LINKSYSWRT330_LINKSYSWRT300_BROADCOM[3] = {0x00, 0x1a, 0x70};
static u8 LINKSYSWRT350_LINKSYSWRT150_BROADCOM[3] = {0x00, 0x1d, 0x7e};
static u8 BELKINF5D8233V1_RALINK[3] = {0x00, 0x17, 0x3f};	
static u8 BELKINF5D82334V3_RALINK[3] = {0x00, 0x1c, 0xdf};
static u8 PCI_RALINK[3] = {0x00, 0x90, 0xcc};
static u8 EDIMAX_RALINK[3] = {0x00, 0x0e, 0x2e};
static u8 AIRLINK_RALINK[3] = {0x00, 0x18, 0x02};
static u8 DLINK_ATHEROS_1[3] = {0x00, 0x1c, 0xf0};
static u8 DLINK_ATHEROS_2[3] = {0x00, 0x21, 0x91};
static u8 CISCO_BROADCOM[3] = {0x00, 0x17, 0x94};
#if defined(RTL8192SU)
static u8 NETGEAR_BROADCOM[3] = {0x00, 0x1f, 0x33};
#endif
static u8 LINKSYS_MARVELL_4400N[3] = {0x00, 0x14, 0xa4}; 
void HTUpdateDefaultSetting(struct rtllib_device* ieee)
{
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	
#ifdef RTL8192CE
	pHTInfo->bRDGEnable = 0;
#endif
	
	pHTInfo->bRegShortGI20MHz= 1;
	pHTInfo->bRegShortGI40MHz= 1;

	pHTInfo->bRegBW40MHz = 1;

	if(pHTInfo->bRegBW40MHz)
		pHTInfo->bRegSuppCCK = 1;
	else
		pHTInfo->bRegSuppCCK = true;

	pHTInfo->nAMSDU_MaxSize = 7935UL;
	pHTInfo->bAMSDU_Support = 0;

	pHTInfo->bAMPDUEnable = 1; 
	pHTInfo->AMPDU_Factor = 2; 
	pHTInfo->MPDU_Density = 0;

	pHTInfo->SelfMimoPs = 3;
	if(pHTInfo->SelfMimoPs == 2)
		pHTInfo->SelfMimoPs = 3;
	ieee->bTxDisableRateFallBack = 0;
	ieee->bTxUseDriverAssingedRate = 0;	

	ieee->bTxEnableFwCalcDur = 1;

	pHTInfo->bRegRT2RTAggregation = 1;
	
	pHTInfo->bRegRxReorderEnable = 1;
	pHTInfo->RxReorderWinSize = 64;
	pHTInfo->RxReorderPendingTime = 30;

#ifdef USB_TX_DRIVER_AGGREGATION_ENABLE
	pHTInfo->UsbTxAggrNum = 4;
#endif
#ifdef USB_RX_AGGREGATION_SUPPORT
#ifdef RTL8192SU
	pHTInfo->UsbRxFwAggrEn = 1;
	pHTInfo->UsbRxFwAggrPageNum = 48;
	pHTInfo->UsbRxFwAggrPacketNum = 8;
	pHTInfo->UsbRxFwAggrTimeout = 4;
	pHTInfo->UsbRxPageSize= 128;
#else
	pHTInfo->UsbRxFwAggrEn = 1;
	pHTInfo->UsbRxFwAggrPageNum = 24;
	pHTInfo->UsbRxFwAggrPacketNum = 8;
	pHTInfo->UsbRxFwAggrTimeout = 8; 
#endif
#endif
	

}
void HTDebugHTCapability(u8* CapIE, u8* TitleString )
{
	
	static u8	EWC11NHTCap[] = {0x00, 0x90, 0x4c, 0x33};	
	PHT_CAPABILITY_ELE 		pCapELE;
	
	if(!memcmp(CapIE, EWC11NHTCap, sizeof(EWC11NHTCap)))
	{
		RTLLIB_DEBUG(RTLLIB_DL_HT, "EWC IE in %s()\n", __FUNCTION__);
		pCapELE = (PHT_CAPABILITY_ELE)(&CapIE[4]);		
	}else
		pCapELE = (PHT_CAPABILITY_ELE)(&CapIE[0]);		
	
	RTLLIB_DEBUG(RTLLIB_DL_HT, "<Log HT Capability>. Called by %s\n", TitleString );

	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tSupported Channel Width = %s\n", (pCapELE->ChlWidth)?"20MHz": "20/40MHz");
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tSupport Short GI for 20M = %s\n", (pCapELE->ShortGI20Mhz)?"YES": "NO");
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tSupport Short GI for 40M = %s\n", (pCapELE->ShortGI40Mhz)?"YES": "NO");
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tSupport TX STBC = %s\n", (pCapELE->TxSTBC)?"YES": "NO");
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tMax AMSDU Size = %s\n", (pCapELE->MaxAMSDUSize)?"3839": "7935");
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tSupport CCK in 20/40 mode = %s\n", (pCapELE->DssCCk)?"YES": "NO");
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tMax AMPDU Factor = %d\n", pCapELE->MaxRxAMPDUFactor);
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tMPDU Density = %d\n", pCapELE->MPDUDensity);
	RTLLIB_DEBUG(RTLLIB_DL_HT,  "\tMCS Rate Set = [%x][%x][%x][%x][%x]\n", pCapELE->MCS[0],\
				pCapELE->MCS[1], pCapELE->MCS[2], pCapELE->MCS[3], pCapELE->MCS[4]);
	return;
		
}
void HTDebugHTInfo(u8*	InfoIE, u8* TitleString)
{
	
	static u8	EWC11NHTInfo[] = {0x00, 0x90, 0x4c, 0x34};	
	PHT_INFORMATION_ELE		pHTInfoEle;
	
	if(!memcmp(InfoIE, EWC11NHTInfo, sizeof(EWC11NHTInfo)))
	{
		RTLLIB_DEBUG(RTLLIB_DL_HT, "EWC IE in %s()\n", __FUNCTION__);
		pHTInfoEle = (PHT_INFORMATION_ELE)(&InfoIE[4]);			
	}else
		pHTInfoEle = (PHT_INFORMATION_ELE)(&InfoIE[0]);
	
		
	RTLLIB_DEBUG(RTLLIB_DL_HT, "<Log HT Information Element>. Called by %s\n", TitleString);

	RTLLIB_DEBUG(RTLLIB_DL_HT, "\tPrimary channel = %d\n", pHTInfoEle->ControlChl);
	RTLLIB_DEBUG(RTLLIB_DL_HT, "\tSenondary channel =");
	switch(pHTInfoEle->ExtChlOffset)
	{
		case 0:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "Not Present\n");		
			break;
		case 1:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "Upper channel\n");
			break;
		case 2:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "Reserved. Eooro!!!\n");		
			break;
		case 3:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "Lower Channel\n");		
			break;
	}
	RTLLIB_DEBUG(RTLLIB_DL_HT, "\tRecommended channel width = %s\n", (pHTInfoEle->RecommemdedTxWidth)?"20Mhz": "40Mhz");

	RTLLIB_DEBUG(RTLLIB_DL_HT, "\tOperation mode for protection = ");
	switch(pHTInfoEle->OptMode)
	{
		case 0:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "No Protection\n");		
			break;
		case 1:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "HT non-member protection mode\n");
			break;
		case 2:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "Suggest to open protection\n");		
			break;
		case 3:
			RTLLIB_DEBUG(RTLLIB_DL_HT, "HT mixed mode\n");		
			break;
	}

	RTLLIB_DEBUG(RTLLIB_DL_HT, "\tBasic MCS Rate Set = [%x][%x][%x][%x][%x]\n", pHTInfoEle->BasicMSC[0],\
				pHTInfoEle->BasicMSC[1], pHTInfoEle->BasicMSC[2], pHTInfoEle->BasicMSC[3], pHTInfoEle->BasicMSC[4]);
	return;
}

bool IsHTHalfNmode40Bandwidth(struct rtllib_device* ieee)
{
	bool			retValue = false;
	PRT_HIGH_THROUGHPUT	 pHTInfo = ieee->pHTInfo;

	if(pHTInfo->bCurrentHTSupport == false )	
		retValue = false;
	else if(pHTInfo->bRegBW40MHz == false)	
		retValue = false;
	else if(!ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev)) 	
		retValue = false;
	else if(((PHT_CAPABILITY_ELE)(pHTInfo->PeerHTCapBuf))->ChlWidth) 
		retValue = true;
	else
		retValue = false;

	return retValue;	
}

bool IsHTHalfNmodeSGI(struct rtllib_device* ieee, bool is40MHz)
{
	bool			retValue = false;
	PRT_HIGH_THROUGHPUT	 pHTInfo = ieee->pHTInfo;

	if(pHTInfo->bCurrentHTSupport == false )	
		retValue = false;
	else if(!ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev)) 	
		retValue = false;
	else if(is40MHz) 
	{
		if(((PHT_CAPABILITY_ELE)(pHTInfo->PeerHTCapBuf))->ShortGI40Mhz) 
			retValue = true;
		else
			retValue = false;
	}
	else
	{
		if(((PHT_CAPABILITY_ELE)(pHTInfo->PeerHTCapBuf))->ShortGI20Mhz) 
			retValue = true;
		else
			retValue = false;
	}	

	return retValue;	
}

u16 HTHalfMcsToDataRate(struct rtllib_device* ieee, 	u8	nMcsRate)
{
	
	u8	is40MHz;
	u8	isShortGI;
	
	is40MHz  =  (IsHTHalfNmode40Bandwidth(ieee))?1:0;
	isShortGI = (IsHTHalfNmodeSGI(ieee, is40MHz))? 1:0;
						
	return MCS_DATA_RATE[is40MHz][isShortGI][(nMcsRate&0x7f)];
}


u16 HTMcsToDataRate( struct rtllib_device* ieee, u8 nMcsRate)
{
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	
	u8	is40MHz = (pHTInfo->bCurBW40MHz)?1:0;
	u8	isShortGI = (pHTInfo->bCurBW40MHz)?
						((pHTInfo->bCurShortGI40MHz)?1:0):
						((pHTInfo->bCurShortGI20MHz)?1:0);
	return MCS_DATA_RATE[is40MHz][isShortGI][(nMcsRate&0x7f)];
}

u16  TxCountToDataRate( struct rtllib_device* ieee, u8 nDataRate)
{
	u16		CCKOFDMRate[12] = {0x02 , 0x04 , 0x0b , 0x16 , 0x0c , 0x12 , 0x18 , 0x24 , 0x30 , 0x48 , 0x60 , 0x6c};
	u8	is40MHz = 0;
	u8	isShortGI = 0;
	
	if(nDataRate < 12)
	{
		return CCKOFDMRate[nDataRate];
	}
	else
	{
		if (nDataRate >= 0x10 && nDataRate <= 0x1f)
		{
			is40MHz = 0;
			isShortGI = 0;

		}
		else if(nDataRate >=0x20  && nDataRate <= 0x2f ) 
		{
			is40MHz = 1;
			isShortGI = 0;		

		}
		else if(nDataRate >= 0x30  && nDataRate <= 0x3f )  
		{
			is40MHz = 0;
			isShortGI = 1;		

		}
		else if(nDataRate >= 0x40  && nDataRate <= 0x4f ) 
		{
			is40MHz = 1;
			isShortGI = 1;		

		}
		return MCS_DATA_RATE[is40MHz][isShortGI][nDataRate&0xf];
	}
}



bool IsHTHalfNmodeAPs(struct rtllib_device* ieee)
{
	bool			retValue = false;
	struct rtllib_network* net = &ieee->current_network;
#if 0
	if(ieee->bHalfNMode == false)
		retValue = false;		
	else
#endif		
	if((memcmp(net->bssid, BELKINF5D8233V1_RALINK, 3)==0) ||
		     (memcmp(net->bssid, BELKINF5D82334V3_RALINK, 3)==0) ||
		     (memcmp(net->bssid, PCI_RALINK, 3)==0) ||
		     (memcmp(net->bssid, EDIMAX_RALINK, 3)==0) ||
		     (memcmp(net->bssid, AIRLINK_RALINK, 3)==0) ||
		     (net->ralink_cap_exist))
		retValue = true;
	else if((memcmp(net->bssid, UNKNOWN_BORADCOM, 3)==0) ||
    		    (memcmp(net->bssid, LINKSYSWRT330_LINKSYSWRT300_BROADCOM, 3)==0)||
    		    (memcmp(net->bssid, LINKSYSWRT350_LINKSYSWRT150_BROADCOM, 3)==0)||
    		    (net->broadcom_cap_exist))
    		  retValue = true;
	else if(net->bssht.bdRT2RTAggregation)
		retValue = true;
	else
		retValue = false;

	return retValue;
}

void HTIOTPeerDetermine(struct rtllib_device* ieee)
{
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	struct rtllib_network* net = &ieee->current_network;
	if(net->bssht.bdRT2RTAggregation){
		pHTInfo->IOTPeer = HT_IOT_PEER_REALTEK;
		if(net->bssht.RT2RT_HT_Mode & RT_HT_CAP_USE_92SE){
			pHTInfo->IOTPeer = HT_IOT_PEER_REALTEK_92SE;
		}
		if(net->bssht.RT2RT_HT_Mode & RT_HT_CAP_USE_SOFTAP){
			pHTInfo->IOTPeer = HT_IOT_PEER_92U_SOFTAP;
		}
	}
	else if(net->broadcom_cap_exist)
		pHTInfo->IOTPeer = HT_IOT_PEER_BROADCOM;
	else if((memcmp(net->bssid, UNKNOWN_BORADCOM, 3)==0) ||
			(memcmp(net->bssid, LINKSYSWRT330_LINKSYSWRT300_BROADCOM, 3)==0)||
			(memcmp(net->bssid, LINKSYSWRT350_LINKSYSWRT150_BROADCOM, 3)==0)/*||
			(memcmp(net->bssid, NETGEAR834Bv2_BROADCOM, 3)==0) */)
		pHTInfo->IOTPeer = HT_IOT_PEER_BROADCOM;
	else if((memcmp(net->bssid, BELKINF5D8233V1_RALINK, 3)==0) ||
			(memcmp(net->bssid, BELKINF5D82334V3_RALINK, 3)==0) ||
			(memcmp(net->bssid, PCI_RALINK, 3)==0) ||
			(memcmp(net->bssid, EDIMAX_RALINK, 3)==0) || 
			(memcmp(net->bssid, AIRLINK_RALINK, 3)==0) ||
			 net->ralink_cap_exist)
		pHTInfo->IOTPeer = HT_IOT_PEER_RALINK;
	else if((net->atheros_cap_exist )|| 
		(memcmp(net->bssid, DLINK_ATHEROS_1, 3) == 0)||
		(memcmp(net->bssid, DLINK_ATHEROS_2, 3) == 0))
		pHTInfo->IOTPeer = HT_IOT_PEER_ATHEROS;
	else if((memcmp(net->bssid, CISCO_BROADCOM, 3)==0)||net->cisco_cap_exist)
		pHTInfo->IOTPeer = HT_IOT_PEER_CISCO;
	else if ((memcmp(net->bssid, LINKSYS_MARVELL_4400N, 3) == 0) ||
		  net->marvell_cap_exist)
		pHTInfo->IOTPeer = HT_IOT_PEER_MARVELL;
	else
		pHTInfo->IOTPeer = HT_IOT_PEER_UNKNOWN;

	RTLLIB_DEBUG(RTLLIB_DL_IOT, "Joseph debug!! IOTPEER: %x\n", pHTInfo->IOTPeer);
}

u8 HTIOTActIsDisableMCS14(struct rtllib_device* ieee, u8* PeerMacAddr)
{
	u8 ret = 0;
#if 0
#if (HAL_CODE_BASE==RTL8192 && DEV_BUS_TYPE==USB_INTERFACE)
	if((memcmp(PeerMacAddr, UNKNOWN_BORADCOM, 3)==0) ||
    		(memcmp(PeerMacAddr, LINKSYSWRT330_LINKSYSWRT300_BROADCOM, 3)==0)	
	    )
	{
		ret = 1;
	}

		
	if(pHTInfo->bCurrentRT2RTAggregation)
	{
		ret = 1;
	}
#endif
#endif		
	return ret;
 }


bool HTIOTActIsDisableMCS15(struct rtllib_device* ieee)
{
	bool retValue = false;

#if defined(RTL8192U)
	if(ieee->current_network.bssht.bdBandWidth == HT_CHANNEL_WIDTH_20_40)
	retValue = true;
	else
		retValue = false;
#endif

	
	return retValue;
}

bool HTIOTActIsDisableMCSTwoSpatialStream(struct rtllib_device* ieee)
{
	bool retValue = false;
#ifdef RTL8192U
	struct rtllib_network* net = &ieee->current_network;

	if((ieee->pHTInfo->bCurrentHTSupport == true) && (ieee->pairwise_key_type == KEY_TYPE_CCMP))
	{
		if((memcmp(net->bssid, BELKINF5D8233V1_RALINK, 3)==0) ||
				(memcmp(net->bssid, PCI_RALINK, 3)==0) ||
				(memcmp(net->bssid, EDIMAX_RALINK, 3)==0))
		{
			retValue = false;
		}
	}
#endif
#if defined(RTL8192SU) || defined RTL8192CE
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	if (ieee->rtllib_ap_sec_type && 
		(ieee->rtllib_ap_sec_type(ieee)&(SEC_ALG_WEP|SEC_ALG_TKIP)))
	{
		if( (pHTInfo->IOTPeer != HT_IOT_PEER_ATHEROS) &&
			(pHTInfo->IOTPeer != HT_IOT_PEER_UNKNOWN) &&
			(pHTInfo->IOTPeer != HT_IOT_PEER_MARVELL) &&
			(pHTInfo->IOTPeer != HT_IOT_PEER_REALTEK_92SE) &&
			(pHTInfo->IOTPeer != HT_IOT_PEER_RALINK) )
			retValue = true;
	}
#elif defined(RTL8192SE) 
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	if (ieee->rtllib_ap_sec_type && 
		(ieee->rtllib_ap_sec_type(ieee)&SEC_ALG_TKIP)) {
			if(pHTInfo->IOTPeer == HT_IOT_PEER_RALINK){
				retValue = true;
			}
		}
#endif
	return retValue;
}

u8 HTIOTActIsDisableEDCATurbo(struct rtllib_device* 	ieee, u8* PeerMacAddr)
{
	u8	retValue = false;	
	
	return retValue;
#if 0
	if((memcmp(PeerMacAddr, UNKNOWN_BORADCOM, 3)==0)|| 
		(memcmp(PeerMacAddr, LINKSYSWRT330_LINKSYSWRT300_BROADCOM, 3)==0)||
		(memcmp(PeerMacAddr, LINKSYSWRT350_LINKSYSWRT150_BROADCOM, 3)==0))

	{
		retValue = 1;	
	}

	return retValue;
#endif
}


bool HTIOTActIsEnableBETxOPLimit(struct rtllib_device* ieee)
{
	bool	retValue = false;

#if defined RTL8192SU 
	if(ieee->mode == IEEE_G)
		retValue = true;
#elif defined RTL8192CE
	if(ieee->mode == IEEE_G ||
		(ieee->rtllib_ap_sec_type(ieee)&(SEC_ALG_WEP|SEC_ALG_TKIP)))
		retValue = true;
#endif

	return retValue;
}


u8 HTIOTActIsMgntUseCCK6M(struct rtllib_device* ieee,struct rtllib_network *network)
{
	u8	retValue = 0;

		
#if (defined RTL8192U || defined RTL8192E || defined RTL8190P)	
	{		
	if(ieee->pHTInfo->IOTPeer == HT_IOT_PEER_BROADCOM)	
	{
		retValue = 1;
	}	
	}
#endif

	return retValue;
}

u8
HTIOTActWAIOTBroadcom(struct rtllib_device* ieee)
{
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	u8		retValue = false;
	u8		boundary=59;

	pHTInfo->bWAIotBroadcom = false;
	if(ieee->pHTInfo->IOTPeer == HT_IOT_PEER_BROADCOM)	
	{	
		if(ieee->current_network.bssht.bdBandWidth == HT_CHANNEL_WIDTH_20_40)		
		{	
			if(!(pHTInfo->bCurBW40MHz))
			{	
				if(ieee->current_network.mode != WIRELESS_MODE_B)
				{
					pHTInfo->bWAIotBroadcom = true;
					
					if(ieee->b_customer_lenovo_id == true)
						boundary = 30;

					if( ieee->current_network.RSSI >= boundary)
						retValue = true;
				}
			}else{
				;
			}
		}
	}
	return retValue;
}

u8 HTIOTActIsForcedCTS2Self(struct rtllib_device *ieee, struct rtllib_network *network)
{
	u8 	retValue = 0;
#if (defined RTL8192SE || defined RTL8192SU || defined RTL8192CE)
	if((ieee->pHTInfo->IOTPeer == HT_IOT_PEER_MARVELL) ||(ieee->pHTInfo->IOTPeer == HT_IOT_PEER_ATHEROS) )
#else
	if(ieee->pHTInfo->IOTPeer == HT_IOT_PEER_MARVELL)
#endif
	{
		retValue = 1;
	}
	
	return retValue;
}

u8 HTIOTActIsForcedRTSCTS(struct rtllib_device *ieee, struct rtllib_network *network)
{
	u8	retValue = 0;
#if defined(RTL8192SE) || defined(RTL8192SU) 
	if(ieee->pHTInfo->bCurrentHTSupport)
	{
		if((ieee->pHTInfo->IOTPeer != HT_IOT_PEER_REALTEK)&&
		   (ieee->pHTInfo->IOTPeer != HT_IOT_PEER_REALTEK_92SE))
	{
			if((ieee->pHTInfo->IOTAction & HT_IOT_ACT_TX_NO_AGGREGATION) == 0)
				retValue = 1;
		}
	}
#endif
	return retValue;
}

u8
HTIOTActIsForcedAMSDU8K(struct rtllib_device *ieee, struct rtllib_network *network)
{
	u8 retValue = 0;

	return retValue;
}

u8 HTIOTActIsCCDFsync(struct rtllib_device *ieee)
{
	u8	retValue = 0;
#if (defined RTL8190P || defined RTL8192U  || defined RTL8192SU)
	if(ieee->pHTInfo->IOTPeer == HT_IOT_PEER_BROADCOM)
	{
		retValue = 1;
	}
#endif	
	return retValue;
}
	
u8
HTIOCActRejcectADDBARequest(struct rtllib_network *network)
{
	u8	retValue = 0;
#if (defined RTL8192SE || defined RTL8192SU || defined RTL8192CE)
	{
		
		
	}
#endif
	
	return retValue;

}

u8
  HTIOTActIsEDCABiasRx(struct rtllib_device* ieee,struct rtllib_network *network)
{
	u8	retValue = 0;
#ifdef RTL8192SU
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	{
		if(pHTInfo->IOTPeer==HT_IOT_PEER_ATHEROS || 
		   pHTInfo->IOTPeer==HT_IOT_PEER_BROADCOM ||
		   pHTInfo->IOTPeer==HT_IOT_PEER_RALINK)
			return 1;
		
	}
#elif defined RTL8192CE
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	{
		if(pHTInfo->IOTPeer==HT_IOT_PEER_ATHEROS || 
		   pHTInfo->IOTPeer==HT_IOT_PEER_RALINK)
			return 1;
		
	}
#elif defined RTL8192SE 
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	{
            if(ieee->rtllib_ap_sec_type != NULL) 
                if(ieee->rtllib_ap_sec_type(ieee) == SEC_ALG_CCMP)
                    if(pHTInfo->IOTPeer==HT_IOT_PEER_RALINK){
                        return 1;
                    }
		
	}
#endif
	return retValue;
}

u8
HTIOTActDisableShortGI(struct rtllib_device* ieee,struct rtllib_network *network)
{
	u8	retValue = 0;
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;

	if(pHTInfo->IOTPeer==HT_IOT_PEER_RALINK)
	{
			retValue = 1;
	}

	return retValue;
}

u8
HTIOTActDisableHighPower(struct rtllib_device* ieee,struct rtllib_network *network)
{
	u8	retValue = 0;
#if (defined RTL8192SE || defined RTL8192SU || defined RTL8192CE)
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
#endif

#ifdef RTL8192SU
	if(pHTInfo->IOTPeer==HT_IOT_PEER_RALINK ||
		pHTInfo->IOTPeer==HT_IOT_PEER_REALTEK ||
		pHTInfo->IOTPeer==HT_IOT_PEER_REALTEK_92SE)
	{
			retValue = 1;
	}
#elif defined RTL8192SE || defined RTL8192CE
	if(pHTInfo->IOTPeer==HT_IOT_PEER_RALINK ||
		pHTInfo->IOTPeer==HT_IOT_PEER_REALTEK )
	{
			retValue = 1;
	}
#endif
	return retValue;
}

void
HTIOTActDetermineRaFunc(struct rtllib_device* ieee,	bool	bPeerRx2ss)
{
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	pHTInfo->IOTRaFunc &= HT_IOT_RAFUNC_DISABLE_ALL;

	if(pHTInfo->IOTPeer == HT_IOT_PEER_RALINK && !bPeerRx2ss)
		pHTInfo->IOTRaFunc |= HT_IOT_RAFUNC_PEER_1R;

	if(pHTInfo->IOTAction & HT_IOT_ACT_AMSDU_ENABLE)
		pHTInfo->IOTRaFunc |= HT_IOT_RAFUNC_TX_AMSDU;

}


u8
HTIOTActIsDisableTx40MHz(struct rtllib_device* ieee,struct rtllib_network *network)
{
	u8	retValue = 0;

#if (defined RTL8192SU || defined RTL8192SE || defined RTL8192CE)
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	if(	(KEY_TYPE_WEP104 == ieee->pairwise_key_type) || 
		(KEY_TYPE_WEP40 == ieee->pairwise_key_type) ||
		(KEY_TYPE_WEP104 == ieee->group_key_type) ||
		(KEY_TYPE_WEP40 == ieee->group_key_type) ||
		(KEY_TYPE_TKIP == ieee->pairwise_key_type) )
	{
		if((pHTInfo->IOTPeer==HT_IOT_PEER_REALTEK) && (network->bssht.bdSupportHT)) 
			retValue = 1;
	}
#endif

	return retValue;
}

u8
HTIOTActIsTxNoAggregation(struct rtllib_device* ieee,struct rtllib_network *network)
{
	u8 retValue = 0;

#if (defined RTL8192SU || defined RTL8192SE || defined RTL8192CE)
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	if(	(KEY_TYPE_WEP104 == ieee->pairwise_key_type) || 
		(KEY_TYPE_WEP40 == ieee->pairwise_key_type) ||
		(KEY_TYPE_WEP104 == ieee->group_key_type) ||
		(KEY_TYPE_WEP40 == ieee->group_key_type) ||
		(KEY_TYPE_TKIP == ieee->pairwise_key_type) )
	{
		if(pHTInfo->IOTPeer==HT_IOT_PEER_REALTEK)
			retValue = 1;
	}
#endif

	return retValue;
}


u8
HTIOTActIsDisableTx2SS(struct rtllib_device* ieee,struct rtllib_network *network)
{
	u8	retValue = 0;

#if (defined RTL8192SU || defined RTL8192SE || defined RTL8192CE)
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	if(	(KEY_TYPE_WEP104 == ieee->pairwise_key_type) || 
		(KEY_TYPE_WEP40 == ieee->pairwise_key_type) ||
		(KEY_TYPE_WEP104 == ieee->group_key_type) ||
		(KEY_TYPE_WEP40 == ieee->group_key_type) ||
		(KEY_TYPE_TKIP == ieee->pairwise_key_type) )
	{
		if((pHTInfo->IOTPeer==HT_IOT_PEER_REALTEK) && (network->bssht.bdSupportHT))
			retValue = 1;
	}
#endif

	return retValue;
}


bool HTIOCActIsDisableCckRate(struct rtllib_device* ieee,struct rtllib_network *network)
{
	bool 	retValue = false;
#if defined(RTL8192SU)
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	if(pHTInfo->IOTPeer == HT_IOT_PEER_BROADCOM)
	{
		if((memcmp(network->bssid, NETGEAR_BROADCOM, 3)==0)
			&& (network->bssht.bdBandWidth == HT_CHANNEL_WIDTH_20_40))
			return true;
	}
#endif
	return retValue;
}


bool HTIOCActAllowPeerAggOnePacket(struct rtllib_device* ieee,struct rtllib_network *network)
{
	bool 	retValue = false;
#if defined(RTL8192SE) || defined(RTL8192SU) 
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	{
		if(ieee->VersionID<2)
		if(pHTInfo->IOTPeer == HT_IOT_PEER_MARVELL)
			return true;
		
	}
#endif
	return retValue;
}

bool
HTIOTActIsNullDataPowerSaving(struct rtllib_device* ieee,struct rtllib_network *network)
{
	bool	retValue = false;
#if defined(RTL8192SE) || defined(RTL8192SU)
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	{
		if(pHTInfo->IOTPeer == HT_IOT_PEER_BROADCOM) 
			return true;
		
	}
#endif
	return retValue;
}

void HTResetIOTSetting(
	PRT_HIGH_THROUGHPUT		pHTInfo
)
{
	pHTInfo->IOTAction = 0;
	pHTInfo->IOTPeer = HT_IOT_PEER_UNKNOWN;
	pHTInfo->IOTRaFunc = 0;
}


#ifdef _RTL8192_EXT_PATCH_
void HTConstructCapabilityElement(struct rtllib_device* ieee, u8* posHTCap, u8* len, u8 IsEncrypt, u8 bIsBcn)
#else	
void HTConstructCapabilityElement(struct rtllib_device* ieee, u8* posHTCap, u8* len, u8 IsEncrypt)
#endif	
{	
	PRT_HIGH_THROUGHPUT	pHT = ieee->pHTInfo;
	PHT_CAPABILITY_ELE 	pCapELE = NULL;
	
	if ((posHTCap == NULL) || (pHT == NULL))
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "posHTCap or pHTInfo can't be null in HTConstructCapabilityElement()\n");
		return;
	}
	memset(posHTCap, 0, *len);	
	if(pHT->ePeerHTSpecVer == HT_SPEC_VER_EWC)
	{
		u8	EWC11NHTCap[] = {0x00, 0x90, 0x4c, 0x33};	
		memcpy(posHTCap, EWC11NHTCap, sizeof(EWC11NHTCap));
		pCapELE = (PHT_CAPABILITY_ELE)&(posHTCap[4]);
	}else 
	{
		pCapELE = (PHT_CAPABILITY_ELE)posHTCap;
	}

	pCapELE->AdvCoding 		= 0; 
	if(ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev))
	{
		pCapELE->ChlWidth = 0;
	}	
	else
	{
#ifdef _RTL8192_EXT_PATCH_
		if(bIsBcn)
			pCapELE->ChlWidth = (pHT->bCurBW40MHz?1:0);
		else
#endif	
			pCapELE->ChlWidth = (pHT->bRegBW40MHz?1:0);
	}
	
	pCapELE->MimoPwrSave 		= pHT->SelfMimoPs;
	pCapELE->GreenField		= 0; 
	pCapELE->ShortGI20Mhz		= 1; 
	pCapELE->ShortGI40Mhz		= 1; 
	pCapELE->TxSTBC 		= 1;
#ifdef Rtl8192SE
	pCapELE->TxSTBC 		= 0;
#endif
	pCapELE->RxSTBC 		= 0;
	pCapELE->DelayBA		= 0;	
	pCapELE->MaxAMSDUSize	= (MAX_RECEIVE_BUFFER_SIZE>=7935)?1:0;
	pCapELE->DssCCk 		= ((pHT->bRegBW40MHz)?(pHT->bRegSuppCCK?1:0):0);
	pCapELE->PSMP			= 0; 
	pCapELE->LSigTxopProtect	= 0; 


	RTLLIB_DEBUG(RTLLIB_DL_HT, "TX HT cap/info ele BW=%d MaxAMSDUSize:%d DssCCk:%d\n", pCapELE->ChlWidth, pCapELE->MaxAMSDUSize, pCapELE->DssCCk);

	if( IsEncrypt) 
	{
		pCapELE->MPDUDensity 	= 7; 
		pCapELE->MaxRxAMPDUFactor 	= 2; 
	}
	else
	{
		pCapELE->MaxRxAMPDUFactor 	= 3; 
		pCapELE->MPDUDensity 	= 0; 
	}		

	memcpy(pCapELE->MCS, ieee->Regdot11HTOperationalRateSet, 16);
	if(pHT->IOTAction & HT_IOT_ACT_DISABLE_MCS15)
		pCapELE->MCS[1] &= 0x7f;

	if(pHT->IOTAction & HT_IOT_ACT_DISABLE_MCS14)
		pCapELE->MCS[1] &= 0xbf;

	if(pHT->IOTAction & HT_IOT_ACT_DISABLE_ALL_2SS)
		pCapELE->MCS[1] &= 0x00;

	if(ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev))
	{	
		int i;
		for(i = 1; i< 16; i++)
			pCapELE->MCS[i] = 0;
	}
	
	memset(&pCapELE->ExtHTCapInfo, 0, 2);


	memset(pCapELE->TxBFCap, 0, 4);

	pCapELE->ASCap = 0;
	if(pHT->ePeerHTSpecVer == HT_SPEC_VER_EWC)
		*len = 30 + 2;
	else
		*len = 26 + 2;
		

		
	
	return;
	
}
void HTConstructInfoElement(struct rtllib_device* ieee, u8* posHTInfo, u8* len, u8 IsEncrypt)
{
	PRT_HIGH_THROUGHPUT	pHT = ieee->pHTInfo;	
	PHT_INFORMATION_ELE		pHTInfoEle = (PHT_INFORMATION_ELE)posHTInfo;
	if ((posHTInfo == NULL) || (pHTInfoEle == NULL))
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "posHTInfo or pHTInfoEle can't be null in HTConstructInfoElement()\n");
		return;
	}
	
	memset(posHTInfo, 0, *len);
#ifdef _RTL8192_EXT_PATCH_
	if ((ieee->iw_mode == IW_MODE_ADHOC) || (ieee->iw_mode == IW_MODE_MASTER) ||(ieee->iw_mode == IW_MODE_MESH) ) 
#else
	if ( (ieee->iw_mode == IW_MODE_ADHOC) || (ieee->iw_mode == IW_MODE_MASTER)) 
#endif
	{
		pHTInfoEle->ControlChl 			= ieee->current_network.channel; 
#ifdef _RTL8192_EXT_PATCH_
		if((!ieee->only_mesh) && (ieee->iw_mode == IW_MODE_MESH) && (ieee->state == RTLLIB_LINKED))
			pHTInfoEle->ExtChlOffset 			= ((pHT->bRegBW40MHz == false)?HT_EXTCHNL_OFFSET_NO_EXT:
												ieee->APExtChlOffset);
		else if(ieee->iw_mode == IW_MODE_MESH)
			pHTInfoEle->ExtChlOffset 			= ((pHT->bRegBW40MHz == false)?HT_EXTCHNL_OFFSET_NO_EXT:
											(ieee->current_mesh_network.channel<=6)?
												HT_EXTCHNL_OFFSET_UPPER:HT_EXTCHNL_OFFSET_LOWER);
		else
#endif
			pHTInfoEle->ExtChlOffset 			= ((pHT->bRegBW40MHz == false)?HT_EXTCHNL_OFFSET_NO_EXT:
											(ieee->current_network.channel<=6)?
												HT_EXTCHNL_OFFSET_UPPER:HT_EXTCHNL_OFFSET_LOWER);
		pHTInfoEle->RecommemdedTxWidth	= pHT->bRegBW40MHz;
		pHTInfoEle->RIFS 					= 0;
		pHTInfoEle->PSMPAccessOnly		= 0;
		pHTInfoEle->SrvIntGranularity		= 0;
		pHTInfoEle->OptMode				= pHT->CurrentOpMode;
		pHTInfoEle->NonGFDevPresent		= 0;
		pHTInfoEle->DualBeacon			= 0;
		pHTInfoEle->SecondaryBeacon		= 0;
		pHTInfoEle->LSigTxopProtectFull		= 0;
		pHTInfoEle->PcoActive				= 0;
		pHTInfoEle->PcoPhase				= 0;

		memset(pHTInfoEle->BasicMSC, 0, 16);


		*len = 22 + 2; 

	}
	else
	{
		*len = 0;
	}	
	return;
}	

void HTConstructRT2RTAggElement(struct rtllib_device* ieee, u8* posRT2RTAgg, u8* len)
{
	if (posRT2RTAgg == NULL) {
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "posRT2RTAgg can't be null in HTConstructRT2RTAggElement()\n");
		return;
	}
	memset(posRT2RTAgg, 0, *len);
	*posRT2RTAgg++ = 0x00;
	*posRT2RTAgg++ = 0xe0;
	*posRT2RTAgg++ = 0x4c;
	*posRT2RTAgg++ = 0x02;
	*posRT2RTAgg++ = 0x01;

#ifdef RTL8192CE
	*posRT2RTAgg = 0x70;
#else
	*posRT2RTAgg = 0x10;
#endif
	
	if(ieee->bSupportRemoteWakeUp) {
		*posRT2RTAgg |= RT_HT_CAP_USE_WOW;
	}

	*len = 6 + 2;
	
	return;

#ifdef TODO
	posRT2RTAgg->Length = 6;
#endif




}

u8 HT_PickMCSRate(struct rtllib_device* ieee, u8* pOperateMCS)
{
	u8					i;
	if (pOperateMCS == NULL)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "pOperateMCS can't be null in HT_PickMCSRate()\n");
		return false;
	}

	switch(ieee->mode)
	{
	case IEEE_A:
	case IEEE_B:
	case IEEE_G:
			
			for(i=0;i<=15;i++){
				pOperateMCS[i] = 0;
			}
			break;
		
	case IEEE_N_24G:	
	case IEEE_N_5G:
			
			pOperateMCS[0] &=RATE_ADPT_1SS_MASK;	
			pOperateMCS[1] &=RATE_ADPT_2SS_MASK;
			pOperateMCS[3] &=RATE_ADPT_MCS32_MASK;
			break;

	default:
			
			break;
		
	}

	return true;
}

u8 HTGetHighestMCSRate(struct rtllib_device* ieee, u8* pMCSRateSet, u8* pMCSFilter)
{
	u8		i, j;
	u8		bitMap;
	u8		mcsRate = 0;
	u8		availableMcsRate[16];
	if (pMCSRateSet == NULL || pMCSFilter == NULL)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "pMCSRateSet or pMCSFilter can't be null in HTGetHighestMCSRate()\n");
		return false;
	}
	for(i=0; i<16; i++)
		availableMcsRate[i] = pMCSRateSet[i] & pMCSFilter[i];

	for(i = 0; i < 16; i++)
	{
		if(availableMcsRate[i] != 0)
			break;
	}
	if(i == 16)
		return false;

	for(i = 0; i < 16; i++)
	{
		if(availableMcsRate[i] != 0)
		{
			bitMap = availableMcsRate[i];
			for(j = 0; j < 8; j++)
			{
				if((bitMap%2) != 0)
				{
					if(HTMcsToDataRate(ieee, (8*i+j)) > HTMcsToDataRate(ieee, mcsRate))
						mcsRate = (8*i+j);
				}
				bitMap = bitMap>>1;
			}
		}
	}
	return (mcsRate|0x80);
}
	
u8 HTFilterMCSRate( struct rtllib_device* ieee, u8* pSupportMCS, u8* pOperateMCS)
{
	
	u8 i=0;
	
	for(i=0;i<=15;i++){
		pOperateMCS[i] = ieee->Regdot11TxHTOperationalRateSet[i]&pSupportMCS[i];
	}

	

	HT_PickMCSRate(ieee, pOperateMCS);

	if(ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev))
		pOperateMCS[1] = 0;
	
	for(i=2; i<=15; i++)
		pOperateMCS[i] = 0;
	
	return true;
}
void HTSetConnectBwMode(struct rtllib_device* ieee, HT_CHANNEL_WIDTH	Bandwidth, HT_EXTCHNL_OFFSET	Offset);
void HTOnAssocRsp(struct rtllib_device *ieee)
{
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	PHT_CAPABILITY_ELE		pPeerHTCap = NULL;
	PHT_INFORMATION_ELE		pPeerHTInfo = NULL;
	u16	nMaxAMSDUSize = 0;
	u8*	pMcsFilter = NULL;

	static u8				EWC11NHTCap[] = {0x00, 0x90, 0x4c, 0x33};		
	static u8				EWC11NHTInfo[] = {0x00, 0x90, 0x4c, 0x34};	
	
	if( pHTInfo->bCurrentHTSupport == false )
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "<=== HTOnAssocRsp(): HT_DISABLE\n");
		return;
	}
	RTLLIB_DEBUG(RTLLIB_DL_HT, "===> HTOnAssocRsp_wq(): HT_ENABLE\n");
		
	if(!memcmp(pHTInfo->PeerHTCapBuf,EWC11NHTCap, sizeof(EWC11NHTCap)))
		pPeerHTCap = (PHT_CAPABILITY_ELE)(&pHTInfo->PeerHTCapBuf[4]);
	else
		pPeerHTCap = (PHT_CAPABILITY_ELE)(pHTInfo->PeerHTCapBuf);

	if(!memcmp(pHTInfo->PeerHTInfoBuf, EWC11NHTInfo, sizeof(EWC11NHTInfo)))
		pPeerHTInfo = (PHT_INFORMATION_ELE)(&pHTInfo->PeerHTInfoBuf[4]);
	else		
		pPeerHTInfo = (PHT_INFORMATION_ELE)(pHTInfo->PeerHTInfoBuf);
	
#ifdef _RTL8192_EXT_PATCH_
	ieee->APExtChlOffset = (HT_EXTCHNL_OFFSET)(pPeerHTInfo->ExtChlOffset);
#endif
	RTLLIB_DEBUG_DATA(RTLLIB_DL_DATA|RTLLIB_DL_HT, pPeerHTCap, sizeof(HT_CAPABILITY_ELE));
	HTSetConnectBwMode(ieee, (HT_CHANNEL_WIDTH)(pPeerHTCap->ChlWidth), (HT_EXTCHNL_OFFSET)(pPeerHTInfo->ExtChlOffset));
#if defined RTL8192SE || defined RTL8192SU || defined RTL8192CE
	if(pHTInfo->bCurBW40MHz == true)
#endif
		pHTInfo->bCurTxBW40MHz = ((pPeerHTInfo->RecommemdedTxWidth == 1)?true:false);

	pHTInfo->bCurShortGI20MHz= 
		((pHTInfo->bRegShortGI20MHz)?((pPeerHTCap->ShortGI20Mhz==1)?true:false):false);
	pHTInfo->bCurShortGI40MHz= 
		((pHTInfo->bRegShortGI40MHz)?((pPeerHTCap->ShortGI40Mhz==1)?true:false):false);

	pHTInfo->bCurSuppCCK = 
		((pHTInfo->bRegSuppCCK)?((pPeerHTCap->DssCCk==1)?true:false):false);


	pHTInfo->bCurrent_AMSDU_Support = pHTInfo->bAMSDU_Support;

	nMaxAMSDUSize = (pPeerHTCap->MaxAMSDUSize==0)?3839:7935;

	if(pHTInfo->nAMSDU_MaxSize > nMaxAMSDUSize )
		pHTInfo->nCurrent_AMSDU_MaxSize = nMaxAMSDUSize;
	else
		pHTInfo->nCurrent_AMSDU_MaxSize = pHTInfo->nAMSDU_MaxSize;

	pHTInfo->bCurrentAMPDUEnable = pHTInfo->bAMPDUEnable;
	if (ieee->rtllib_ap_sec_type && 
	   (ieee->rtllib_ap_sec_type(ieee)&(SEC_ALG_WEP|SEC_ALG_TKIP))){
		if( (pHTInfo->IOTPeer== HT_IOT_PEER_ATHEROS) ||
				(pHTInfo->IOTPeer == HT_IOT_PEER_UNKNOWN) )
			pHTInfo->bCurrentAMPDUEnable = false;
	}		
		
	if(!pHTInfo->bRegRT2RTAggregation)
	{
		if(pHTInfo->AMPDU_Factor > pPeerHTCap->MaxRxAMPDUFactor)
			pHTInfo->CurrentAMPDUFactor = pPeerHTCap->MaxRxAMPDUFactor;
		else
			pHTInfo->CurrentAMPDUFactor = pHTInfo->AMPDU_Factor;

	} else {
#if 0	
		osTmp= PacketGetElement( asocpdu, EID_Vendor, OUI_SUB_REALTEK_AGG, OUI_SUBTYPE_DONT_CARE);
		if(osTmp.Length >= 5)	
#endif
		if (ieee->current_network.bssht.bdRT2RTAggregation)
		{
			if( ieee->pairwise_key_type != KEY_TYPE_NA) 
				pHTInfo->CurrentAMPDUFactor = pPeerHTCap->MaxRxAMPDUFactor;
			else
				pHTInfo->CurrentAMPDUFactor = HT_AGG_SIZE_64K;
		}else
		{
			if(pPeerHTCap->MaxRxAMPDUFactor < HT_AGG_SIZE_32K)
				pHTInfo->CurrentAMPDUFactor = pPeerHTCap->MaxRxAMPDUFactor;
			else
				pHTInfo->CurrentAMPDUFactor = HT_AGG_SIZE_32K;
		}
	}

#if 0
	if(pHTInfo->MPDU_Density > pPeerHTCap->MPDUDensity)
		pHTInfo->CurrentMPDUDensity = pHTInfo->MPDU_Density;
	else
		pHTInfo->CurrentMPDUDensity = pPeerHTCap->MPDUDensity;
	if(ieee->pairwise_key_type != KEY_TYPE_NA ) 
		pHTInfo->CurrentMPDUDensity 	= 7; 
#else
	if(pHTInfo->MPDU_Density > pPeerHTCap->MPDUDensity)
		pHTInfo->CurrentMPDUDensity = pHTInfo->MPDU_Density;
	else
		pHTInfo->CurrentMPDUDensity = pPeerHTCap->MPDUDensity;
#endif
#if (defined RTL8192SE || defined RTL8192SU || defined RTL8192CE)
        if(ieee->SetHwRegHandler != NULL) {
            ieee->SetHwRegHandler( ieee->dev, HW_VAR_SHORTGI_DENSITY,  (u8*)(&ieee->MaxMssDensity));
            ieee->SetHwRegHandler(ieee->dev, HW_VAR_AMPDU_FACTOR, &pHTInfo->CurrentAMPDUFactor);
            ieee->SetHwRegHandler(ieee->dev, HW_VAR_AMPDU_MIN_SPACE, &pHTInfo->CurrentMPDUDensity);
        }
#elif defined RTL8192CE
        if(ieee->SetHwRegHandler != NULL) {
            ieee->SetHwRegHandler(ieee->dev, HW_VAR_AMPDU_FACTOR, &pHTInfo->CurrentAMPDUFactor);
            ieee->SetHwRegHandler(ieee->dev, HW_VAR_AMPDU_MIN_SPACE, &pHTInfo->CurrentMPDUDensity);
        }
#endif        
#ifndef RTL8190P
	if(pHTInfo->IOTAction & HT_IOT_ACT_TX_USE_AMSDU_8K)
#else
	if( 0 )
#endif
	{
		pHTInfo->bCurrentAMPDUEnable = false;
		pHTInfo->ForcedAMSDUMode = HT_AGG_FORCE_ENABLE;
		pHTInfo->ForcedAMSDUMaxSize = 7935;
	}
	pHTInfo->bCurRxReorderEnable = pHTInfo->bRegRxReorderEnable;

	
	if(pPeerHTCap->MCS[0] == 0)
		pPeerHTCap->MCS[0] = 0xff;
		
	HTIOTActDetermineRaFunc(ieee, ((pPeerHTCap->MCS[1])!=0));

	HTFilterMCSRate(ieee, pPeerHTCap->MCS, ieee->dot11HTOperationalRateSet);

	pHTInfo->PeerMimoPs = pPeerHTCap->MimoPwrSave;
	if(pHTInfo->PeerMimoPs == MIMO_PS_STATIC)
		pMcsFilter = MCS_FILTER_1SS;
	else
		pMcsFilter = MCS_FILTER_ALL;
	ieee->HTHighestOperaRate = HTGetHighestMCSRate(ieee, ieee->dot11HTOperationalRateSet, pMcsFilter);
	ieee->HTCurrentOperaRate = ieee->HTHighestOperaRate;

	pHTInfo->CurrentOpMode = pPeerHTInfo->OptMode;

}	

void HTSetConnectBwModeCallback(struct rtllib_device* ieee);
void HTInitializeHTInfo(struct rtllib_device* ieee)
{
	PRT_HIGH_THROUGHPUT pHTInfo = ieee->pHTInfo;

	RTLLIB_DEBUG(RTLLIB_DL_HT, "===========>%s()\n", __FUNCTION__);
	pHTInfo->bCurrentHTSupport = false;

	pHTInfo->bCurBW40MHz = false;
	pHTInfo->bCurTxBW40MHz = false;

	pHTInfo->bCurShortGI20MHz = false;
	pHTInfo->bCurShortGI40MHz = false;
	pHTInfo->bForcedShortGI = false;

	pHTInfo->bCurSuppCCK = true;

	pHTInfo->bCurrent_AMSDU_Support = false;
	pHTInfo->nCurrent_AMSDU_MaxSize = pHTInfo->nAMSDU_MaxSize;
#ifdef _RTL8192_EXT_PATCH_
	pHTInfo->bCurrent_Mesh_AMSDU_Support = true;
#endif
	pHTInfo->CurrentMPDUDensity = pHTInfo->MPDU_Density;
	pHTInfo->CurrentAMPDUFactor = pHTInfo->AMPDU_Factor;

	memset((void*)(&(pHTInfo->SelfHTCap)), 0, sizeof(pHTInfo->SelfHTCap));
	memset((void*)(&(pHTInfo->SelfHTInfo)), 0, sizeof(pHTInfo->SelfHTInfo));
	memset((void*)(&(pHTInfo->PeerHTCapBuf)), 0, sizeof(pHTInfo->PeerHTCapBuf));
	memset((void*)(&(pHTInfo->PeerHTInfoBuf)), 0, sizeof(pHTInfo->PeerHTInfoBuf));

	pHTInfo->bSwBwInProgress = false;
	pHTInfo->ChnlOp = CHNLOP_NONE;

	pHTInfo->ePeerHTSpecVer = HT_SPEC_VER_IEEE;

	pHTInfo->bCurrentRT2RTAggregation = false;
	pHTInfo->bCurrentRT2RTLongSlotTime = false;
	pHTInfo->RT2RT_HT_Mode = (RT_HT_CAPBILITY)0;
	
	pHTInfo->IOTPeer = 0;
	pHTInfo->IOTAction = 0;
	pHTInfo->IOTRaFunc = 0;
	
	{
		u8* RegHTSuppRateSets = &(ieee->RegHTSuppRateSet[0]);
		RegHTSuppRateSets[0] = 0xFF;	
		RegHTSuppRateSets[1] = 0xFF;	
		RegHTSuppRateSets[4] = 0x01;	
	}
}
void HTInitializeBssDesc(PBSS_HT pBssHT)
{

	pBssHT->bdSupportHT = false;
	memset(pBssHT->bdHTCapBuf, 0, sizeof(pBssHT->bdHTCapBuf));
	pBssHT->bdHTCapLen = 0;
	memset(pBssHT->bdHTInfoBuf, 0, sizeof(pBssHT->bdHTInfoBuf));
	pBssHT->bdHTInfoLen = 0;

	pBssHT->bdHTSpecVer= HT_SPEC_VER_IEEE;

	pBssHT->bdRT2RTAggregation = false;
	pBssHT->bdRT2RTLongSlotTime = false;
	pBssHT->RT2RT_HT_Mode = (RT_HT_CAPBILITY)0;
}

void HTResetSelfAndSavePeerSetting(struct rtllib_device* ieee, 	struct rtllib_network * pNetwork)
{
	PRT_HIGH_THROUGHPUT		pHTInfo = ieee->pHTInfo;
	u8	bIOTAction = 0;

	RTLLIB_DEBUG(RTLLIB_DL_HT, "==============>%s()\n", __FUNCTION__);
	/*unmark bEnableHT flag here is the same reason why unmarked in function rtllib_softmac_new_net. WB 2008.09.10*/
	if (pNetwork->bssht.bdSupportHT)
	{
		pHTInfo->bCurrentHTSupport = true;
		pHTInfo->ePeerHTSpecVer = pNetwork->bssht.bdHTSpecVer;

		if(pNetwork->bssht.bdHTCapLen > 0 && 	pNetwork->bssht.bdHTCapLen <= sizeof(pHTInfo->PeerHTCapBuf))
			memcpy(pHTInfo->PeerHTCapBuf, pNetwork->bssht.bdHTCapBuf, pNetwork->bssht.bdHTCapLen);

		if(pNetwork->bssht.bdHTInfoLen > 0 && pNetwork->bssht.bdHTInfoLen <= sizeof(pHTInfo->PeerHTInfoBuf))
			memcpy(pHTInfo->PeerHTInfoBuf, pNetwork->bssht.bdHTInfoBuf, pNetwork->bssht.bdHTInfoLen);

		if(pHTInfo->bRegRT2RTAggregation)
		{
			pHTInfo->bCurrentRT2RTAggregation = pNetwork->bssht.bdRT2RTAggregation;
			pHTInfo->bCurrentRT2RTLongSlotTime = pNetwork->bssht.bdRT2RTLongSlotTime;
			pHTInfo->RT2RT_HT_Mode = pNetwork->bssht.RT2RT_HT_Mode;
		}
		else
		{
			pHTInfo->bCurrentRT2RTAggregation = false;	
			pHTInfo->bCurrentRT2RTLongSlotTime = false;
			pHTInfo->RT2RT_HT_Mode = (RT_HT_CAPBILITY)0;
		}
	
		HTIOTPeerDetermine(ieee);
				 			
		pHTInfo->IOTAction = 0;
		bIOTAction = HTIOTActIsDisableMCS14(ieee, pNetwork->bssid);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_MCS14;

		bIOTAction = HTIOTActIsDisableMCS15(ieee);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_MCS15;

		bIOTAction = HTIOTActIsDisableMCSTwoSpatialStream(ieee);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_ALL_2SS;


		bIOTAction = HTIOTActIsDisableEDCATurbo(ieee, pNetwork->bssid);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_EDCA_TURBO;

#if defined(RTL8190P) || defined(RTL8192E) || defined(RTL8192U)
		bIOTAction = HTIOTActIsMgntUseCCK6M(ieee,pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_MGNT_USE_CCK_6M;
#elif defined(RTL8192SE) || defined(RTL8192SU) || defined RTL8192CE
		bIOTAction = HTIOTActWAIOTBroadcom(ieee);
		if(bIOTAction)
		{
			pHTInfo->IOTAction |= HT_IOT_ACT_WA_IOT_Broadcom;
		}
#endif
		bIOTAction = HTIOTActIsCCDFsync(ieee);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_CDD_FSYNC;
#if defined(RTL8192SU) || defined(RTL8192SE) || defined RTL8192CE
		bIOTAction = HTIOTActIsForcedCTS2Self(ieee,pNetwork);
		if(bIOTAction)	
			pHTInfo->IOTAction |= HT_IOT_ACT_FORCED_CTS2SELF;


		bIOTAction = HTIOTActIsEnableBETxOPLimit(ieee);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_FORCED_ENABLE_BE_TXOP;

#if defined(RTL8192SU)
		bIOTAction = HTIOCActRejcectADDBARequest(pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_REJECT_ADDBA_REQ;
#endif

		bIOTAction = HTIOCActAllowPeerAggOnePacket(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_ALLOW_PEER_AGG_ONE_PKT;

		bIOTAction = HTIOTActIsEDCABiasRx(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_EDCA_BIAS_ON_RX;

#if defined(RTL8192SU)
		bIOTAction = HTIOCActIsDisableCckRate(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_CCK_RATE;
#endif
		bIOTAction = HTIOTActDisableShortGI(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_SHORT_GI;

		bIOTAction = HTIOTActDisableHighPower(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_HIGH_POWER;


		bIOTAction = HTIOTActIsForcedAMSDU8K(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_TX_USE_AMSDU_8K;

#if defined(RTL8192SU)
		bIOTAction = HTIOTActIsTxNoAggregation(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_TX_NO_AGGREGATION;

		bIOTAction = HTIOTActIsDisableTx40MHz(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_TX_40_MHZ;

		bIOTAction = HTIOTActIsDisableTx2SS(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_DISABLE_TX_2SS;
#endif

		bIOTAction = HTIOTActIsForcedRTSCTS(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_FORCED_RTS;

		bIOTAction = HTIOTActIsNullDataPowerSaving(ieee, pNetwork);
		if(bIOTAction)
			pHTInfo->IOTAction |= HT_IOT_ACT_NULL_DATA_POWER_SAVING;
#endif
	}
	else
	{
		pHTInfo->bCurrentHTSupport = false;
		pHTInfo->bCurrentRT2RTAggregation = false;
		pHTInfo->bCurrentRT2RTLongSlotTime = false;
		pHTInfo->RT2RT_HT_Mode = (RT_HT_CAPBILITY)0;

		pHTInfo->IOTAction = 0;
		pHTInfo->IOTRaFunc = 0;
	}
	
}

void HTUpdateSelfAndPeerSetting(struct rtllib_device* ieee, 	struct rtllib_network * pNetwork)
{
	PRT_HIGH_THROUGHPUT	pHTInfo = ieee->pHTInfo;
	PHT_INFORMATION_ELE		pPeerHTInfo = (PHT_INFORMATION_ELE)pNetwork->bssht.bdHTInfoBuf;

	if(pHTInfo->bCurrentHTSupport)
	{
		if(pNetwork->bssht.bdHTInfoLen != 0)
			pHTInfo->CurrentOpMode = pPeerHTInfo->OptMode;

	}
}

void HTUseDefaultSetting(struct rtllib_device* ieee)
{
	PRT_HIGH_THROUGHPUT pHTInfo = ieee->pHTInfo;
		
#ifdef _RTL8192_EXT_PATCH_
	ieee->current_mesh_network.qos_data.supported = 1;
	ieee->current_mesh_network.qos_data.active = ieee->current_mesh_network.qos_data.supported;
#endif	
	if(pHTInfo->bEnableHT)
	{
		pHTInfo->bCurrentHTSupport = true;
		pHTInfo->bCurSuppCCK = pHTInfo->bRegSuppCCK;

#ifdef _RTL8192_EXT_PATCH_
		if(!((ieee->iw_mode == IW_MODE_MESH) && ieee->proto_started && (ieee->state == RTLLIB_LINKED)))
			pHTInfo->bCurBW40MHz = pHTInfo->bRegBW40MHz;
#else
		pHTInfo->bCurBW40MHz = pHTInfo->bRegBW40MHz;
#endif
		pHTInfo->bCurShortGI20MHz= pHTInfo->bRegShortGI20MHz;

		pHTInfo->bCurShortGI40MHz= pHTInfo->bRegShortGI40MHz;
#ifdef _RTL8192_EXT_PATCH_
		ieee->current_mesh_network.qos_data.supported = 1;
		ieee->current_mesh_network.qos_data.active = ieee->current_mesh_network.qos_data.supported;
#endif		

		if(ieee->iw_mode == IW_MODE_ADHOC)
		{
			ieee->current_network.qos_data.active = ieee->current_network.qos_data.supported;
		}
#ifdef ENABLE_AMSDU
		if(ieee->iw_mode == IW_MODE_ADHOC)
		{
			pHTInfo->bCurrent_AMSDU_Support = 1;
		}
#ifdef _RTL8192_EXT_PATCH_
		else if(ieee->iw_mode == IW_MODE_MESH)
		{
#ifdef COMPATIBLE_WITH_RALINK_MESH
			pHTInfo->bCurrent_Mesh_AMSDU_Support = 0;
#else
			pHTInfo->bCurrent_Mesh_AMSDU_Support = 1;
#endif
			pHTInfo->bCurrent_AMSDU_Support = pHTInfo->bAMSDU_Support;
		}
#endif
		else
			pHTInfo->bCurrent_AMSDU_Support = pHTInfo->bAMSDU_Support;
#else
		pHTInfo->bCurrent_AMSDU_Support = pHTInfo->bAMSDU_Support;
#endif
		pHTInfo->nCurrent_AMSDU_MaxSize = pHTInfo->nAMSDU_MaxSize;

#ifdef ENABLE_AMSDU
		if(ieee->iw_mode == IW_MODE_ADHOC)
			pHTInfo->bCurrentAMPDUEnable = 0;
#ifdef _RTL8192_EXT_PATCH_
		else if(ieee->iw_mode == IW_MODE_MESH)
		{
#ifdef COMPATIBLE_WITH_RALINK_MESH
			pHTInfo->bCurrentMeshAMPDUEnable = 1;
#else
			pHTInfo->bCurrentMeshAMPDUEnable = 0;
#endif
			pHTInfo->bCurrentAMPDUEnable = pHTInfo->bAMPDUEnable;
		}
#endif
		else
			pHTInfo->bCurrentAMPDUEnable = pHTInfo->bAMPDUEnable;
#else
		pHTInfo->bCurrentAMPDUEnable = pHTInfo->bAMPDUEnable;
#endif
		pHTInfo->CurrentAMPDUFactor = pHTInfo->AMPDU_Factor;

		pHTInfo->CurrentMPDUDensity = pHTInfo->CurrentMPDUDensity;


		HTFilterMCSRate(ieee, ieee->Regdot11TxHTOperationalRateSet, ieee->dot11HTOperationalRateSet);
#ifdef TODO
		Adapter->HalFunc.InitHalRATRTableHandler( Adapter, &pMgntInfo->dot11OperationalRateSet, pMgntInfo->dot11HTOperationalRateSet);
#endif
		ieee->HTHighestOperaRate = HTGetHighestMCSRate(ieee, ieee->dot11HTOperationalRateSet, MCS_FILTER_ALL);
		ieee->HTCurrentOperaRate = ieee->HTHighestOperaRate;

#if (defined RTL8192SE || defined RTL8192SU || defined RTL8192CE)
        	if(ieee->SetHwRegHandler != NULL) {
           	 	ieee->SetHwRegHandler( ieee->dev, HW_VAR_SHORTGI_DENSITY,  (u8*)(&ieee->MaxMssDensity));
            		ieee->SetHwRegHandler(ieee->dev, HW_VAR_AMPDU_FACTOR, &pHTInfo->CurrentAMPDUFactor);
           	 	ieee->SetHwRegHandler(ieee->dev, HW_VAR_AMPDU_MIN_SPACE, &pHTInfo->CurrentMPDUDensity);
        	}
#endif  

	}
	else
	{
		pHTInfo->bCurrentHTSupport = false;
	}
	return;
}
u8 HTCCheck(struct rtllib_device* ieee, u8*	pFrame)
{
	if(ieee->pHTInfo->bCurrentHTSupport)
	{
		if( (IsQoSDataFrame(pFrame) && Frame_Order(pFrame)) == 1)
		{
			RTLLIB_DEBUG(RTLLIB_DL_HT, "HT CONTROL FILED EXIST!!\n");
			return true;
		}
	}
	return false;
}

void HTSetConnectBwMode(struct rtllib_device* ieee, HT_CHANNEL_WIDTH	Bandwidth, HT_EXTCHNL_OFFSET	Offset)
{
	PRT_HIGH_THROUGHPUT pHTInfo = ieee->pHTInfo;

	if(pHTInfo->bRegBW40MHz == false)
		return;

	if(ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev))
		Bandwidth=HT_CHANNEL_WIDTH_20;
	

	if(pHTInfo->bSwBwInProgress) {
		printk("%s: bSwBwInProgress!!\n", __FUNCTION__);
		return;
	}
	if(Bandwidth==HT_CHANNEL_WIDTH_20_40)
	 {
		if(ieee->current_network.channel<2 && Offset==HT_EXTCHNL_OFFSET_LOWER)
			Offset = HT_EXTCHNL_OFFSET_NO_EXT;
		if(Offset==HT_EXTCHNL_OFFSET_UPPER || Offset==HT_EXTCHNL_OFFSET_LOWER) {
			pHTInfo->bCurBW40MHz = true;
			pHTInfo->CurSTAExtChnlOffset = Offset;
		} else {
			pHTInfo->bCurBW40MHz = false;
			pHTInfo->CurSTAExtChnlOffset = HT_EXTCHNL_OFFSET_NO_EXT;
		}
	} else {
		pHTInfo->bCurBW40MHz = false;
		pHTInfo->CurSTAExtChnlOffset = HT_EXTCHNL_OFFSET_NO_EXT;
	}

	printk("%s():pHTInfo->bCurBW40MHz:%x\n", __func__, pHTInfo->bCurBW40MHz);

	pHTInfo->bSwBwInProgress = true;

	HTSetConnectBwModeCallback(ieee);

}

void HTSetConnectBwModeCallback(struct rtllib_device* ieee)
{
	PRT_HIGH_THROUGHPUT pHTInfo = ieee->pHTInfo;

	RTLLIB_DEBUG(RTLLIB_DL_HT, "======>%s()\n", __FUNCTION__);
	if(pHTInfo->bCurBW40MHz)
	{
		if(pHTInfo->CurSTAExtChnlOffset==HT_EXTCHNL_OFFSET_UPPER)
			ieee->set_chan(ieee->dev, ieee->current_network.channel+2);
		else if(pHTInfo->CurSTAExtChnlOffset==HT_EXTCHNL_OFFSET_LOWER)
			ieee->set_chan(ieee->dev, ieee->current_network.channel-2);
		else
			ieee->set_chan(ieee->dev, ieee->current_network.channel);
		
		ieee->SetBWModeHandler(ieee->dev, HT_CHANNEL_WIDTH_20_40, pHTInfo->CurSTAExtChnlOffset);
	} else {
		ieee->set_chan(ieee->dev, ieee->current_network.channel);
		ieee->SetBWModeHandler(ieee->dev, HT_CHANNEL_WIDTH_20, HT_EXTCHNL_OFFSET_NO_EXT);
	}

	pHTInfo->bSwBwInProgress = false;
}

#ifndef BUILT_IN_RTLLIB
EXPORT_SYMBOL_RSL(HTUpdateSelfAndPeerSetting);
EXPORT_SYMBOL_RSL(HTFilterMCSRate);
EXPORT_SYMBOL_RSL(HTGetHighestMCSRate);
EXPORT_SYMBOL_RSL(MCS_FILTER_ALL);
EXPORT_SYMBOL_RSL(MCS_FILTER_1SS);
#ifdef _RTL8192_EXT_PATCH_
EXPORT_SYMBOL_RSL(HTSetConnectBwMode);
EXPORT_SYMBOL_RSL(HTConstructCapabilityElement);
EXPORT_SYMBOL_RSL(HTConstructRT2RTAggElement);
EXPORT_SYMBOL_RSL(HTUseDefaultSetting);
EXPORT_SYMBOL_RSL(HTConstructInfoElement);
#endif
#endif
