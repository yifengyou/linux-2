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
#include "rtl819x_BA.h"
#ifdef RTK_DMP_PLATFORM
#include <linux/usb_setting.h> 
#endif

void ActivateBAEntry(struct rtllib_device* ieee, PBA_RECORD pBA, u16 Time)
{
	pBA->bValid = true;
	if(Time != 0)
		mod_timer(&pBA->Timer, jiffies + MSECS(Time));
}

void DeActivateBAEntry( struct rtllib_device* ieee, PBA_RECORD pBA)
{
	pBA->bValid = false;
	del_timer_sync(&pBA->Timer);
}
u8 TxTsDeleteBA( struct rtllib_device* ieee, PTX_TS_RECORD	pTxTs)
{
	PBA_RECORD		pAdmittedBa = &pTxTs->TxAdmittedBARecord;  
	PBA_RECORD		pPendingBa = &pTxTs->TxPendingBARecord;
	u8			bSendDELBA = false;

	if(pPendingBa->bValid)
	{
		DeActivateBAEntry(ieee, pPendingBa);
		bSendDELBA = true;
	}

	if(pAdmittedBa->bValid)
	{
		DeActivateBAEntry(ieee, pAdmittedBa);
		bSendDELBA = true;
	}

	return bSendDELBA;
}

u8 RxTsDeleteBA( struct rtllib_device* ieee, PRX_TS_RECORD	pRxTs)
{
	PBA_RECORD		pBa = &pRxTs->RxAdmittedBARecord;
	u8			bSendDELBA = false;

	if(pBa->bValid)
	{
		DeActivateBAEntry(ieee, pBa);
		bSendDELBA = true;
	}

	return bSendDELBA;
}

void ResetBaEntry( PBA_RECORD pBA)
{
	pBA->bValid			= false;
	pBA->BaParamSet.shortData	= 0;
	pBA->BaTimeoutValue		= 0;
	pBA->DialogToken		= 0;
	pBA->BaStartSeqCtrl.ShortData	= 0;
}
static struct sk_buff* rtllib_ADDBA(struct rtllib_device* ieee, u8* Dst, PBA_RECORD pBA, u16 StatusCode, u8 type)
{
	struct sk_buff *skb = NULL;
	 struct rtllib_hdr_3addr* BAReq = NULL;
	u8* tag = NULL;
	u16 tmp = 0;
	u16 len = ieee->tx_headroom + 9;
	RTLLIB_DEBUG(RTLLIB_DL_TRACE | RTLLIB_DL_BA, "========>%s(), frame(%d) sentd to:"MAC_FMT", ieee->dev:%p\n", __FUNCTION__, type, MAC_ARG(Dst), ieee->dev);
	if (pBA == NULL||ieee == NULL)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "pBA(%p) is NULL or ieee(%p) is NULL\n", pBA, ieee);
		return NULL;
	}
#ifdef USB_USE_ALIGNMENT
        u32 Tmpaddr=0;
        int alignment=0;
        skb = dev_alloc_skb(len + sizeof( struct rtllib_hdr_3addr) + USB_512B_ALIGNMENT_SIZE); 
#else
	skb = dev_alloc_skb(len + sizeof( struct rtllib_hdr_3addr)); 
#endif
	if (skb == NULL)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "can't alloc skb for ADDBA_REQ\n");
		return NULL;
	}

	memset(skb->data, 0, sizeof( struct rtllib_hdr_3addr));  	

#ifdef USB_USE_ALIGNMENT
        Tmpaddr = (u32)skb->data;
        alignment = Tmpaddr & 0x1ff;
        skb_reserve(skb,(USB_512B_ALIGNMENT_SIZE - alignment));
#endif

	skb_reserve(skb, ieee->tx_headroom);

	BAReq = ( struct rtllib_hdr_3addr *) skb_put(skb,sizeof( struct rtllib_hdr_3addr));

	memcpy(BAReq->addr1, Dst, ETH_ALEN);
	memcpy(BAReq->addr2, ieee->dev->dev_addr, ETH_ALEN);

#ifdef _RTL8192_EXT_PATCH_ 
	if((ieee->iw_mode == IW_MODE_MESH) && (ieee->only_mesh == 0) && ieee->ext_patch_rtllib_is_mesh && ieee->ext_patch_rtllib_is_mesh(ieee, Dst)){
#ifdef COMPATIBLE_WITH_RALINK_MESH		
		memcpy(BAReq->addr3, Dst, ETH_ALEN);
#else
		memcpy(BAReq->addr3, ieee->current_mesh_network.bssid, ETH_ALEN);
#endif		
	}
	else
		memcpy(BAReq->addr3, ieee->current_network.bssid, ETH_ALEN);
#else	
	memcpy(BAReq->addr3, ieee->current_network.bssid, ETH_ALEN);
#endif
	BAReq->frame_ctl = cpu_to_le16(RTLLIB_STYPE_MANAGE_ACT); 

	tag = (u8*)skb_put(skb, 9);
	*tag ++= ACT_CAT_BA;  
	*tag ++= type;
	*tag ++= pBA->DialogToken;

	if (ACT_ADDBARSP == type)
	{
		printk("====>to send ADDBARSP\n");
		tmp = cpu_to_le16(StatusCode);
		memcpy(tag, (u8*)&tmp, 2);
		tag += 2;	
	}
	tmp = cpu_to_le16(pBA->BaParamSet.shortData);
	memcpy(tag, (u8*)&tmp, 2);
	tag += 2;
	tmp = cpu_to_le16(pBA->BaTimeoutValue);
	memcpy(tag, (u8*)&tmp, 2);
	tag += 2;
	
	if (ACT_ADDBAREQ == type)
	{
		memcpy(tag,(u8*)&(pBA->BaStartSeqCtrl), 2);
		tag += 2;
	}
	
	RTLLIB_DEBUG_DATA(RTLLIB_DL_DATA|RTLLIB_DL_BA, skb->data, skb->len);
	return skb;
}

static struct sk_buff* rtllib_DELBA(
	struct rtllib_device* ieee,
	u8*		         dst,
	PBA_RECORD		 pBA,
	TR_SELECT		 TxRxSelect,
	u16			 ReasonCode
	)
{
	DELBA_PARAM_SET	DelbaParamSet;
	struct sk_buff *skb = NULL;
	 struct rtllib_hdr_3addr* Delba = NULL;
	u8* tag = NULL;
	u16 tmp = 0;
	u16 len = 6 + ieee->tx_headroom;	

	if (net_ratelimit())
	RTLLIB_DEBUG(RTLLIB_DL_TRACE | RTLLIB_DL_BA, "========>%s(), ReasonCode(%d) sentd to:"MAC_FMT"\n", __FUNCTION__, ReasonCode, MAC_ARG(dst));

	memset(&DelbaParamSet, 0, 2);

	DelbaParamSet.field.Initiator	= (TxRxSelect==TX_DIR)?1:0;
	DelbaParamSet.field.TID	= pBA->BaParamSet.field.TID;
	
#ifdef USB_USE_ALIGNMENT
        u32 Tmpaddr=0;
        int alignment=0;
	skb = dev_alloc_skb(len + sizeof( struct rtllib_hdr_3addr) + USB_512B_ALIGNMENT_SIZE); 
#else	
	skb = dev_alloc_skb(len + sizeof( struct rtllib_hdr_3addr)); 
#endif
	if (skb == NULL)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "can't alloc skb for ADDBA_REQ\n");
		return NULL;
	}

#ifdef USB_USE_ALIGNMENT
        Tmpaddr = (u32)skb->data;
        alignment = Tmpaddr & 0x1ff;
        skb_reserve(skb,(USB_512B_ALIGNMENT_SIZE - alignment));
#endif
	skb_reserve(skb, ieee->tx_headroom);
	
	Delba = ( struct rtllib_hdr_3addr *) skb_put(skb,sizeof( struct rtllib_hdr_3addr));

	memcpy(Delba->addr1, dst, ETH_ALEN);
	memcpy(Delba->addr2, ieee->dev->dev_addr, ETH_ALEN);
#ifdef _RTL8192_EXT_PATCH_ 
	if((ieee->iw_mode == IW_MODE_MESH) && (ieee->only_mesh == 0) && ieee->ext_patch_rtllib_is_mesh && ieee->ext_patch_rtllib_is_mesh(ieee, dst)){
#ifdef COMPATIBLE_WITH_RALINK_MESH		
		memcpy(Delba->addr3, dst, ETH_ALEN);
#else
		memcpy(Delba->addr3, ieee->current_mesh_network.bssid, ETH_ALEN);
#endif		
	}
	else
		memcpy(Delba->addr3, ieee->current_network.bssid, ETH_ALEN);
#else	
	memcpy(Delba->addr3, ieee->current_network.bssid, ETH_ALEN);
#endif
	Delba->frame_ctl = cpu_to_le16(RTLLIB_STYPE_MANAGE_ACT); 
	
	tag = (u8*)skb_put(skb, 6);	

	*tag ++= ACT_CAT_BA;  
	*tag ++= ACT_DELBA;

	tmp = cpu_to_le16(DelbaParamSet.shortData);
	memcpy(tag, (u8*)&tmp, 2);
	tag += 2;
	tmp = cpu_to_le16(ReasonCode);
	memcpy(tag, (u8*)&tmp, 2);
	tag += 2;

	RTLLIB_DEBUG_DATA(RTLLIB_DL_DATA|RTLLIB_DL_BA, skb->data, skb->len);
	if (net_ratelimit())
	RTLLIB_DEBUG(RTLLIB_DL_TRACE | RTLLIB_DL_BA, "<=====%s()\n", __FUNCTION__);
	return skb;
}

void rtllib_send_ADDBAReq(struct rtllib_device* ieee, u8*	dst, PBA_RECORD	pBA)
{
	struct sk_buff *skb = NULL;
	skb = rtllib_ADDBA(ieee, dst, pBA, 0, ACT_ADDBAREQ); 

	if (skb)
	{
		printk("====>to send ADDBAREQ!!!!!\n");
		softmac_mgmt_xmit(skb, ieee);
	}
	else
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "alloc skb error in function %s()\n", __FUNCTION__);
	}
	return;
}

void rtllib_send_ADDBARsp(struct rtllib_device* ieee, u8* dst, PBA_RECORD pBA, u16 StatusCode) 
{
	struct sk_buff *skb = NULL;
	skb = rtllib_ADDBA(ieee, dst, pBA, StatusCode, ACT_ADDBARSP); 
	if (skb)
	{
		softmac_mgmt_xmit(skb, ieee);
	}
	else
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "alloc skb error in function %s()\n", __FUNCTION__);
	}

	return;

}

void rtllib_send_DELBA(struct rtllib_device* ieee, u8* dst, PBA_RECORD pBA, TR_SELECT TxRxSelect, u16 ReasonCode)
{
	struct sk_buff *skb = NULL;
	skb = rtllib_DELBA(ieee, dst, pBA, TxRxSelect, ReasonCode); 
	if (skb)
	{
		softmac_mgmt_xmit(skb, ieee);
	}
	else
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "alloc skb error in function %s()\n", __FUNCTION__);
	}
	return ;
}

int rtllib_rx_ADDBAReq( struct rtllib_device* ieee, struct sk_buff *skb)
{
	 struct rtllib_hdr_3addr* req = NULL;
	u16 rc = 0;
	u8 * dst = NULL, *pDialogToken = NULL, *tag = NULL;
	PBA_RECORD pBA = NULL;
	PBA_PARAM_SET	pBaParamSet = NULL;
	u16* pBaTimeoutVal = NULL;
	PSEQUENCE_CONTROL pBaStartSeqCtrl = NULL;
	PRX_TS_RECORD	pTS = NULL;	

	if (skb->len < sizeof( struct rtllib_hdr_3addr) + 9)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, " Invalid skb len in BAREQ(%d / %d)\n",(int)skb->len, 	(int)(sizeof( struct rtllib_hdr_3addr) + 9));
		return -1;
	}

	RTLLIB_DEBUG_DATA(RTLLIB_DL_DATA|RTLLIB_DL_BA, skb->data, skb->len);
	
	req = ( struct rtllib_hdr_3addr*) skb->data;
	tag = (u8*)req;
	dst = (u8*)(&req->addr2[0]);
	tag += sizeof( struct rtllib_hdr_3addr);
	pDialogToken = tag + 2;  
	pBaParamSet = (PBA_PARAM_SET)(tag + 3);   
	pBaTimeoutVal = (u16*)(tag + 5); 
	pBaStartSeqCtrl = (PSEQUENCE_CONTROL)(req + 7);
	
	printk("====>rx ADDBAREQ from :"MAC_FMT"\n", MAC_ARG(dst));	
	if(
#ifdef _RTL8192_EXT_PATCH_
		(ieee->current_network.qos_data.active == 0 && ieee->current_mesh_network.qos_data.active==0) ||
#else
		ieee->current_network.qos_data.active == 0  ||
#endif	
		(ieee->pHTInfo->bCurrentHTSupport == false) ||
		(ieee->pHTInfo->IOTAction & HT_IOT_ACT_REJECT_ADDBA_REQ)) 
	{
		rc = ADDBA_STATUS_REFUSED;
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "Failed to reply on ADDBA_REQ as some capability is not ready(%d, %d)\n", ieee->current_network.qos_data.active, ieee->pHTInfo->bCurrentHTSupport);
		goto OnADDBAReq_Fail;
	}
	if(	!GetTs(
			ieee, 
			(PTS_COMMON_INFO*)(&pTS), 
			dst, 
			(u8)(pBaParamSet->field.TID), 
			RX_DIR,
			true)	)
	{
		rc = ADDBA_STATUS_REFUSED;
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "can't get TS in %s()\n", __FUNCTION__);
		goto OnADDBAReq_Fail;
	}
	pBA = &pTS->RxAdmittedBARecord;

	if(pBaParamSet->field.BAPolicy == BA_POLICY_DELAYED)
	{
		rc = ADDBA_STATUS_INVALID_PARAM;
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "BA Policy is not correct in %s()\n", __FUNCTION__);
		goto OnADDBAReq_Fail;
	}


	rtllib_FlushRxTsPendingPkts(ieee, pTS);
	
	DeActivateBAEntry(ieee, pBA);	
	pBA->DialogToken = *pDialogToken;
	pBA->BaParamSet = *pBaParamSet;
	pBA->BaTimeoutValue = *pBaTimeoutVal;
	pBA->BaStartSeqCtrl = *pBaStartSeqCtrl;
	
	if (ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev)||
	(ieee->pHTInfo->IOTAction & HT_IOT_ACT_ALLOW_PEER_AGG_ONE_PKT))
	pBA->BaParamSet.field.BufferSize = 1;
	else
	pBA->BaParamSet.field.BufferSize = 32;
	
	ActivateBAEntry(ieee, pBA, 0);
	rtllib_send_ADDBARsp(ieee, dst, pBA, ADDBA_STATUS_SUCCESS);

	return 0;
	
OnADDBAReq_Fail:
	{
		BA_RECORD	BA;
		BA.BaParamSet = *pBaParamSet;
		BA.BaTimeoutValue = *pBaTimeoutVal;
		BA.DialogToken = *pDialogToken;
		BA.BaParamSet.field.BAPolicy = BA_POLICY_IMMEDIATE;
		rtllib_send_ADDBARsp(ieee, dst, &BA, rc);
		return 0; 
	}

}

int rtllib_rx_ADDBARsp( struct rtllib_device* ieee, struct sk_buff *skb)
{
	 struct rtllib_hdr_3addr* rsp = NULL;
	PBA_RECORD		pPendingBA, pAdmittedBA;
	PTX_TS_RECORD		pTS = NULL;
	u8* dst = NULL, *pDialogToken = NULL, *tag = NULL;
	u16* pStatusCode = NULL, *pBaTimeoutVal = NULL;
	PBA_PARAM_SET		pBaParamSet = NULL;
	u16			ReasonCode;

	if (skb->len < sizeof( struct rtllib_hdr_3addr) + 9)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, " Invalid skb len in BARSP(%d / %d)\n", (int)skb->len, 	(int)(sizeof( struct rtllib_hdr_3addr) + 9));
		return -1;
	}
	rsp = ( struct rtllib_hdr_3addr*)skb->data;
	tag = (u8*)rsp;
	dst = (u8*)(&rsp->addr2[0]);
	tag += sizeof( struct rtllib_hdr_3addr);
	pDialogToken = tag + 2;
	pStatusCode = (u16*)(tag + 3);
	pBaParamSet = (PBA_PARAM_SET)(tag + 5);
	pBaTimeoutVal = (u16*)(tag + 7);

	printk("====>rx ADDBARSP from :"MAC_FMT"\n", MAC_ARG(dst));	
	if(     
#ifdef _RTL8192_EXT_PATCH_
		(ieee->current_network.qos_data.active == 0 && ieee->current_mesh_network.qos_data.active==0) ||
#else
		ieee->current_network.qos_data.active == 0  ||
#endif	
		ieee->pHTInfo->bCurrentHTSupport == false ||
		ieee->pHTInfo->bCurrentAMPDUEnable == false )
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "reject to ADDBA_RSP as some capability is not ready(%d, %d, %d)\n",ieee->current_network.qos_data.active, ieee->pHTInfo->bCurrentHTSupport, ieee->pHTInfo->bCurrentAMPDUEnable);
		ReasonCode = DELBA_REASON_UNKNOWN_BA;
		goto OnADDBARsp_Reject;
	}

	
	if (!GetTs(
			ieee, 
			(PTS_COMMON_INFO*)(&pTS), 
			dst, 
			(u8)(pBaParamSet->field.TID), 
			TX_DIR,
			false)	)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "can't get TS in %s()\n", __FUNCTION__);
		ReasonCode = DELBA_REASON_UNKNOWN_BA;
		goto OnADDBARsp_Reject;
	}
	
	pTS->bAddBaReqInProgress = false;
	pPendingBA = &pTS->TxPendingBARecord;
	pAdmittedBA = &pTS->TxAdmittedBARecord;


	if((pAdmittedBA->bValid==true))
	{
		RTLLIB_DEBUG(RTLLIB_DL_BA, "OnADDBARsp(): Recv ADDBA Rsp. Drop because already admit it! \n");
		return -1;
	}
	else if((pPendingBA->bValid == false) ||(*pDialogToken != pPendingBA->DialogToken))
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR,  "OnADDBARsp(): Recv ADDBA Rsp. BA invalid, DELBA! \n");
		ReasonCode = DELBA_REASON_UNKNOWN_BA;
		goto OnADDBARsp_Reject;
	}
	else
	{
		RTLLIB_DEBUG(RTLLIB_DL_BA, "OnADDBARsp(): Recv ADDBA Rsp. BA is admitted! Status code:%X\n", *pStatusCode);
		DeActivateBAEntry(ieee, pPendingBA);
	}


	if(*pStatusCode == ADDBA_STATUS_SUCCESS)
	{
		if(pBaParamSet->field.BAPolicy == BA_POLICY_DELAYED)
		{
			pTS->bAddBaReqDelayed = true;
			DeActivateBAEntry(ieee, pAdmittedBA);
			ReasonCode = DELBA_REASON_END_BA;
			goto OnADDBARsp_Reject;
		}


		pAdmittedBA->DialogToken = *pDialogToken;
		pAdmittedBA->BaTimeoutValue = *pBaTimeoutVal;
		pAdmittedBA->BaStartSeqCtrl = pPendingBA->BaStartSeqCtrl;
		pAdmittedBA->BaParamSet = *pBaParamSet;
		DeActivateBAEntry(ieee, pAdmittedBA);
		ActivateBAEntry(ieee, pAdmittedBA, *pBaTimeoutVal);
	} else {
		pTS->bAddBaReqDelayed = true;
		pTS->bDisable_AddBa = true;
		ReasonCode = DELBA_REASON_END_BA;
		goto OnADDBARsp_Reject;
	}

	return 0;

OnADDBARsp_Reject:
	{
		BA_RECORD	BA;
		BA.BaParamSet = *pBaParamSet;
		rtllib_send_DELBA(ieee, dst, &BA, TX_DIR, ReasonCode);
		return 0;
	}
	
}

int rtllib_rx_DELBA(struct rtllib_device* ieee,struct sk_buff *skb)
{
	 struct rtllib_hdr_3addr* delba = NULL;
	PDELBA_PARAM_SET	pDelBaParamSet = NULL;
	u16*			pReasonCode = NULL;
	u8*			dst = NULL;

	if (skb->len < sizeof( struct rtllib_hdr_3addr) + 6)
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, " Invalid skb len in DELBA(%d / %d)\n", (int)skb->len, 	(int)(sizeof( struct rtllib_hdr_3addr) + 6));
		return -1;
	}
	
	if(
#ifdef _RTL8192_EXT_PATCH_
		(ieee->current_network.qos_data.active == 0 && ieee->current_mesh_network.qos_data.active==0) ||
#else
		ieee->current_network.qos_data.active == 0  ||
#endif	
		ieee->pHTInfo->bCurrentHTSupport == false )
	{
		RTLLIB_DEBUG(RTLLIB_DL_ERR, "received DELBA while QOS or HT is not supported(%d, %d)\n",ieee->current_network.qos_data.active, ieee->pHTInfo->bCurrentHTSupport);
		return -1;
	}
	
	RTLLIB_DEBUG_DATA(RTLLIB_DL_DATA|RTLLIB_DL_BA, skb->data, skb->len);
	delba = ( struct rtllib_hdr_3addr*)skb->data;
	dst = (u8*)(&delba->addr2[0]);
	delba += sizeof( struct rtllib_hdr_3addr);
	pDelBaParamSet = (PDELBA_PARAM_SET)(delba+2);
	pReasonCode = (u16*)(delba+4);

	if(pDelBaParamSet->field.Initiator == 1)
	{
		PRX_TS_RECORD 	pRxTs;

		if( !GetTs(
				ieee, 
				(PTS_COMMON_INFO*)&pRxTs, 
				dst, 
				(u8)pDelBaParamSet->field.TID, 
				RX_DIR,
				false)	)
		{
			RTLLIB_DEBUG(RTLLIB_DL_ERR,  "can't get TS for RXTS in %s().dst:"MAC_FMT" TID:%d\n", __FUNCTION__, MAC_ARG(dst), (u8)pDelBaParamSet->field.TID);
			return -1;
		}
		
		RxTsDeleteBA(ieee, pRxTs);
	}
	else
	{
		PTX_TS_RECORD	pTxTs;

		if(!GetTs(
			ieee, 
			(PTS_COMMON_INFO*)&pTxTs, 
			dst, 
			(u8)pDelBaParamSet->field.TID, 
			TX_DIR,
			false)	)
		{
			RTLLIB_DEBUG(RTLLIB_DL_ERR,  "can't get TS for TXTS in %s()\n", __FUNCTION__);
			return -1;
		}
		
		pTxTs->bUsingBa = false;
		pTxTs->bAddBaReqInProgress = false;
		pTxTs->bAddBaReqDelayed = false;
		del_timer_sync(&pTxTs->TsAddBaTimer);
		TxTsDeleteBA(ieee, pTxTs);
	}
	return 0;
}

void
TsInitAddBA(
	struct rtllib_device* ieee,
	PTX_TS_RECORD	pTS,
	u8		Policy,
	u8		bOverwritePending
	)
{
	PBA_RECORD			pBA = &pTS->TxPendingBARecord;

	if(pBA->bValid==true && bOverwritePending==false)
		return;

	DeActivateBAEntry(ieee, pBA);
	
	pBA->DialogToken++;						
	pBA->BaParamSet.field.AMSDU_Support = 0;	
	pBA->BaParamSet.field.BAPolicy = Policy;	
	pBA->BaParamSet.field.TID = pTS->TsCommonInfo.TSpec.f.TSInfo.field.ucTSID;	
	pBA->BaParamSet.field.BufferSize = 32;		
	pBA->BaTimeoutValue = 0;					
	pBA->BaStartSeqCtrl.field.SeqNum = (pTS->TxCurSeq + 3) % 4096; 	

	ActivateBAEntry(ieee, pBA, BA_SETUP_TIMEOUT);

	rtllib_send_ADDBAReq(ieee, pTS->TsCommonInfo.Addr, pBA);
}

void
TsInitDelBA( struct rtllib_device* ieee, PTS_COMMON_INFO pTsCommonInfo, TR_SELECT TxRxSelect)
{

	if(TxRxSelect == TX_DIR)
	{
		PTX_TS_RECORD	pTxTs = (PTX_TS_RECORD)pTsCommonInfo;

		if(TxTsDeleteBA(ieee, pTxTs))
			rtllib_send_DELBA(
				ieee, 
				pTsCommonInfo->Addr, 
				(pTxTs->TxAdmittedBARecord.bValid)?(&pTxTs->TxAdmittedBARecord):(&pTxTs->TxPendingBARecord), 
				TxRxSelect, 
				DELBA_REASON_END_BA);
	}
	else if(TxRxSelect == RX_DIR)
	{
		PRX_TS_RECORD	pRxTs = (PRX_TS_RECORD)pTsCommonInfo;
		if(RxTsDeleteBA(ieee, pRxTs))
			rtllib_send_DELBA(
				ieee, 
				pTsCommonInfo->Addr, 
				&pRxTs->RxAdmittedBARecord, 
				TxRxSelect, 
				DELBA_REASON_END_BA	);
	}
}
void BaSetupTimeOut(unsigned long data)
{
	PTX_TS_RECORD	pTxTs = (PTX_TS_RECORD)data;

	pTxTs->bAddBaReqInProgress = false;
	pTxTs->bAddBaReqDelayed = true;
	pTxTs->TxPendingBARecord.bValid = false;
}

void TxBaInactTimeout(unsigned long data)
{
	PTX_TS_RECORD	pTxTs = (PTX_TS_RECORD)data;
	struct rtllib_device *ieee = container_of(pTxTs, struct rtllib_device, TxTsRecord[pTxTs->num]);
	TxTsDeleteBA(ieee, pTxTs);
	rtllib_send_DELBA(
		ieee, 
		pTxTs->TsCommonInfo.Addr, 
		&pTxTs->TxAdmittedBARecord,
		TX_DIR, 
		DELBA_REASON_TIMEOUT);
}

void RxBaInactTimeout(unsigned long data)
{
	PRX_TS_RECORD	pRxTs = (PRX_TS_RECORD)data;
	struct rtllib_device *ieee = container_of(pRxTs, struct rtllib_device, RxTsRecord[pRxTs->num]);
	
	RxTsDeleteBA(ieee, pRxTs);
	rtllib_send_DELBA(
		ieee, 
		pRxTs->TsCommonInfo.Addr, 
		&pRxTs->RxAdmittedBARecord,
		RX_DIR, 
		DELBA_REASON_TIMEOUT);
	return ;
}

