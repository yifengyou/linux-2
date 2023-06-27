/* IEEE 802.11 SoftMAC layer
 * Copyright (c) 2005 Andrea Merello <andreamrl@tiscali.it>
 *
 * Mostly extracted from the rtl8180-sa2400 driver for the 
 * in-kernel generic ieee802.11 stack.
 *
 * Some pieces of code might be stolen from ipw2100 driver
 * copyright of who own it's copyright ;-)
 *
 * PS wx handler mostly stolen from hostap, copyright who
 * own it's copyright ;-)
 *
 * released under the GPL
 */


#include "rtllib.h"
#ifdef ENABLE_DOT11D
#include "dot11d.h"
#endif
/* FIXME: add A freqs */

const long rtllib_wlan_frequencies[] = {  
	2412, 2417, 2422, 2427, 
	2432, 2437, 2442, 2447, 
	2452, 2457, 2462, 2467, 
	2472, 2484  
};


int rtllib_wx_set_freq(struct rtllib_device *ieee, struct iw_request_info *a,
			     union iwreq_data *wrqu, char *b)
{
	int ret;
	struct iw_freq *fwrq = & wrqu->freq;

	down(&ieee->wx_sem);
	
	if(ieee->iw_mode == IW_MODE_INFRA){ 
		ret = 0;
		goto out;
	}

	/* if setting by freq convert to channel */
	if (fwrq->e == 1) {
		if ((fwrq->m >= (int) 2.412e8 &&
		     fwrq->m <= (int) 2.487e8)) {
			int f = fwrq->m / 100000;
			int c = 0;
			
			while ((c < 14) && (f != rtllib_wlan_frequencies[c]))
				c++;
			
			/* hack to fall through */
			fwrq->e = 0;
			fwrq->m = c + 1;
		}
	}
	
	if (fwrq->e > 0 || fwrq->m > 14 || fwrq->m < 1 ){ 
		ret = -EOPNOTSUPP;
		goto out;
	
	}else { /* Set the channel */
		
#ifdef ENABLE_DOT11D
		if (ieee->active_channel_map[fwrq->m] != 1) {
			ret = -EINVAL;
			goto out;
		}
#endif
		ieee->current_network.channel = fwrq->m;
		ieee->set_chan(ieee->dev, ieee->current_network.channel);
		
		if(ieee->iw_mode == IW_MODE_ADHOC || ieee->iw_mode == IW_MODE_MASTER)
			if(ieee->state == RTLLIB_LINKED){
			
			rtllib_stop_send_beacons(ieee);
			rtllib_start_send_beacons(ieee);
			}
	}

	ret = 0;
out:
	up(&ieee->wx_sem);
	return ret;
}


#ifdef _RTL8192_EXT_PATCH_	
int rtllib_wx_get_freq(struct rtllib_device *ieee,
			     struct iw_request_info *a,
			     union iwreq_data *wrqu, char *b, u8 is_mesh)
#else
int rtllib_wx_get_freq(struct rtllib_device *ieee,
			     struct iw_request_info *a,
			     union iwreq_data *wrqu, char *b)
#endif	
{
	struct iw_freq *fwrq = & wrqu->freq;

#ifdef _RTL8192_EXT_PATCH_	
	if(is_mesh)
	{
		if (ieee->current_mesh_network.channel == 0)
			return -1;
		fwrq->m = rtllib_wlan_frequencies[ieee->current_mesh_network.channel-1] * 100000;
		fwrq->e = 1;	
	}
	else
#endif	
	{
	if (ieee->current_network.channel == 0)
		return -1;
	fwrq->m = rtllib_wlan_frequencies[ieee->current_network.channel-1] * 100000;
	fwrq->e = 1;	
	}
	return 0;
}

int rtllib_wx_get_wap(struct rtllib_device *ieee, 
			    struct iw_request_info *info, 
			    union iwreq_data *wrqu, char *extra)
{
	unsigned long flags;	
	
	wrqu->ap_addr.sa_family = ARPHRD_ETHER;
	
	if (ieee->iw_mode == IW_MODE_MONITOR)
		return -1;
	
	/* We want avoid to give to the user inconsistent infos*/
	spin_lock_irqsave(&ieee->lock, flags);
	
	if (ieee->state != RTLLIB_LINKED && 
		ieee->state != RTLLIB_LINKED_SCANNING &&
		ieee->wap_set == 0)
		
		memset(wrqu->ap_addr.sa_data, 0, ETH_ALEN);
	else
		memcpy(wrqu->ap_addr.sa_data, 
		       ieee->current_network.bssid, ETH_ALEN);
	
	spin_unlock_irqrestore(&ieee->lock, flags);
	
	return 0;
}


int rtllib_wx_set_wap(struct rtllib_device *ieee,
			 struct iw_request_info *info,
			 union iwreq_data *awrq,
			 char *extra)
{
	
	int ret = 0;
	u8 zero[] = {0,0,0,0,0,0};
	unsigned long flags;
	
	short ifup = ieee->proto_started;
	struct sockaddr *temp = (struct sockaddr *)awrq;

	rtllib_stop_scan_syncro(ieee);

	down(&ieee->wx_sem);
	/* use ifconfig hw ether */
	if (ieee->iw_mode == IW_MODE_MASTER){
		ret = -1;
		goto out;
	}
	
	if (temp->sa_family != ARPHRD_ETHER){
		ret = -EINVAL;
		goto out;
	}
	
        if (memcmp(temp->sa_data, zero,ETH_ALEN) == 0){
                spin_lock_irqsave(&ieee->lock, flags);
                memcpy(ieee->current_network.bssid, temp->sa_data, ETH_ALEN);
                ieee->wap_set = 0;
                spin_unlock_irqrestore(&ieee->lock, flags);
                ret = -1;
                goto out;
        }

	
	if (ifup)
		rtllib_stop_protocol(ieee,true);
	
	/* just to avoid to give inconsistent infos in the
	 * get wx method. not really needed otherwise 
	 */
	spin_lock_irqsave(&ieee->lock, flags);
	
	ieee->cannot_notify = false;
	memcpy(ieee->current_network.bssid, temp->sa_data, ETH_ALEN); 
	ieee->wap_set = (memcmp(temp->sa_data, zero,ETH_ALEN)!=0);
	
	spin_unlock_irqrestore(&ieee->lock, flags);
	
	if (ifup)
		rtllib_start_protocol(ieee);
out:
	up(&ieee->wx_sem);
	return ret;
}
	
 int rtllib_wx_get_essid(struct rtllib_device *ieee, struct iw_request_info *a,union iwreq_data *wrqu,char *b)
{
	int len,ret = 0;
	unsigned long flags;
	
	if (ieee->iw_mode == IW_MODE_MONITOR)
		return -1;
	
	/* We want avoid to give to the user inconsistent infos*/	
	spin_lock_irqsave(&ieee->lock, flags);
	
	if (ieee->current_network.ssid[0] == '\0' ||
		ieee->current_network.ssid_len == 0){ 
		ret = -1;
		goto out;
	}
	
	if (ieee->state != RTLLIB_LINKED && 
		ieee->state != RTLLIB_LINKED_SCANNING &&
		ieee->ssid_set == 0){
		ret = -1;
		goto out;
	}
	len = ieee->current_network.ssid_len;
	wrqu->essid.length = len;
	strncpy(b,ieee->current_network.ssid,len);
	wrqu->essid.flags = 1;

out:
	spin_unlock_irqrestore(&ieee->lock, flags);
	
	return ret;
	
}

int rtllib_wx_set_rate(struct rtllib_device *ieee, 
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{

	u32 target_rate = wrqu->bitrate.value;
	
	ieee->rate = target_rate/100000;
	return 0; 
}

int rtllib_wx_get_rate(struct rtllib_device *ieee, 
			     struct iw_request_info *info, 
			     union iwreq_data *wrqu, char *extra)
{
	u32 tmp_rate = 0;
#if defined RTL8192SU|| defined RTL8192CE
	if (ieee->mode & (IEEE_A | IEEE_B | IEEE_G))
		tmp_rate = ieee->rate;
	else if (ieee->mode & IEEE_N_5G)
		tmp_rate = 580;
	else if (ieee->mode & IEEE_N_24G) {
		if (ieee->GetHalfNmodeSupportByAPsHandler(ieee->dev))
			tmp_rate = HTHalfMcsToDataRate(ieee, 15);
		else
			tmp_rate = HTMcsToDataRate(ieee, 15);
	}
#elif defined RTL8192SE
	tmp_rate = ieee->rtl_11n_user_show_rates(ieee->dev);
#else
        tmp_rate = TxCountToDataRate(ieee, ieee->softmac_stats.CurrentShowTxate);
#endif
	wrqu->bitrate.value = tmp_rate * 500000;
	
	return 0;
}


int rtllib_wx_set_rts(struct rtllib_device *ieee, 
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	if (wrqu->rts.disabled || !wrqu->rts.fixed)
		ieee->rts = DEFAULT_RTS_THRESHOLD;
	else
	{
		if (wrqu->rts.value < MIN_RTS_THRESHOLD ||
				wrqu->rts.value > MAX_RTS_THRESHOLD) 
			return -EINVAL;
		ieee->rts = wrqu->rts.value;
	}
	return 0;
}

int rtllib_wx_get_rts(struct rtllib_device *ieee, 
			     struct iw_request_info *info, 
			     union iwreq_data *wrqu, char *extra)
{
	wrqu->rts.value = ieee->rts;
	wrqu->rts.fixed = 0;	/* no auto select */
	wrqu->rts.disabled = (wrqu->rts.value == DEFAULT_RTS_THRESHOLD);
	return 0;
}

int rtllib_wx_set_mode(struct rtllib_device *ieee, struct iw_request_info *a,
			     union iwreq_data *wrqu, char *b)
{
	int set_mode_status = 0;

	rtllib_stop_scan_syncro(ieee);
	down(&ieee->wx_sem);
	switch (wrqu->mode) {
	case IW_MODE_MONITOR:
	case IW_MODE_ADHOC:
	case IW_MODE_INFRA:
#ifdef _RTL8192_EXT_PATCH_
	case IW_MODE_MESH:
#endif
		break;
	case IW_MODE_AUTO:
		wrqu->mode = IW_MODE_INFRA;
		break;
	default:
		set_mode_status = -EINVAL;
		goto out;
	}

	if (wrqu->mode == ieee->iw_mode)
		goto out;
	
	if (wrqu->mode == IW_MODE_MONITOR) {
#ifdef CONFIG_RTL819x_RADIOTAP
		ieee->dev->type = ARPHRD_IEEE80211_RADIOTAP;
#else
		ieee->dev->type = ARPHRD_IEEE80211;
#endif
		rtllib_EnableNetMonitorMode(ieee->dev,false);	
		
	} else {
		ieee->dev->type = ARPHRD_ETHER;
		if (ieee->iw_mode == IW_MODE_MONITOR)
			rtllib_DisableNetMonitorMode(ieee->dev,false);
	}
	
	if (!ieee->proto_started) {
		ieee->iw_mode = wrqu->mode;
	} else {
		rtllib_stop_protocol(ieee,true);
		ieee->iw_mode = wrqu->mode;
#if defined (RTL8192S_WAPI_SUPPORT)
		if(ieee->iw_mode == IW_MODE_ADHOC)
			ieee->wapiInfo.bWapiPSK = true;
#endif
		rtllib_start_protocol(ieee);
	}

out:
	up(&ieee->wx_sem);
	return set_mode_status;
}

void rtllib_wx_sync_scan_wq(void *data)
{
	struct rtllib_device *ieee = container_of_work_rsl(data, struct rtllib_device, wx_sync_scan_wq);
	short chan;
	HT_EXTCHNL_OFFSET chan_offset=0;
	HT_CHANNEL_WIDTH bandwidth=0;
	int b40M = 0;
	static int count = 0;

	if (!(ieee->softmac_features & IEEE_SOFTMAC_SCAN)){	
		rtllib_start_scan_syncro(ieee, 0);
		goto out;
	}

	chan = ieee->current_network.channel;

#ifdef ENABLE_LPS
	if (ieee->LeisurePSLeave) {
		ieee->LeisurePSLeave(ieee->dev);
	}
	/* notify AP to be in PS mode */
	rtllib_sta_ps_send_null_frame(ieee, 1);
	rtllib_sta_ps_send_null_frame(ieee, 1);
#endif

	rtllib_stop_all_queues(ieee);

	if (ieee->data_hard_stop)
		ieee->data_hard_stop(ieee->dev);
	rtllib_stop_send_beacons(ieee);
	ieee->state = RTLLIB_LINKED_SCANNING;
	ieee->link_change(ieee->dev);
	/* wait for ps packet to be kicked out successfully */
	msleep(50);

#if !(defined RTL8192SE ||defined RTL8192CE)	
	ieee->InitialGainHandler(ieee->dev,IG_Backup);
#endif
#if defined(RTL8192SE)
#if(RTL8192S_DISABLE_FW_DM == 0)
	if (ieee->SetFwCmdHandler) {
		ieee->SetFwCmdHandler(ieee->dev, FW_CMD_PAUSE_DM_BY_SCAN);
	}
#endif
#endif	
#if defined RTL8192SU || defined RTL8192CE
	ieee->ScanOperationBackupHandler(ieee->dev,SCAN_OPT_BACKUP);
#endif

	if (ieee->pHTInfo->bCurrentHTSupport && ieee->pHTInfo->bEnableHT && ieee->pHTInfo->bCurBW40MHz) {
		b40M = 1;
		chan_offset = ieee->pHTInfo->CurSTAExtChnlOffset;
		bandwidth = (HT_CHANNEL_WIDTH)ieee->pHTInfo->bCurBW40MHz;
		printk("Scan in 40M, force to 20M first:%d, %d\n", chan_offset, bandwidth);
		ieee->SetBWModeHandler(ieee->dev, HT_CHANNEL_WIDTH_20, HT_EXTCHNL_OFFSET_NO_EXT);
		}

	rtllib_start_scan_syncro(ieee, 0);

	if (b40M) {
		printk("Scan in 20M, back to 40M\n");
		if (chan_offset == HT_EXTCHNL_OFFSET_UPPER)
			ieee->set_chan(ieee->dev, chan + 2);
		else if (chan_offset == HT_EXTCHNL_OFFSET_LOWER)
			ieee->set_chan(ieee->dev, chan - 2);
		else
			ieee->set_chan(ieee->dev, chan);
		ieee->SetBWModeHandler(ieee->dev, bandwidth, chan_offset);
	} else {
		ieee->set_chan(ieee->dev, chan);
	}
	
#if !(defined RTL8192SE ||defined RTL8192CE)
	ieee->InitialGainHandler(ieee->dev,IG_Restore);
#endif

#if defined(RTL8192SE)
#if(RTL8192S_DISABLE_FW_DM == 0)
	if (ieee->SetFwCmdHandler) {
		ieee->SetFwCmdHandler(ieee->dev, FW_CMD_RESUME_DM_BY_SCAN);
	}
#endif
#endif	
#if defined RTL8192SU || defined RTL8192CE
	ieee->ScanOperationBackupHandler(ieee->dev,SCAN_OPT_RESTORE);
#endif
	ieee->state = RTLLIB_LINKED;
	ieee->link_change(ieee->dev);

#ifdef ENABLE_LPS
	/* Notify AP that I wake up again */
	rtllib_sta_ps_send_null_frame(ieee, 0);
#endif

	if (ieee->LinkDetectInfo.NumRecvBcnInPeriod == 0 || 
			ieee->LinkDetectInfo.NumRecvDataInPeriod == 0 ) {
		ieee->LinkDetectInfo.NumRecvBcnInPeriod = 1;
		ieee->LinkDetectInfo.NumRecvDataInPeriod= 1;	
	}

	if (ieee->data_hard_resume)
		ieee->data_hard_resume(ieee->dev);
	
	if(ieee->iw_mode == IW_MODE_ADHOC || ieee->iw_mode == IW_MODE_MASTER)
		rtllib_start_send_beacons(ieee);
	
	rtllib_wake_all_queues(ieee);

	count = 0;	
out:
	up(&ieee->wx_sem);
	
}

int rtllib_wx_set_scan(struct rtllib_device *ieee, struct iw_request_info *a,
			     union iwreq_data *wrqu, char *b)
{
	int ret = 0;
	
	down(&ieee->wx_sem);
	
	if (ieee->iw_mode == IW_MODE_MONITOR || !(ieee->proto_started)){ 
		ret = -1;
		goto out;
	}
	
	if ( ieee->state == RTLLIB_LINKED){
		queue_work_rsl(ieee->wq, &ieee->wx_sync_scan_wq);
		/* intentionally forget to up sem */
		return 0;
	}
		
out:
	up(&ieee->wx_sem);
	return ret;
}

int rtllib_wx_set_essid(struct rtllib_device *ieee, 
			      struct iw_request_info *a,
			      union iwreq_data *wrqu, char *extra)
{
	
	int ret=0,len,i;
	short proto_started;
	unsigned long flags;
	
	rtllib_stop_scan_syncro(ieee);
	down(&ieee->wx_sem);
	
	proto_started = ieee->proto_started;
	
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
	len = ((wrqu->essid.length-1) < IW_ESSID_MAX_SIZE) ? (wrqu->essid.length-1) : IW_ESSID_MAX_SIZE;
#else
	len = (wrqu->essid.length < IW_ESSID_MAX_SIZE) ? wrqu->essid.length : IW_ESSID_MAX_SIZE;
#endif

	if (len > IW_ESSID_MAX_SIZE){
		ret= -E2BIG;
		goto out;
	}
	
	if (ieee->iw_mode == IW_MODE_MONITOR){
		ret= -1;
		goto out;
	}
	
	for (i=0; i<len; i++){
		if(extra[i] < 0){
			ret= -1;
			goto out;
		}
	}
	
	if(proto_started)
		rtllib_stop_protocol(ieee,true);
	
	
	/* this is just to be sure that the GET wx callback
	 * has consisten infos. not needed otherwise
	 */
	spin_lock_irqsave(&ieee->lock, flags);
	
	if (wrqu->essid.flags && wrqu->essid.length) {
		strncpy(ieee->current_network.ssid, extra, len);
		ieee->current_network.ssid_len = len;
#if 0
		{
			int i;
			for (i=0; i<len; i++)
				printk("%c:%d ", extra[i], extra[i]);
			printk("\n");
		}
#endif
		ieee->cannot_notify = false;
		ieee->ssid_set = 1;
	}
	else{ 
		ieee->ssid_set = 0;
		ieee->current_network.ssid[0] = '\0';
		ieee->current_network.ssid_len = 0;
	}
	spin_unlock_irqrestore(&ieee->lock, flags);
	
	if (proto_started)
		rtllib_start_protocol(ieee);
out:
	up(&ieee->wx_sem);
	return ret;
}

 int rtllib_wx_get_mode(struct rtllib_device *ieee, struct iw_request_info *a,
			     union iwreq_data *wrqu, char *b)
{
#ifdef _RTL8192_EXT_PATCH_
	if(ieee->iw_mode == IW_MODE_MESH) {
		/* WEXT could not show mesh mode properly,
		 * just disable it */
		if(ieee->only_mesh) {
			return -1;
		} else {
			wrqu->mode = IW_MODE_INFRA;
		}
	}
	else
#endif
		wrqu->mode = ieee->iw_mode;
	return 0;
}

 int rtllib_wx_set_rawtx(struct rtllib_device *ieee, 
			       struct iw_request_info *info, 
			       union iwreq_data *wrqu, char *extra)
{
	
	int *parms = (int *)extra;
	int enable = (parms[0] > 0);
	short prev = ieee->raw_tx;

	down(&ieee->wx_sem);
	
	if(enable) 
		ieee->raw_tx = 1;
	else 
		ieee->raw_tx = 0;

	printk(KERN_INFO"raw TX is %s\n", 
	      ieee->raw_tx ? "enabled" : "disabled");

	if(ieee->iw_mode == IW_MODE_MONITOR)
	{
		if(prev == 0 && ieee->raw_tx){
			if (ieee->data_hard_resume)
				ieee->data_hard_resume(ieee->dev);
	
			netif_carrier_on(ieee->dev);	
		}
		
		if(prev && ieee->raw_tx == 1)
			netif_carrier_off(ieee->dev); 
	}
	
	up(&ieee->wx_sem);
	
	return 0;
}
 
int rtllib_wx_get_name(struct rtllib_device *ieee, 
			     struct iw_request_info *info, 
			     union iwreq_data *wrqu, char *extra)
{
	strcpy(wrqu->name, "802.11");

	if (ieee->modulation & RTLLIB_CCK_MODULATION)
		strcat(wrqu->name, "b");
	if (ieee->modulation & RTLLIB_OFDM_MODULATION)
		strcat(wrqu->name, "g");
	if (ieee->mode & (IEEE_N_24G | IEEE_N_5G))
		strcat(wrqu->name, "n");
#if 0	
	if((ieee->state == RTLLIB_LINKED) || 
		(ieee->state == RTLLIB_LINKED_SCANNING))
		strcat(wrqu->name," linked");
	else if(ieee->state != RTLLIB_NOLINK)
		strcat(wrqu->name," link..");
#endif	
	return 0;
}


/* this is mostly stolen from hostap */
int rtllib_wx_set_power(struct rtllib_device *ieee,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
#if 1
	if(
		(!ieee->sta_wake_up) ||
		(!ieee->enter_sleep_state) ||
		(!ieee->ps_is_queue_empty)){
		
		RTLLIB_DEBUG(RTLLIB_DL_ERR,"%s(): PS mode is tryied to be use but driver missed a callback\n\n",__FUNCTION__);	
	
		return -1;
	}
#endif	
	down(&ieee->wx_sem);
	
	if (wrqu->power.disabled){
		printk("===>%s(): power disable\n",__FUNCTION__);
		ieee->ps = RTLLIB_PS_DISABLED;
		goto exit;
	}
	if (wrqu->power.flags & IW_POWER_TIMEOUT) {
		ieee->ps_timeout = wrqu->power.value / 1000;
		printk("===>%s():ps_timeout is %d\n",__FUNCTION__,ieee->ps_timeout);
	}
	
	if (wrqu->power.flags & IW_POWER_PERIOD) {
		
		ieee->ps_period = wrqu->power.value / 1000;
		
	}
	switch (wrqu->power.flags & IW_POWER_MODE) {
	case IW_POWER_UNICAST_R:
		ieee->ps = RTLLIB_PS_UNICAST;
		break;
	case IW_POWER_MULTICAST_R:
		ieee->ps = RTLLIB_PS_MBCAST;
		break;
	case IW_POWER_ALL_R:
		ieee->ps = RTLLIB_PS_UNICAST | RTLLIB_PS_MBCAST;	
		break;
		
	case IW_POWER_ON:
		break;
		
	default:
		ret = -EINVAL;
		goto exit;
		
	}
exit:
	up(&ieee->wx_sem);
	return ret;

}

/* this is stolen from hostap */
int rtllib_wx_get_power(struct rtllib_device *ieee,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	int ret =0;
	
	down(&ieee->wx_sem);
	
	if(ieee->ps == RTLLIB_PS_DISABLED){	
		wrqu->power.disabled = 1;
		goto exit;
	}

	wrqu->power.disabled = 0;

	if ((wrqu->power.flags & IW_POWER_TYPE) == IW_POWER_TIMEOUT) {
		wrqu->power.flags = IW_POWER_TIMEOUT;
		wrqu->power.value = ieee->ps_timeout * 1000;
	} else {
		wrqu->power.flags = IW_POWER_PERIOD;
		wrqu->power.value = ieee->ps_period * 1000; 
	}

       if ((ieee->ps & (RTLLIB_PS_MBCAST | RTLLIB_PS_UNICAST)) == (RTLLIB_PS_MBCAST | RTLLIB_PS_UNICAST))
	   	wrqu->power.flags |= IW_POWER_ALL_R;
	else if (ieee->ps & RTLLIB_PS_MBCAST)
		wrqu->power.flags |= IW_POWER_MULTICAST_R;
	else
		wrqu->power.flags |= IW_POWER_UNICAST_R;

exit:
	up(&ieee->wx_sem);
	return ret;

}

#ifndef BUILT_IN_RTLLIB
EXPORT_SYMBOL_RSL(rtllib_wx_get_essid);
EXPORT_SYMBOL_RSL(rtllib_wx_set_essid);
EXPORT_SYMBOL_RSL(rtllib_wx_set_rate);
EXPORT_SYMBOL_RSL(rtllib_wx_get_rate);
EXPORT_SYMBOL_RSL(rtllib_wx_set_wap);
EXPORT_SYMBOL_RSL(rtllib_wx_get_wap);
EXPORT_SYMBOL_RSL(rtllib_wx_set_mode);
EXPORT_SYMBOL_RSL(rtllib_wx_get_mode);
EXPORT_SYMBOL_RSL(rtllib_wx_set_scan);
EXPORT_SYMBOL_RSL(rtllib_wx_get_freq);
EXPORT_SYMBOL_RSL(rtllib_wx_set_freq);
EXPORT_SYMBOL_RSL(rtllib_wx_set_rawtx);
EXPORT_SYMBOL_RSL(rtllib_wx_get_name);
EXPORT_SYMBOL_RSL(rtllib_wx_set_power);
EXPORT_SYMBOL_RSL(rtllib_wx_get_power);
EXPORT_SYMBOL_RSL(rtllib_wlan_frequencies);
EXPORT_SYMBOL_RSL(rtllib_wx_set_rts);
EXPORT_SYMBOL_RSL(rtllib_wx_get_rts);
#endif
