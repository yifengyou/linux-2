/*
 * BSS client mode implementation
 * Copyright 2003, Jouni Malinen <jkmaline@cc.hut.fi>
 * Copyright 2004, Instant802 Networks, Inc.
 * Copyright 2005, Devicescape Software, Inc.
 * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
 * Copyright 2007, Michael Wu <flamingice@sourmilk.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* TODO:
 * order BSS list by RSSI(?) ("quality of AP")
 * scan result table filtering (by capability (privacy, IBSS/BSS, WPA/RSN IE,
 *    SSID)
 */
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>
#include <linux/random.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <net/iw_handler.h>
#include <asm/types.h>

#include <net/mac80211.h>
#include "ieee80211_i.h"
#include "rate.h"
#include "led.h"
#include "mesh.h"

#define IEEE80211_AUTH_TIMEOUT (HZ / 5)
#define IEEE80211_AUTH_MAX_TRIES 3
#define IEEE80211_ASSOC_TIMEOUT (HZ / 5)
#define IEEE80211_ASSOC_MAX_TRIES 3
#define IEEE80211_MONITORING_INTERVAL (2 * HZ)
#define IEEE80211_MESH_HOUSEKEEPING_INTERVAL (60 * HZ)
#define IEEE80211_PROBE_INTERVAL (60 * HZ)
#define IEEE80211_RETRY_AUTH_INTERVAL (1 * HZ)
#define IEEE80211_SCAN_INTERVAL (2 * HZ)
#define IEEE80211_SCAN_INTERVAL_SLOW (15 * HZ)
#define IEEE80211_IBSS_JOIN_TIMEOUT (7 * HZ)

#define IEEE80211_PROBE_DELAY (HZ / 33)
#define IEEE80211_CHANNEL_TIME (HZ / 33)
#define IEEE80211_PASSIVE_CHANNEL_TIME (HZ / 5)
#define IEEE80211_SCAN_RESULT_EXPIRE (10 * HZ)
#define IEEE80211_IBSS_MERGE_INTERVAL (30 * HZ)
#define IEEE80211_IBSS_INACTIVITY_LIMIT (60 * HZ)
#define IEEE80211_MESH_PEER_INACTIVITY_LIMIT (1800 * HZ)

#define IEEE80211_IBSS_MAX_STA_ENTRIES 128


#define ERP_INFO_USE_PROTECTION BIT(1)

/* mgmt header + 1 byte action code */
#define IEEE80211_MIN_ACTION_SIZE (24 + 1)

#define IEEE80211_ADDBA_PARAM_POLICY_MASK 0x0002
#define IEEE80211_ADDBA_PARAM_TID_MASK 0x003C
#define IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK 0xFFA0
#define IEEE80211_DELBA_PARAM_TID_MASK 0xF000
#define IEEE80211_DELBA_PARAM_INITIATOR_MASK 0x0800

/* next values represent the buffer size for A-MPDU frame.
 * According to IEEE802.11n spec size varies from 8K to 64K (in powers of 2) */
#define IEEE80211_MIN_AMPDU_BUF 0x8
#define IEEE80211_MAX_AMPDU_BUF 0x40

static void ieee80211_send_probe_req(struct net_device *dev, u8 *dst,
				     u8 *ssid, size_t ssid_len);
static struct ieee80211_sta_bss *
ieee80211_rx_bss_get(struct net_device *dev, u8 *bssid, int freq,
		     u8 *ssid, u8 ssid_len);
static void ieee80211_rx_bss_put(struct net_device *dev,
				 struct ieee80211_sta_bss *bss);
static int ieee80211_sta_find_ibss(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta);
static int ieee80211_sta_wep_configured(struct net_device *dev);
static int ieee80211_sta_start_scan(struct net_device *dev,
				    u8 *ssid, size_t ssid_len);
static int ieee80211_sta_config_auth(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta);


void ieee802_11_parse_elems(u8 *start, size_t len,
			    struct ieee802_11_elems *elems)
{
	size_t left = len;
	u8 *pos = start;

	memset(elems, 0, sizeof(*elems));

	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left)
			return;

		switch (id) {
		case WLAN_EID_SSID:
			elems->ssid = pos;
			elems->ssid_len = elen;
			break;
		case WLAN_EID_SUPP_RATES:
			elems->supp_rates = pos;
			elems->supp_rates_len = elen;
			break;
		case WLAN_EID_FH_PARAMS:
			elems->fh_params = pos;
			elems->fh_params_len = elen;
			break;
		case WLAN_EID_DS_PARAMS:
			elems->ds_params = pos;
			elems->ds_params_len = elen;
			break;
		case WLAN_EID_CF_PARAMS:
			elems->cf_params = pos;
			elems->cf_params_len = elen;
			break;
		case WLAN_EID_TIM:
			elems->tim = pos;
			elems->tim_len = elen;
			break;
		case WLAN_EID_IBSS_PARAMS:
			elems->ibss_params = pos;
			elems->ibss_params_len = elen;
			break;
		case WLAN_EID_CHALLENGE:
			elems->challenge = pos;
			elems->challenge_len = elen;
			break;
		case WLAN_EID_WPA:
			if (elen >= 4 && pos[0] == 0x00 && pos[1] == 0x50 &&
			    pos[2] == 0xf2) {
				/* Microsoft OUI (00:50:F2) */
				if (pos[3] == 1) {
					/* OUI Type 1 - WPA IE */
					elems->wpa = pos;
					elems->wpa_len = elen;
				} else if (elen >= 5 && pos[3] == 2) {
					if (pos[4] == 0) {
						elems->wmm_info = pos;
						elems->wmm_info_len = elen;
					} else if (pos[4] == 1) {
						elems->wmm_param = pos;
						elems->wmm_param_len = elen;
					}
				}
			}
			break;
		case WLAN_EID_RSN:
			elems->rsn = pos;
			elems->rsn_len = elen;
			break;
		case WLAN_EID_ERP_INFO:
			elems->erp_info = pos;
			elems->erp_info_len = elen;
			break;
		case WLAN_EID_EXT_SUPP_RATES:
			elems->ext_supp_rates = pos;
			elems->ext_supp_rates_len = elen;
			break;
		case WLAN_EID_HT_CAPABILITY:
			elems->ht_cap_elem = pos;
			elems->ht_cap_elem_len = elen;
			break;
		case WLAN_EID_HT_EXTRA_INFO:
			elems->ht_info_elem = pos;
			elems->ht_info_elem_len = elen;
			break;
		case WLAN_EID_MESH_ID:
			elems->mesh_id = pos;
			elems->mesh_id_len = elen;
			break;
		case WLAN_EID_MESH_CONFIG:
			elems->mesh_config = pos;
			elems->mesh_config_len = elen;
			break;
		case WLAN_EID_PEER_LINK:
			elems->peer_link = pos;
			elems->peer_link_len = elen;
			break;
		case WLAN_EID_PREQ:
			elems->preq = pos;
			elems->preq_len = elen;
			break;
		case WLAN_EID_PREP:
			elems->prep = pos;
			elems->prep_len = elen;
			break;
		case WLAN_EID_PERR:
			elems->perr = pos;
			elems->perr_len = elen;
			break;
		default:
			break;
		}

		left -= elen;
		pos += elen;
	}
}


static int ecw2cw(int ecw)
{
	return (1 << ecw) - 1;
}


static void ieee80211_sta_def_wmm_params(struct net_device *dev,
					 struct ieee80211_sta_bss *bss,
					 int ibss)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	int i, have_higher_than_11mbit = 0;


	/* cf. IEEE 802.11 9.2.12 */
	for (i = 0; i < bss->supp_rates_len; i++)
		if ((bss->supp_rates[i] & 0x7f) * 5 > 110)
			have_higher_than_11mbit = 1;

	if (local->hw.conf.channel->band == IEEE80211_BAND_2GHZ &&
	    have_higher_than_11mbit)
		sdata->flags |= IEEE80211_SDATA_OPERATING_GMODE;
	else
		sdata->flags &= ~IEEE80211_SDATA_OPERATING_GMODE;


	if (local->ops->conf_tx) {
		struct ieee80211_tx_queue_params qparam;

		memset(&qparam, 0, sizeof(qparam));

		qparam.aifs = 2;

		if (local->hw.conf.channel->band == IEEE80211_BAND_2GHZ &&
		    !(sdata->flags & IEEE80211_SDATA_OPERATING_GMODE))
			qparam.cw_min = 31;
		else
			qparam.cw_min = 15;

		qparam.cw_max = 1023;
		qparam.txop = 0;

		for (i = IEEE80211_TX_QUEUE_DATA0; i < NUM_TX_DATA_QUEUES; i++)
			local->ops->conf_tx(local_to_hw(local),
					   i + IEEE80211_TX_QUEUE_DATA0,
					   &qparam);

		if (ibss) {
			/* IBSS uses different parameters for Beacon sending */
			qparam.cw_min++;
			qparam.cw_min *= 2;
			qparam.cw_min--;
			local->ops->conf_tx(local_to_hw(local),
					   IEEE80211_TX_QUEUE_BEACON, &qparam);
		}
	}
}

static void ieee80211_sta_wmm_params(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     u8 *wmm_param, size_t wmm_param_len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_tx_queue_params params;
	size_t left;
	int count;
	u8 *pos;

	if (wmm_param_len < 8 || wmm_param[5] /* version */ != 1)
		return;
	count = wmm_param[6] & 0x0f;
	if (count == ifsta->wmm_last_param_set)
		return;
	ifsta->wmm_last_param_set = count;

	pos = wmm_param + 8;
	left = wmm_param_len - 8;

	memset(&params, 0, sizeof(params));

	if (!local->ops->conf_tx)
		return;

	local->wmm_acm = 0;
	for (; left >= 4; left -= 4, pos += 4) {
		int aci = (pos[0] >> 5) & 0x03;
		int acm = (pos[0] >> 4) & 0x01;
		int queue;

		switch (aci) {
		case 1:
			queue = IEEE80211_TX_QUEUE_DATA3;
			if (acm) {
				local->wmm_acm |= BIT(0) | BIT(3);
			}
			break;
		case 2:
			queue = IEEE80211_TX_QUEUE_DATA1;
			if (acm) {
				local->wmm_acm |= BIT(4) | BIT(5);
			}
			break;
		case 3:
			queue = IEEE80211_TX_QUEUE_DATA0;
			if (acm) {
				local->wmm_acm |= BIT(6) | BIT(7);
			}
			break;
		case 0:
		default:
			queue = IEEE80211_TX_QUEUE_DATA2;
			if (acm) {
				local->wmm_acm |= BIT(1) | BIT(2);
			}
			break;
		}

		params.aifs = pos[0] & 0x0f;
		params.cw_max = ecw2cw((pos[1] & 0xf0) >> 4);
		params.cw_min = ecw2cw(pos[1] & 0x0f);
		params.txop = pos[2] | (pos[3] << 8);
#ifdef CONFIG_MAC80211_DEBUG
		printk(KERN_DEBUG "%s: WMM queue=%d aci=%d acm=%d aifs=%d "
		       "cWmin=%d cWmax=%d txop=%d\n",
		       dev->name, queue, aci, acm, params.aifs, params.cw_min,
		       params.cw_max, params.txop);
#endif
		/* TODO: handle ACM (block TX, fallback to next lowest allowed
		 * AC for now) */
		if (local->ops->conf_tx(local_to_hw(local), queue, &params)) {
			printk(KERN_DEBUG "%s: failed to set TX queue "
			       "parameters for queue %d\n", dev->name, queue);
		}
	}
}

static u32 ieee80211_handle_protect_preamb(struct ieee80211_sub_if_data *sdata,
					   bool use_protection,
					   bool use_short_preamble)
{
	struct ieee80211_bss_conf *bss_conf = &sdata->bss_conf;
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	DECLARE_MAC_BUF(mac);
	u32 changed = 0;

	if (use_protection != bss_conf->use_cts_prot) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: CTS protection %s (BSSID="
			       "%s)\n",
			       sdata->dev->name,
			       use_protection ? "enabled" : "disabled",
			       print_mac(mac, ifsta->bssid));
		}
		bss_conf->use_cts_prot = use_protection;
		changed |= BSS_CHANGED_ERP_CTS_PROT;
	}

	if (use_short_preamble != bss_conf->use_short_preamble) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: switched to %s barker preamble"
			       " (BSSID=%s)\n",
			       sdata->dev->name,
			       use_short_preamble ? "short" : "long",
			       print_mac(mac, ifsta->bssid));
		}
		bss_conf->use_short_preamble = use_short_preamble;
		changed |= BSS_CHANGED_ERP_PREAMBLE;
	}

	return changed;
}

static u32 ieee80211_handle_erp_ie(struct ieee80211_sub_if_data *sdata,
				   u8 erp_value)
{
	bool use_protection = (erp_value & WLAN_ERP_USE_PROTECTION) != 0;
	bool use_short_preamble = (erp_value & WLAN_ERP_BARKER_PREAMBLE) == 0;

	return ieee80211_handle_protect_preamb(sdata,
			use_protection, use_short_preamble);
}

static u32 ieee80211_handle_bss_capability(struct ieee80211_sub_if_data *sdata,
					   struct ieee80211_sta_bss *bss)
{
	u32 changed = 0;

	if (bss->has_erp_value)
		changed |= ieee80211_handle_erp_ie(sdata, bss->erp_value);
	else {
		u16 capab = bss->capability;
		changed |= ieee80211_handle_protect_preamb(sdata, false,
				(capab & WLAN_CAPABILITY_SHORT_PREAMBLE) != 0);
	}

	return changed;
}

int ieee80211_ht_cap_ie_to_ht_info(struct ieee80211_ht_cap *ht_cap_ie,
				   struct ieee80211_ht_info *ht_info)
{

	if (ht_info == NULL)
		return -EINVAL;

	memset(ht_info, 0, sizeof(*ht_info));

	if (ht_cap_ie) {
		u8 ampdu_info = ht_cap_ie->ampdu_params_info;

		ht_info->ht_supported = 1;
		ht_info->cap = le16_to_cpu(ht_cap_ie->cap_info);
		ht_info->ampdu_factor =
			ampdu_info & IEEE80211_HT_CAP_AMPDU_FACTOR;
		ht_info->ampdu_density =
			(ampdu_info & IEEE80211_HT_CAP_AMPDU_DENSITY) >> 2;
		memcpy(ht_info->supp_mcs_set, ht_cap_ie->supp_mcs_set, 16);
	} else
		ht_info->ht_supported = 0;

	return 0;
}

int ieee80211_ht_addt_info_ie_to_ht_bss_info(
			struct ieee80211_ht_addt_info *ht_add_info_ie,
			struct ieee80211_ht_bss_info *bss_info)
{
	if (bss_info == NULL)
		return -EINVAL;

	memset(bss_info, 0, sizeof(*bss_info));

	if (ht_add_info_ie) {
		u16 op_mode;
		op_mode = le16_to_cpu(ht_add_info_ie->operation_mode);

		bss_info->primary_channel = ht_add_info_ie->control_chan;
		bss_info->bss_cap = ht_add_info_ie->ht_param;
		bss_info->bss_op_mode = (u8)(op_mode & 0xff);
	}

	return 0;
}

static void ieee80211_sta_send_associnfo(struct net_device *dev,
					 struct ieee80211_if_sta *ifsta)
{
	char *buf;
	size_t len;
	int i;
	union iwreq_data wrqu;

	if (!ifsta->assocreq_ies && !ifsta->assocresp_ies)
		return;

	buf = kmalloc(50 + 2 * (ifsta->assocreq_ies_len +
				ifsta->assocresp_ies_len), GFP_KERNEL);
	if (!buf)
		return;

	len = sprintf(buf, "ASSOCINFO(");
	if (ifsta->assocreq_ies) {
		len += sprintf(buf + len, "ReqIEs=");
		for (i = 0; i < ifsta->assocreq_ies_len; i++) {
			len += sprintf(buf + len, "%02x",
				       ifsta->assocreq_ies[i]);
		}
	}
	if (ifsta->assocresp_ies) {
		if (ifsta->assocreq_ies)
			len += sprintf(buf + len, " ");
		len += sprintf(buf + len, "RespIEs=");
		for (i = 0; i < ifsta->assocresp_ies_len; i++) {
			len += sprintf(buf + len, "%02x",
				       ifsta->assocresp_ies[i]);
		}
	}
	len += sprintf(buf + len, ")");

	if (len > IW_CUSTOM_MAX) {
		len = sprintf(buf, "ASSOCRESPIE=");
		for (i = 0; i < ifsta->assocresp_ies_len; i++) {
			len += sprintf(buf + len, "%02x",
				       ifsta->assocresp_ies[i]);
		}
	}

	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.length = len;
	wireless_send_event(dev, IWEVCUSTOM, &wrqu, buf);

	kfree(buf);
}


static void ieee80211_set_associated(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     bool assoc)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_conf *conf = &local_to_hw(local)->conf;
	union iwreq_data wrqu;
	u32 changed = BSS_CHANGED_ASSOC;

	if (assoc) {
		struct ieee80211_sta_bss *bss;

		ifsta->flags |= IEEE80211_STA_ASSOCIATED;

		if (sdata->vif.type != IEEE80211_IF_TYPE_STA)
			return;

		bss = ieee80211_rx_bss_get(dev, ifsta->bssid,
					   conf->channel->center_freq,
					   ifsta->ssid, ifsta->ssid_len);
		if (bss) {
			/* set timing information */
			sdata->bss_conf.beacon_int = bss->beacon_int;
			sdata->bss_conf.timestamp = bss->timestamp;

			changed |= ieee80211_handle_bss_capability(sdata, bss);

			ieee80211_rx_bss_put(dev, bss);
		}

		if (conf->flags & IEEE80211_CONF_SUPPORT_HT_MODE) {
			changed |= BSS_CHANGED_HT;
			sdata->bss_conf.assoc_ht = 1;
			sdata->bss_conf.ht_conf = &conf->ht_conf;
			sdata->bss_conf.ht_bss_conf = &conf->ht_bss_conf;
		}

		ifsta->flags |= IEEE80211_STA_PREV_BSSID_SET;
		memcpy(ifsta->prev_bssid, sdata->u.sta.bssid, ETH_ALEN);
		memcpy(wrqu.ap_addr.sa_data, sdata->u.sta.bssid, ETH_ALEN);
		ieee80211_sta_send_associnfo(dev, ifsta);
	} else {
		netif_carrier_off(dev);
		ieee80211_sta_tear_down_BA_sessions(dev, ifsta->bssid);
		ifsta->flags &= ~IEEE80211_STA_ASSOCIATED;
		ieee80211_reset_erp_info(dev);

		sdata->bss_conf.assoc_ht = 0;
		sdata->bss_conf.ht_conf = NULL;
		sdata->bss_conf.ht_bss_conf = NULL;

		memset(wrqu.ap_addr.sa_data, 0, ETH_ALEN);
	}
	ifsta->last_probe = jiffies;
	ieee80211_led_assoc(local, assoc);

	sdata->bss_conf.assoc = assoc;
	ieee80211_bss_info_change_notify(sdata, changed);

	if (assoc)
		netif_carrier_on(dev);

	wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	wireless_send_event(dev, SIOCGIWAP, &wrqu, NULL);
}

static void ieee80211_set_disassoc(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta, int deauth)
{
	if (deauth)
		ifsta->auth_tries = 0;
	ifsta->assoc_tries = 0;
	ieee80211_set_associated(dev, ifsta, 0);
}

void ieee80211_sta_tx(struct net_device *dev, struct sk_buff *skb,
		      int encrypt)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_tx_packet_data *pkt_data;

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	skb->dev = sdata->local->mdev;
	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, 0);
	skb_set_transport_header(skb, 0);

	pkt_data = (struct ieee80211_tx_packet_data *) skb->cb;
	memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
	pkt_data->ifindex = sdata->dev->ifindex;
	if (!encrypt)
		pkt_data->flags |= IEEE80211_TXPD_DO_NOT_ENCRYPT;

	dev_queue_xmit(skb);
}


static void ieee80211_send_auth(struct net_device *dev,
				struct ieee80211_if_sta *ifsta,
				int transaction, u8 *extra, size_t extra_len,
				int encrypt)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom +
			    sizeof(*mgmt) + 6 + extra_len);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for auth "
		       "frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24 + 6);
	memset(mgmt, 0, 24 + 6);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_AUTH);
	if (encrypt)
		mgmt->frame_control |= cpu_to_le16(IEEE80211_FCTL_PROTECTED);
	memcpy(mgmt->da, ifsta->bssid, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
	mgmt->u.auth.auth_alg = cpu_to_le16(ifsta->auth_alg);
	mgmt->u.auth.auth_transaction = cpu_to_le16(transaction);
	ifsta->auth_transaction = transaction + 1;
	mgmt->u.auth.status_code = cpu_to_le16(0);
	if (extra)
		memcpy(skb_put(skb, extra_len), extra, extra_len);

	ieee80211_sta_tx(dev, skb, encrypt);
}


static void ieee80211_authenticate(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta)
{
	DECLARE_MAC_BUF(mac);

	ifsta->auth_tries++;
	if (ifsta->auth_tries > IEEE80211_AUTH_MAX_TRIES) {
		printk(KERN_DEBUG "%s: authentication with AP %s"
		       " timed out\n",
		       dev->name, print_mac(mac, ifsta->bssid));
		ifsta->state = IEEE80211_DISABLED;
		return;
	}

	ifsta->state = IEEE80211_AUTHENTICATE;
	printk(KERN_DEBUG "%s: authenticate with AP %s\n",
	       dev->name, print_mac(mac, ifsta->bssid));

	ieee80211_send_auth(dev, ifsta, 1, NULL, 0, 0);

	mod_timer(&ifsta->timer, jiffies + IEEE80211_AUTH_TIMEOUT);
}

static int ieee80211_compatible_rates(struct ieee80211_sta_bss *bss,
				      struct ieee80211_supported_band *sband,
				      u64 *rates)
{
	int i, j, count;
	*rates = 0;
	count = 0;
	for (i = 0; i < bss->supp_rates_len; i++) {
		int rate = (bss->supp_rates[i] & 0x7F) * 5;

		for (j = 0; j < sband->n_bitrates; j++)
			if (sband->bitrates[j].bitrate == rate) {
				*rates |= BIT(j);
				count++;
				break;
			}
	}

	return count;
}

static void ieee80211_send_assoc(struct net_device *dev,
				 struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u8 *pos, *ies;
	int i, len, count, rates_len, supp_rates_len;
	u16 capab;
	struct ieee80211_sta_bss *bss;
	int wmm = 0;
	struct ieee80211_supported_band *sband;
	u64 rates = 0;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom +
			    sizeof(*mgmt) + 200 + ifsta->extra_ie_len +
			    ifsta->ssid_len);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for assoc "
		       "frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	sband = local->hw.wiphy->bands[local->hw.conf.channel->band];

	capab = ifsta->capab;

	if (local->hw.conf.channel->band == IEEE80211_BAND_2GHZ) {
		if (!(local->hw.flags & IEEE80211_HW_2GHZ_SHORT_SLOT_INCAPABLE))
			capab |= WLAN_CAPABILITY_SHORT_SLOT_TIME;
		if (!(local->hw.flags & IEEE80211_HW_2GHZ_SHORT_PREAMBLE_INCAPABLE))
			capab |= WLAN_CAPABILITY_SHORT_PREAMBLE;
	}

	bss = ieee80211_rx_bss_get(dev, ifsta->bssid,
				   local->hw.conf.channel->center_freq,
				   ifsta->ssid, ifsta->ssid_len);
	if (bss) {
		if (bss->capability & WLAN_CAPABILITY_PRIVACY)
			capab |= WLAN_CAPABILITY_PRIVACY;
		if (bss->wmm_ie) {
			wmm = 1;
		}

		/* get all rates supported by the device and the AP as
		 * some APs don't like getting a superset of their rates
		 * in the association request (e.g. D-Link DAP 1353 in
		 * b-only mode) */
		rates_len = ieee80211_compatible_rates(bss, sband, &rates);

		ieee80211_rx_bss_put(dev, bss);
	} else {
		rates = ~0;
		rates_len = sband->n_bitrates;
	}

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, ifsta->bssid, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);

	if (ifsta->flags & IEEE80211_STA_PREV_BSSID_SET) {
		skb_put(skb, 10);
		mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
						   IEEE80211_STYPE_REASSOC_REQ);
		mgmt->u.reassoc_req.capab_info = cpu_to_le16(capab);
		mgmt->u.reassoc_req.listen_interval = cpu_to_le16(1);
		memcpy(mgmt->u.reassoc_req.current_ap, ifsta->prev_bssid,
		       ETH_ALEN);
	} else {
		skb_put(skb, 4);
		mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
						   IEEE80211_STYPE_ASSOC_REQ);
		mgmt->u.assoc_req.capab_info = cpu_to_le16(capab);
		mgmt->u.assoc_req.listen_interval = cpu_to_le16(1);
	}

	/* SSID */
	ies = pos = skb_put(skb, 2 + ifsta->ssid_len);
	*pos++ = WLAN_EID_SSID;
	*pos++ = ifsta->ssid_len;
	memcpy(pos, ifsta->ssid, ifsta->ssid_len);

	/* add all rates which were marked to be used above */
	supp_rates_len = rates_len;
	if (supp_rates_len > 8)
		supp_rates_len = 8;

	len = sband->n_bitrates;
	pos = skb_put(skb, supp_rates_len + 2);
	*pos++ = WLAN_EID_SUPP_RATES;
	*pos++ = supp_rates_len;

	count = 0;
	for (i = 0; i < sband->n_bitrates; i++) {
		if (BIT(i) & rates) {
			int rate = sband->bitrates[i].bitrate;
			*pos++ = (u8) (rate / 5);
			if (++count == 8)
				break;
		}
	}

	if (count == 8) {
		pos = skb_put(skb, rates_len - count + 2);
		*pos++ = WLAN_EID_EXT_SUPP_RATES;
		*pos++ = rates_len - count;

		for (i++; i < sband->n_bitrates; i++) {
			if (BIT(i) & rates) {
				int rate = sband->bitrates[i].bitrate;
				*pos++ = (u8) (rate / 5);
			}
		}
	}

	if (ifsta->extra_ie) {
		pos = skb_put(skb, ifsta->extra_ie_len);
		memcpy(pos, ifsta->extra_ie, ifsta->extra_ie_len);
	}

	if (wmm && (ifsta->flags & IEEE80211_STA_WMM_ENABLED)) {
		pos = skb_put(skb, 9);
		*pos++ = WLAN_EID_VENDOR_SPECIFIC;
		*pos++ = 7; /* len */
		*pos++ = 0x00; /* Microsoft OUI 00:50:F2 */
		*pos++ = 0x50;
		*pos++ = 0xf2;
		*pos++ = 2; /* WME */
		*pos++ = 0; /* WME info */
		*pos++ = 1; /* WME ver */
		*pos++ = 0;
	}
	/* wmm support is a must to HT */
	if (wmm && sband->ht_info.ht_supported) {
		__le16 tmp = cpu_to_le16(sband->ht_info.cap);
		pos = skb_put(skb, sizeof(struct ieee80211_ht_cap)+2);
		*pos++ = WLAN_EID_HT_CAPABILITY;
		*pos++ = sizeof(struct ieee80211_ht_cap);
		memset(pos, 0, sizeof(struct ieee80211_ht_cap));
		memcpy(pos, &tmp, sizeof(u16));
		pos += sizeof(u16);
		/* TODO: needs a define here for << 2 */
		*pos++ = sband->ht_info.ampdu_factor |
			 (sband->ht_info.ampdu_density << 2);
		memcpy(pos, sband->ht_info.supp_mcs_set, 16);
	}

	kfree(ifsta->assocreq_ies);
	ifsta->assocreq_ies_len = (skb->data + skb->len) - ies;
	ifsta->assocreq_ies = kmalloc(ifsta->assocreq_ies_len, GFP_KERNEL);
	if (ifsta->assocreq_ies)
		memcpy(ifsta->assocreq_ies, ies, ifsta->assocreq_ies_len);

	ieee80211_sta_tx(dev, skb, 0);
}


static void ieee80211_send_deauth(struct net_device *dev,
				  struct ieee80211_if_sta *ifsta, u16 reason)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*mgmt));
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for deauth "
		       "frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, ifsta->bssid, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_DEAUTH);
	skb_put(skb, 2);
	mgmt->u.deauth.reason_code = cpu_to_le16(reason);

	ieee80211_sta_tx(dev, skb, 0);
}


static void ieee80211_send_disassoc(struct net_device *dev,
				    struct ieee80211_if_sta *ifsta, u16 reason)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*mgmt));
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for disassoc "
		       "frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, ifsta->bssid, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_DISASSOC);
	skb_put(skb, 2);
	mgmt->u.disassoc.reason_code = cpu_to_le16(reason);

	ieee80211_sta_tx(dev, skb, 0);
}


static int ieee80211_privacy_mismatch(struct net_device *dev,
				      struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;
	int bss_privacy;
	int wep_privacy;
	int privacy_invoked;

	if (!ifsta || (ifsta->flags & IEEE80211_STA_MIXED_CELL))
		return 0;

	bss = ieee80211_rx_bss_get(dev, ifsta->bssid,
				   local->hw.conf.channel->center_freq,
				   ifsta->ssid, ifsta->ssid_len);
	if (!bss)
		return 0;

	bss_privacy = !!(bss->capability & WLAN_CAPABILITY_PRIVACY);
	wep_privacy = !!ieee80211_sta_wep_configured(dev);
	privacy_invoked = !!(ifsta->flags & IEEE80211_STA_PRIVACY_INVOKED);

	ieee80211_rx_bss_put(dev, bss);

	if ((bss_privacy == wep_privacy) || (bss_privacy == privacy_invoked))
		return 0;

	return 1;
}


static void ieee80211_associate(struct net_device *dev,
				struct ieee80211_if_sta *ifsta)
{
	DECLARE_MAC_BUF(mac);

	ifsta->assoc_tries++;
	if (ifsta->assoc_tries > IEEE80211_ASSOC_MAX_TRIES) {
		printk(KERN_DEBUG "%s: association with AP %s"
		       " timed out\n",
		       dev->name, print_mac(mac, ifsta->bssid));
		ifsta->state = IEEE80211_DISABLED;
		return;
	}

	ifsta->state = IEEE80211_ASSOCIATE;
	printk(KERN_DEBUG "%s: associate with AP %s\n",
	       dev->name, print_mac(mac, ifsta->bssid));
	if (ieee80211_privacy_mismatch(dev, ifsta)) {
		printk(KERN_DEBUG "%s: mismatch in privacy configuration and "
		       "mixed-cell disabled - abort association\n", dev->name);
		ifsta->state = IEEE80211_DISABLED;
		return;
	}

	ieee80211_send_assoc(dev, ifsta);

	mod_timer(&ifsta->timer, jiffies + IEEE80211_ASSOC_TIMEOUT);
}


static void ieee80211_associated(struct net_device *dev,
				 struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta;
	int disassoc;
	DECLARE_MAC_BUF(mac);

	/* TODO: start monitoring current AP signal quality and number of
	 * missed beacons. Scan other channels every now and then and search
	 * for better APs. */
	/* TODO: remove expired BSSes */

	ifsta->state = IEEE80211_ASSOCIATED;

	rcu_read_lock();

	sta = sta_info_get(local, ifsta->bssid);
	if (!sta) {
		printk(KERN_DEBUG "%s: No STA entry for own AP %s\n",
		       dev->name, print_mac(mac, ifsta->bssid));
		disassoc = 1;
	} else {
		disassoc = 0;
		if (time_after(jiffies,
			       sta->last_rx + IEEE80211_MONITORING_INTERVAL)) {
			if (ifsta->flags & IEEE80211_STA_PROBEREQ_POLL) {
				printk(KERN_DEBUG "%s: No ProbeResp from "
				       "current AP %s - assume out of "
				       "range\n",
				       dev->name, print_mac(mac, ifsta->bssid));
				disassoc = 1;
				sta_info_unlink(&sta);
			} else
				ieee80211_send_probe_req(dev, ifsta->bssid,
							 local->scan_ssid,
							 local->scan_ssid_len);
			ifsta->flags ^= IEEE80211_STA_PROBEREQ_POLL;
		} else {
			ifsta->flags &= ~IEEE80211_STA_PROBEREQ_POLL;
			if (time_after(jiffies, ifsta->last_probe +
				       IEEE80211_PROBE_INTERVAL)) {
				ifsta->last_probe = jiffies;
				ieee80211_send_probe_req(dev, ifsta->bssid,
							 ifsta->ssid,
							 ifsta->ssid_len);
			}
		}
	}

	rcu_read_unlock();

	if (disassoc && sta)
		sta_info_destroy(sta);

	if (disassoc) {
		ifsta->state = IEEE80211_DISABLED;
		ieee80211_set_associated(dev, ifsta, 0);
	} else {
		mod_timer(&ifsta->timer, jiffies +
				      IEEE80211_MONITORING_INTERVAL);
	}
}


static void ieee80211_send_probe_req(struct net_device *dev, u8 *dst,
				     u8 *ssid, size_t ssid_len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_supported_band *sband;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u8 *pos, *supp_rates, *esupp_rates = NULL;
	int i;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*mgmt) + 200);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for probe "
		       "request\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_PROBE_REQ);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	if (dst) {
		memcpy(mgmt->da, dst, ETH_ALEN);
		memcpy(mgmt->bssid, dst, ETH_ALEN);
	} else {
		memset(mgmt->da, 0xff, ETH_ALEN);
		memset(mgmt->bssid, 0xff, ETH_ALEN);
	}
	pos = skb_put(skb, 2 + ssid_len);
	*pos++ = WLAN_EID_SSID;
	*pos++ = ssid_len;
	memcpy(pos, ssid, ssid_len);

	supp_rates = skb_put(skb, 2);
	supp_rates[0] = WLAN_EID_SUPP_RATES;
	supp_rates[1] = 0;
	sband = local->hw.wiphy->bands[local->hw.conf.channel->band];

	for (i = 0; i < sband->n_bitrates; i++) {
		struct ieee80211_rate *rate = &sband->bitrates[i];
		if (esupp_rates) {
			pos = skb_put(skb, 1);
			esupp_rates[1]++;
		} else if (supp_rates[1] == 8) {
			esupp_rates = skb_put(skb, 3);
			esupp_rates[0] = WLAN_EID_EXT_SUPP_RATES;
			esupp_rates[1] = 1;
			pos = &esupp_rates[2];
		} else {
			pos = skb_put(skb, 1);
			supp_rates[1]++;
		}
		*pos = rate->bitrate / 5;
	}

	ieee80211_sta_tx(dev, skb, 0);
}


static int ieee80211_sta_wep_configured(struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	if (!sdata || !sdata->default_key ||
	    sdata->default_key->conf.alg != ALG_WEP)
		return 0;
	return 1;
}


static void ieee80211_auth_completed(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	printk(KERN_DEBUG "%s: authenticated\n", dev->name);
	ifsta->flags |= IEEE80211_STA_AUTHENTICATED;
	ieee80211_associate(dev, ifsta);
}


static void ieee80211_auth_challenge(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	u8 *pos;
	struct ieee802_11_elems elems;

	printk(KERN_DEBUG "%s: replying to auth challenge\n", dev->name);
	pos = mgmt->u.auth.variable;
	ieee802_11_parse_elems(pos, len - (pos - (u8 *) mgmt), &elems);
	if (!elems.challenge) {
		printk(KERN_DEBUG "%s: no challenge IE in shared key auth "
		       "frame\n", dev->name);
		return;
	}
	ieee80211_send_auth(dev, ifsta, 3, elems.challenge - 2,
			    elems.challenge_len + 2, 1);
}

static void ieee80211_send_addba_resp(struct net_device *dev, u8 *da, u16 tid,
					u8 dialog_token, u16 status, u16 policy,
					u16 buf_size, u16 timeout)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u16 capab;

	skb = dev_alloc_skb(sizeof(*mgmt) + local->hw.extra_tx_headroom + 1 +
					sizeof(mgmt->u.action.u.addba_resp));
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer "
		       "for addba resp frame\n", dev->name);
		return;
	}

	skb_reserve(skb, local->hw.extra_tx_headroom);
	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, da, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	if (sdata->vif.type == IEEE80211_IF_TYPE_AP)
		memcpy(mgmt->bssid, dev->dev_addr, ETH_ALEN);
	else
		memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_ACTION);

	skb_put(skb, 1 + sizeof(mgmt->u.action.u.addba_resp));
	mgmt->u.action.category = WLAN_CATEGORY_BACK;
	mgmt->u.action.u.addba_resp.action_code = WLAN_ACTION_ADDBA_RESP;
	mgmt->u.action.u.addba_resp.dialog_token = dialog_token;

	capab = (u16)(policy << 1);	/* bit 1 aggregation policy */
	capab |= (u16)(tid << 2); 	/* bit 5:2 TID number */
	capab |= (u16)(buf_size << 6);	/* bit 15:6 max size of aggregation */

	mgmt->u.action.u.addba_resp.capab = cpu_to_le16(capab);
	mgmt->u.action.u.addba_resp.timeout = cpu_to_le16(timeout);
	mgmt->u.action.u.addba_resp.status = cpu_to_le16(status);

	ieee80211_sta_tx(dev, skb, 0);

	return;
}

void ieee80211_send_addba_request(struct net_device *dev, const u8 *da,
				u16 tid, u8 dialog_token, u16 start_seq_num,
				u16 agg_size, u16 timeout)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u16 capab;

	skb = dev_alloc_skb(sizeof(*mgmt) + local->hw.extra_tx_headroom + 1 +
				sizeof(mgmt->u.action.u.addba_req));


	if (!skb) {
		printk(KERN_ERR "%s: failed to allocate buffer "
				"for addba request frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);
	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, da, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	if (sdata->vif.type == IEEE80211_IF_TYPE_AP)
		memcpy(mgmt->bssid, dev->dev_addr, ETH_ALEN);
	else
		memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);

	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					IEEE80211_STYPE_ACTION);

	skb_put(skb, 1 + sizeof(mgmt->u.action.u.addba_req));

	mgmt->u.action.category = WLAN_CATEGORY_BACK;
	mgmt->u.action.u.addba_req.action_code = WLAN_ACTION_ADDBA_REQ;

	mgmt->u.action.u.addba_req.dialog_token = dialog_token;
	capab = (u16)(1 << 1);		/* bit 1 aggregation policy */
	capab |= (u16)(tid << 2); 	/* bit 5:2 TID number */
	capab |= (u16)(agg_size << 6);	/* bit 15:6 max size of aggergation */

	mgmt->u.action.u.addba_req.capab = cpu_to_le16(capab);

	mgmt->u.action.u.addba_req.timeout = cpu_to_le16(timeout);
	mgmt->u.action.u.addba_req.start_seq_num =
					cpu_to_le16(start_seq_num << 4);

	ieee80211_sta_tx(dev, skb, 0);
}

static void ieee80211_sta_process_addba_request(struct net_device *dev,
						struct ieee80211_mgmt *mgmt,
						size_t len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_hw *hw = &local->hw;
	struct ieee80211_conf *conf = &hw->conf;
	struct sta_info *sta;
	struct tid_ampdu_rx *tid_agg_rx;
	u16 capab, tid, timeout, ba_policy, buf_size, start_seq_num, status;
	u8 dialog_token;
	int ret = -EOPNOTSUPP;
	DECLARE_MAC_BUF(mac);

	rcu_read_lock();

	sta = sta_info_get(local, mgmt->sa);
	if (!sta) {
		rcu_read_unlock();
		return;
	}

	/* extract session parameters from addba request frame */
	dialog_token = mgmt->u.action.u.addba_req.dialog_token;
	timeout = le16_to_cpu(mgmt->u.action.u.addba_req.timeout);
	start_seq_num =
		le16_to_cpu(mgmt->u.action.u.addba_req.start_seq_num) >> 4;

	capab = le16_to_cpu(mgmt->u.action.u.addba_req.capab);
	ba_policy = (capab & IEEE80211_ADDBA_PARAM_POLICY_MASK) >> 1;
	tid = (capab & IEEE80211_ADDBA_PARAM_TID_MASK) >> 2;
	buf_size = (capab & IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK) >> 6;

	status = WLAN_STATUS_REQUEST_DECLINED;

	/* sanity check for incoming parameters:
	 * check if configuration can support the BA policy
	 * and if buffer size does not exceeds max value */
	if (((ba_policy != 1)
		&& (!(conf->ht_conf.cap & IEEE80211_HT_CAP_DELAY_BA)))
		|| (buf_size > IEEE80211_MAX_AMPDU_BUF)) {
		status = WLAN_STATUS_INVALID_QOS_PARAM;
#ifdef CONFIG_MAC80211_HT_DEBUG
		if (net_ratelimit())
			printk(KERN_DEBUG "AddBA Req with bad params from "
				"%s on tid %u. policy %d, buffer size %d\n",
				print_mac(mac, mgmt->sa), tid, ba_policy,
				buf_size);
#endif /* CONFIG_MAC80211_HT_DEBUG */
		goto end_no_lock;
	}
	/* determine default buffer size */
	if (buf_size == 0) {
		struct ieee80211_supported_band *sband;

		sband = local->hw.wiphy->bands[conf->channel->band];
		buf_size = IEEE80211_MIN_AMPDU_BUF;
		buf_size = buf_size << sband->ht_info.ampdu_factor;
	}


	/* examine state machine */
	spin_lock_bh(&sta->ampdu_mlme.ampdu_rx);

	if (sta->ampdu_mlme.tid_state_rx[tid] != HT_AGG_STATE_IDLE) {
#ifdef CONFIG_MAC80211_HT_DEBUG
		if (net_ratelimit())
			printk(KERN_DEBUG "unexpected AddBA Req from "
				"%s on tid %u\n",
				print_mac(mac, mgmt->sa), tid);
#endif /* CONFIG_MAC80211_HT_DEBUG */
		goto end;
	}

	/* prepare A-MPDU MLME for Rx aggregation */
	sta->ampdu_mlme.tid_rx[tid] =
			kmalloc(sizeof(struct tid_ampdu_rx), GFP_ATOMIC);
	if (!sta->ampdu_mlme.tid_rx[tid]) {
		if (net_ratelimit())
			printk(KERN_ERR "allocate rx mlme to tid %d failed\n",
					tid);
		goto end;
	}
	/* rx timer */
	sta->ampdu_mlme.tid_rx[tid]->session_timer.function =
				sta_rx_agg_session_timer_expired;
	sta->ampdu_mlme.tid_rx[tid]->session_timer.data =
				(unsigned long)&sta->timer_to_tid[tid];
	init_timer(&sta->ampdu_mlme.tid_rx[tid]->session_timer);

	tid_agg_rx = sta->ampdu_mlme.tid_rx[tid];

	/* prepare reordering buffer */
	tid_agg_rx->reorder_buf =
		kmalloc(buf_size * sizeof(struct sk_buff *), GFP_ATOMIC);
	if (!tid_agg_rx->reorder_buf) {
		if (net_ratelimit())
			printk(KERN_ERR "can not allocate reordering buffer "
			       "to tid %d\n", tid);
		kfree(sta->ampdu_mlme.tid_rx[tid]);
		goto end;
	}
	memset(tid_agg_rx->reorder_buf, 0,
		buf_size * sizeof(struct sk_buff *));

	if (local->ops->ampdu_action)
		ret = local->ops->ampdu_action(hw, IEEE80211_AMPDU_RX_START,
					       sta->addr, tid, &start_seq_num);
#ifdef CONFIG_MAC80211_HT_DEBUG
	printk(KERN_DEBUG "Rx A-MPDU request on tid %d result %d\n", tid, ret);
#endif /* CONFIG_MAC80211_HT_DEBUG */

	if (ret) {
		kfree(tid_agg_rx->reorder_buf);
		kfree(tid_agg_rx);
		sta->ampdu_mlme.tid_rx[tid] = NULL;
		goto end;
	}

	/* change state and send addba resp */
	sta->ampdu_mlme.tid_state_rx[tid] = HT_AGG_STATE_OPERATIONAL;
	tid_agg_rx->dialog_token = dialog_token;
	tid_agg_rx->ssn = start_seq_num;
	tid_agg_rx->head_seq_num = start_seq_num;
	tid_agg_rx->buf_size = buf_size;
	tid_agg_rx->timeout = timeout;
	tid_agg_rx->stored_mpdu_num = 0;
	status = WLAN_STATUS_SUCCESS;
end:
	spin_unlock_bh(&sta->ampdu_mlme.ampdu_rx);

end_no_lock:
	ieee80211_send_addba_resp(sta->sdata->dev, sta->addr, tid,
				  dialog_token, status, 1, buf_size, timeout);
	rcu_read_unlock();
}

static void ieee80211_sta_process_addba_resp(struct net_device *dev,
					     struct ieee80211_mgmt *mgmt,
					     size_t len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_hw *hw = &local->hw;
	struct sta_info *sta;
	u16 capab;
	u16 tid;
	u8 *state;

	rcu_read_lock();

	sta = sta_info_get(local, mgmt->sa);
	if (!sta) {
		rcu_read_unlock();
		return;
	}

	capab = le16_to_cpu(mgmt->u.action.u.addba_resp.capab);
	tid = (capab & IEEE80211_ADDBA_PARAM_TID_MASK) >> 2;

	state = &sta->ampdu_mlme.tid_state_tx[tid];

	spin_lock_bh(&sta->ampdu_mlme.ampdu_tx);

	if (!(*state & HT_ADDBA_REQUESTED_MSK)) {
		spin_unlock_bh(&sta->ampdu_mlme.ampdu_tx);
		printk(KERN_DEBUG "state not HT_ADDBA_REQUESTED_MSK:"
			"%d\n", *state);
		goto addba_resp_exit;
	}

	if (mgmt->u.action.u.addba_resp.dialog_token !=
		sta->ampdu_mlme.tid_tx[tid]->dialog_token) {
		spin_unlock_bh(&sta->ampdu_mlme.ampdu_tx);
#ifdef CONFIG_MAC80211_HT_DEBUG
		printk(KERN_DEBUG "wrong addBA response token, tid %d\n", tid);
#endif /* CONFIG_MAC80211_HT_DEBUG */
		goto addba_resp_exit;
	}

	del_timer_sync(&sta->ampdu_mlme.tid_tx[tid]->addba_resp_timer);
#ifdef CONFIG_MAC80211_HT_DEBUG
	printk(KERN_DEBUG "switched off addBA timer for tid %d \n", tid);
#endif /* CONFIG_MAC80211_HT_DEBUG */
	if (le16_to_cpu(mgmt->u.action.u.addba_resp.status)
			== WLAN_STATUS_SUCCESS) {
		if (*state & HT_ADDBA_RECEIVED_MSK)
			printk(KERN_DEBUG "double addBA response\n");

		*state |= HT_ADDBA_RECEIVED_MSK;
		sta->ampdu_mlme.addba_req_num[tid] = 0;

		if (*state == HT_AGG_STATE_OPERATIONAL) {
			printk(KERN_DEBUG "Aggregation on for tid %d \n", tid);
			ieee80211_wake_queue(hw, sta->tid_to_tx_q[tid]);
		}

		spin_unlock_bh(&sta->ampdu_mlme.ampdu_tx);
		printk(KERN_DEBUG "recipient accepted agg: tid %d \n", tid);
	} else {
		printk(KERN_DEBUG "recipient rejected agg: tid %d \n", tid);

		sta->ampdu_mlme.addba_req_num[tid]++;
		/* this will allow the state check in stop_BA_session */
		*state = HT_AGG_STATE_OPERATIONAL;
		spin_unlock_bh(&sta->ampdu_mlme.ampdu_tx);
		ieee80211_stop_tx_ba_session(hw, sta->addr, tid,
					     WLAN_BACK_INITIATOR);
	}

addba_resp_exit:
	rcu_read_unlock();
}

void ieee80211_send_delba(struct net_device *dev, const u8 *da, u16 tid,
			  u16 initiator, u16 reason_code)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u16 params;

	skb = dev_alloc_skb(sizeof(*mgmt) + local->hw.extra_tx_headroom + 1 +
					sizeof(mgmt->u.action.u.delba));

	if (!skb) {
		printk(KERN_ERR "%s: failed to allocate buffer "
					"for delba frame\n", dev->name);
		return;
	}

	skb_reserve(skb, local->hw.extra_tx_headroom);
	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, da, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	if (sdata->vif.type == IEEE80211_IF_TYPE_AP)
		memcpy(mgmt->bssid, dev->dev_addr, ETH_ALEN);
	else
		memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					IEEE80211_STYPE_ACTION);

	skb_put(skb, 1 + sizeof(mgmt->u.action.u.delba));

	mgmt->u.action.category = WLAN_CATEGORY_BACK;
	mgmt->u.action.u.delba.action_code = WLAN_ACTION_DELBA;
	params = (u16)(initiator << 11); 	/* bit 11 initiator */
	params |= (u16)(tid << 12); 		/* bit 15:12 TID number */

	mgmt->u.action.u.delba.params = cpu_to_le16(params);
	mgmt->u.action.u.delba.reason_code = cpu_to_le16(reason_code);

	ieee80211_sta_tx(dev, skb, 0);
}

void ieee80211_sta_stop_rx_ba_session(struct net_device *dev, u8 *ra, u16 tid,
					u16 initiator, u16 reason)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_hw *hw = &local->hw;
	struct sta_info *sta;
	int ret, i;
	DECLARE_MAC_BUF(mac);

	rcu_read_lock();

	sta = sta_info_get(local, ra);
	if (!sta) {
		rcu_read_unlock();
		return;
	}

	/* check if TID is in operational state */
	spin_lock_bh(&sta->ampdu_mlme.ampdu_rx);
	if (sta->ampdu_mlme.tid_state_rx[tid]
				!= HT_AGG_STATE_OPERATIONAL) {
		spin_unlock_bh(&sta->ampdu_mlme.ampdu_rx);
		rcu_read_unlock();
		return;
	}
	sta->ampdu_mlme.tid_state_rx[tid] =
		HT_AGG_STATE_REQ_STOP_BA_MSK |
		(initiator << HT_AGG_STATE_INITIATOR_SHIFT);
	spin_unlock_bh(&sta->ampdu_mlme.ampdu_rx);

	/* stop HW Rx aggregation. ampdu_action existence
	 * already verified in session init so we add the BUG_ON */
	BUG_ON(!local->ops->ampdu_action);

#ifdef CONFIG_MAC80211_HT_DEBUG
	printk(KERN_DEBUG "Rx BA session stop requested for %s tid %u\n",
				print_mac(mac, ra), tid);
#endif /* CONFIG_MAC80211_HT_DEBUG */

	ret = local->ops->ampdu_action(hw, IEEE80211_AMPDU_RX_STOP,
					ra, tid, NULL);
	if (ret)
		printk(KERN_DEBUG "HW problem - can not stop rx "
				"aggergation for tid %d\n", tid);

	/* shutdown timer has not expired */
	if (initiator != WLAN_BACK_TIMER)
		del_timer_sync(&sta->ampdu_mlme.tid_rx[tid]->session_timer);

	/* check if this is a self generated aggregation halt */
	if (initiator == WLAN_BACK_RECIPIENT || initiator == WLAN_BACK_TIMER)
		ieee80211_send_delba(dev, ra, tid, 0, reason);

	/* free the reordering buffer */
	for (i = 0; i < sta->ampdu_mlme.tid_rx[tid]->buf_size; i++) {
		if (sta->ampdu_mlme.tid_rx[tid]->reorder_buf[i]) {
			/* release the reordered frames */
			dev_kfree_skb(sta->ampdu_mlme.tid_rx[tid]->reorder_buf[i]);
			sta->ampdu_mlme.tid_rx[tid]->stored_mpdu_num--;
			sta->ampdu_mlme.tid_rx[tid]->reorder_buf[i] = NULL;
		}
	}
	/* free resources */
	kfree(sta->ampdu_mlme.tid_rx[tid]->reorder_buf);
	kfree(sta->ampdu_mlme.tid_rx[tid]);
	sta->ampdu_mlme.tid_rx[tid] = NULL;
	sta->ampdu_mlme.tid_state_rx[tid] = HT_AGG_STATE_IDLE;

	rcu_read_unlock();
}


static void ieee80211_sta_process_delba(struct net_device *dev,
			struct ieee80211_mgmt *mgmt, size_t len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta;
	u16 tid, params;
	u16 initiator;
	DECLARE_MAC_BUF(mac);

	rcu_read_lock();

	sta = sta_info_get(local, mgmt->sa);
	if (!sta) {
		rcu_read_unlock();
		return;
	}

	params = le16_to_cpu(mgmt->u.action.u.delba.params);
	tid = (params & IEEE80211_DELBA_PARAM_TID_MASK) >> 12;
	initiator = (params & IEEE80211_DELBA_PARAM_INITIATOR_MASK) >> 11;

#ifdef CONFIG_MAC80211_HT_DEBUG
	if (net_ratelimit())
		printk(KERN_DEBUG "delba from %s (%s) tid %d reason code %d\n",
			print_mac(mac, mgmt->sa),
			initiator ? "initiator" : "recipient", tid,
			mgmt->u.action.u.delba.reason_code);
#endif /* CONFIG_MAC80211_HT_DEBUG */

	if (initiator == WLAN_BACK_INITIATOR)
		ieee80211_sta_stop_rx_ba_session(dev, sta->addr, tid,
						 WLAN_BACK_INITIATOR, 0);
	else { /* WLAN_BACK_RECIPIENT */
		spin_lock_bh(&sta->ampdu_mlme.ampdu_tx);
		sta->ampdu_mlme.tid_state_tx[tid] =
				HT_AGG_STATE_OPERATIONAL;
		spin_unlock_bh(&sta->ampdu_mlme.ampdu_tx);
		ieee80211_stop_tx_ba_session(&local->hw, sta->addr, tid,
					     WLAN_BACK_RECIPIENT);
	}
	rcu_read_unlock();
}

/*
 * After sending add Block Ack request we activated a timer until
 * add Block Ack response will arrive from the recipient.
 * If this timer expires sta_addba_resp_timer_expired will be executed.
 */
void sta_addba_resp_timer_expired(unsigned long data)
{
	/* not an elegant detour, but there is no choice as the timer passes
	 * only one argument, and both sta_info and TID are needed, so init
	 * flow in sta_info_create gives the TID as data, while the timer_to_id
	 * array gives the sta through container_of */
	u16 tid = *(u8 *)data;
	struct sta_info *temp_sta = container_of((void *)data,
		struct sta_info, timer_to_tid[tid]);

	struct ieee80211_local *local = temp_sta->local;
	struct ieee80211_hw *hw = &local->hw;
	struct sta_info *sta;
	u8 *state;

	rcu_read_lock();

	sta = sta_info_get(local, temp_sta->addr);
	if (!sta) {
		rcu_read_unlock();
		return;
	}

	state = &sta->ampdu_mlme.tid_state_tx[tid];
	/* check if the TID waits for addBA response */
	spin_lock_bh(&sta->ampdu_mlme.ampdu_tx);
	if (!(*state & HT_ADDBA_REQUESTED_MSK)) {
		spin_unlock_bh(&sta->ampdu_mlme.ampdu_tx);
		*state = HT_AGG_STATE_IDLE;
		printk(KERN_DEBUG "timer expired on tid %d but we are not "
				"expecting addBA response there", tid);
		goto timer_expired_exit;
	}

	printk(KERN_DEBUG "addBA response timer expired on tid %d\n", tid);

	/* go through the state check in stop_BA_session */
	*state = HT_AGG_STATE_OPERATIONAL;
	spin_unlock_bh(&sta->ampdu_mlme.ampdu_tx);
	ieee80211_stop_tx_ba_session(hw, temp_sta->addr, tid,
				     WLAN_BACK_INITIATOR);

timer_expired_exit:
	rcu_read_unlock();
}

/*
 * After accepting the AddBA Request we activated a timer,
 * resetting it after each frame that arrives from the originator.
 * if this timer expires ieee80211_sta_stop_rx_ba_session will be executed.
 */
void sta_rx_agg_session_timer_expired(unsigned long data)
{
	/* not an elegant detour, but there is no choice as the timer passes
	 * only one argument, and various sta_info are needed here, so init
	 * flow in sta_info_create gives the TID as data, while the timer_to_id
	 * array gives the sta through container_of */
	u8 *ptid = (u8 *)data;
	u8 *timer_to_id = ptid - *ptid;
	struct sta_info *sta = container_of(timer_to_id, struct sta_info,
					 timer_to_tid[0]);

	printk(KERN_DEBUG "rx session timer expired on tid %d\n", (u16)*ptid);
	ieee80211_sta_stop_rx_ba_session(sta->sdata->dev, sta->addr,
					 (u16)*ptid, WLAN_BACK_TIMER,
					 WLAN_REASON_QSTA_TIMEOUT);
}

void ieee80211_sta_tear_down_BA_sessions(struct net_device *dev, u8 *addr)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	int i;

	for (i = 0; i <  STA_TID_NUM; i++) {
		ieee80211_stop_tx_ba_session(&local->hw, addr, i,
					     WLAN_BACK_INITIATOR);
		ieee80211_sta_stop_rx_ba_session(dev, addr, i,
						 WLAN_BACK_RECIPIENT,
						 WLAN_REASON_QSTA_LEAVE_QBSS);
	}
}

static void ieee80211_rx_mgmt_auth(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta,
				   struct ieee80211_mgmt *mgmt,
				   size_t len)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	u16 auth_alg, auth_transaction, status_code;
	DECLARE_MAC_BUF(mac);

	if (ifsta->state != IEEE80211_AUTHENTICATE &&
	    sdata->vif.type != IEEE80211_IF_TYPE_IBSS) {
		printk(KERN_DEBUG "%s: authentication frame received from "
		       "%s, but not in authenticate state - ignored\n",
		       dev->name, print_mac(mac, mgmt->sa));
		return;
	}

	if (len < 24 + 6) {
		printk(KERN_DEBUG "%s: too short (%zd) authentication frame "
		       "received from %s - ignored\n",
		       dev->name, len, print_mac(mac, mgmt->sa));
		return;
	}

	if (sdata->vif.type != IEEE80211_IF_TYPE_IBSS &&
	    memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: authentication frame received from "
		       "unknown AP (SA=%s BSSID=%s) - "
		       "ignored\n", dev->name, print_mac(mac, mgmt->sa),
		       print_mac(mac, mgmt->bssid));
		return;
	}

	if (sdata->vif.type != IEEE80211_IF_TYPE_IBSS &&
	    memcmp(ifsta->bssid, mgmt->bssid, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: authentication frame received from "
		       "unknown BSSID (SA=%s BSSID=%s) - "
		       "ignored\n", dev->name, print_mac(mac, mgmt->sa),
		       print_mac(mac, mgmt->bssid));
		return;
	}

	auth_alg = le16_to_cpu(mgmt->u.auth.auth_alg);
	auth_transaction = le16_to_cpu(mgmt->u.auth.auth_transaction);
	status_code = le16_to_cpu(mgmt->u.auth.status_code);

	printk(KERN_DEBUG "%s: RX authentication from %s (alg=%d "
	       "transaction=%d status=%d)\n",
	       dev->name, print_mac(mac, mgmt->sa), auth_alg,
	       auth_transaction, status_code);

	if (sdata->vif.type == IEEE80211_IF_TYPE_IBSS) {
		/* IEEE 802.11 standard does not require authentication in IBSS
		 * networks and most implementations do not seem to use it.
		 * However, try to reply to authentication attempts if someone
		 * has actually implemented this.
		 * TODO: Could implement shared key authentication. */
		if (auth_alg != WLAN_AUTH_OPEN || auth_transaction != 1) {
			printk(KERN_DEBUG "%s: unexpected IBSS authentication "
			       "frame (alg=%d transaction=%d)\n",
			       dev->name, auth_alg, auth_transaction);
			return;
		}
		ieee80211_send_auth(dev, ifsta, 2, NULL, 0, 0);
	}

	if (auth_alg != ifsta->auth_alg ||
	    auth_transaction != ifsta->auth_transaction) {
		printk(KERN_DEBUG "%s: unexpected authentication frame "
		       "(alg=%d transaction=%d)\n",
		       dev->name, auth_alg, auth_transaction);
		return;
	}

	if (status_code != WLAN_STATUS_SUCCESS) {
		printk(KERN_DEBUG "%s: AP denied authentication (auth_alg=%d "
		       "code=%d)\n", dev->name, ifsta->auth_alg, status_code);
		if (status_code == WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG) {
			u8 algs[3];
			const int num_algs = ARRAY_SIZE(algs);
			int i, pos;
			algs[0] = algs[1] = algs[2] = 0xff;
			if (ifsta->auth_algs & IEEE80211_AUTH_ALG_OPEN)
				algs[0] = WLAN_AUTH_OPEN;
			if (ifsta->auth_algs & IEEE80211_AUTH_ALG_SHARED_KEY)
				algs[1] = WLAN_AUTH_SHARED_KEY;
			if (ifsta->auth_algs & IEEE80211_AUTH_ALG_LEAP)
				algs[2] = WLAN_AUTH_LEAP;
			if (ifsta->auth_alg == WLAN_AUTH_OPEN)
				pos = 0;
			else if (ifsta->auth_alg == WLAN_AUTH_SHARED_KEY)
				pos = 1;
			else
				pos = 2;
			for (i = 0; i < num_algs; i++) {
				pos++;
				if (pos >= num_algs)
					pos = 0;
				if (algs[pos] == ifsta->auth_alg ||
				    algs[pos] == 0xff)
					continue;
				if (algs[pos] == WLAN_AUTH_SHARED_KEY &&
				    !ieee80211_sta_wep_configured(dev))
					continue;
				ifsta->auth_alg = algs[pos];
				printk(KERN_DEBUG "%s: set auth_alg=%d for "
				       "next try\n",
				       dev->name, ifsta->auth_alg);
				break;
			}
		}
		return;
	}

	switch (ifsta->auth_alg) {
	case WLAN_AUTH_OPEN:
	case WLAN_AUTH_LEAP:
		ieee80211_auth_completed(dev, ifsta);
		break;
	case WLAN_AUTH_SHARED_KEY:
		if (ifsta->auth_transaction == 4)
			ieee80211_auth_completed(dev, ifsta);
		else
			ieee80211_auth_challenge(dev, ifsta, mgmt, len);
		break;
	}
}


static void ieee80211_rx_mgmt_deauth(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	u16 reason_code;
	DECLARE_MAC_BUF(mac);

	if (len < 24 + 2) {
		printk(KERN_DEBUG "%s: too short (%zd) deauthentication frame "
		       "received from %s - ignored\n",
		       dev->name, len, print_mac(mac, mgmt->sa));
		return;
	}

	if (memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: deauthentication frame received from "
		       "unknown AP (SA=%s BSSID=%s) - "
		       "ignored\n", dev->name, print_mac(mac, mgmt->sa),
		       print_mac(mac, mgmt->bssid));
		return;
	}

	reason_code = le16_to_cpu(mgmt->u.deauth.reason_code);

	printk(KERN_DEBUG "%s: RX deauthentication from %s"
	       " (reason=%d)\n",
	       dev->name, print_mac(mac, mgmt->sa), reason_code);

	if (ifsta->flags & IEEE80211_STA_AUTHENTICATED) {
		printk(KERN_DEBUG "%s: deauthenticated\n", dev->name);
	}

	if (ifsta->state == IEEE80211_AUTHENTICATE ||
	    ifsta->state == IEEE80211_ASSOCIATE ||
	    ifsta->state == IEEE80211_ASSOCIATED) {
		ifsta->state = IEEE80211_AUTHENTICATE;
		mod_timer(&ifsta->timer, jiffies +
				      IEEE80211_RETRY_AUTH_INTERVAL);
	}

	ieee80211_set_disassoc(dev, ifsta, 1);
	ifsta->flags &= ~IEEE80211_STA_AUTHENTICATED;
}


static void ieee80211_rx_mgmt_disassoc(struct net_device *dev,
				       struct ieee80211_if_sta *ifsta,
				       struct ieee80211_mgmt *mgmt,
				       size_t len)
{
	u16 reason_code;
	DECLARE_MAC_BUF(mac);

	if (len < 24 + 2) {
		printk(KERN_DEBUG "%s: too short (%zd) disassociation frame "
		       "received from %s - ignored\n",
		       dev->name, len, print_mac(mac, mgmt->sa));
		return;
	}

	if (memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: disassociation frame received from "
		       "unknown AP (SA=%s BSSID=%s) - "
		       "ignored\n", dev->name, print_mac(mac, mgmt->sa),
		       print_mac(mac, mgmt->bssid));
		return;
	}

	reason_code = le16_to_cpu(mgmt->u.disassoc.reason_code);

	printk(KERN_DEBUG "%s: RX disassociation from %s"
	       " (reason=%d)\n",
	       dev->name, print_mac(mac, mgmt->sa), reason_code);

	if (ifsta->flags & IEEE80211_STA_ASSOCIATED)
		printk(KERN_DEBUG "%s: disassociated\n", dev->name);

	if (ifsta->state == IEEE80211_ASSOCIATED) {
		ifsta->state = IEEE80211_ASSOCIATE;
		mod_timer(&ifsta->timer, jiffies +
				      IEEE80211_RETRY_AUTH_INTERVAL);
	}

	ieee80211_set_disassoc(dev, ifsta, 0);
}


static void ieee80211_rx_mgmt_assoc_resp(struct ieee80211_sub_if_data *sdata,
					 struct ieee80211_if_sta *ifsta,
					 struct ieee80211_mgmt *mgmt,
					 size_t len,
					 int reassoc)
{
	struct ieee80211_local *local = sdata->local;
	struct net_device *dev = sdata->dev;
	struct ieee80211_supported_band *sband;
	struct sta_info *sta;
	u64 rates, basic_rates;
	u16 capab_info, status_code, aid;
	struct ieee802_11_elems elems;
	struct ieee80211_bss_conf *bss_conf = &sdata->bss_conf;
	u8 *pos;
	int i, j;
	DECLARE_MAC_BUF(mac);
	bool have_higher_than_11mbit = false;

	/* AssocResp and ReassocResp have identical structure, so process both
	 * of them in this function. */

	if (ifsta->state != IEEE80211_ASSOCIATE) {
		printk(KERN_DEBUG "%s: association frame received from "
		       "%s, but not in associate state - ignored\n",
		       dev->name, print_mac(mac, mgmt->sa));
		return;
	}

	if (len < 24 + 6) {
		printk(KERN_DEBUG "%s: too short (%zd) association frame "
		       "received from %s - ignored\n",
		       dev->name, len, print_mac(mac, mgmt->sa));
		return;
	}

	if (memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: association frame received from "
		       "unknown AP (SA=%s BSSID=%s) - "
		       "ignored\n", dev->name, print_mac(mac, mgmt->sa),
		       print_mac(mac, mgmt->bssid));
		return;
	}

	capab_info = le16_to_cpu(mgmt->u.assoc_resp.capab_info);
	status_code = le16_to_cpu(mgmt->u.assoc_resp.status_code);
	aid = le16_to_cpu(mgmt->u.assoc_resp.aid);

	printk(KERN_DEBUG "%s: RX %sssocResp from %s (capab=0x%x "
	       "status=%d aid=%d)\n",
	       dev->name, reassoc ? "Rea" : "A", print_mac(mac, mgmt->sa),
	       capab_info, status_code, (u16)(aid & ~(BIT(15) | BIT(14))));

	if (status_code != WLAN_STATUS_SUCCESS) {
		printk(KERN_DEBUG "%s: AP denied association (code=%d)\n",
		       dev->name, status_code);
		/* if this was a reassociation, ensure we try a "full"
		 * association next time. This works around some broken APs
		 * which do not correctly reject reassociation requests. */
		ifsta->flags &= ~IEEE80211_STA_PREV_BSSID_SET;
		return;
	}

	if ((aid & (BIT(15) | BIT(14))) != (BIT(15) | BIT(14)))
		printk(KERN_DEBUG "%s: invalid aid value %d; bits 15:14 not "
		       "set\n", dev->name, aid);
	aid &= ~(BIT(15) | BIT(14));

	pos = mgmt->u.assoc_resp.variable;
	ieee802_11_parse_elems(pos, len - (pos - (u8 *) mgmt), &elems);

	if (!elems.supp_rates) {
		printk(KERN_DEBUG "%s: no SuppRates element in AssocResp\n",
		       dev->name);
		return;
	}

	printk(KERN_DEBUG "%s: associated\n", dev->name);
	ifsta->aid = aid;
	ifsta->ap_capab = capab_info;

	kfree(ifsta->assocresp_ies);
	ifsta->assocresp_ies_len = len - (pos - (u8 *) mgmt);
	ifsta->assocresp_ies = kmalloc(ifsta->assocresp_ies_len, GFP_KERNEL);
	if (ifsta->assocresp_ies)
		memcpy(ifsta->assocresp_ies, pos, ifsta->assocresp_ies_len);

	rcu_read_lock();

	/* Add STA entry for the AP */
	sta = sta_info_get(local, ifsta->bssid);
	if (!sta) {
		struct ieee80211_sta_bss *bss;
		int err;

		sta = sta_info_alloc(sdata, ifsta->bssid, GFP_ATOMIC);
		if (!sta) {
			printk(KERN_DEBUG "%s: failed to alloc STA entry for"
			       " the AP\n", dev->name);
			rcu_read_unlock();
			return;
		}
		bss = ieee80211_rx_bss_get(dev, ifsta->bssid,
					   local->hw.conf.channel->center_freq,
					   ifsta->ssid, ifsta->ssid_len);
		if (bss) {
			sta->last_rssi = bss->rssi;
			sta->last_signal = bss->signal;
			sta->last_noise = bss->noise;
			ieee80211_rx_bss_put(dev, bss);
		}

		err = sta_info_insert(sta);
		if (err) {
			printk(KERN_DEBUG "%s: failed to insert STA entry for"
			       " the AP (error %d)\n", dev->name, err);
			rcu_read_unlock();
			return;
		}
	}

	/*
	 * FIXME: Do we really need to update the sta_info's information here?
	 *	  We already know about the AP (we found it in our list) so it
	 *	  should already be filled with the right info, no?
	 *	  As is stands, all this is racy because typically we assume
	 *	  the information that is filled in here (except flags) doesn't
	 *	  change while a STA structure is alive. As such, it should move
	 *	  to between the sta_info_alloc() and sta_info_insert() above.
	 */

	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC | WLAN_STA_ASSOC_AP |
		      WLAN_STA_AUTHORIZED;

	rates = 0;
	basic_rates = 0;
	sband = local->hw.wiphy->bands[local->hw.conf.channel->band];

	for (i = 0; i < elems.supp_rates_len; i++) {
		int rate = (elems.supp_rates[i] & 0x7f) * 5;

		if (rate > 110)
			have_higher_than_11mbit = true;

		for (j = 0; j < sband->n_bitrates; j++) {
			if (sband->bitrates[j].bitrate == rate)
				rates |= BIT(j);
			if (elems.supp_rates[i] & 0x80)
				basic_rates |= BIT(j);
		}
	}

	for (i = 0; i < elems.ext_supp_rates_len; i++) {
		int rate = (elems.ext_supp_rates[i] & 0x7f) * 5;

		if (rate > 110)
			have_higher_than_11mbit = true;

		for (j = 0; j < sband->n_bitrates; j++) {
			if (sband->bitrates[j].bitrate == rate)
				rates |= BIT(j);
			if (elems.ext_supp_rates[i] & 0x80)
				basic_rates |= BIT(j);
		}
	}

	sta->supp_rates[local->hw.conf.channel->band] = rates;
	sdata->basic_rates = basic_rates;

	/* cf. IEEE 802.11 9.2.12 */
	if (local->hw.conf.channel->band == IEEE80211_BAND_2GHZ &&
	    have_higher_than_11mbit)
		sdata->flags |= IEEE80211_SDATA_OPERATING_GMODE;
	else
		sdata->flags &= ~IEEE80211_SDATA_OPERATING_GMODE;

	if (elems.ht_cap_elem && elems.ht_info_elem && elems.wmm_param) {
		struct ieee80211_ht_bss_info bss_info;
		ieee80211_ht_cap_ie_to_ht_info(
				(struct ieee80211_ht_cap *)
				elems.ht_cap_elem, &sta->ht_info);
		ieee80211_ht_addt_info_ie_to_ht_bss_info(
				(struct ieee80211_ht_addt_info *)
				elems.ht_info_elem, &bss_info);
		ieee80211_handle_ht(local, 1, &sta->ht_info, &bss_info);
	}

	rate_control_rate_init(sta, local);

	if (elems.wmm_param && (ifsta->flags & IEEE80211_STA_WMM_ENABLED)) {
		sta->flags |= WLAN_STA_WME;
		rcu_read_unlock();
		ieee80211_sta_wmm_params(dev, ifsta, elems.wmm_param,
					 elems.wmm_param_len);
	} else
		rcu_read_unlock();

	/* set AID and assoc capability,
	 * ieee80211_set_associated() will tell the driver */
	bss_conf->aid = aid;
	bss_conf->assoc_capability = capab_info;
	ieee80211_set_associated(dev, ifsta, 1);

	ieee80211_associated(dev, ifsta);
}


/* Caller must hold local->sta_bss_lock */
static void __ieee80211_rx_bss_hash_add(struct net_device *dev,
					struct ieee80211_sta_bss *bss)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	u8 hash_idx;

	if (bss_mesh_cfg(bss))
		hash_idx = mesh_id_hash(bss_mesh_id(bss),
					bss_mesh_id_len(bss));
	else
		hash_idx = STA_HASH(bss->bssid);

	bss->hnext = local->sta_bss_hash[hash_idx];
	local->sta_bss_hash[hash_idx] = bss;
}


/* Caller must hold local->sta_bss_lock */
static void __ieee80211_rx_bss_hash_del(struct net_device *dev,
					struct ieee80211_sta_bss *bss)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *b, *prev = NULL;
	b = local->sta_bss_hash[STA_HASH(bss->bssid)];
	while (b) {
		if (b == bss) {
			if (!prev)
				local->sta_bss_hash[STA_HASH(bss->bssid)] =
					bss->hnext;
			else
				prev->hnext = bss->hnext;
			break;
		}
		prev = b;
		b = b->hnext;
	}
}


static struct ieee80211_sta_bss *
ieee80211_rx_bss_add(struct net_device *dev, u8 *bssid, int freq,
		     u8 *ssid, u8 ssid_len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;

	bss = kzalloc(sizeof(*bss), GFP_ATOMIC);
	if (!bss)
		return NULL;
	atomic_inc(&bss->users);
	atomic_inc(&bss->users);
	memcpy(bss->bssid, bssid, ETH_ALEN);
	bss->freq = freq;
	if (ssid && ssid_len <= IEEE80211_MAX_SSID_LEN) {
		memcpy(bss->ssid, ssid, ssid_len);
		bss->ssid_len = ssid_len;
	}

	spin_lock_bh(&local->sta_bss_lock);
	/* TODO: order by RSSI? */
	list_add_tail(&bss->list, &local->sta_bss_list);
	__ieee80211_rx_bss_hash_add(dev, bss);
	spin_unlock_bh(&local->sta_bss_lock);
	return bss;
}

static struct ieee80211_sta_bss *
ieee80211_rx_bss_get(struct net_device *dev, u8 *bssid, int freq,
		     u8 *ssid, u8 ssid_len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;

	spin_lock_bh(&local->sta_bss_lock);
	bss = local->sta_bss_hash[STA_HASH(bssid)];
	while (bss) {
		if (!bss_mesh_cfg(bss) &&
		    !memcmp(bss->bssid, bssid, ETH_ALEN) &&
		    bss->freq == freq &&
		    bss->ssid_len == ssid_len &&
		    (ssid_len == 0 || !memcmp(bss->ssid, ssid, ssid_len))) {
			atomic_inc(&bss->users);
			break;
		}
		bss = bss->hnext;
	}
	spin_unlock_bh(&local->sta_bss_lock);
	return bss;
}

#ifdef CONFIG_MAC80211_MESH
static struct ieee80211_sta_bss *
ieee80211_rx_mesh_bss_get(struct net_device *dev, u8 *mesh_id, int mesh_id_len,
			  u8 *mesh_cfg, int freq)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;

	spin_lock_bh(&local->sta_bss_lock);
	bss = local->sta_bss_hash[mesh_id_hash(mesh_id, mesh_id_len)];
	while (bss) {
		if (bss_mesh_cfg(bss) &&
		    !memcmp(bss_mesh_cfg(bss), mesh_cfg, MESH_CFG_CMP_LEN) &&
		    bss->freq == freq &&
		    mesh_id_len == bss->mesh_id_len &&
		    (mesh_id_len == 0 || !memcmp(bss->mesh_id, mesh_id,
						 mesh_id_len))) {
			atomic_inc(&bss->users);
			break;
		}
		bss = bss->hnext;
	}
	spin_unlock_bh(&local->sta_bss_lock);
	return bss;
}

static struct ieee80211_sta_bss *
ieee80211_rx_mesh_bss_add(struct net_device *dev, u8 *mesh_id, int mesh_id_len,
			  u8 *mesh_cfg, int mesh_config_len, int freq)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;

	if (mesh_config_len != MESH_CFG_LEN)
		return NULL;

	bss = kzalloc(sizeof(*bss), GFP_ATOMIC);
	if (!bss)
		return NULL;

	bss->mesh_cfg = kmalloc(MESH_CFG_CMP_LEN, GFP_ATOMIC);
	if (!bss->mesh_cfg) {
		kfree(bss);
		return NULL;
	}

	if (mesh_id_len && mesh_id_len <= IEEE80211_MAX_MESH_ID_LEN) {
		bss->mesh_id = kmalloc(mesh_id_len, GFP_ATOMIC);
		if (!bss->mesh_id) {
			kfree(bss->mesh_cfg);
			kfree(bss);
			return NULL;
		}
		memcpy(bss->mesh_id, mesh_id, mesh_id_len);
	}

	atomic_inc(&bss->users);
	atomic_inc(&bss->users);
	memcpy(bss->mesh_cfg, mesh_cfg, MESH_CFG_CMP_LEN);
	bss->mesh_id_len = mesh_id_len;
	bss->freq = freq;
	spin_lock_bh(&local->sta_bss_lock);
	/* TODO: order by RSSI? */
	list_add_tail(&bss->list, &local->sta_bss_list);
	__ieee80211_rx_bss_hash_add(dev, bss);
	spin_unlock_bh(&local->sta_bss_lock);
	return bss;
}
#endif

static void ieee80211_rx_bss_free(struct ieee80211_sta_bss *bss)
{
	kfree(bss->wpa_ie);
	kfree(bss->rsn_ie);
	kfree(bss->wmm_ie);
	kfree(bss->ht_ie);
	kfree(bss_mesh_id(bss));
	kfree(bss_mesh_cfg(bss));
	kfree(bss);
}


static void ieee80211_rx_bss_put(struct net_device *dev,
				 struct ieee80211_sta_bss *bss)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	local_bh_disable();
	if (!atomic_dec_and_lock(&bss->users, &local->sta_bss_lock)) {
		local_bh_enable();
		return;
	}

	__ieee80211_rx_bss_hash_del(dev, bss);
	list_del(&bss->list);
	spin_unlock_bh(&local->sta_bss_lock);
	ieee80211_rx_bss_free(bss);
}


void ieee80211_rx_bss_list_init(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	spin_lock_init(&local->sta_bss_lock);
	INIT_LIST_HEAD(&local->sta_bss_list);
}


void ieee80211_rx_bss_list_deinit(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss, *tmp;

	list_for_each_entry_safe(bss, tmp, &local->sta_bss_list, list)
		ieee80211_rx_bss_put(dev, bss);
}


static int ieee80211_sta_join_ibss(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta,
				   struct ieee80211_sta_bss *bss)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	int res, rates, i, j;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	struct ieee80211_tx_control control;
	struct rate_selection ratesel;
	u8 *pos;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_supported_band *sband;
	union iwreq_data wrqu;

	sband = local->hw.wiphy->bands[local->hw.conf.channel->band];

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	/* Remove possible STA entries from other IBSS networks. */
	sta_info_flush_delayed(sdata);

	if (local->ops->reset_tsf) {
		/* Reset own TSF to allow time synchronization work. */
		local->ops->reset_tsf(local_to_hw(local));
	}
	memcpy(ifsta->bssid, bss->bssid, ETH_ALEN);
	res = ieee80211_if_config(dev);
	if (res)
		return res;

	local->hw.conf.beacon_int = bss->beacon_int >= 10 ? bss->beacon_int : 10;

	sdata->drop_unencrypted = bss->capability &
		WLAN_CAPABILITY_PRIVACY ? 1 : 0;

	res = ieee80211_set_freq(dev, bss->freq);

	if (res)
		return res;

	/* Set beacon template */
	skb = dev_alloc_skb(local->hw.extra_tx_headroom + 400);
	do {
		if (!skb)
			break;

		skb_reserve(skb, local->hw.extra_tx_headroom);

		mgmt = (struct ieee80211_mgmt *)
			skb_put(skb, 24 + sizeof(mgmt->u.beacon));
		memset(mgmt, 0, 24 + sizeof(mgmt->u.beacon));
		mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
						   IEEE80211_STYPE_BEACON);
		memset(mgmt->da, 0xff, ETH_ALEN);
		memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
		memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
		mgmt->u.beacon.beacon_int =
			cpu_to_le16(local->hw.conf.beacon_int);
		mgmt->u.beacon.capab_info = cpu_to_le16(bss->capability);

		pos = skb_put(skb, 2 + ifsta->ssid_len);
		*pos++ = WLAN_EID_SSID;
		*pos++ = ifsta->ssid_len;
		memcpy(pos, ifsta->ssid, ifsta->ssid_len);

		rates = bss->supp_rates_len;
		if (rates > 8)
			rates = 8;
		pos = skb_put(skb, 2 + rates);
		*pos++ = WLAN_EID_SUPP_RATES;
		*pos++ = rates;
		memcpy(pos, bss->supp_rates, rates);

		if (bss->band == IEEE80211_BAND_2GHZ) {
			pos = skb_put(skb, 2 + 1);
			*pos++ = WLAN_EID_DS_PARAMS;
			*pos++ = 1;
			*pos++ = ieee80211_frequency_to_channel(bss->freq);
		}

		pos = skb_put(skb, 2 + 2);
		*pos++ = WLAN_EID_IBSS_PARAMS;
		*pos++ = 2;
		/* FIX: set ATIM window based on scan results */
		*pos++ = 0;
		*pos++ = 0;

		if (bss->supp_rates_len > 8) {
			rates = bss->supp_rates_len - 8;
			pos = skb_put(skb, 2 + rates);
			*pos++ = WLAN_EID_EXT_SUPP_RATES;
			*pos++ = rates;
			memcpy(pos, &bss->supp_rates[8], rates);
		}

		memset(&control, 0, sizeof(control));
		rate_control_get_rate(dev, sband, skb, &ratesel);
		if (!ratesel.rate) {
			printk(KERN_DEBUG "%s: Failed to determine TX rate "
			       "for IBSS beacon\n", dev->name);
			break;
		}
		control.vif = &sdata->vif;
		control.tx_rate = ratesel.rate;
		if (sdata->bss_conf.use_short_preamble &&
		    ratesel.rate->flags & IEEE80211_RATE_SHORT_PREAMBLE)
			control.flags |= IEEE80211_TXCTL_SHORT_PREAMBLE;
		control.antenna_sel_tx = local->hw.conf.antenna_sel_tx;
		control.flags |= IEEE80211_TXCTL_NO_ACK;
		control.retry_limit = 1;

		ifsta->probe_resp = skb_copy(skb, GFP_ATOMIC);
		if (ifsta->probe_resp) {
			mgmt = (struct ieee80211_mgmt *)
				ifsta->probe_resp->data;
			mgmt->frame_control =
				IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					     IEEE80211_STYPE_PROBE_RESP);
		} else {
			printk(KERN_DEBUG "%s: Could not allocate ProbeResp "
			       "template for IBSS\n", dev->name);
		}

		if (local->ops->beacon_update &&
		    local->ops->beacon_update(local_to_hw(local),
					     skb, &control) == 0) {
			printk(KERN_DEBUG "%s: Configured IBSS beacon "
			       "template\n", dev->name);
			skb = NULL;
		}

		rates = 0;
		sband = local->hw.wiphy->bands[local->hw.conf.channel->band];
		for (i = 0; i < bss->supp_rates_len; i++) {
			int bitrate = (bss->supp_rates[i] & 0x7f) * 5;
			for (j = 0; j < sband->n_bitrates; j++)
				if (sband->bitrates[j].bitrate == bitrate)
					rates |= BIT(j);
		}
		ifsta->supp_rates_bits[local->hw.conf.channel->band] = rates;

		ieee80211_sta_def_wmm_params(dev, bss, 1);
	} while (0);

	if (skb) {
		printk(KERN_DEBUG "%s: Failed to configure IBSS beacon "
		       "template\n", dev->name);
		dev_kfree_skb(skb);
	}

	ifsta->state = IEEE80211_IBSS_JOINED;
	mod_timer(&ifsta->timer, jiffies + IEEE80211_IBSS_MERGE_INTERVAL);

	memset(&wrqu, 0, sizeof(wrqu));
	memcpy(wrqu.ap_addr.sa_data, bss->bssid, ETH_ALEN);
	wireless_send_event(dev, SIOCGIWAP, &wrqu, NULL);

	return res;
}

u64 ieee80211_sta_get_rates(struct ieee80211_local *local,
			    struct ieee802_11_elems *elems,
			    enum ieee80211_band band)
{
	struct ieee80211_supported_band *sband;
	struct ieee80211_rate *bitrates;
	size_t num_rates;
	u64 supp_rates;
	int i, j;
	sband = local->hw.wiphy->bands[band];

	if (!sband) {
		WARN_ON(1);
		sband = local->hw.wiphy->bands[local->hw.conf.channel->band];
	}

	bitrates = sband->bitrates;
	num_rates = sband->n_bitrates;
	supp_rates = 0;
	for (i = 0; i < elems->supp_rates_len +
		     elems->ext_supp_rates_len; i++) {
		u8 rate = 0;
		int own_rate;
		if (i < elems->supp_rates_len)
			rate = elems->supp_rates[i];
		else if (elems->ext_supp_rates)
			rate = elems->ext_supp_rates
				[i - elems->supp_rates_len];
		own_rate = 5 * (rate & 0x7f);
		for (j = 0; j < num_rates; j++)
			if (bitrates[j].bitrate == own_rate)
				supp_rates |= BIT(j);
	}
	return supp_rates;
}


static void ieee80211_rx_bss_info(struct net_device *dev,
				  struct ieee80211_mgmt *mgmt,
				  size_t len,
				  struct ieee80211_rx_status *rx_status,
				  int beacon)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee802_11_elems elems;
	size_t baselen;
	int freq, clen;
	struct ieee80211_sta_bss *bss;
	struct sta_info *sta;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	u64 beacon_timestamp, rx_timestamp;
	struct ieee80211_channel *channel;
	DECLARE_MAC_BUF(mac);
	DECLARE_MAC_BUF(mac2);

	if (!beacon && memcmp(mgmt->da, dev->dev_addr, ETH_ALEN))
		return; /* ignore ProbeResp to foreign address */

#if 0
	printk(KERN_DEBUG "%s: RX %s from %s to %s\n",
	       dev->name, beacon ? "Beacon" : "Probe Response",
	       print_mac(mac, mgmt->sa), print_mac(mac2, mgmt->da));
#endif

	baselen = (u8 *) mgmt->u.beacon.variable - (u8 *) mgmt;
	if (baselen > len)
		return;

	beacon_timestamp = le64_to_cpu(mgmt->u.beacon.timestamp);
	ieee802_11_parse_elems(mgmt->u.beacon.variable, len - baselen, &elems);

	if (ieee80211_vif_is_mesh(&sdata->vif) && elems.mesh_id &&
	    elems.mesh_config && mesh_matches_local(&elems, dev)) {
		u64 rates = ieee80211_sta_get_rates(local, &elems,
						rx_status->band);

		mesh_neighbour_update(mgmt->sa, rates, dev,
				      mesh_peer_accepts_plinks(&elems, dev));
	}

	rcu_read_lock();

	if (sdata->vif.type == IEEE80211_IF_TYPE_IBSS && elems.supp_rates &&
	    memcmp(mgmt->bssid, sdata->u.sta.bssid, ETH_ALEN) == 0 &&
	    (sta = sta_info_get(local, mgmt->sa))) {
		u64 prev_rates;
		u64 supp_rates = ieee80211_sta_get_rates(local, &elems,
							rx_status->band);

		prev_rates = sta->supp_rates[rx_status->band];
		sta->supp_rates[rx_status->band] &= supp_rates;
		if (sta->supp_rates[rx_status->band] == 0) {
			/* No matching rates - this should not really happen.
			 * Make sure that at least one rate is marked
			 * supported to avoid issues with TX rate ctrl. */
			sta->supp_rates[rx_status->band] =
				sdata->u.sta.supp_rates_bits[rx_status->band];
		}
		if (sta->supp_rates[rx_status->band] != prev_rates) {
			printk(KERN_DEBUG "%s: updated supp_rates set for "
			       "%s based on beacon info (0x%llx & 0x%llx -> "
			       "0x%llx)\n",
			       dev->name, print_mac(mac, sta->addr),
			       (unsigned long long) prev_rates,
			       (unsigned long long) supp_rates,
			       (unsigned long long) sta->supp_rates[rx_status->band]);
		}
	}

	rcu_read_unlock();

	if (elems.ds_params && elems.ds_params_len == 1)
		freq = ieee80211_channel_to_frequency(elems.ds_params[0]);
	else
		freq = rx_status->freq;

	channel = ieee80211_get_channel(local->hw.wiphy, freq);

	if (!channel || channel->flags & IEEE80211_CHAN_DISABLED)
		return;

#ifdef CONFIG_MAC80211_MESH
	if (elems.mesh_config)
		bss = ieee80211_rx_mesh_bss_get(dev, elems.mesh_id,
				elems.mesh_id_len, elems.mesh_config, freq);
	else
#endif
		bss = ieee80211_rx_bss_get(dev, mgmt->bssid, freq,
					   elems.ssid, elems.ssid_len);
	if (!bss) {
#ifdef CONFIG_MAC80211_MESH
		if (elems.mesh_config)
			bss = ieee80211_rx_mesh_bss_add(dev, elems.mesh_id,
				elems.mesh_id_len, elems.mesh_config,
				elems.mesh_config_len, freq);
		else
#endif
			bss = ieee80211_rx_bss_add(dev, mgmt->bssid, freq,
						   elems.ssid, elems.ssid_len);
		if (!bss)
			return;
	} else {
#if 0
		/* TODO: order by RSSI? */
		spin_lock_bh(&local->sta_bss_lock);
		list_move_tail(&bss->list, &local->sta_bss_list);
		spin_unlock_bh(&local->sta_bss_lock);
#endif
	}

	/* save the ERP value so that it is available at association time */
	if (elems.erp_info && elems.erp_info_len >= 1) {
		bss->erp_value = elems.erp_info[0];
		bss->has_erp_value = 1;
	}

	if (elems.ht_cap_elem &&
	     (!bss->ht_ie || bss->ht_ie_len != elems.ht_cap_elem_len ||
	     memcmp(bss->ht_ie, elems.ht_cap_elem, elems.ht_cap_elem_len))) {
		kfree(bss->ht_ie);
		bss->ht_ie = kmalloc(elems.ht_cap_elem_len + 2, GFP_ATOMIC);
		if (bss->ht_ie) {
			memcpy(bss->ht_ie, elems.ht_cap_elem - 2,
				elems.ht_cap_elem_len + 2);
			bss->ht_ie_len = elems.ht_cap_elem_len + 2;
		} else
			bss->ht_ie_len = 0;
	} else if (!elems.ht_cap_elem && bss->ht_ie) {
		kfree(bss->ht_ie);
		bss->ht_ie = NULL;
		bss->ht_ie_len = 0;
	}

	bss->beacon_int = le16_to_cpu(mgmt->u.beacon.beacon_int);
	bss->capability = le16_to_cpu(mgmt->u.beacon.capab_info);

	bss->supp_rates_len = 0;
	if (elems.supp_rates) {
		clen = IEEE80211_MAX_SUPP_RATES - bss->supp_rates_len;
		if (clen > elems.supp_rates_len)
			clen = elems.supp_rates_len;
		memcpy(&bss->supp_rates[bss->supp_rates_len], elems.supp_rates,
		       clen);
		bss->supp_rates_len += clen;
	}
	if (elems.ext_supp_rates) {
		clen = IEEE80211_MAX_SUPP_RATES - bss->supp_rates_len;
		if (clen > elems.ext_supp_rates_len)
			clen = elems.ext_supp_rates_len;
		memcpy(&bss->supp_rates[bss->supp_rates_len],
		       elems.ext_supp_rates, clen);
		bss->supp_rates_len += clen;
	}

	bss->band = rx_status->band;

	bss->timestamp = beacon_timestamp;
	bss->last_update = jiffies;
	bss->rssi = rx_status->ssi;
	bss->signal = rx_status->signal;
	bss->noise = rx_status->noise;
	if (!beacon && !bss->probe_resp)
		bss->probe_resp = true;

	/*
	 * In STA mode, the remaining parameters should not be overridden
	 * by beacons because they're not necessarily accurate there.
	 */
	if (sdata->vif.type != IEEE80211_IF_TYPE_IBSS &&
	    bss->probe_resp && beacon) {
		ieee80211_rx_bss_put(dev, bss);
		return;
	}

	if (elems.wpa &&
	    (!bss->wpa_ie || bss->wpa_ie_len != elems.wpa_len ||
	     memcmp(bss->wpa_ie, elems.wpa, elems.wpa_len))) {
		kfree(bss->wpa_ie);
		bss->wpa_ie = kmalloc(elems.wpa_len + 2, GFP_ATOMIC);
		if (bss->wpa_ie) {
			memcpy(bss->wpa_ie, elems.wpa - 2, elems.wpa_len + 2);
			bss->wpa_ie_len = elems.wpa_len + 2;
		} else
			bss->wpa_ie_len = 0;
	} else if (!elems.wpa && bss->wpa_ie) {
		kfree(bss->wpa_ie);
		bss->wpa_ie = NULL;
		bss->wpa_ie_len = 0;
	}

	if (elems.rsn &&
	    (!bss->rsn_ie || bss->rsn_ie_len != elems.rsn_len ||
	     memcmp(bss->rsn_ie, elems.rsn, elems.rsn_len))) {
		kfree(bss->rsn_ie);
		bss->rsn_ie = kmalloc(elems.rsn_len + 2, GFP_ATOMIC);
		if (bss->rsn_ie) {
			memcpy(bss->rsn_ie, elems.rsn - 2, elems.rsn_len + 2);
			bss->rsn_ie_len = elems.rsn_len + 2;
		} else
			bss->rsn_ie_len = 0;
	} else if (!elems.rsn && bss->rsn_ie) {
		kfree(bss->rsn_ie);
		bss->rsn_ie = NULL;
		bss->rsn_ie_len = 0;
	}

	/*
	 * Cf.
	 * http://www.wipo.int/pctdb/en/wo.jsp?wo=2007047181&IA=WO2007047181&DISPLAY=DESC
	 *
	 * quoting:
	 *
	 * In particular, "Wi-Fi CERTIFIED for WMM - Support for Multimedia
	 * Applications with Quality of Service in Wi-Fi Networks," Wi- Fi
	 * Alliance (September 1, 2004) is incorporated by reference herein.
	 * The inclusion of the WMM Parameters in probe responses and
	 * association responses is mandatory for WMM enabled networks. The
	 * inclusion of the WMM Parameters in beacons, however, is optional.
	 */

	if (elems.wmm_param &&
	    (!bss->wmm_ie || bss->wmm_ie_len != elems.wmm_param_len ||
	     memcmp(bss->wmm_ie, elems.wmm_param, elems.wmm_param_len))) {
		kfree(bss->wmm_ie);
		bss->wmm_ie = kmalloc(elems.wmm_param_len + 2, GFP_ATOMIC);
		if (bss->wmm_ie) {
			memcpy(bss->wmm_ie, elems.wmm_param - 2,
			       elems.wmm_param_len + 2);
			bss->wmm_ie_len = elems.wmm_param_len + 2;
		} else
			bss->wmm_ie_len = 0;
	} else if (elems.wmm_info &&
		    (!bss->wmm_ie || bss->wmm_ie_len != elems.wmm_info_len ||
		     memcmp(bss->wmm_ie, elems.wmm_info, elems.wmm_info_len))) {
		 /* As for certain AP's Fifth bit is not set in WMM IE in
		  * beacon frames.So while parsing the beacon frame the
		  * wmm_info structure is used instead of wmm_param.
		  * wmm_info structure was never used to set bss->wmm_ie.
		  * This code fixes this problem by copying the WME
		  * information from wmm_info to bss->wmm_ie and enabling
		  * n-band association.
		  */
		kfree(bss->wmm_ie);
		bss->wmm_ie = kmalloc(elems.wmm_info_len + 2, GFP_ATOMIC);
		if (bss->wmm_ie) {
			memcpy(bss->wmm_ie, elems.wmm_info - 2,
			       elems.wmm_info_len + 2);
			bss->wmm_ie_len = elems.wmm_info_len + 2;
		} else
			bss->wmm_ie_len = 0;
	} else if (!elems.wmm_param && !elems.wmm_info && bss->wmm_ie) {
		kfree(bss->wmm_ie);
		bss->wmm_ie = NULL;
		bss->wmm_ie_len = 0;
	}

	/* check if we need to merge IBSS */
	if (sdata->vif.type == IEEE80211_IF_TYPE_IBSS && beacon &&
	    !local->sta_sw_scanning && !local->sta_hw_scanning &&
	    bss->capability & WLAN_CAPABILITY_IBSS &&
	    bss->freq == local->oper_channel->center_freq &&
	    elems.ssid_len == sdata->u.sta.ssid_len &&
	    memcmp(elems.ssid, sdata->u.sta.ssid, sdata->u.sta.ssid_len) == 0) {
		if (rx_status->flag & RX_FLAG_TSFT) {
			/* in order for correct IBSS merging we need mactime
			 *
			 * since mactime is defined as the time the first data
			 * symbol of the frame hits the PHY, and the timestamp
			 * of the beacon is defined as "the time that the data
			 * symbol containing the first bit of the timestamp is
			 * transmitted to the PHY plus the transmitting STA’s
			 * delays through its local PHY from the MAC-PHY
			 * interface to its interface with the WM"
			 * (802.11 11.1.2) - equals the time this bit arrives at
			 * the receiver - we have to take into account the
			 * offset between the two.
			 * e.g: at 1 MBit that means mactime is 192 usec earlier
			 * (=24 bytes * 8 usecs/byte) than the beacon timestamp.
			 */
			int rate = local->hw.wiphy->bands[rx_status->band]->
					bitrates[rx_status->rate_idx].bitrate;
			rx_timestamp = rx_status->mactime + (24 * 8 * 10 / rate);
		} else if (local && local->ops && local->ops->get_tsf)
			/* second best option: get current TSF */
			rx_timestamp = local->ops->get_tsf(local_to_hw(local));
		else
			/* can't merge without knowing the TSF */
			rx_timestamp = -1LLU;
#ifdef CONFIG_MAC80211_IBSS_DEBUG
		printk(KERN_DEBUG "RX beacon SA=%s BSSID="
		       "%s TSF=0x%llx BCN=0x%llx diff=%lld @%lu\n",
		       print_mac(mac, mgmt->sa),
		       print_mac(mac2, mgmt->bssid),
		       (unsigned long long)rx_timestamp,
		       (unsigned long long)beacon_timestamp,
		       (unsigned long long)(rx_timestamp - beacon_timestamp),
		       jiffies);
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
		if (beacon_timestamp > rx_timestamp) {
#ifndef CONFIG_MAC80211_IBSS_DEBUG
			if (net_ratelimit())
#endif
				printk(KERN_DEBUG "%s: beacon TSF higher than "
				       "local TSF - IBSS merge with BSSID %s\n",
				       dev->name, print_mac(mac, mgmt->bssid));
			ieee80211_sta_join_ibss(dev, &sdata->u.sta, bss);
			ieee80211_ibss_add_sta(dev, NULL,
					       mgmt->bssid, mgmt->sa);
		}
	}

	ieee80211_rx_bss_put(dev, bss);
}


static void ieee80211_rx_mgmt_probe_resp(struct net_device *dev,
					 struct ieee80211_mgmt *mgmt,
					 size_t len,
					 struct ieee80211_rx_status *rx_status)
{
	ieee80211_rx_bss_info(dev, mgmt, len, rx_status, 0);
}


static void ieee80211_rx_mgmt_beacon(struct net_device *dev,
				     struct ieee80211_mgmt *mgmt,
				     size_t len,
				     struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	size_t baselen;
	struct ieee802_11_elems elems;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_conf *conf = &local->hw.conf;
	u32 changed = 0;

	ieee80211_rx_bss_info(dev, mgmt, len, rx_status, 1);

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	if (sdata->vif.type != IEEE80211_IF_TYPE_STA)
		return;
	ifsta = &sdata->u.sta;

	if (!(ifsta->flags & IEEE80211_STA_ASSOCIATED) ||
	    memcmp(ifsta->bssid, mgmt->bssid, ETH_ALEN) != 0)
		return;

	/* Process beacon from the current BSS */
	baselen = (u8 *) mgmt->u.beacon.variable - (u8 *) mgmt;
	if (baselen > len)
		return;

	ieee802_11_parse_elems(mgmt->u.beacon.variable, len - baselen, &elems);

	if (elems.wmm_param && (ifsta->flags & IEEE80211_STA_WMM_ENABLED)) {
		ieee80211_sta_wmm_params(dev, ifsta, elems.wmm_param,
					 elems.wmm_param_len);
	}

	/* Do not send changes to driver if we are scanning. This removes
	 * requirement that driver's bss_info_changed function needs to be
	 * atomic. */
	if (local->sta_sw_scanning || local->sta_hw_scanning)
		return;

	if (elems.erp_info && elems.erp_info_len >= 1)
		changed |= ieee80211_handle_erp_ie(sdata, elems.erp_info[0]);
	else {
		u16 capab = le16_to_cpu(mgmt->u.beacon.capab_info);
		changed |= ieee80211_handle_protect_preamb(sdata, false,
				(capab & WLAN_CAPABILITY_SHORT_PREAMBLE) != 0);
	}

	if (elems.ht_cap_elem && elems.ht_info_elem &&
	    elems.wmm_param && conf->flags & IEEE80211_CONF_SUPPORT_HT_MODE) {
		struct ieee80211_ht_bss_info bss_info;

		ieee80211_ht_addt_info_ie_to_ht_bss_info(
				(struct ieee80211_ht_addt_info *)
				elems.ht_info_elem, &bss_info);
		changed |= ieee80211_handle_ht(local, 1, &conf->ht_conf,
					       &bss_info);
	}

	ieee80211_bss_info_change_notify(sdata, changed);
}


static void ieee80211_rx_mgmt_probe_req(struct net_device *dev,
					struct ieee80211_if_sta *ifsta,
					struct ieee80211_mgmt *mgmt,
					size_t len,
					struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	int tx_last_beacon;
	struct sk_buff *skb;
	struct ieee80211_mgmt *resp;
	u8 *pos, *end;
	DECLARE_MAC_BUF(mac);
#ifdef CONFIG_MAC80211_IBSS_DEBUG
	DECLARE_MAC_BUF(mac2);
	DECLARE_MAC_BUF(mac3);
#endif

	if (sdata->vif.type != IEEE80211_IF_TYPE_IBSS ||
	    ifsta->state != IEEE80211_IBSS_JOINED ||
	    len < 24 + 2 || !ifsta->probe_resp)
		return;

	if (local->ops->tx_last_beacon)
		tx_last_beacon = local->ops->tx_last_beacon(local_to_hw(local));
	else
		tx_last_beacon = 1;

#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "%s: RX ProbeReq SA=%s DA=%s BSSID="
	       "%s (tx_last_beacon=%d)\n",
	       dev->name, print_mac(mac, mgmt->sa), print_mac(mac2, mgmt->da),
	       print_mac(mac3, mgmt->bssid), tx_last_beacon);
#endif /* CONFIG_MAC80211_IBSS_DEBUG */

	if (!tx_last_beacon)
		return;

	if (memcmp(mgmt->bssid, ifsta->bssid, ETH_ALEN) != 0 &&
	    memcmp(mgmt->bssid, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) != 0)
		return;

	end = ((u8 *) mgmt) + len;
	pos = mgmt->u.probe_req.variable;
	if (pos[0] != WLAN_EID_SSID ||
	    pos + 2 + pos[1] > end) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: Invalid SSID IE in ProbeReq "
			       "from %s\n",
			       dev->name, print_mac(mac, mgmt->sa));
		}
		return;
	}
	if (pos[1] != 0 &&
	    (pos[1] != ifsta->ssid_len ||
	     memcmp(pos + 2, ifsta->ssid, ifsta->ssid_len) != 0)) {
		/* Ignore ProbeReq for foreign SSID */
		return;
	}

	/* Reply with ProbeResp */
	skb = skb_copy(ifsta->probe_resp, GFP_KERNEL);
	if (!skb)
		return;

	resp = (struct ieee80211_mgmt *) skb->data;
	memcpy(resp->da, mgmt->sa, ETH_ALEN);
#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "%s: Sending ProbeResp to %s\n",
	       dev->name, print_mac(mac, resp->da));
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
	ieee80211_sta_tx(dev, skb, 0);
}

static void ieee80211_rx_mgmt_action(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     struct ieee80211_mgmt *mgmt,
				     size_t len,
				     struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	if (len < IEEE80211_MIN_ACTION_SIZE)
		return;

	switch (mgmt->u.action.category) {
	case WLAN_CATEGORY_BACK:
		switch (mgmt->u.action.u.addba_req.action_code) {
		case WLAN_ACTION_ADDBA_REQ:
			if (len < (IEEE80211_MIN_ACTION_SIZE +
				   sizeof(mgmt->u.action.u.addba_req)))
				break;
			ieee80211_sta_process_addba_request(dev, mgmt, len);
			break;
		case WLAN_ACTION_ADDBA_RESP:
			if (len < (IEEE80211_MIN_ACTION_SIZE +
				   sizeof(mgmt->u.action.u.addba_resp)))
				break;
			ieee80211_sta_process_addba_resp(dev, mgmt, len);
			break;
		case WLAN_ACTION_DELBA:
			if (len < (IEEE80211_MIN_ACTION_SIZE +
				   sizeof(mgmt->u.action.u.delba)))
				break;
			ieee80211_sta_process_delba(dev, mgmt, len);
			break;
		default:
			if (net_ratelimit())
			   printk(KERN_DEBUG "%s: Rx unknown A-MPDU action\n",
					dev->name);
			break;
		}
		break;
	case PLINK_CATEGORY:
		if (ieee80211_vif_is_mesh(&sdata->vif))
			mesh_rx_plink_frame(dev, mgmt, len, rx_status);
		break;
	case MESH_PATH_SEL_CATEGORY:
		if (ieee80211_vif_is_mesh(&sdata->vif))
			mesh_rx_path_sel_frame(dev, mgmt, len);
		break;
	default:
		if (net_ratelimit())
			printk(KERN_DEBUG "%s: Rx unknown action frame - "
			"category=%d\n", dev->name, mgmt->u.action.category);
		break;
	}
}

void ieee80211_sta_rx_mgmt(struct net_device *dev, struct sk_buff *skb,
			   struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	struct ieee80211_mgmt *mgmt;
	u16 fc;

	if (skb->len < 24)
		goto fail;

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;

	mgmt = (struct ieee80211_mgmt *) skb->data;
	fc = le16_to_cpu(mgmt->frame_control);

	switch (fc & IEEE80211_FCTL_STYPE) {
	case IEEE80211_STYPE_PROBE_REQ:
	case IEEE80211_STYPE_PROBE_RESP:
	case IEEE80211_STYPE_BEACON:
	case IEEE80211_STYPE_ACTION:
		memcpy(skb->cb, rx_status, sizeof(*rx_status));
	case IEEE80211_STYPE_AUTH:
	case IEEE80211_STYPE_ASSOC_RESP:
	case IEEE80211_STYPE_REASSOC_RESP:
	case IEEE80211_STYPE_DEAUTH:
	case IEEE80211_STYPE_DISASSOC:
		skb_queue_tail(&ifsta->skb_queue, skb);
		queue_work(local->hw.workqueue, &ifsta->work);
		return;
	default:
		printk(KERN_DEBUG "%s: received unknown management frame - "
		       "stype=%d\n", dev->name,
		       (fc & IEEE80211_FCTL_STYPE) >> 4);
		break;
	}

 fail:
	kfree_skb(skb);
}


static void ieee80211_sta_rx_queued_mgmt(struct net_device *dev,
					 struct sk_buff *skb)
{
	struct ieee80211_rx_status *rx_status;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	struct ieee80211_mgmt *mgmt;
	u16 fc;

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;

	rx_status = (struct ieee80211_rx_status *) skb->cb;
	mgmt = (struct ieee80211_mgmt *) skb->data;
	fc = le16_to_cpu(mgmt->frame_control);

	switch (fc & IEEE80211_FCTL_STYPE) {
	case IEEE80211_STYPE_PROBE_REQ:
		ieee80211_rx_mgmt_probe_req(dev, ifsta, mgmt, skb->len,
					    rx_status);
		break;
	case IEEE80211_STYPE_PROBE_RESP:
		ieee80211_rx_mgmt_probe_resp(dev, mgmt, skb->len, rx_status);
		break;
	case IEEE80211_STYPE_BEACON:
		ieee80211_rx_mgmt_beacon(dev, mgmt, skb->len, rx_status);
		break;
	case IEEE80211_STYPE_AUTH:
		ieee80211_rx_mgmt_auth(dev, ifsta, mgmt, skb->len);
		break;
	case IEEE80211_STYPE_ASSOC_RESP:
		ieee80211_rx_mgmt_assoc_resp(sdata, ifsta, mgmt, skb->len, 0);
		break;
	case IEEE80211_STYPE_REASSOC_RESP:
		ieee80211_rx_mgmt_assoc_resp(sdata, ifsta, mgmt, skb->len, 1);
		break;
	case IEEE80211_STYPE_DEAUTH:
		ieee80211_rx_mgmt_deauth(dev, ifsta, mgmt, skb->len);
		break;
	case IEEE80211_STYPE_DISASSOC:
		ieee80211_rx_mgmt_disassoc(dev, ifsta, mgmt, skb->len);
		break;
	case IEEE80211_STYPE_ACTION:
		ieee80211_rx_mgmt_action(dev, ifsta, mgmt, skb->len, rx_status);
		break;
	}

	kfree_skb(skb);
}


ieee80211_rx_result
ieee80211_sta_rx_scan(struct net_device *dev, struct sk_buff *skb,
		      struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_mgmt *mgmt;
	u16 fc;

	if (skb->len < 2)
		return RX_DROP_UNUSABLE;

	mgmt = (struct ieee80211_mgmt *) skb->data;
	fc = le16_to_cpu(mgmt->frame_control);

	if ((fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_CTL)
		return RX_CONTINUE;

	if (skb->len < 24)
		return RX_DROP_MONITOR;

	if ((fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT) {
		if ((fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_PROBE_RESP) {
			ieee80211_rx_mgmt_probe_resp(dev, mgmt,
						     skb->len, rx_status);
			dev_kfree_skb(skb);
			return RX_QUEUED;
		} else if ((fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_BEACON) {
			ieee80211_rx_mgmt_beacon(dev, mgmt, skb->len,
						 rx_status);
			dev_kfree_skb(skb);
			return RX_QUEUED;
		}
	}
	return RX_CONTINUE;
}


static int ieee80211_sta_active_ibss(struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	int active = 0;
	struct sta_info *sta;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	rcu_read_lock();

	list_for_each_entry_rcu(sta, &local->sta_list, list) {
		if (sta->sdata == sdata &&
		    time_after(sta->last_rx + IEEE80211_IBSS_MERGE_INTERVAL,
			       jiffies)) {
			active++;
			break;
		}
	}

	rcu_read_unlock();

	return active;
}


static void ieee80211_sta_expire(struct net_device *dev, unsigned long exp_time)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta, *tmp;
	LIST_HEAD(tmp_list);
	DECLARE_MAC_BUF(mac);
	unsigned long flags;

	spin_lock_irqsave(&local->sta_lock, flags);
	list_for_each_entry_safe(sta, tmp, &local->sta_list, list)
		if (time_after(jiffies, sta->last_rx + exp_time)) {
			printk(KERN_DEBUG "%s: expiring inactive STA %s\n",
			       dev->name, print_mac(mac, sta->addr));
			__sta_info_unlink(&sta);
			if (sta)
				list_add(&sta->list, &tmp_list);
		}
	spin_unlock_irqrestore(&local->sta_lock, flags);

	list_for_each_entry_safe(sta, tmp, &tmp_list, list)
		sta_info_destroy(sta);
}


static void ieee80211_sta_merge_ibss(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	mod_timer(&ifsta->timer, jiffies + IEEE80211_IBSS_MERGE_INTERVAL);

	ieee80211_sta_expire(dev, IEEE80211_IBSS_INACTIVITY_LIMIT);
	if (ieee80211_sta_active_ibss(dev))
		return;

	printk(KERN_DEBUG "%s: No active IBSS STAs - trying to scan for other "
	       "IBSS networks with same SSID (merge)\n", dev->name);
	ieee80211_sta_req_scan(dev, ifsta->ssid, ifsta->ssid_len);
}


#ifdef CONFIG_MAC80211_MESH
static void ieee80211_mesh_housekeeping(struct net_device *dev,
			   struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	bool free_plinks;

	ieee80211_sta_expire(dev, IEEE80211_MESH_PEER_INACTIVITY_LIMIT);
	mesh_path_expire(dev);

	free_plinks = mesh_plink_availables(sdata);
	if (free_plinks != sdata->u.sta.accepting_plinks)
		ieee80211_if_config_beacon(dev);

	mod_timer(&ifsta->timer, jiffies +
			IEEE80211_MESH_HOUSEKEEPING_INTERVAL);
}


void ieee80211_start_mesh(struct net_device *dev)
{
	struct ieee80211_if_sta *ifsta;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;
	ifsta->state = IEEE80211_MESH_UP;
	ieee80211_sta_timer((unsigned long)sdata);
}
#endif


void ieee80211_sta_timer(unsigned long data)
{
	struct ieee80211_sub_if_data *sdata =
		(struct ieee80211_sub_if_data *) data;
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	struct ieee80211_local *local = wdev_priv(&sdata->wdev);

	set_bit(IEEE80211_STA_REQ_RUN, &ifsta->request);
	queue_work(local->hw.workqueue, &ifsta->work);
}

void ieee80211_sta_work(struct work_struct *work)
{
	struct ieee80211_sub_if_data *sdata =
		container_of(work, struct ieee80211_sub_if_data, u.sta.work);
	struct net_device *dev = sdata->dev;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_if_sta *ifsta;
	struct sk_buff *skb;

	if (!netif_running(dev))
		return;

	if (local->sta_sw_scanning || local->sta_hw_scanning)
		return;

	if (sdata->vif.type != IEEE80211_IF_TYPE_STA &&
	    sdata->vif.type != IEEE80211_IF_TYPE_IBSS &&
	    sdata->vif.type != IEEE80211_IF_TYPE_MESH_POINT) {
		printk(KERN_DEBUG "%s: ieee80211_sta_work: non-STA interface "
		       "(type=%d)\n", dev->name, sdata->vif.type);
		return;
	}
	ifsta = &sdata->u.sta;

	while ((skb = skb_dequeue(&ifsta->skb_queue)))
		ieee80211_sta_rx_queued_mgmt(dev, skb);

#ifdef CONFIG_MAC80211_MESH
	if (ifsta->preq_queue_len &&
	    time_after(jiffies,
		       ifsta->last_preq + msecs_to_jiffies(ifsta->mshcfg.dot11MeshHWMPpreqMinInterval)))
		mesh_path_start_discovery(dev);
#endif

	if (ifsta->state != IEEE80211_AUTHENTICATE &&
	    ifsta->state != IEEE80211_ASSOCIATE &&
	    test_and_clear_bit(IEEE80211_STA_REQ_SCAN, &ifsta->request)) {
		if (ifsta->scan_ssid_len)
			ieee80211_sta_start_scan(dev, ifsta->scan_ssid, ifsta->scan_ssid_len);
		else
			ieee80211_sta_start_scan(dev, NULL, 0);
		return;
	}

	if (test_and_clear_bit(IEEE80211_STA_REQ_AUTH, &ifsta->request)) {
		if (ieee80211_sta_config_auth(dev, ifsta))
			return;
		clear_bit(IEEE80211_STA_REQ_RUN, &ifsta->request);
	} else if (!test_and_clear_bit(IEEE80211_STA_REQ_RUN, &ifsta->request))
		return;

	switch (ifsta->state) {
	case IEEE80211_DISABLED:
		break;
	case IEEE80211_AUTHENTICATE:
		ieee80211_authenticate(dev, ifsta);
		break;
	case IEEE80211_ASSOCIATE:
		ieee80211_associate(dev, ifsta);
		break;
	case IEEE80211_ASSOCIATED:
		ieee80211_associated(dev, ifsta);
		break;
	case IEEE80211_IBSS_SEARCH:
		ieee80211_sta_find_ibss(dev, ifsta);
		break;
	case IEEE80211_IBSS_JOINED:
		ieee80211_sta_merge_ibss(dev, ifsta);
		break;
#ifdef CONFIG_MAC80211_MESH
	case IEEE80211_MESH_UP:
		ieee80211_mesh_housekeeping(dev, ifsta);
		break;
#endif
	default:
		printk(KERN_DEBUG "ieee80211_sta_work: Unknown state %d\n",
		       ifsta->state);
		break;
	}

	if (ieee80211_privacy_mismatch(dev, ifsta)) {
		printk(KERN_DEBUG "%s: privacy configuration mismatch and "
		       "mixed-cell disabled - disassociate\n", dev->name);

		ieee80211_send_disassoc(dev, ifsta, WLAN_REASON_UNSPECIFIED);
		ieee80211_set_disassoc(dev, ifsta, 0);
	}
}


static void ieee80211_sta_reset_auth(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	if (local->ops->reset_tsf) {
		/* Reset own TSF to allow time synchronization work. */
		local->ops->reset_tsf(local_to_hw(local));
	}

	ifsta->wmm_last_param_set = -1; /* allow any WMM update */


	if (ifsta->auth_algs & IEEE80211_AUTH_ALG_OPEN)
		ifsta->auth_alg = WLAN_AUTH_OPEN;
	else if (ifsta->auth_algs & IEEE80211_AUTH_ALG_SHARED_KEY)
		ifsta->auth_alg = WLAN_AUTH_SHARED_KEY;
	else if (ifsta->auth_algs & IEEE80211_AUTH_ALG_LEAP)
		ifsta->auth_alg = WLAN_AUTH_LEAP;
	else
		ifsta->auth_alg = WLAN_AUTH_OPEN;
	printk(KERN_DEBUG "%s: Initial auth_alg=%d\n", dev->name,
	       ifsta->auth_alg);
	ifsta->auth_transaction = -1;
	ifsta->flags &= ~IEEE80211_STA_ASSOCIATED;
	ifsta->auth_tries = ifsta->assoc_tries = 0;
	netif_carrier_off(dev);
}


void ieee80211_sta_req_auth(struct net_device *dev,
			    struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	if (sdata->vif.type != IEEE80211_IF_TYPE_STA)
		return;

	if ((ifsta->flags & (IEEE80211_STA_BSSID_SET |
				IEEE80211_STA_AUTO_BSSID_SEL)) &&
	    (ifsta->flags & (IEEE80211_STA_SSID_SET |
				IEEE80211_STA_AUTO_SSID_SEL))) {
		set_bit(IEEE80211_STA_REQ_AUTH, &ifsta->request);
		queue_work(local->hw.workqueue, &ifsta->work);
	}
}

static int ieee80211_sta_match_ssid(struct ieee80211_if_sta *ifsta,
				    const char *ssid, int ssid_len)
{
	int tmp, hidden_ssid;

	if (ssid_len == ifsta->ssid_len &&
	    !memcmp(ifsta->ssid, ssid, ssid_len))
		return 1;

	if (ifsta->flags & IEEE80211_STA_AUTO_BSSID_SEL)
		return 0;

	hidden_ssid = 1;
	tmp = ssid_len;
	while (tmp--) {
		if (ssid[tmp] != '\0') {
			hidden_ssid = 0;
			break;
		}
	}

	if (hidden_ssid && ifsta->ssid_len == ssid_len)
		return 1;

	if (ssid_len == 1 && ssid[0] == ' ')
		return 1;

	return 0;
}

static int ieee80211_sta_config_auth(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_sta_bss *bss, *selected = NULL;
	int top_rssi = 0, freq;

	spin_lock_bh(&local->sta_bss_lock);
	freq = local->oper_channel->center_freq;
	list_for_each_entry(bss, &local->sta_bss_list, list) {
		if (!(bss->capability & WLAN_CAPABILITY_ESS))
			continue;

		if ((ifsta->flags & (IEEE80211_STA_AUTO_SSID_SEL |
			IEEE80211_STA_AUTO_BSSID_SEL |
			IEEE80211_STA_AUTO_CHANNEL_SEL)) &&
		    (!!(bss->capability & WLAN_CAPABILITY_PRIVACY) ^
		     !!sdata->default_key))
			continue;

		if (!(ifsta->flags & IEEE80211_STA_AUTO_CHANNEL_SEL) &&
		    bss->freq != freq)
			continue;

		if (!(ifsta->flags & IEEE80211_STA_AUTO_BSSID_SEL) &&
		    memcmp(bss->bssid, ifsta->bssid, ETH_ALEN))
			continue;

		if (!(ifsta->flags & IEEE80211_STA_AUTO_SSID_SEL) &&
		    !ieee80211_sta_match_ssid(ifsta, bss->ssid, bss->ssid_len))
			continue;

		if (!selected || top_rssi < bss->rssi) {
			selected = bss;
			top_rssi = bss->rssi;
		}
	}
	if (selected)
		atomic_inc(&selected->users);
	spin_unlock_bh(&local->sta_bss_lock);

	if (selected) {
		ieee80211_set_freq(dev, selected->freq);
		if (!(ifsta->flags & IEEE80211_STA_SSID_SET))
			ieee80211_sta_set_ssid(dev, selected->ssid,
					       selected->ssid_len);
		ieee80211_sta_set_bssid(dev, selected->bssid);
		ieee80211_sta_def_wmm_params(dev, selected, 0);
		ieee80211_rx_bss_put(dev, selected);
		ifsta->state = IEEE80211_AUTHENTICATE;
		ieee80211_sta_reset_auth(dev, ifsta);
		return 0;
	} else {
		if (ifsta->state != IEEE80211_AUTHENTICATE) {
			if (ifsta->flags & IEEE80211_STA_AUTO_SSID_SEL)
				ieee80211_sta_start_scan(dev, NULL, 0);
			else
				ieee80211_sta_start_scan(dev, ifsta->ssid,
							 ifsta->ssid_len);
			ifsta->state = IEEE80211_AUTHENTICATE;
			set_bit(IEEE80211_STA_REQ_AUTH, &ifsta->request);
		} else
			ifsta->state = IEEE80211_DISABLED;
	}
	return -1;
}


static int ieee80211_sta_create_ibss(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_supported_band *sband;
	u8 bssid[ETH_ALEN], *pos;
	int i;
	int ret;
	DECLARE_MAC_BUF(mac);

#if 0
	/* Easier testing, use fixed BSSID. */
	memset(bssid, 0xfe, ETH_ALEN);
#else
	/* Generate random, not broadcast, locally administered BSSID. Mix in
	 * own MAC address to make sure that devices that do not have proper
	 * random number generator get different BSSID. */
	get_random_bytes(bssid, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++)
		bssid[i] ^= dev->dev_addr[i];
	bssid[0] &= ~0x01;
	bssid[0] |= 0x02;
#endif

	printk(KERN_DEBUG "%s: Creating new IBSS network, BSSID %s\n",
	       dev->name, print_mac(mac, bssid));

	bss = ieee80211_rx_bss_add(dev, bssid,
				   local->hw.conf.channel->center_freq,
				   sdata->u.sta.ssid, sdata->u.sta.ssid_len);
	if (!bss)
		return -ENOMEM;

	bss->band = local->hw.conf.channel->band;
	sband = local->hw.wiphy->bands[bss->band];

	if (local->hw.conf.beacon_int == 0)
		local->hw.conf.beacon_int = 10000;
	bss->beacon_int = local->hw.conf.beacon_int;
	bss->last_update = jiffies;
	bss->capability = WLAN_CAPABILITY_IBSS;
	if (sdata->default_key) {
		bss->capability |= WLAN_CAPABILITY_PRIVACY;
	} else
		sdata->drop_unencrypted = 0;
	bss->supp_rates_len = sband->n_bitrates;
	pos = bss->supp_rates;
	for (i = 0; i < sband->n_bitrates; i++) {
		int rate = sband->bitrates[i].bitrate;
		*pos++ = (u8) (rate / 5);
	}

	ret = ieee80211_sta_join_ibss(dev, ifsta, bss);
	ieee80211_rx_bss_put(dev, bss);
	return ret;
}


static int ieee80211_sta_find_ibss(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;
	int found = 0;
	u8 bssid[ETH_ALEN];
	int active_ibss;
	DECLARE_MAC_BUF(mac);
	DECLARE_MAC_BUF(mac2);

	if (ifsta->ssid_len == 0)
		return -EINVAL;

	active_ibss = ieee80211_sta_active_ibss(dev);
#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "%s: sta_find_ibss (active_ibss=%d)\n",
	       dev->name, active_ibss);
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
	spin_lock_bh(&local->sta_bss_lock);
	list_for_each_entry(bss, &local->sta_bss_list, list) {
		if (ifsta->ssid_len != bss->ssid_len ||
		    memcmp(ifsta->ssid, bss->ssid, bss->ssid_len) != 0
		    || !(bss->capability & WLAN_CAPABILITY_IBSS))
			continue;
#ifdef CONFIG_MAC80211_IBSS_DEBUG
		printk(KERN_DEBUG "   bssid=%s found\n",
		       print_mac(mac, bss->bssid));
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
		memcpy(bssid, bss->bssid, ETH_ALEN);
		found = 1;
		if (active_ibss || memcmp(bssid, ifsta->bssid, ETH_ALEN) != 0)
			break;
	}
	spin_unlock_bh(&local->sta_bss_lock);

#ifdef CONFIG_MAC80211_IBSS_DEBUG
	if (found)
		printk(KERN_DEBUG "   sta_find_ibss: selected %s current "
		       "%s\n", print_mac(mac, bssid),
		       print_mac(mac2, ifsta->bssid));
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
	if (found && memcmp(ifsta->bssid, bssid, ETH_ALEN) != 0 &&
	    (bss = ieee80211_rx_bss_get(dev, bssid,
					local->hw.conf.channel->center_freq,
					ifsta->ssid, ifsta->ssid_len))) {
		int ret;
		printk(KERN_DEBUG "%s: Selected IBSS BSSID %s"
		       " based on configured SSID\n",
		       dev->name, print_mac(mac, bssid));
		ret = ieee80211_sta_join_ibss(dev, ifsta, bss);
		ieee80211_rx_bss_put(dev, bss);
		return ret;
	}
#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "   did not try to join ibss\n");
#endif /* CONFIG_MAC80211_IBSS_DEBUG */

	/* Selected IBSS not found in current scan results - try to scan */
	if (ifsta->state == IEEE80211_IBSS_JOINED &&
	    !ieee80211_sta_active_ibss(dev)) {
		mod_timer(&ifsta->timer, jiffies +
				      IEEE80211_IBSS_MERGE_INTERVAL);
	} else if (time_after(jiffies, local->last_scan_completed +
			      IEEE80211_SCAN_INTERVAL)) {
		printk(KERN_DEBUG "%s: Trigger new scan to find an IBSS to "
		       "join\n", dev->name);
		return ieee80211_sta_req_scan(dev, ifsta->ssid,
					      ifsta->ssid_len);
	} else if (ifsta->state != IEEE80211_IBSS_JOINED) {
		int interval = IEEE80211_SCAN_INTERVAL;

		if (time_after(jiffies, ifsta->ibss_join_req +
			       IEEE80211_IBSS_JOIN_TIMEOUT)) {
			if ((ifsta->flags & IEEE80211_STA_CREATE_IBSS) &&
			    (!(local->oper_channel->flags &
					IEEE80211_CHAN_NO_IBSS)))
				return ieee80211_sta_create_ibss(dev, ifsta);
			if (ifsta->flags & IEEE80211_STA_CREATE_IBSS) {
				printk(KERN_DEBUG "%s: IBSS not allowed on"
				       " %d MHz\n", dev->name,
				       local->hw.conf.channel->center_freq);
			}

			/* No IBSS found - decrease scan interval and continue
			 * scanning. */
			interval = IEEE80211_SCAN_INTERVAL_SLOW;
		}

		ifsta->state = IEEE80211_IBSS_SEARCH;
		mod_timer(&ifsta->timer, jiffies + interval);
		return 0;
	}

	return 0;
}


int ieee80211_sta_set_ssid(struct net_device *dev, char *ssid, size_t len)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta;

	if (len > IEEE80211_MAX_SSID_LEN)
		return -EINVAL;

	ifsta = &sdata->u.sta;

	if (ifsta->ssid_len != len || memcmp(ifsta->ssid, ssid, len) != 0)
		ifsta->flags &= ~IEEE80211_STA_PREV_BSSID_SET;
	memcpy(ifsta->ssid, ssid, len);
	memset(ifsta->ssid + len, 0, IEEE80211_MAX_SSID_LEN - len);
	ifsta->ssid_len = len;

	if (len)
		ifsta->flags |= IEEE80211_STA_SSID_SET;
	else
		ifsta->flags &= ~IEEE80211_STA_SSID_SET;
	if (sdata->vif.type == IEEE80211_IF_TYPE_IBSS &&
	    !(ifsta->flags & IEEE80211_STA_BSSID_SET)) {
		ifsta->ibss_join_req = jiffies;
		ifsta->state = IEEE80211_IBSS_SEARCH;
		return ieee80211_sta_find_ibss(dev, ifsta);
	}
	return 0;
}


int ieee80211_sta_get_ssid(struct net_device *dev, char *ssid, size_t *len)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	memcpy(ssid, ifsta->ssid, ifsta->ssid_len);
	*len = ifsta->ssid_len;
	return 0;
}


int ieee80211_sta_set_bssid(struct net_device *dev, u8 *bssid)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	int res;

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;

	if (memcmp(ifsta->bssid, bssid, ETH_ALEN) != 0) {
		memcpy(ifsta->bssid, bssid, ETH_ALEN);
		res = ieee80211_if_config(dev);
		if (res) {
			printk(KERN_DEBUG "%s: Failed to config new BSSID to "
			       "the low-level driver\n", dev->name);
			return res;
		}
	}

	if (is_valid_ether_addr(bssid))
		ifsta->flags |= IEEE80211_STA_BSSID_SET;
	else
		ifsta->flags &= ~IEEE80211_STA_BSSID_SET;

	return 0;
}


static void ieee80211_send_nullfunc(struct ieee80211_local *local,
				    struct ieee80211_sub_if_data *sdata,
				    int powersave)
{
	struct sk_buff *skb;
	struct ieee80211_hdr *nullfunc;
	u16 fc;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + 24);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for nullfunc "
		       "frame\n", sdata->dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	nullfunc = (struct ieee80211_hdr *) skb_put(skb, 24);
	memset(nullfunc, 0, 24);
	fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC |
	     IEEE80211_FCTL_TODS;
	if (powersave)
		fc |= IEEE80211_FCTL_PM;
	nullfunc->frame_control = cpu_to_le16(fc);
	memcpy(nullfunc->addr1, sdata->u.sta.bssid, ETH_ALEN);
	memcpy(nullfunc->addr2, sdata->dev->dev_addr, ETH_ALEN);
	memcpy(nullfunc->addr3, sdata->u.sta.bssid, ETH_ALEN);

	ieee80211_sta_tx(sdata->dev, skb, 0);
}


static void ieee80211_restart_sta_timer(struct ieee80211_sub_if_data *sdata)
{
	if (sdata->vif.type == IEEE80211_IF_TYPE_STA ||
	    ieee80211_vif_is_mesh(&sdata->vif))
		ieee80211_sta_timer((unsigned long)sdata);
}

void ieee80211_scan_completed(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct net_device *dev = local->scan_dev;
	struct ieee80211_sub_if_data *sdata;
	union iwreq_data wrqu;

	local->last_scan_completed = jiffies;
	memset(&wrqu, 0, sizeof(wrqu));
	wireless_send_event(dev, SIOCGIWSCAN, &wrqu, NULL);

	if (local->sta_hw_scanning) {
		local->sta_hw_scanning = 0;
		if (ieee80211_hw_config(local))
			printk(KERN_DEBUG "%s: failed to restore operational "
			       "channel after scan\n", dev->name);
		/* Restart STA timer for HW scan case */
		rcu_read_lock();
		list_for_each_entry_rcu(sdata, &local->interfaces, list)
			ieee80211_restart_sta_timer(sdata);
		rcu_read_unlock();

		goto done;
	}

	local->sta_sw_scanning = 0;
	if (ieee80211_hw_config(local))
		printk(KERN_DEBUG "%s: failed to restore operational "
		       "channel after scan\n", dev->name);


	netif_tx_lock_bh(local->mdev);
	local->filter_flags &= ~FIF_BCN_PRBRESP_PROMISC;
	local->ops->configure_filter(local_to_hw(local),
				     FIF_BCN_PRBRESP_PROMISC,
				     &local->filter_flags,
				     local->mdev->mc_count,
				     local->mdev->mc_list);

	netif_tx_unlock_bh(local->mdev);

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &local->interfaces, list) {

		/* No need to wake the master device. */
		if (sdata->dev == local->mdev)
			continue;

		/* Tell AP we're back */
		if (sdata->vif.type == IEEE80211_IF_TYPE_STA &&
		    sdata->u.sta.flags & IEEE80211_STA_ASSOCIATED)
			ieee80211_send_nullfunc(local, sdata, 0);

		ieee80211_restart_sta_timer(sdata);

		netif_wake_queue(sdata->dev);
	}
	rcu_read_unlock();

done:
	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	if (sdata->vif.type == IEEE80211_IF_TYPE_IBSS) {
		struct ieee80211_if_sta *ifsta = &sdata->u.sta;
		if (!(ifsta->flags & IEEE80211_STA_BSSID_SET) ||
		    (!ifsta->state == IEEE80211_IBSS_JOINED &&
		    !ieee80211_sta_active_ibss(dev)))
			ieee80211_sta_find_ibss(dev, ifsta);
	}
}
EXPORT_SYMBOL(ieee80211_scan_completed);

void ieee80211_sta_scan_work(struct work_struct *work)
{
	struct ieee80211_local *local =
		container_of(work, struct ieee80211_local, scan_work.work);
	struct net_device *dev = local->scan_dev;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_supported_band *sband;
	struct ieee80211_channel *chan;
	int skip;
	unsigned long next_delay = 0;

	if (!local->sta_sw_scanning)
		return;

	switch (local->scan_state) {
	case SCAN_SET_CHANNEL:
		/*
		 * Get current scan band. scan_band may be IEEE80211_NUM_BANDS
		 * after we successfully scanned the last channel of the last
		 * band (and the last band is supported by the hw)
		 */
		if (local->scan_band < IEEE80211_NUM_BANDS)
			sband = local->hw.wiphy->bands[local->scan_band];
		else
			sband = NULL;

		/*
		 * If we are at an unsupported band and have more bands
		 * left to scan, advance to the next supported one.
		 */
		while (!sband && local->scan_band < IEEE80211_NUM_BANDS - 1) {
			local->scan_band++;
			sband = local->hw.wiphy->bands[local->scan_band];
			local->scan_channel_idx = 0;
		}

		/* if no more bands/channels left, complete scan */
		if (!sband || local->scan_channel_idx >= sband->n_channels) {
			ieee80211_scan_completed(local_to_hw(local));
			return;
		}
		skip = 0;
		chan = &sband->channels[local->scan_channel_idx];

		if (chan->flags & IEEE80211_CHAN_DISABLED ||
		    (sdata->vif.type == IEEE80211_IF_TYPE_IBSS &&
		     chan->flags & IEEE80211_CHAN_NO_IBSS))
			skip = 1;

		if (!skip) {
			local->scan_channel = chan;
			if (ieee80211_hw_config(local)) {
				printk(KERN_DEBUG "%s: failed to set freq to "
				       "%d MHz for scan\n", dev->name,
				       chan->center_freq);
				skip = 1;
			}
		}

		/* advance state machine to next channel/band */
		local->scan_channel_idx++;
		if (local->scan_channel_idx >= sband->n_channels) {
			/*
			 * scan_band may end up == IEEE80211_NUM_BANDS, but
			 * we'll catch that case above and complete the scan
			 * if that is the case.
			 */
			local->scan_band++;
			local->scan_channel_idx = 0;
		}

		if (skip)
			break;

		next_delay = IEEE80211_PROBE_DELAY +
			     usecs_to_jiffies(local->hw.channel_change_time);
		local->scan_state = SCAN_SEND_PROBE;
		break;
	case SCAN_SEND_PROBE:
		next_delay = IEEE80211_PASSIVE_CHANNEL_TIME;
		local->scan_state = SCAN_SET_CHANNEL;

		if (local->scan_channel->flags & IEEE80211_CHAN_PASSIVE_SCAN)
			break;
		ieee80211_send_probe_req(dev, NULL, local->scan_ssid,
					 local->scan_ssid_len);
		next_delay = IEEE80211_CHANNEL_TIME;
		break;
	}

	if (local->sta_sw_scanning)
		queue_delayed_work(local->hw.workqueue, &local->scan_work,
				   next_delay);
}


static int ieee80211_sta_start_scan(struct net_device *dev,
				    u8 *ssid, size_t ssid_len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata;

	if (ssid_len > IEEE80211_MAX_SSID_LEN)
		return -EINVAL;

	/* MLME-SCAN.request (page 118)  page 144 (11.1.3.1)
	 * BSSType: INFRASTRUCTURE, INDEPENDENT, ANY_BSS
	 * BSSID: MACAddress
	 * SSID
	 * ScanType: ACTIVE, PASSIVE
	 * ProbeDelay: delay (in microseconds) to be used prior to transmitting
	 *    a Probe frame during active scanning
	 * ChannelList
	 * MinChannelTime (>= ProbeDelay), in TU
	 * MaxChannelTime: (>= MinChannelTime), in TU
	 */

	 /* MLME-SCAN.confirm
	  * BSSDescriptionSet
	  * ResultCode: SUCCESS, INVALID_PARAMETERS
	 */

	if (local->sta_sw_scanning || local->sta_hw_scanning) {
		if (local->scan_dev == dev)
			return 0;
		return -EBUSY;
	}

	if (local->ops->hw_scan) {
		int rc = local->ops->hw_scan(local_to_hw(local),
					     ssid, ssid_len);
		if (!rc) {
			local->sta_hw_scanning = 1;
			local->scan_dev = dev;
		}
		return rc;
	}

	local->sta_sw_scanning = 1;

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &local->interfaces, list) {

		/* Don't stop the master interface, otherwise we can't transmit
		 * probes! */
		if (sdata->dev == local->mdev)
			continue;

		netif_stop_queue(sdata->dev);
		if (sdata->vif.type == IEEE80211_IF_TYPE_STA &&
		    (sdata->u.sta.flags & IEEE80211_STA_ASSOCIATED))
			ieee80211_send_nullfunc(local, sdata, 1);
	}
	rcu_read_unlock();

	if (ssid) {
		local->scan_ssid_len = ssid_len;
		memcpy(local->scan_ssid, ssid, ssid_len);
	} else
		local->scan_ssid_len = 0;
	local->scan_state = SCAN_SET_CHANNEL;
	local->scan_channel_idx = 0;
	local->scan_band = IEEE80211_BAND_2GHZ;
	local->scan_dev = dev;

	netif_tx_lock_bh(local->mdev);
	local->filter_flags |= FIF_BCN_PRBRESP_PROMISC;
	local->ops->configure_filter(local_to_hw(local),
				     FIF_BCN_PRBRESP_PROMISC,
				     &local->filter_flags,
				     local->mdev->mc_count,
				     local->mdev->mc_list);
	netif_tx_unlock_bh(local->mdev);

	/* TODO: start scan as soon as all nullfunc frames are ACKed */
	queue_delayed_work(local->hw.workqueue, &local->scan_work,
			   IEEE80211_CHANNEL_TIME);

	return 0;
}


int ieee80211_sta_req_scan(struct net_device *dev, u8 *ssid, size_t ssid_len)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	if (sdata->vif.type != IEEE80211_IF_TYPE_STA)
		return ieee80211_sta_start_scan(dev, ssid, ssid_len);

	if (local->sta_sw_scanning || local->sta_hw_scanning) {
		if (local->scan_dev == dev)
			return 0;
		return -EBUSY;
	}

	ifsta->scan_ssid_len = ssid_len;
	if (ssid_len)
		memcpy(ifsta->scan_ssid, ssid, ssid_len);
	set_bit(IEEE80211_STA_REQ_SCAN, &ifsta->request);
	queue_work(local->hw.workqueue, &ifsta->work);
	return 0;
}

static char *
ieee80211_sta_scan_result(struct net_device *dev,
			  struct ieee80211_sta_bss *bss,
			  char *current_ev, char *end_buf)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct iw_event iwe;

	if (time_after(jiffies,
		       bss->last_update + IEEE80211_SCAN_RESULT_EXPIRE))
		return current_ev;

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWAP;
	iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
	memcpy(iwe.u.ap_addr.sa_data, bss->bssid, ETH_ALEN);
	current_ev = iwe_stream_add_event(current_ev, end_buf, &iwe,
					  IW_EV_ADDR_LEN);

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWESSID;
	if (bss_mesh_cfg(bss)) {
		iwe.u.data.length = bss_mesh_id_len(bss);
		iwe.u.data.flags = 1;
		current_ev = iwe_stream_add_point(current_ev, end_buf, &iwe,
						  bss_mesh_id(bss));
	} else {
		iwe.u.data.length = bss->ssid_len;
		iwe.u.data.flags = 1;
		current_ev = iwe_stream_add_point(current_ev, end_buf, &iwe,
						  bss->ssid);
	}

	if (bss->capability & (WLAN_CAPABILITY_ESS | WLAN_CAPABILITY_IBSS)
	    || bss_mesh_cfg(bss)) {
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWMODE;
		if (bss_mesh_cfg(bss))
			iwe.u.mode = IW_MODE_MESH;
		else if (bss->capability & WLAN_CAPABILITY_ESS)
			iwe.u.mode = IW_MODE_MASTER;
		else
			iwe.u.mode = IW_MODE_ADHOC;
		current_ev = iwe_stream_add_event(current_ev, end_buf, &iwe,
						  IW_EV_UINT_LEN);
	}

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWFREQ;
	iwe.u.freq.m = ieee80211_frequency_to_channel(bss->freq);
	iwe.u.freq.e = 0;
	current_ev = iwe_stream_add_event(current_ev, end_buf, &iwe,
					  IW_EV_FREQ_LEN);

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWFREQ;
	iwe.u.freq.m = bss->freq;
	iwe.u.freq.e = 6;
	current_ev = iwe_stream_add_event(current_ev, end_buf, &iwe,
					  IW_EV_FREQ_LEN);
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVQUAL;
	iwe.u.qual.qual = bss->signal;
	iwe.u.qual.level = bss->rssi;
	iwe.u.qual.noise = bss->noise;
	iwe.u.qual.updated = local->wstats_flags;
	current_ev = iwe_stream_add_event(current_ev, end_buf, &iwe,
					  IW_EV_QUAL_LEN);

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWENCODE;
	if (bss->capability & WLAN_CAPABILITY_PRIVACY)
		iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
	else
		iwe.u.data.flags = IW_ENCODE_DISABLED;
	iwe.u.data.length = 0;
	current_ev = iwe_stream_add_point(current_ev, end_buf, &iwe, "");

	if (bss && bss->wpa_ie) {
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = IWEVGENIE;
		iwe.u.data.length = bss->wpa_ie_len;
		current_ev = iwe_stream_add_point(current_ev, end_buf, &iwe,
						  bss->wpa_ie);
	}

	if (bss && bss->rsn_ie) {
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = IWEVGENIE;
		iwe.u.data.length = bss->rsn_ie_len;
		current_ev = iwe_stream_add_point(current_ev, end_buf, &iwe,
						  bss->rsn_ie);
	}

	if (bss && bss->supp_rates_len > 0) {
		/* display all supported rates in readable format */
		char *p = current_ev + IW_EV_LCP_LEN;
		int i;

		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWRATE;
		/* Those two flags are ignored... */
		iwe.u.bitrate.fixed = iwe.u.bitrate.disabled = 0;

		for (i = 0; i < bss->supp_rates_len; i++) {
			iwe.u.bitrate.value = ((bss->supp_rates[i] &
							0x7f) * 500000);
			p = iwe_stream_add_value(current_ev, p,
					end_buf, &iwe, IW_EV_PARAM_LEN);
		}
		current_ev = p;
	}

	if (bss) {
		char *buf;
		buf = kmalloc(30, GFP_ATOMIC);
		if (buf) {
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = IWEVCUSTOM;
			sprintf(buf, "tsf=%016llx", (unsigned long long)(bss->timestamp));
			iwe.u.data.length = strlen(buf);
			current_ev = iwe_stream_add_point(current_ev, end_buf,
							  &iwe, buf);
			kfree(buf);
		}
	}

	if (bss_mesh_cfg(bss)) {
		char *buf;
		u8 *cfg = bss_mesh_cfg(bss);
		buf = kmalloc(50, GFP_ATOMIC);
		if (buf) {
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = IWEVCUSTOM;
			sprintf(buf, "Mesh network (version %d)", cfg[0]);
			iwe.u.data.length = strlen(buf);
			current_ev = iwe_stream_add_point(current_ev, end_buf,
							  &iwe, buf);
			sprintf(buf, "Path Selection Protocol ID: "
				"0x%02X%02X%02X%02X", cfg[1], cfg[2], cfg[3],
							cfg[4]);
			iwe.u.data.length = strlen(buf);
			current_ev = iwe_stream_add_point(current_ev, end_buf,
							  &iwe, buf);
			sprintf(buf, "Path Selection Metric ID: "
				"0x%02X%02X%02X%02X", cfg[5], cfg[6], cfg[7],
							cfg[8]);
			iwe.u.data.length = strlen(buf);
			current_ev = iwe_stream_add_point(current_ev, end_buf,
							  &iwe, buf);
			sprintf(buf, "Congestion Control Mode ID: "
				"0x%02X%02X%02X%02X", cfg[9], cfg[10],
							cfg[11], cfg[12]);
			iwe.u.data.length = strlen(buf);
			current_ev = iwe_stream_add_point(current_ev, end_buf,
							  &iwe, buf);
			sprintf(buf, "Channel Precedence: "
				"0x%02X%02X%02X%02X", cfg[13], cfg[14],
							cfg[15], cfg[16]);
			iwe.u.data.length = strlen(buf);
			current_ev = iwe_stream_add_point(current_ev, end_buf,
							  &iwe, buf);
			kfree(buf);
		}
	}

	return current_ev;
}


int ieee80211_sta_scan_results(struct net_device *dev, char *buf, size_t len)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	char *current_ev = buf;
	char *end_buf = buf + len;
	struct ieee80211_sta_bss *bss;

	spin_lock_bh(&local->sta_bss_lock);
	list_for_each_entry(bss, &local->sta_bss_list, list) {
		if (buf + len - current_ev <= IW_EV_ADDR_LEN) {
			spin_unlock_bh(&local->sta_bss_lock);
			return -E2BIG;
		}
		current_ev = ieee80211_sta_scan_result(dev, bss, current_ev,
						       end_buf);
	}
	spin_unlock_bh(&local->sta_bss_lock);
	return current_ev - buf;
}


int ieee80211_sta_set_extra_ie(struct net_device *dev, char *ie, size_t len)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	kfree(ifsta->extra_ie);
	if (len == 0) {
		ifsta->extra_ie = NULL;
		ifsta->extra_ie_len = 0;
		return 0;
	}
	ifsta->extra_ie = kmalloc(len, GFP_KERNEL);
	if (!ifsta->extra_ie) {
		ifsta->extra_ie_len = 0;
		return -ENOMEM;
	}
	memcpy(ifsta->extra_ie, ie, len);
	ifsta->extra_ie_len = len;
	return 0;
}


struct sta_info * ieee80211_ibss_add_sta(struct net_device *dev,
					 struct sk_buff *skb, u8 *bssid,
					 u8 *addr)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	DECLARE_MAC_BUF(mac);

	/* TODO: Could consider removing the least recently used entry and
	 * allow new one to be added. */
	if (local->num_sta >= IEEE80211_IBSS_MAX_STA_ENTRIES) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: No room for a new IBSS STA "
			       "entry %s\n", dev->name, print_mac(mac, addr));
		}
		return NULL;
	}

	printk(KERN_DEBUG "%s: Adding new IBSS station %s (dev=%s)\n",
	       wiphy_name(local->hw.wiphy), print_mac(mac, addr), dev->name);

	sta = sta_info_alloc(sdata, addr, GFP_ATOMIC);
	if (!sta)
		return NULL;

	sta->flags |= WLAN_STA_AUTHORIZED;

	sta->supp_rates[local->hw.conf.channel->band] =
		sdata->u.sta.supp_rates_bits[local->hw.conf.channel->band];

	rate_control_rate_init(sta, local);

	if (sta_info_insert(sta))
		return NULL;

	return sta;
}


int ieee80211_sta_deauthenticate(struct net_device *dev, u16 reason)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;

	printk(KERN_DEBUG "%s: deauthenticate(reason=%d)\n",
	       dev->name, reason);

	if (sdata->vif.type != IEEE80211_IF_TYPE_STA &&
	    sdata->vif.type != IEEE80211_IF_TYPE_IBSS)
		return -EINVAL;

	ieee80211_send_deauth(dev, ifsta, reason);
	ieee80211_set_disassoc(dev, ifsta, 1);
	return 0;
}


int ieee80211_sta_disassociate(struct net_device *dev, u16 reason)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;

	printk(KERN_DEBUG "%s: disassociate(reason=%d)\n",
	       dev->name, reason);

	if (sdata->vif.type != IEEE80211_IF_TYPE_STA)
		return -EINVAL;

	if (!(ifsta->flags & IEEE80211_STA_ASSOCIATED))
		return -1;

	ieee80211_send_disassoc(dev, ifsta, reason);
	ieee80211_set_disassoc(dev, ifsta, 0);
	return 0;
}

void ieee80211_notify_mac(struct ieee80211_hw *hw,
			  enum ieee80211_notification_types  notif_type)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_sub_if_data *sdata;

	switch (notif_type) {
	case IEEE80211_NOTIFY_RE_ASSOC:
		rcu_read_lock();
		list_for_each_entry_rcu(sdata, &local->interfaces, list) {

			if (sdata->vif.type == IEEE80211_IF_TYPE_STA) {
				ieee80211_sta_req_auth(sdata->dev,
						       &sdata->u.sta);
			}

		}
		rcu_read_unlock();
		break;
	}
}
EXPORT_SYMBOL(ieee80211_notify_mac);
