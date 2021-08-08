/*

  Broadcom B43 wireless driver

  Copyright (c) 2005 Martin Langer <martin-langer@gmx.de>,
  Copyright (c) 2005-2007 Stefano Brivio <stefano.brivio@polimi.it>
  Copyright (c) 2005, 2006 Michael Buesch <mb@bu3sch.de>
  Copyright (c) 2005, 2006 Danny van Dyk <kugelfang@gentoo.org>
  Copyright (c) 2005, 2006 Andreas Jaggi <andreas.jaggi@waterwave.ch>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Steet, Fifth Floor,
  Boston, MA 02110-1301, USA.

*/

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/types.h>

#include "b43.h"
#include "phy.h"
#include "nphy.h"
#include "main.h"
#include "tables.h"
#include "lo.h"
#include "wa.h"


static const s8 b43_tssi2dbm_b_table[] = {
	0x4D, 0x4C, 0x4B, 0x4A,
	0x4A, 0x49, 0x48, 0x47,
	0x47, 0x46, 0x45, 0x45,
	0x44, 0x43, 0x42, 0x42,
	0x41, 0x40, 0x3F, 0x3E,
	0x3D, 0x3C, 0x3B, 0x3A,
	0x39, 0x38, 0x37, 0x36,
	0x35, 0x34, 0x32, 0x31,
	0x30, 0x2F, 0x2D, 0x2C,
	0x2B, 0x29, 0x28, 0x26,
	0x25, 0x23, 0x21, 0x1F,
	0x1D, 0x1A, 0x17, 0x14,
	0x10, 0x0C, 0x06, 0x00,
	-7, -7, -7, -7,
	-7, -7, -7, -7,
	-7, -7, -7, -7,
};

static const s8 b43_tssi2dbm_g_table[] = {
	77, 77, 77, 76,
	76, 76, 75, 75,
	74, 74, 73, 73,
	73, 72, 72, 71,
	71, 70, 70, 69,
	68, 68, 67, 67,
	66, 65, 65, 64,
	63, 63, 62, 61,
	60, 59, 58, 57,
	56, 55, 54, 53,
	52, 50, 49, 47,
	45, 43, 40, 37,
	33, 28, 22, 14,
	5, -7, -20, -20,
	-20, -20, -20, -20,
	-20, -20, -20, -20,
};

const u8 b43_radio_channel_codes_bg[] = {
	12, 17, 22, 27,
	32, 37, 42, 47,
	52, 57, 62, 67,
	72, 84,
};

static void b43_phy_initg(struct b43_wldev *dev);

/* Reverse the bits of a 4bit value.
 * Example:  1101 is flipped 1011
 */
static u16 flip_4bit(u16 value)
{
	u16 flipped = 0x0000;

	B43_WARN_ON(value & ~0x000F);

	flipped |= (value & 0x0001) << 3;
	flipped |= (value & 0x0002) << 1;
	flipped |= (value & 0x0004) >> 1;
	flipped |= (value & 0x0008) >> 3;

	return flipped;
}

static void generate_rfatt_list(struct b43_wldev *dev,
				struct b43_rfatt_list *list)
{
	struct b43_phy *phy = &dev->phy;

	/* APHY.rev < 5 || GPHY.rev < 6 */
	static const struct b43_rfatt rfatt_0[] = {
		{.att = 3,.with_padmix = 0,},
		{.att = 1,.with_padmix = 0,},
		{.att = 5,.with_padmix = 0,},
		{.att = 7,.with_padmix = 0,},
		{.att = 9,.with_padmix = 0,},
		{.att = 2,.with_padmix = 0,},
		{.att = 0,.with_padmix = 0,},
		{.att = 4,.with_padmix = 0,},
		{.att = 6,.with_padmix = 0,},
		{.att = 8,.with_padmix = 0,},
		{.att = 1,.with_padmix = 1,},
		{.att = 2,.with_padmix = 1,},
		{.att = 3,.with_padmix = 1,},
		{.att = 4,.with_padmix = 1,},
	};
	/* Radio.rev == 8 && Radio.version == 0x2050 */
	static const struct b43_rfatt rfatt_1[] = {
		{.att = 2,.with_padmix = 1,},
		{.att = 4,.with_padmix = 1,},
		{.att = 6,.with_padmix = 1,},
		{.att = 8,.with_padmix = 1,},
		{.att = 10,.with_padmix = 1,},
		{.att = 12,.with_padmix = 1,},
		{.att = 14,.with_padmix = 1,},
	};
	/* Otherwise */
	static const struct b43_rfatt rfatt_2[] = {
		{.att = 0,.with_padmix = 1,},
		{.att = 2,.with_padmix = 1,},
		{.att = 4,.with_padmix = 1,},
		{.att = 6,.with_padmix = 1,},
		{.att = 8,.with_padmix = 1,},
		{.att = 9,.with_padmix = 1,},
		{.att = 9,.with_padmix = 1,},
	};

	if ((phy->type == B43_PHYTYPE_A && phy->rev < 5) ||
	    (phy->type == B43_PHYTYPE_G && phy->rev < 6)) {
		/* Software pctl */
		list->list = rfatt_0;
		list->len = ARRAY_SIZE(rfatt_0);
		list->min_val = 0;
		list->max_val = 9;
		return;
	}
	if (phy->radio_ver == 0x2050 && phy->radio_rev == 8) {
		/* Hardware pctl */
		list->list = rfatt_1;
		list->len = ARRAY_SIZE(rfatt_1);
		list->min_val = 2;
		list->max_val = 14;
		return;
	}
	/* Hardware pctl */
	list->list = rfatt_2;
	list->len = ARRAY_SIZE(rfatt_2);
	list->min_val = 0;
	list->max_val = 9;
}

static void generate_bbatt_list(struct b43_wldev *dev,
				struct b43_bbatt_list *list)
{
	static const struct b43_bbatt bbatt_0[] = {
		{.att = 0,},
		{.att = 1,},
		{.att = 2,},
		{.att = 3,},
		{.att = 4,},
		{.att = 5,},
		{.att = 6,},
		{.att = 7,},
		{.att = 8,},
	};

	list->list = bbatt_0;
	list->len = ARRAY_SIZE(bbatt_0);
	list->min_val = 0;
	list->max_val = 8;
}

bool b43_has_hardware_pctl(struct b43_phy *phy)
{
	if (!phy->hardware_power_control)
		return 0;
	switch (phy->type) {
	case B43_PHYTYPE_A:
		if (phy->rev >= 5)
			return 1;
		break;
	case B43_PHYTYPE_G:
		if (phy->rev >= 6)
			return 1;
		break;
	default:
		B43_WARN_ON(1);
	}
	return 0;
}

static void b43_shm_clear_tssi(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;

	switch (phy->type) {
	case B43_PHYTYPE_A:
		b43_shm_write16(dev, B43_SHM_SHARED, 0x0068, 0x7F7F);
		b43_shm_write16(dev, B43_SHM_SHARED, 0x006a, 0x7F7F);
		break;
	case B43_PHYTYPE_B:
	case B43_PHYTYPE_G:
		b43_shm_write16(dev, B43_SHM_SHARED, 0x0058, 0x7F7F);
		b43_shm_write16(dev, B43_SHM_SHARED, 0x005a, 0x7F7F);
		b43_shm_write16(dev, B43_SHM_SHARED, 0x0070, 0x7F7F);
		b43_shm_write16(dev, B43_SHM_SHARED, 0x0072, 0x7F7F);
		break;
	}
}

/* Lock the PHY registers against concurrent access from the microcode.
 * This lock is nonrecursive. */
void b43_phy_lock(struct b43_wldev *dev)
{
#if B43_DEBUG
	B43_WARN_ON(dev->phy.phy_locked);
	dev->phy.phy_locked = 1;
#endif
	B43_WARN_ON(dev->dev->id.revision < 3);

	if (!b43_is_mode(dev->wl, IEEE80211_IF_TYPE_AP))
		b43_power_saving_ctl_bits(dev, B43_PS_AWAKE);
}

void b43_phy_unlock(struct b43_wldev *dev)
{
#if B43_DEBUG
	B43_WARN_ON(!dev->phy.phy_locked);
	dev->phy.phy_locked = 0;
#endif
	B43_WARN_ON(dev->dev->id.revision < 3);

	if (!b43_is_mode(dev->wl, IEEE80211_IF_TYPE_AP))
		b43_power_saving_ctl_bits(dev, 0);
}

/* Different PHYs require different register routing flags.
 * This adjusts (and does sanity checks on) the routing flags.
 */
static inline u16 adjust_phyreg_for_phytype(struct b43_phy *phy,
					    u16 offset, struct b43_wldev *dev)
{
	if (phy->type == B43_PHYTYPE_A) {
		/* OFDM registers are base-registers for the A-PHY. */
		if ((offset & B43_PHYROUTE) == B43_PHYROUTE_OFDM_GPHY) {
			offset &= ~B43_PHYROUTE;
			offset |= B43_PHYROUTE_BASE;
		}
	}

#if B43_DEBUG
	if ((offset & B43_PHYROUTE) == B43_PHYROUTE_EXT_GPHY) {
		/* Ext-G registers are only available on G-PHYs */
		if (phy->type != B43_PHYTYPE_G) {
			b43err(dev->wl, "Invalid EXT-G PHY access at "
			       "0x%04X on PHY type %u\n", offset, phy->type);
			dump_stack();
		}
	}
	if ((offset & B43_PHYROUTE) == B43_PHYROUTE_N_BMODE) {
		/* N-BMODE registers are only available on N-PHYs */
		if (phy->type != B43_PHYTYPE_N) {
			b43err(dev->wl, "Invalid N-BMODE PHY access at "
			       "0x%04X on PHY type %u\n", offset, phy->type);
			dump_stack();
		}
	}
#endif /* B43_DEBUG */

	return offset;
}

u16 b43_phy_read(struct b43_wldev * dev, u16 offset)
{
	struct b43_phy *phy = &dev->phy;

	offset = adjust_phyreg_for_phytype(phy, offset, dev);
	b43_write16(dev, B43_MMIO_PHY_CONTROL, offset);
	return b43_read16(dev, B43_MMIO_PHY_DATA);
}

void b43_phy_write(struct b43_wldev *dev, u16 offset, u16 val)
{
	struct b43_phy *phy = &dev->phy;

	offset = adjust_phyreg_for_phytype(phy, offset, dev);
	b43_write16(dev, B43_MMIO_PHY_CONTROL, offset);
	b43_write16(dev, B43_MMIO_PHY_DATA, val);
}

void b43_phy_mask(struct b43_wldev *dev, u16 offset, u16 mask)
{
	b43_phy_write(dev, offset,
		      b43_phy_read(dev, offset) & mask);
}

void b43_phy_set(struct b43_wldev *dev, u16 offset, u16 set)
{
	b43_phy_write(dev, offset,
		      b43_phy_read(dev, offset) | set);
}

void b43_phy_maskset(struct b43_wldev *dev, u16 offset, u16 mask, u16 set)
{
	b43_phy_write(dev, offset,
		      (b43_phy_read(dev, offset) & mask) | set);
}

/* Adjust the transmission power output (G-PHY) */
void b43_set_txpower_g(struct b43_wldev *dev,
		       const struct b43_bbatt *bbatt,
		       const struct b43_rfatt *rfatt, u8 tx_control)
{
	struct b43_phy *phy = &dev->phy;
	struct b43_txpower_lo_control *lo = phy->lo_control;
	u16 bb, rf;
	u16 tx_bias, tx_magn;

	bb = bbatt->att;
	rf = rfatt->att;
	tx_bias = lo->tx_bias;
	tx_magn = lo->tx_magn;
	if (unlikely(tx_bias == 0xFF))
		tx_bias = 0;

	/* Save the values for later */
	phy->tx_control = tx_control;
	memcpy(&phy->rfatt, rfatt, sizeof(*rfatt));
	memcpy(&phy->bbatt, bbatt, sizeof(*bbatt));

	if (b43_debug(dev, B43_DBG_XMITPOWER)) {
		b43dbg(dev->wl, "Tuning TX-power to bbatt(%u), "
		       "rfatt(%u), tx_control(0x%02X), "
		       "tx_bias(0x%02X), tx_magn(0x%02X)\n",
		       bb, rf, tx_control, tx_bias, tx_magn);
	}

	b43_phy_set_baseband_attenuation(dev, bb);
	b43_shm_write16(dev, B43_SHM_SHARED, B43_SHM_SH_RFATT, rf);
	if (phy->radio_ver == 0x2050 && phy->radio_rev == 8) {
		b43_radio_write16(dev, 0x43,
				  (rf & 0x000F) | (tx_control & 0x0070));
	} else {
		b43_radio_write16(dev, 0x43, (b43_radio_read16(dev, 0x43)
					      & 0xFFF0) | (rf & 0x000F));
		b43_radio_write16(dev, 0x52, (b43_radio_read16(dev, 0x52)
					      & ~0x0070) | (tx_control &
							    0x0070));
	}
	if (has_tx_magnification(phy)) {
		b43_radio_write16(dev, 0x52, tx_magn | tx_bias);
	} else {
		b43_radio_write16(dev, 0x52, (b43_radio_read16(dev, 0x52)
					      & 0xFFF0) | (tx_bias & 0x000F));
	}
	if (phy->type == B43_PHYTYPE_G)
		b43_lo_g_adjust(dev);
}

static void default_baseband_attenuation(struct b43_wldev *dev,
					 struct b43_bbatt *bb)
{
	struct b43_phy *phy = &dev->phy;

	if (phy->radio_ver == 0x2050 && phy->radio_rev < 6)
		bb->att = 0;
	else
		bb->att = 2;
}

static void default_radio_attenuation(struct b43_wldev *dev,
				      struct b43_rfatt *rf)
{
	struct ssb_bus *bus = dev->dev->bus;
	struct b43_phy *phy = &dev->phy;

	rf->with_padmix = 0;

	if (bus->boardinfo.vendor == SSB_BOARDVENDOR_BCM &&
	    bus->boardinfo.type == SSB_BOARD_BCM4309G) {
		if (bus->boardinfo.rev < 0x43) {
			rf->att = 2;
			return;
		} else if (bus->boardinfo.rev < 0x51) {
			rf->att = 3;
			return;
		}
	}

	if (phy->type == B43_PHYTYPE_A) {
		rf->att = 0x60;
		return;
	}

	switch (phy->radio_ver) {
	case 0x2053:
		switch (phy->radio_rev) {
		case 1:
			rf->att = 6;
			return;
		}
		break;
	case 0x2050:
		switch (phy->radio_rev) {
		case 0:
			rf->att = 5;
			return;
		case 1:
			if (phy->type == B43_PHYTYPE_G) {
				if (bus->boardinfo.vendor == SSB_BOARDVENDOR_BCM
				    && bus->boardinfo.type == SSB_BOARD_BCM4309G
				    && bus->boardinfo.rev >= 30)
					rf->att = 3;
				else if (bus->boardinfo.vendor ==
					 SSB_BOARDVENDOR_BCM
					 && bus->boardinfo.type ==
					 SSB_BOARD_BU4306)
					rf->att = 3;
				else
					rf->att = 1;
			} else {
				if (bus->boardinfo.vendor == SSB_BOARDVENDOR_BCM
				    && bus->boardinfo.type == SSB_BOARD_BCM4309G
				    && bus->boardinfo.rev >= 30)
					rf->att = 7;
				else
					rf->att = 6;
			}
			return;
		case 2:
			if (phy->type == B43_PHYTYPE_G) {
				if (bus->boardinfo.vendor == SSB_BOARDVENDOR_BCM
				    && bus->boardinfo.type == SSB_BOARD_BCM4309G
				    && bus->boardinfo.rev >= 30)
					rf->att = 3;
				else if (bus->boardinfo.vendor ==
					 SSB_BOARDVENDOR_BCM
					 && bus->boardinfo.type ==
					 SSB_BOARD_BU4306)
					rf->att = 5;
				else if (bus->chip_id == 0x4320)
					rf->att = 4;
				else
					rf->att = 3;
			} else
				rf->att = 6;
			return;
		case 3:
			rf->att = 5;
			return;
		case 4:
		case 5:
			rf->att = 1;
			return;
		case 6:
		case 7:
			rf->att = 5;
			return;
		case 8:
			rf->att = 0xA;
			rf->with_padmix = 1;
			return;
		case 9:
		default:
			rf->att = 5;
			return;
		}
	}
	rf->att = 5;
}

static u16 default_tx_control(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;

	if (phy->radio_ver != 0x2050)
		return 0;
	if (phy->radio_rev == 1)
		return B43_TXCTL_PA2DB | B43_TXCTL_TXMIX;
	if (phy->radio_rev < 6)
		return B43_TXCTL_PA2DB;
	if (phy->radio_rev == 8)
		return B43_TXCTL_TXMIX;
	return 0;
}

/* This func is called "PHY calibrate" in the specs... */
void b43_phy_early_init(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	struct b43_txpower_lo_control *lo = phy->lo_control;

	default_baseband_attenuation(dev, &phy->bbatt);
	default_radio_attenuation(dev, &phy->rfatt);
	phy->tx_control = (default_tx_control(dev) << 4);

	/* Commit previous writes */
	b43_read32(dev, B43_MMIO_MACCTL);

	if (phy->type == B43_PHYTYPE_B || phy->type == B43_PHYTYPE_G) {
		generate_rfatt_list(dev, &lo->rfatt_list);
		generate_bbatt_list(dev, &lo->bbatt_list);
	}
	if (phy->type == B43_PHYTYPE_G && phy->rev == 1) {
		/* Workaround: Temporarly disable gmode through the early init
		 * phase, as the gmode stuff is not needed for phy rev 1 */
		phy->gmode = 0;
		b43_wireless_core_reset(dev, 0);
		b43_phy_initg(dev);
		phy->gmode = 1;
		b43_wireless_core_reset(dev, B43_TMSLOW_GMODE);
	}
}

/* GPHY_TSSI_Power_Lookup_Table_Init */
static void b43_gphy_tssi_power_lt_init(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	int i;
	u16 value;

	for (i = 0; i < 32; i++)
		b43_ofdmtab_write16(dev, 0x3C20, i, phy->tssi2dbm[i]);
	for (i = 32; i < 64; i++)
		b43_ofdmtab_write16(dev, 0x3C00, i - 32, phy->tssi2dbm[i]);
	for (i = 0; i < 64; i += 2) {
		value = (u16) phy->tssi2dbm[i];
		value |= ((u16) phy->tssi2dbm[i + 1]) << 8;
		b43_phy_write(dev, 0x380 + (i / 2), value);
	}
}

/* GPHY_Gain_Lookup_Table_Init */
static void b43_gphy_gain_lt_init(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	struct b43_txpower_lo_control *lo = phy->lo_control;
	u16 nr_written = 0;
	u16 tmp;
	u8 rf, bb;

	if (!lo->lo_measured) {
		b43_phy_write(dev, 0x3FF, 0);
		return;
	}

	for (rf = 0; rf < lo->rfatt_list.len; rf++) {
		for (bb = 0; bb < lo->bbatt_list.len; bb++) {
			if (nr_written >= 0x40)
				return;
			tmp = lo->bbatt_list.list[bb].att;
			tmp <<= 8;
			if (phy->radio_rev == 8)
				tmp |= 0x50;
			else
				tmp |= 0x40;
			tmp |= lo->rfatt_list.list[rf].att;
			b43_phy_write(dev, 0x3C0 + nr_written, tmp);
			nr_written++;
		}
	}
}

/* GPHY_DC_Lookup_Table */
void b43_gphy_dc_lt_init(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	struct b43_txpower_lo_control *lo = phy->lo_control;
	struct b43_loctl *loctl0;
	struct b43_loctl *loctl1;
	int i;
	int rf_offset, bb_offset;
	u16 tmp;

	for (i = 0; i < lo->rfatt_list.len + lo->bbatt_list.len; i += 2) {
		rf_offset = i / lo->rfatt_list.len;
		bb_offset = i % lo->rfatt_list.len;

		loctl0 = b43_get_lo_g_ctl(dev, &lo->rfatt_list.list[rf_offset],
					  &lo->bbatt_list.list[bb_offset]);
		if (i + 1 < lo->rfatt_list.len * lo->bbatt_list.len) {
			rf_offset = (i + 1) / lo->rfatt_list.len;
			bb_offset = (i + 1) % lo->rfatt_list.len;

			loctl1 =
			    b43_get_lo_g_ctl(dev,
					     &lo->rfatt_list.list[rf_offset],
					     &lo->bbatt_list.list[bb_offset]);
		} else
			loctl1 = loctl0;

		tmp = ((u16) loctl0->q & 0xF);
		tmp |= ((u16) loctl0->i & 0xF) << 4;
		tmp |= ((u16) loctl1->q & 0xF) << 8;
		tmp |= ((u16) loctl1->i & 0xF) << 12;	//FIXME?
		b43_phy_write(dev, 0x3A0 + (i / 2), tmp);
	}
}

static void hardware_pctl_init_aphy(struct b43_wldev *dev)
{
	//TODO
}

static void hardware_pctl_init_gphy(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;

	b43_phy_write(dev, 0x0036, (b43_phy_read(dev, 0x0036) & 0xFFC0)
		      | (phy->tgt_idle_tssi - phy->cur_idle_tssi));
	b43_phy_write(dev, 0x0478, (b43_phy_read(dev, 0x0478) & 0xFF00)
		      | (phy->tgt_idle_tssi - phy->cur_idle_tssi));
	b43_gphy_tssi_power_lt_init(dev);
	b43_gphy_gain_lt_init(dev);
	b43_phy_write(dev, 0x0060, b43_phy_read(dev, 0x0060) & 0xFFBF);
	b43_phy_write(dev, 0x0014, 0x0000);

	B43_WARN_ON(phy->rev < 6);
	b43_phy_write(dev, 0x0478, b43_phy_read(dev, 0x0478)
		      | 0x0800);
	b43_phy_write(dev, 0x0478, b43_phy_read(dev, 0x0478)
		      & 0xFEFF);
	b43_phy_write(dev, 0x0801, b43_phy_read(dev, 0x0801)
		      & 0xFFBF);

	b43_gphy_dc_lt_init(dev);
}

/* HardwarePowerControl init for A and G PHY */
static void b43_hardware_pctl_init(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;

	if (!b43_has_hardware_pctl(phy)) {
		/* No hardware power control */
		b43_hf_write(dev, b43_hf_read(dev) & ~B43_HF_HWPCTL);
		return;
	}
	/* Init the hwpctl related hardware */
	switch (phy->type) {
	case B43_PHYTYPE_A:
		hardware_pctl_init_aphy(dev);
		break;
	case B43_PHYTYPE_G:
		hardware_pctl_init_gphy(dev);
		break;
	default:
		B43_WARN_ON(1);
	}
	/* Enable hardware pctl in firmware. */
	b43_hf_write(dev, b43_hf_read(dev) | B43_HF_HWPCTL);
}

static void b43_hardware_pctl_early_init(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;

	if (!b43_has_hardware_pctl(phy)) {
		b43_phy_write(dev, 0x047A, 0xC111);
		return;
	}

	b43_phy_write(dev, 0x0036, b43_phy_read(dev, 0x0036) & 0xFEFF);
	b43_phy_write(dev, 0x002F, 0x0202);
	b43_phy_write(dev, 0x047C, b43_phy_read(dev, 0x047C) | 0x0002);
	b43_phy_write(dev, 0x047A, b43_phy_read(dev, 0x047A) | 0xF000);
	if (phy->radio_ver == 0x2050 && phy->radio_rev == 8) {
		b43_phy_write(dev, 0x047A, (b43_phy_read(dev, 0x047A)
					    & 0xFF0F) | 0x0010);
		b43_phy_write(dev, 0x005D, b43_phy_read(dev, 0x005D)
			      | 0x8000);
		b43_phy_write(dev, 0x004E, (b43_phy_read(dev, 0x004E)
					    & 0xFFC0) | 0x0010);
		b43_phy_write(dev, 0x002E, 0xC07F);
		b43_phy_write(dev, 0x0036, b43_phy_read(dev, 0x0036)
			      | 0x0400);
	} else {
		b43_phy_write(dev, 0x0036, b43_phy_read(dev, 0x0036)
			      | 0x0200);
		b43_phy_write(dev, 0x0036, b43_phy_read(dev, 0x0036)
			      | 0x0400);
		b43_phy_write(dev, 0x005D, b43_phy_read(dev, 0x005D)
			      & 0x7FFF);
		b43_phy_write(dev, 0x004F, b43_phy_read(dev, 0x004F)
			      & 0xFFFE);
		b43_phy_write(dev, 0x004E, (b43_phy_read(dev, 0x004E)
					    & 0xFFC0) | 0x0010);
		b43_phy_write(dev, 0x002E, 0xC07F);
		b43_phy_write(dev, 0x047A, (b43_phy_read(dev, 0x047A)
					    & 0xFF0F) | 0x0010);
	}
}

/* Intialize B/G PHY power control
 * as described in http://bcm-specs.sipsolutions.net/InitPowerControl
 */
static void b43_phy_init_pctl(struct b43_wldev *dev)
{
	struct ssb_bus *bus = dev->dev->bus;
	struct b43_phy *phy = &dev->phy;
	struct b43_rfatt old_rfatt;
	struct b43_bbatt old_bbatt;
	u8 old_tx_control = 0;

	if ((bus->boardinfo.vendor == SSB_BOARDVENDOR_BCM) &&
	    (bus->boardinfo.type == SSB_BOARD_BU4306))
		return;

	b43_phy_write(dev, 0x0028, 0x8018);

	/* This does something with the Analog... */
	b43_write16(dev, B43_MMIO_PHY0, b43_read16(dev, B43_MMIO_PHY0)
		    & 0xFFDF);

	if (phy->type == B43_PHYTYPE_G && !phy->gmode)
		return;
	b43_hardware_pctl_early_init(dev);
	if (phy->cur_idle_tssi == 0) {
		if (phy->radio_ver == 0x2050 && phy->analog == 0) {
			b43_radio_write16(dev, 0x0076,
					  (b43_radio_read16(dev, 0x0076)
					   & 0x00F7) | 0x0084);
		} else {
			struct b43_rfatt rfatt;
			struct b43_bbatt bbatt;

			memcpy(&old_rfatt, &phy->rfatt, sizeof(old_rfatt));
			memcpy(&old_bbatt, &phy->bbatt, sizeof(old_bbatt));
			old_tx_control = phy->tx_control;

			bbatt.att = 11;
			if (phy->radio_rev == 8) {
				rfatt.att = 15;
				rfatt.with_padmix = 1;
			} else {
				rfatt.att = 9;
				rfatt.with_padmix = 0;
			}
			b43_set_txpower_g(dev, &bbatt, &rfatt, 0);
		}
		b43_dummy_transmission(dev);
		phy->cur_idle_tssi = b43_phy_read(dev, B43_PHY_ITSSI);
		if (B43_DEBUG) {
			/* Current-Idle-TSSI sanity check. */
			if (abs(phy->cur_idle_tssi - phy->tgt_idle_tssi) >= 20) {
				b43dbg(dev->wl,
				       "!WARNING! Idle-TSSI phy->cur_idle_tssi "
				       "measuring failed. (cur=%d, tgt=%d). Disabling TX power "
				       "adjustment.\n", phy->cur_idle_tssi,
				       phy->tgt_idle_tssi);
				phy->cur_idle_tssi = 0;
			}
		}
		if (phy->radio_ver == 0x2050 && phy->analog == 0) {
			b43_radio_write16(dev, 0x0076,
					  b43_radio_read16(dev, 0x0076)
					  & 0xFF7B);
		} else {
			b43_set_txpower_g(dev, &old_bbatt,
					  &old_rfatt, old_tx_control);
		}
	}
	b43_hardware_pctl_init(dev);
	b43_shm_clear_tssi(dev);
}

static void b43_phy_rssiagc(struct b43_wldev *dev, u8 enable)
{
	int i;

	if (dev->phy.rev < 3) {
		if (enable)
			for (i = 0; i < B43_TAB_RSSIAGC1_SIZE; i++) {
				b43_ofdmtab_write16(dev,
					B43_OFDMTAB_LNAHPFGAIN1, i, 0xFFF8);
				b43_ofdmtab_write16(dev,
					B43_OFDMTAB_WRSSI, i, 0xFFF8);
			}
		else
			for (i = 0; i < B43_TAB_RSSIAGC1_SIZE; i++) {
				b43_ofdmtab_write16(dev,
					B43_OFDMTAB_LNAHPFGAIN1, i, b43_tab_rssiagc1[i]);
				b43_ofdmtab_write16(dev,
					B43_OFDMTAB_WRSSI, i, b43_tab_rssiagc1[i]);
			}
	} else {
		if (enable)
			for (i = 0; i < B43_TAB_RSSIAGC1_SIZE; i++)
				b43_ofdmtab_write16(dev,
					B43_OFDMTAB_WRSSI, i, 0x0820);
		else
			for (i = 0; i < B43_TAB_RSSIAGC2_SIZE; i++)
				b43_ofdmtab_write16(dev,
					B43_OFDMTAB_WRSSI, i, b43_tab_rssiagc2[i]);
	}
}

static void b43_phy_ww(struct b43_wldev *dev)
{
	u16 b, curr_s, best_s = 0xFFFF;
	int i;

	b43_phy_write(dev, B43_PHY_CRS0,
		b43_phy_read(dev, B43_PHY_CRS0) & ~B43_PHY_CRS0_EN);
	b43_phy_write(dev, B43_PHY_OFDM(0x1B),
		b43_phy_read(dev, B43_PHY_OFDM(0x1B)) | 0x1000);
	b43_phy_write(dev, B43_PHY_OFDM(0x82),
		(b43_phy_read(dev, B43_PHY_OFDM(0x82)) & 0xF0FF) | 0x0300);
	b43_radio_write16(dev, 0x0009,
		b43_radio_read16(dev, 0x0009) | 0x0080);
	b43_radio_write16(dev, 0x0012,
		(b43_radio_read16(dev, 0x0012) & 0xFFFC) | 0x0002);
	b43_wa_initgains(dev);
	b43_phy_write(dev, B43_PHY_OFDM(0xBA), 0x3ED5);
	b = b43_phy_read(dev, B43_PHY_PWRDOWN);
	b43_phy_write(dev, B43_PHY_PWRDOWN, (b & 0xFFF8) | 0x0005);
	b43_radio_write16(dev, 0x0004,
		b43_radio_read16(dev, 0x0004) | 0x0004);
	for (i = 0x10; i <= 0x20; i++) {
		b43_radio_write16(dev, 0x0013, i);
		curr_s = b43_phy_read(dev, B43_PHY_OTABLEQ) & 0x00FF;
		if (!curr_s) {
			best_s = 0x0000;
			break;
		} else if (curr_s >= 0x0080)
			curr_s = 0x0100 - curr_s;
		if (curr_s < best_s)
			best_s = curr_s;
	}
	b43_phy_write(dev, B43_PHY_PWRDOWN, b);
	b43_radio_write16(dev, 0x0004,
		b43_radio_read16(dev, 0x0004) & 0xFFFB);
	b43_radio_write16(dev, 0x0013, best_s);
	b43_ofdmtab_write16(dev, B43_OFDMTAB_AGC1_R1, 0, 0xFFEC);
	b43_phy_write(dev, B43_PHY_OFDM(0xB7), 0x1E80);
	b43_phy_write(dev, B43_PHY_OFDM(0xB6), 0x1C00);
	b43_phy_write(dev, B43_PHY_OFDM(0xB5), 0x0EC0);
	b43_phy_write(dev, B43_PHY_OFDM(0xB2), 0x00C0);
	b43_phy_write(dev, B43_PHY_OFDM(0xB9), 0x1FFF);
	b43_phy_write(dev, B43_PHY_OFDM(0xBB),
		(b43_phy_read(dev, B43_PHY_OFDM(0xBB)) & 0xF000) | 0x0053);
	b43_phy_write(dev, B43_PHY_OFDM61,
		(b43_phy_read(dev, B43_PHY_OFDM61) & 0xFE1F) | 0x0120);
	b43_phy_write(dev, B43_PHY_OFDM(0x13),
		(b43_phy_read(dev, B43_PHY_OFDM(0x13)) & 0x0FFF) | 0x3000);
	b43_phy_write(dev, B43_PHY_OFDM(0x14),
		(b43_phy_read(dev, B43_PHY_OFDM(0x14)) & 0x0FFF) | 0x3000);
	b43_ofdmtab_write16(dev, B43_OFDMTAB_AGC1, 6, 0x0017);
	for (i = 0; i < 6; i++)
		b43_ofdmtab_write16(dev, B43_OFDMTAB_AGC1, i, 0x000F);
	b43_ofdmtab_write16(dev, B43_OFDMTAB_AGC1, 0x0D, 0x000E);
	b43_ofdmtab_write16(dev, B43_OFDMTAB_AGC1, 0x0E, 0x0011);
	b43_ofdmtab_write16(dev, B43_OFDMTAB_AGC1, 0x0F, 0x0013);
	b43_phy_write(dev, B43_PHY_OFDM(0x33), 0x5030);
	b43_phy_write(dev, B43_PHY_CRS0,
		b43_phy_read(dev, B43_PHY_CRS0) | B43_PHY_CRS0_EN);
}

/* Initialize APHY. This is also called for the GPHY in some cases. */
static void b43_phy_inita(struct b43_wldev *dev)
{
	struct ssb_bus *bus = dev->dev->bus;
	struct b43_phy *phy = &dev->phy;

	might_sleep();

	if (phy->rev >= 6) {
		if (phy->type == B43_PHYTYPE_A)
			b43_phy_write(dev, B43_PHY_OFDM(0x1B),
				b43_phy_read(dev, B43_PHY_OFDM(0x1B)) & ~0x1000);
		if (b43_phy_read(dev, B43_PHY_ENCORE) & B43_PHY_ENCORE_EN)
			b43_phy_write(dev, B43_PHY_ENCORE,
				b43_phy_read(dev, B43_PHY_ENCORE) | 0x0010);
		else
			b43_phy_write(dev, B43_PHY_ENCORE,
				b43_phy_read(dev, B43_PHY_ENCORE) & ~0x1010);
	}

	b43_wa_all(dev);

	if (phy->type == B43_PHYTYPE_A) {
		if (phy->gmode && (phy->rev < 3))
			b43_phy_write(dev, 0x0034,
				b43_phy_read(dev, 0x0034) | 0x0001);
		b43_phy_rssiagc(dev, 0);

		b43_phy_write(dev, B43_PHY_CRS0,
			b43_phy_read(dev, B43_PHY_CRS0) | B43_PHY_CRS0_EN);

		b43_radio_init2060(dev);

		if ((bus->boardinfo.vendor == SSB_BOARDVENDOR_BCM) &&
		    ((bus->boardinfo.type == SSB_BOARD_BU4306) ||
		     (bus->boardinfo.type == SSB_BOARD_BU4309))) {
			; //TODO: A PHY LO
		}

		if (phy->rev >= 3)
			b43_phy_ww(dev);

		hardware_pctl_init_aphy(dev);

		//TODO: radar detection
	}

	if ((phy->type == B43_PHYTYPE_G) &&
	    (dev->dev->bus->sprom.boardflags_lo & B43_BFL_PACTRL)) {
		b43_phy_write(dev, B43_PHY_OFDM(0x6E),
				  (b43_phy_read(dev, B43_PHY_OFDM(0x6E))
				   & 0xE000) | 0x3CF);
	}
}

static void b43_phy_initb2(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 offset, val;

	b43_write16(dev, 0x03EC, 0x3F22);
	b43_phy_write(dev, 0x0020, 0x301C);
	b43_phy_write(dev, 0x0026, 0x0000);
	b43_phy_write(dev, 0x0030, 0x00C6);
	b43_phy_write(dev, 0x0088, 0x3E00);
	val = 0x3C3D;
	for (offset = 0x0089; offset < 0x00A7; offset++) {
		b43_phy_write(dev, offset, val);
		val -= 0x0202;
	}
	b43_phy_write(dev, 0x03E4, 0x3000);
	b43_radio_selectchannel(dev, phy->channel, 0);
	if (phy->radio_ver != 0x2050) {
		b43_radio_write16(dev, 0x0075, 0x0080);
		b43_radio_write16(dev, 0x0079, 0x0081);
	}
	b43_radio_write16(dev, 0x0050, 0x0020);
	b43_radio_write16(dev, 0x0050, 0x0023);
	if (phy->radio_ver == 0x2050) {
		b43_radio_write16(dev, 0x0050, 0x0020);
		b43_radio_write16(dev, 0x005A, 0x0070);
		b43_radio_write16(dev, 0x005B, 0x007B);
		b43_radio_write16(dev, 0x005C, 0x00B0);
		b43_radio_write16(dev, 0x007A, 0x000F);
		b43_phy_write(dev, 0x0038, 0x0677);
		b43_radio_init2050(dev);
	}
	b43_phy_write(dev, 0x0014, 0x0080);
	b43_phy_write(dev, 0x0032, 0x00CA);
	b43_phy_write(dev, 0x0032, 0x00CC);
	b43_phy_write(dev, 0x0035, 0x07C2);
	b43_lo_b_measure(dev);
	b43_phy_write(dev, 0x0026, 0xCC00);
	if (phy->radio_ver != 0x2050)
		b43_phy_write(dev, 0x0026, 0xCE00);
	b43_write16(dev, B43_MMIO_CHANNEL_EXT, 0x1000);
	b43_phy_write(dev, 0x002A, 0x88A3);
	if (phy->radio_ver != 0x2050)
		b43_phy_write(dev, 0x002A, 0x88C2);
	b43_set_txpower_g(dev, &phy->bbatt, &phy->rfatt, phy->tx_control);
	b43_phy_init_pctl(dev);
}

static void b43_phy_initb4(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 offset, val;

	b43_write16(dev, 0x03EC, 0x3F22);
	b43_phy_write(dev, 0x0020, 0x301C);
	b43_phy_write(dev, 0x0026, 0x0000);
	b43_phy_write(dev, 0x0030, 0x00C6);
	b43_phy_write(dev, 0x0088, 0x3E00);
	val = 0x3C3D;
	for (offset = 0x0089; offset < 0x00A7; offset++) {
		b43_phy_write(dev, offset, val);
		val -= 0x0202;
	}
	b43_phy_write(dev, 0x03E4, 0x3000);
	b43_radio_selectchannel(dev, phy->channel, 0);
	if (phy->radio_ver != 0x2050) {
		b43_radio_write16(dev, 0x0075, 0x0080);
		b43_radio_write16(dev, 0x0079, 0x0081);
	}
	b43_radio_write16(dev, 0x0050, 0x0020);
	b43_radio_write16(dev, 0x0050, 0x0023);
	if (phy->radio_ver == 0x2050) {
		b43_radio_write16(dev, 0x0050, 0x0020);
		b43_radio_write16(dev, 0x005A, 0x0070);
		b43_radio_write16(dev, 0x005B, 0x007B);
		b43_radio_write16(dev, 0x005C, 0x00B0);
		b43_radio_write16(dev, 0x007A, 0x000F);
		b43_phy_write(dev, 0x0038, 0x0677);
		b43_radio_init2050(dev);
	}
	b43_phy_write(dev, 0x0014, 0x0080);
	b43_phy_write(dev, 0x0032, 0x00CA);
	if (phy->radio_ver == 0x2050)
		b43_phy_write(dev, 0x0032, 0x00E0);
	b43_phy_write(dev, 0x0035, 0x07C2);

	b43_lo_b_measure(dev);

	b43_phy_write(dev, 0x0026, 0xCC00);
	if (phy->radio_ver == 0x2050)
		b43_phy_write(dev, 0x0026, 0xCE00);
	b43_write16(dev, B43_MMIO_CHANNEL_EXT, 0x1100);
	b43_phy_write(dev, 0x002A, 0x88A3);
	if (phy->radio_ver == 0x2050)
		b43_phy_write(dev, 0x002A, 0x88C2);
	b43_set_txpower_g(dev, &phy->bbatt, &phy->rfatt, phy->tx_control);
	if (dev->dev->bus->sprom.boardflags_lo & B43_BFL_RSSI) {
		b43_calc_nrssi_slope(dev);
		b43_calc_nrssi_threshold(dev);
	}
	b43_phy_init_pctl(dev);
}

static void b43_phy_initb5(struct b43_wldev *dev)
{
	struct ssb_bus *bus = dev->dev->bus;
	struct b43_phy *phy = &dev->phy;
	u16 offset, value;
	u8 old_channel;

	if (phy->analog == 1) {
		b43_radio_write16(dev, 0x007A, b43_radio_read16(dev, 0x007A)
				  | 0x0050);
	}
	if ((bus->boardinfo.vendor != SSB_BOARDVENDOR_BCM) &&
	    (bus->boardinfo.type != SSB_BOARD_BU4306)) {
		value = 0x2120;
		for (offset = 0x00A8; offset < 0x00C7; offset++) {
			b43_phy_write(dev, offset, value);
			value += 0x202;
		}
	}
	b43_phy_write(dev, 0x0035, (b43_phy_read(dev, 0x0035) & 0xF0FF)
		      | 0x0700);
	if (phy->radio_ver == 0x2050)
		b43_phy_write(dev, 0x0038, 0x0667);

	if (phy->gmode || phy->rev >= 2) {
		if (phy->radio_ver == 0x2050) {
			b43_radio_write16(dev, 0x007A,
					  b43_radio_read16(dev, 0x007A)
					  | 0x0020);
			b43_radio_write16(dev, 0x0051,
					  b43_radio_read16(dev, 0x0051)
					  | 0x0004);
		}
		b43_write16(dev, B43_MMIO_PHY_RADIO, 0x0000);

		b43_phy_write(dev, 0x0802, b43_phy_read(dev, 0x0802) | 0x0100);
		b43_phy_write(dev, 0x042B, b43_phy_read(dev, 0x042B) | 0x2000);

		b43_phy_write(dev, 0x001C, 0x186A);

		b43_phy_write(dev, 0x0013,
			      (b43_phy_read(dev, 0x0013) & 0x00FF) | 0x1900);
		b43_phy_write(dev, 0x0035,
			      (b43_phy_read(dev, 0x0035) & 0xFFC0) | 0x0064);
		b43_phy_write(dev, 0x005D,
			      (b43_phy_read(dev, 0x005D) & 0xFF80) | 0x000A);
	}

	if (dev->bad_frames_preempt) {
		b43_phy_write(dev, B43_PHY_RADIO_BITFIELD,
			      b43_phy_read(dev,
					   B43_PHY_RADIO_BITFIELD) | (1 << 11));
	}

	if (phy->analog == 1) {
		b43_phy_write(dev, 0x0026, 0xCE00);
		b43_phy_write(dev, 0x0021, 0x3763);
		b43_phy_write(dev, 0x0022, 0x1BC3);
		b43_phy_write(dev, 0x0023, 0x06F9);
		b43_phy_write(dev, 0x0024, 0x037E);
	} else
		b43_phy_write(dev, 0x0026, 0xCC00);
	b43_phy_write(dev, 0x0030, 0x00C6);
	b43_write16(dev, 0x03EC, 0x3F22);

	if (phy->analog == 1)
		b43_phy_write(dev, 0x0020, 0x3E1C);
	else
		b43_phy_write(dev, 0x0020, 0x301C);

	if (phy->analog == 0)
		b43_write16(dev, 0x03E4, 0x3000);

	old_channel = phy->channel;
	/* Force to channel 7, even if not supported. */
	b43_radio_selectchannel(dev, 7, 0);

	if (phy->radio_ver != 0x2050) {
		b43_radio_write16(dev, 0x0075, 0x0080);
		b43_radio_write16(dev, 0x0079, 0x0081);
	}

	b43_radio_write16(dev, 0x0050, 0x0020);
	b43_radio_write16(dev, 0x0050, 0x0023);

	if (phy->radio_ver == 0x2050) {
		b43_radio_write16(dev, 0x0050, 0x0020);
		b43_radio_write16(dev, 0x005A, 0x0070);
	}

	b43_radio_write16(dev, 0x005B, 0x007B);
	b43_radio_write16(dev, 0x005C, 0x00B0);

	b43_radio_write16(dev, 0x007A, b43_radio_read16(dev, 0x007A) | 0x0007);

	b43_radio_selectchannel(dev, old_channel, 0);

	b43_phy_write(dev, 0x0014, 0x0080);
	b43_phy_write(dev, 0x0032, 0x00CA);
	b43_phy_write(dev, 0x002A, 0x88A3);

	b43_set_txpower_g(dev, &phy->bbatt, &phy->rfatt, phy->tx_control);

	if (phy->radio_ver == 0x2050)
		b43_radio_write16(dev, 0x005D, 0x000D);

	b43_write16(dev, 0x03E4, (b43_read16(dev, 0x03E4) & 0xFFC0) | 0x0004);
}

static void b43_phy_initb6(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 offset, val;
	u8 old_channel;

	b43_phy_write(dev, 0x003E, 0x817A);
	b43_radio_write16(dev, 0x007A,
			  (b43_radio_read16(dev, 0x007A) | 0x0058));
	if (phy->radio_rev == 4 || phy->radio_rev == 5) {
		b43_radio_write16(dev, 0x51, 0x37);
		b43_radio_write16(dev, 0x52, 0x70);
		b43_radio_write16(dev, 0x53, 0xB3);
		b43_radio_write16(dev, 0x54, 0x9B);
		b43_radio_write16(dev, 0x5A, 0x88);
		b43_radio_write16(dev, 0x5B, 0x88);
		b43_radio_write16(dev, 0x5D, 0x88);
		b43_radio_write16(dev, 0x5E, 0x88);
		b43_radio_write16(dev, 0x7D, 0x88);
		b43_hf_write(dev, b43_hf_read(dev)
			     | B43_HF_TSSIRPSMW);
	}
	B43_WARN_ON(phy->radio_rev == 6 || phy->radio_rev == 7);	/* We had code for these revs here... */
	if (phy->radio_rev == 8) {
		b43_radio_write16(dev, 0x51, 0);
		b43_radio_write16(dev, 0x52, 0x40);
		b43_radio_write16(dev, 0x53, 0xB7);
		b43_radio_write16(dev, 0x54, 0x98);
		b43_radio_write16(dev, 0x5A, 0x88);
		b43_radio_write16(dev, 0x5B, 0x6B);
		b43_radio_write16(dev, 0x5C, 0x0F);
		if (dev->dev->bus->sprom.boardflags_lo & B43_BFL_ALTIQ) {
			b43_radio_write16(dev, 0x5D, 0xFA);
			b43_radio_write16(dev, 0x5E, 0xD8);
		} else {
			b43_radio_write16(dev, 0x5D, 0xF5);
			b43_radio_write16(dev, 0x5E, 0xB8);
		}
		b43_radio_write16(dev, 0x0073, 0x0003);
		b43_radio_write16(dev, 0x007D, 0x00A8);
		b43_radio_write16(dev, 0x007C, 0x0001);
		b43_radio_write16(dev, 0x007E, 0x0008);
	}
	val = 0x1E1F;
	for (offset = 0x0088; offset < 0x0098; offset++) {
		b43_phy_write(dev, offset, val);
		val -= 0x0202;
	}
	val = 0x3E3F;
	for (offset = 0x0098; offset < 0x00A8; offset++) {
		b43_phy_write(dev, offset, val);
		val -= 0x0202;
	}
	val = 0x2120;
	for (offset = 0x00A8; offset < 0x00C8; offset++) {
		b43_phy_write(dev, offset, (val & 0x3F3F));
		val += 0x0202;
	}
	if (phy->type == B43_PHYTYPE_G) {
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) | 0x0020);
		b43_radio_write16(dev, 0x0051,
				  b43_radio_read16(dev, 0x0051) | 0x0004);
		b43_phy_write(dev, 0x0802, b43_phy_read(dev, 0x0802) | 0x0100);
		b43_phy_write(dev, 0x042B, b43_phy_read(dev, 0x042B) | 0x2000);
		b43_phy_write(dev, 0x5B, 0);
		b43_phy_write(dev, 0x5C, 0);
	}

	old_channel = phy->channel;
	if (old_channel >= 8)
		b43_radio_selectchannel(dev, 1, 0);
	else
		b43_radio_selectchannel(dev, 13, 0);

	b43_radio_write16(dev, 0x0050, 0x0020);
	b43_radio_write16(dev, 0x0050, 0x0023);
	udelay(40);
	if (phy->radio_rev < 6 || phy->radio_rev == 8) {
		b43_radio_write16(dev, 0x7C, (b43_radio_read16(dev, 0x7C)
					      | 0x0002));
		b43_radio_write16(dev, 0x50, 0x20);
	}
	if (phy->radio_rev <= 2) {
		b43_radio_write16(dev, 0x7C, 0x20);
		b43_radio_write16(dev, 0x5A, 0x70);
		b43_radio_write16(dev, 0x5B, 0x7B);
		b43_radio_write16(dev, 0x5C, 0xB0);
	}
	b43_radio_write16(dev, 0x007A,
			  (b43_radio_read16(dev, 0x007A) & 0x00F8) | 0x0007);

	b43_radio_selectchannel(dev, old_channel, 0);

	b43_phy_write(dev, 0x0014, 0x0200);
	if (phy->radio_rev >= 6)
		b43_phy_write(dev, 0x2A, 0x88C2);
	else
		b43_phy_write(dev, 0x2A, 0x8AC0);
	b43_phy_write(dev, 0x0038, 0x0668);
	b43_set_txpower_g(dev, &phy->bbatt, &phy->rfatt, phy->tx_control);
	if (phy->radio_rev <= 5) {
		b43_phy_write(dev, 0x5D, (b43_phy_read(dev, 0x5D)
					  & 0xFF80) | 0x0003);
	}
	if (phy->radio_rev <= 2)
		b43_radio_write16(dev, 0x005D, 0x000D);

	if (phy->analog == 4) {
		b43_write16(dev, 0x3E4, 9);
		b43_phy_write(dev, 0x61, b43_phy_read(dev, 0x61)
			      & 0x0FFF);
	} else {
		b43_phy_write(dev, 0x0002, (b43_phy_read(dev, 0x0002) & 0xFFC0)
			      | 0x0004);
	}
	if (phy->type == B43_PHYTYPE_B) {
		b43_write16(dev, 0x03E6, 0x8140);
		b43_phy_write(dev, 0x0016, 0x0410);
		b43_phy_write(dev, 0x0017, 0x0820);
		b43_phy_write(dev, 0x0062, 0x0007);
		b43_radio_init2050(dev);
		b43_lo_g_measure(dev);
		if (dev->dev->bus->sprom.boardflags_lo & B43_BFL_RSSI) {
			b43_calc_nrssi_slope(dev);
			b43_calc_nrssi_threshold(dev);
		}
		b43_phy_init_pctl(dev);
	} else if (phy->type == B43_PHYTYPE_G)
		b43_write16(dev, 0x03E6, 0x0);
}

static void b43_calc_loopback_gain(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 backup_phy[16] = { 0 };
	u16 backup_radio[3];
	u16 backup_bband;
	u16 i, j, loop_i_max;
	u16 trsw_rx;
	u16 loop1_outer_done, loop1_inner_done;

	backup_phy[0] = b43_phy_read(dev, B43_PHY_CRS0);
	backup_phy[1] = b43_phy_read(dev, B43_PHY_CCKBBANDCFG);
	backup_phy[2] = b43_phy_read(dev, B43_PHY_RFOVER);
	backup_phy[3] = b43_phy_read(dev, B43_PHY_RFOVERVAL);
	if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
		backup_phy[4] = b43_phy_read(dev, B43_PHY_ANALOGOVER);
		backup_phy[5] = b43_phy_read(dev, B43_PHY_ANALOGOVERVAL);
	}
	backup_phy[6] = b43_phy_read(dev, B43_PHY_CCK(0x5A));
	backup_phy[7] = b43_phy_read(dev, B43_PHY_CCK(0x59));
	backup_phy[8] = b43_phy_read(dev, B43_PHY_CCK(0x58));
	backup_phy[9] = b43_phy_read(dev, B43_PHY_CCK(0x0A));
	backup_phy[10] = b43_phy_read(dev, B43_PHY_CCK(0x03));
	backup_phy[11] = b43_phy_read(dev, B43_PHY_LO_MASK);
	backup_phy[12] = b43_phy_read(dev, B43_PHY_LO_CTL);
	backup_phy[13] = b43_phy_read(dev, B43_PHY_CCK(0x2B));
	backup_phy[14] = b43_phy_read(dev, B43_PHY_PGACTL);
	backup_phy[15] = b43_phy_read(dev, B43_PHY_LO_LEAKAGE);
	backup_bband = phy->bbatt.att;
	backup_radio[0] = b43_radio_read16(dev, 0x52);
	backup_radio[1] = b43_radio_read16(dev, 0x43);
	backup_radio[2] = b43_radio_read16(dev, 0x7A);

	b43_phy_write(dev, B43_PHY_CRS0,
		      b43_phy_read(dev, B43_PHY_CRS0) & 0x3FFF);
	b43_phy_write(dev, B43_PHY_CCKBBANDCFG,
		      b43_phy_read(dev, B43_PHY_CCKBBANDCFG) | 0x8000);
	b43_phy_write(dev, B43_PHY_RFOVER,
		      b43_phy_read(dev, B43_PHY_RFOVER) | 0x0002);
	b43_phy_write(dev, B43_PHY_RFOVERVAL,
		      b43_phy_read(dev, B43_PHY_RFOVERVAL) & 0xFFFD);
	b43_phy_write(dev, B43_PHY_RFOVER,
		      b43_phy_read(dev, B43_PHY_RFOVER) | 0x0001);
	b43_phy_write(dev, B43_PHY_RFOVERVAL,
		      b43_phy_read(dev, B43_PHY_RFOVERVAL) & 0xFFFE);
	if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
		b43_phy_write(dev, B43_PHY_ANALOGOVER,
			      b43_phy_read(dev, B43_PHY_ANALOGOVER) | 0x0001);
		b43_phy_write(dev, B43_PHY_ANALOGOVERVAL,
			      b43_phy_read(dev,
					   B43_PHY_ANALOGOVERVAL) & 0xFFFE);
		b43_phy_write(dev, B43_PHY_ANALOGOVER,
			      b43_phy_read(dev, B43_PHY_ANALOGOVER) | 0x0002);
		b43_phy_write(dev, B43_PHY_ANALOGOVERVAL,
			      b43_phy_read(dev,
					   B43_PHY_ANALOGOVERVAL) & 0xFFFD);
	}
	b43_phy_write(dev, B43_PHY_RFOVER,
		      b43_phy_read(dev, B43_PHY_RFOVER) | 0x000C);
	b43_phy_write(dev, B43_PHY_RFOVERVAL,
		      b43_phy_read(dev, B43_PHY_RFOVERVAL) | 0x000C);
	b43_phy_write(dev, B43_PHY_RFOVER,
		      b43_phy_read(dev, B43_PHY_RFOVER) | 0x0030);
	b43_phy_write(dev, B43_PHY_RFOVERVAL,
		      (b43_phy_read(dev, B43_PHY_RFOVERVAL)
		       & 0xFFCF) | 0x10);

	b43_phy_write(dev, B43_PHY_CCK(0x5A), 0x0780);
	b43_phy_write(dev, B43_PHY_CCK(0x59), 0xC810);
	b43_phy_write(dev, B43_PHY_CCK(0x58), 0x000D);

	b43_phy_write(dev, B43_PHY_CCK(0x0A),
		      b43_phy_read(dev, B43_PHY_CCK(0x0A)) | 0x2000);
	if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
		b43_phy_write(dev, B43_PHY_ANALOGOVER,
			      b43_phy_read(dev, B43_PHY_ANALOGOVER) | 0x0004);
		b43_phy_write(dev, B43_PHY_ANALOGOVERVAL,
			      b43_phy_read(dev,
					   B43_PHY_ANALOGOVERVAL) & 0xFFFB);
	}
	b43_phy_write(dev, B43_PHY_CCK(0x03),
		      (b43_phy_read(dev, B43_PHY_CCK(0x03))
		       & 0xFF9F) | 0x40);

	if (phy->radio_rev == 8) {
		b43_radio_write16(dev, 0x43, 0x000F);
	} else {
		b43_radio_write16(dev, 0x52, 0);
		b43_radio_write16(dev, 0x43, (b43_radio_read16(dev, 0x43)
					      & 0xFFF0) | 0x9);
	}
	b43_phy_set_baseband_attenuation(dev, 11);

	if (phy->rev >= 3)
		b43_phy_write(dev, B43_PHY_LO_MASK, 0xC020);
	else
		b43_phy_write(dev, B43_PHY_LO_MASK, 0x8020);
	b43_phy_write(dev, B43_PHY_LO_CTL, 0);

	b43_phy_write(dev, B43_PHY_CCK(0x2B),
		      (b43_phy_read(dev, B43_PHY_CCK(0x2B))
		       & 0xFFC0) | 0x01);
	b43_phy_write(dev, B43_PHY_CCK(0x2B),
		      (b43_phy_read(dev, B43_PHY_CCK(0x2B))
		       & 0xC0FF) | 0x800);

	b43_phy_write(dev, B43_PHY_RFOVER,
		      b43_phy_read(dev, B43_PHY_RFOVER) | 0x0100);
	b43_phy_write(dev, B43_PHY_RFOVERVAL,
		      b43_phy_read(dev, B43_PHY_RFOVERVAL) & 0xCFFF);

	if (dev->dev->bus->sprom.boardflags_lo & B43_BFL_EXTLNA) {
		if (phy->rev >= 7) {
			b43_phy_write(dev, B43_PHY_RFOVER,
				      b43_phy_read(dev, B43_PHY_RFOVER)
				      | 0x0800);
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      b43_phy_read(dev, B43_PHY_RFOVERVAL)
				      | 0x8000);
		}
	}
	b43_radio_write16(dev, 0x7A, b43_radio_read16(dev, 0x7A)
			  & 0x00F7);

	j = 0;
	loop_i_max = (phy->radio_rev == 8) ? 15 : 9;
	for (i = 0; i < loop_i_max; i++) {
		for (j = 0; j < 16; j++) {
			b43_radio_write16(dev, 0x43, i);
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      (b43_phy_read(dev, B43_PHY_RFOVERVAL)
				       & 0xF0FF) | (j << 8));
			b43_phy_write(dev, B43_PHY_PGACTL,
				      (b43_phy_read(dev, B43_PHY_PGACTL)
				       & 0x0FFF) | 0xA000);
			b43_phy_write(dev, B43_PHY_PGACTL,
				      b43_phy_read(dev, B43_PHY_PGACTL)
				      | 0xF000);
			udelay(20);
			if (b43_phy_read(dev, B43_PHY_LO_LEAKAGE) >= 0xDFC)
				goto exit_loop1;
		}
	}
      exit_loop1:
	loop1_outer_done = i;
	loop1_inner_done = j;
	if (j >= 8) {
		b43_phy_write(dev, B43_PHY_RFOVERVAL,
			      b43_phy_read(dev, B43_PHY_RFOVERVAL)
			      | 0x30);
		trsw_rx = 0x1B;
		for (j = j - 8; j < 16; j++) {
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      (b43_phy_read(dev, B43_PHY_RFOVERVAL)
				       & 0xF0FF) | (j << 8));
			b43_phy_write(dev, B43_PHY_PGACTL,
				      (b43_phy_read(dev, B43_PHY_PGACTL)
				       & 0x0FFF) | 0xA000);
			b43_phy_write(dev, B43_PHY_PGACTL,
				      b43_phy_read(dev, B43_PHY_PGACTL)
				      | 0xF000);
			udelay(20);
			trsw_rx -= 3;
			if (b43_phy_read(dev, B43_PHY_LO_LEAKAGE) >= 0xDFC)
				goto exit_loop2;
		}
	} else
		trsw_rx = 0x18;
      exit_loop2:

	if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
		b43_phy_write(dev, B43_PHY_ANALOGOVER, backup_phy[4]);
		b43_phy_write(dev, B43_PHY_ANALOGOVERVAL, backup_phy[5]);
	}
	b43_phy_write(dev, B43_PHY_CCK(0x5A), backup_phy[6]);
	b43_phy_write(dev, B43_PHY_CCK(0x59), backup_phy[7]);
	b43_phy_write(dev, B43_PHY_CCK(0x58), backup_phy[8]);
	b43_phy_write(dev, B43_PHY_CCK(0x0A), backup_phy[9]);
	b43_phy_write(dev, B43_PHY_CCK(0x03), backup_phy[10]);
	b43_phy_write(dev, B43_PHY_LO_MASK, backup_phy[11]);
	b43_phy_write(dev, B43_PHY_LO_CTL, backup_phy[12]);
	b43_phy_write(dev, B43_PHY_CCK(0x2B), backup_phy[13]);
	b43_phy_write(dev, B43_PHY_PGACTL, backup_phy[14]);

	b43_phy_set_baseband_attenuation(dev, backup_bband);

	b43_radio_write16(dev, 0x52, backup_radio[0]);
	b43_radio_write16(dev, 0x43, backup_radio[1]);
	b43_radio_write16(dev, 0x7A, backup_radio[2]);

	b43_phy_write(dev, B43_PHY_RFOVER, backup_phy[2] | 0x0003);
	udelay(10);
	b43_phy_write(dev, B43_PHY_RFOVER, backup_phy[2]);
	b43_phy_write(dev, B43_PHY_RFOVERVAL, backup_phy[3]);
	b43_phy_write(dev, B43_PHY_CRS0, backup_phy[0]);
	b43_phy_write(dev, B43_PHY_CCKBBANDCFG, backup_phy[1]);

	phy->max_lb_gain =
	    ((loop1_inner_done * 6) - (loop1_outer_done * 4)) - 11;
	phy->trsw_rx_gain = trsw_rx * 2;
}

static void b43_phy_initg(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 tmp;

	if (phy->rev == 1)
		b43_phy_initb5(dev);
	else
		b43_phy_initb6(dev);

	if (phy->rev >= 2 || phy->gmode)
		b43_phy_inita(dev);

	if (phy->rev >= 2) {
		b43_phy_write(dev, B43_PHY_ANALOGOVER, 0);
		b43_phy_write(dev, B43_PHY_ANALOGOVERVAL, 0);
	}
	if (phy->rev == 2) {
		b43_phy_write(dev, B43_PHY_RFOVER, 0);
		b43_phy_write(dev, B43_PHY_PGACTL, 0xC0);
	}
	if (phy->rev > 5) {
		b43_phy_write(dev, B43_PHY_RFOVER, 0x400);
		b43_phy_write(dev, B43_PHY_PGACTL, 0xC0);
	}
	if (phy->gmode || phy->rev >= 2) {
		tmp = b43_phy_read(dev, B43_PHY_VERSION_OFDM);
		tmp &= B43_PHYVER_VERSION;
		if (tmp == 3 || tmp == 5) {
			b43_phy_write(dev, B43_PHY_OFDM(0xC2), 0x1816);
			b43_phy_write(dev, B43_PHY_OFDM(0xC3), 0x8006);
		}
		if (tmp == 5) {
			b43_phy_write(dev, B43_PHY_OFDM(0xCC),
				      (b43_phy_read(dev, B43_PHY_OFDM(0xCC))
				       & 0x00FF) | 0x1F00);
		}
	}
	if ((phy->rev <= 2 && phy->gmode) || phy->rev >= 2)
		b43_phy_write(dev, B43_PHY_OFDM(0x7E), 0x78);
	if (phy->radio_rev == 8) {
		b43_phy_write(dev, B43_PHY_EXTG(0x01),
			      b43_phy_read(dev, B43_PHY_EXTG(0x01))
			      | 0x80);
		b43_phy_write(dev, B43_PHY_OFDM(0x3E),
			      b43_phy_read(dev, B43_PHY_OFDM(0x3E))
			      | 0x4);
	}
	if (has_loopback_gain(phy))
		b43_calc_loopback_gain(dev);

	if (phy->radio_rev != 8) {
		if (phy->initval == 0xFFFF)
			phy->initval = b43_radio_init2050(dev);
		else
			b43_radio_write16(dev, 0x0078, phy->initval);
	}
	if (phy->lo_control->tx_bias == 0xFF) {
		b43_lo_g_measure(dev);
	} else {
		if (has_tx_magnification(phy)) {
			b43_radio_write16(dev, 0x52,
					  (b43_radio_read16(dev, 0x52) & 0xFF00)
					  | phy->lo_control->tx_bias | phy->
					  lo_control->tx_magn);
		} else {
			b43_radio_write16(dev, 0x52,
					  (b43_radio_read16(dev, 0x52) & 0xFFF0)
					  | phy->lo_control->tx_bias);
		}
		if (phy->rev >= 6) {
			b43_phy_write(dev, B43_PHY_CCK(0x36),
				      (b43_phy_read(dev, B43_PHY_CCK(0x36))
				       & 0x0FFF) | (phy->lo_control->
						    tx_bias << 12));
		}
		if (dev->dev->bus->sprom.boardflags_lo & B43_BFL_PACTRL)
			b43_phy_write(dev, B43_PHY_CCK(0x2E), 0x8075);
		else
			b43_phy_write(dev, B43_PHY_CCK(0x2E), 0x807F);
		if (phy->rev < 2)
			b43_phy_write(dev, B43_PHY_CCK(0x2F), 0x101);
		else
			b43_phy_write(dev, B43_PHY_CCK(0x2F), 0x202);
	}
	if (phy->gmode || phy->rev >= 2) {
		b43_lo_g_adjust(dev);
		b43_phy_write(dev, B43_PHY_LO_MASK, 0x8078);
	}

	if (!(dev->dev->bus->sprom.boardflags_lo & B43_BFL_RSSI)) {
		/* The specs state to update the NRSSI LT with
		 * the value 0x7FFFFFFF here. I think that is some weird
		 * compiler optimization in the original driver.
		 * Essentially, what we do here is resetting all NRSSI LT
		 * entries to -32 (see the limit_value() in nrssi_hw_update())
		 */
		b43_nrssi_hw_update(dev, 0xFFFF);	//FIXME?
		b43_calc_nrssi_threshold(dev);
	} else if (phy->gmode || phy->rev >= 2) {
		if (phy->nrssi[0] == -1000) {
			B43_WARN_ON(phy->nrssi[1] != -1000);
			b43_calc_nrssi_slope(dev);
		} else
			b43_calc_nrssi_threshold(dev);
	}
	if (phy->radio_rev == 8)
		b43_phy_write(dev, B43_PHY_EXTG(0x05), 0x3230);
	b43_phy_init_pctl(dev);
	/* FIXME: The spec says in the following if, the 0 should be replaced
	   'if OFDM may not be used in the current locale'
	   but OFDM is legal everywhere */
	if ((dev->dev->bus->chip_id == 0x4306
	     && dev->dev->bus->chip_package == 2) || 0) {
		b43_phy_write(dev, B43_PHY_CRS0, b43_phy_read(dev, B43_PHY_CRS0)
			      & 0xBFFF);
		b43_phy_write(dev, B43_PHY_OFDM(0xC3),
			      b43_phy_read(dev, B43_PHY_OFDM(0xC3))
			      & 0x7FFF);
	}
}

/* Set the baseband attenuation value on chip. */
void b43_phy_set_baseband_attenuation(struct b43_wldev *dev,
				      u16 baseband_attenuation)
{
	struct b43_phy *phy = &dev->phy;

	if (phy->analog == 0) {
		b43_write16(dev, B43_MMIO_PHY0, (b43_read16(dev, B43_MMIO_PHY0)
						 & 0xFFF0) |
			    baseband_attenuation);
	} else if (phy->analog > 1) {
		b43_phy_write(dev, B43_PHY_DACCTL,
			      (b43_phy_read(dev, B43_PHY_DACCTL)
			       & 0xFFC3) | (baseband_attenuation << 2));
	} else {
		b43_phy_write(dev, B43_PHY_DACCTL,
			      (b43_phy_read(dev, B43_PHY_DACCTL)
			       & 0xFF87) | (baseband_attenuation << 3));
	}
}

/* http://bcm-specs.sipsolutions.net/EstimatePowerOut
 * This function converts a TSSI value to dBm in Q5.2
 */
static s8 b43_phy_estimate_power_out(struct b43_wldev *dev, s8 tssi)
{
	struct b43_phy *phy = &dev->phy;
	s8 dbm = 0;
	s32 tmp;

	tmp = (phy->tgt_idle_tssi - phy->cur_idle_tssi + tssi);

	switch (phy->type) {
	case B43_PHYTYPE_A:
		tmp += 0x80;
		tmp = limit_value(tmp, 0x00, 0xFF);
		dbm = phy->tssi2dbm[tmp];
		//TODO: There's a FIXME on the specs
		break;
	case B43_PHYTYPE_B:
	case B43_PHYTYPE_G:
		tmp = limit_value(tmp, 0x00, 0x3F);
		dbm = phy->tssi2dbm[tmp];
		break;
	default:
		B43_WARN_ON(1);
	}

	return dbm;
}

void b43_put_attenuation_into_ranges(struct b43_wldev *dev,
				     int *_bbatt, int *_rfatt)
{
	int rfatt = *_rfatt;
	int bbatt = *_bbatt;
	struct b43_txpower_lo_control *lo = dev->phy.lo_control;

	/* Get baseband and radio attenuation values into their permitted ranges.
	 * Radio attenuation affects power level 4 times as much as baseband. */

	/* Range constants */
	const int rf_min = lo->rfatt_list.min_val;
	const int rf_max = lo->rfatt_list.max_val;
	const int bb_min = lo->bbatt_list.min_val;
	const int bb_max = lo->bbatt_list.max_val;

	while (1) {
		if (rfatt > rf_max && bbatt > bb_max - 4)
			break;	/* Can not get it into ranges */
		if (rfatt < rf_min && bbatt < bb_min + 4)
			break;	/* Can not get it into ranges */
		if (bbatt > bb_max && rfatt > rf_max - 1)
			break;	/* Can not get it into ranges */
		if (bbatt < bb_min && rfatt < rf_min + 1)
			break;	/* Can not get it into ranges */

		if (bbatt > bb_max) {
			bbatt -= 4;
			rfatt += 1;
			continue;
		}
		if (bbatt < bb_min) {
			bbatt += 4;
			rfatt -= 1;
			continue;
		}
		if (rfatt > rf_max) {
			rfatt -= 1;
			bbatt += 4;
			continue;
		}
		if (rfatt < rf_min) {
			rfatt += 1;
			bbatt -= 4;
			continue;
		}
		break;
	}

	*_rfatt = limit_value(rfatt, rf_min, rf_max);
	*_bbatt = limit_value(bbatt, bb_min, bb_max);
}

/* http://bcm-specs.sipsolutions.net/RecalculateTransmissionPower */
void b43_phy_xmitpower(struct b43_wldev *dev)
{
	struct ssb_bus *bus = dev->dev->bus;
	struct b43_phy *phy = &dev->phy;

	if (phy->cur_idle_tssi == 0)
		return;
	if ((bus->boardinfo.vendor == SSB_BOARDVENDOR_BCM) &&
	    (bus->boardinfo.type == SSB_BOARD_BU4306))
		return;
#ifdef CONFIG_B43_DEBUG
	if (phy->manual_txpower_control)
		return;
#endif

	switch (phy->type) {
	case B43_PHYTYPE_A:{

			//TODO: Nothing for A PHYs yet :-/

			break;
		}
	case B43_PHYTYPE_B:
	case B43_PHYTYPE_G:{
			u16 tmp;
			s8 v0, v1, v2, v3;
			s8 average;
			int max_pwr;
			int desired_pwr, estimated_pwr, pwr_adjust;
			int rfatt_delta, bbatt_delta;
			int rfatt, bbatt;
			u8 tx_control;

			tmp = b43_shm_read16(dev, B43_SHM_SHARED, 0x0058);
			v0 = (s8) (tmp & 0x00FF);
			v1 = (s8) ((tmp & 0xFF00) >> 8);
			tmp = b43_shm_read16(dev, B43_SHM_SHARED, 0x005A);
			v2 = (s8) (tmp & 0x00FF);
			v3 = (s8) ((tmp & 0xFF00) >> 8);
			tmp = 0;

			if (v0 == 0x7F || v1 == 0x7F || v2 == 0x7F
			    || v3 == 0x7F) {
				tmp =
				    b43_shm_read16(dev, B43_SHM_SHARED, 0x0070);
				v0 = (s8) (tmp & 0x00FF);
				v1 = (s8) ((tmp & 0xFF00) >> 8);
				tmp =
				    b43_shm_read16(dev, B43_SHM_SHARED, 0x0072);
				v2 = (s8) (tmp & 0x00FF);
				v3 = (s8) ((tmp & 0xFF00) >> 8);
				if (v0 == 0x7F || v1 == 0x7F || v2 == 0x7F
				    || v3 == 0x7F)
					return;
				v0 = (v0 + 0x20) & 0x3F;
				v1 = (v1 + 0x20) & 0x3F;
				v2 = (v2 + 0x20) & 0x3F;
				v3 = (v3 + 0x20) & 0x3F;
				tmp = 1;
			}
			b43_shm_clear_tssi(dev);

			average = (v0 + v1 + v2 + v3 + 2) / 4;

			if (tmp
			    && (b43_shm_read16(dev, B43_SHM_SHARED, 0x005E) &
				0x8))
				average -= 13;

			estimated_pwr =
			    b43_phy_estimate_power_out(dev, average);

			max_pwr = dev->dev->bus->sprom.maxpwr_bg;
			if ((dev->dev->bus->sprom.boardflags_lo
			    & B43_BFL_PACTRL) && (phy->type == B43_PHYTYPE_G))
				max_pwr -= 0x3;
			if (unlikely(max_pwr <= 0)) {
				b43warn(dev->wl,
					"Invalid max-TX-power value in SPROM.\n");
				max_pwr = 60;	/* fake it */
				dev->dev->bus->sprom.maxpwr_bg = max_pwr;
			}

			/*TODO:
			   max_pwr = min(REG - dev->dev->bus->sprom.antennagain_bgphy - 0x6, max_pwr)
			   where REG is the max power as per the regulatory domain
			 */

			/* Get desired power (in Q5.2) */
			desired_pwr = INT_TO_Q52(phy->power_level);
			/* And limit it. max_pwr already is Q5.2 */
			desired_pwr = limit_value(desired_pwr, 0, max_pwr);
			if (b43_debug(dev, B43_DBG_XMITPOWER)) {
				b43dbg(dev->wl,
				       "Current TX power output: " Q52_FMT
				       " dBm, " "Desired TX power output: "
				       Q52_FMT " dBm\n", Q52_ARG(estimated_pwr),
				       Q52_ARG(desired_pwr));
			}

			/* Calculate the adjustment delta. */
			pwr_adjust = desired_pwr - estimated_pwr;

			/* RF attenuation delta. */
			rfatt_delta = ((pwr_adjust + 7) / 8);
			/* Lower attenuation => Bigger power output. Negate it. */
			rfatt_delta = -rfatt_delta;

			/* Baseband attenuation delta. */
			bbatt_delta = pwr_adjust / 2;
			/* Lower attenuation => Bigger power output. Negate it. */
			bbatt_delta = -bbatt_delta;
			/* RF att affects power level 4 times as much as
			 * Baseband attennuation. Subtract it. */
			bbatt_delta -= 4 * rfatt_delta;

			/* So do we finally need to adjust something? */
			if ((rfatt_delta == 0) && (bbatt_delta == 0)) {
				b43_lo_g_ctl_mark_cur_used(dev);
				return;
			}

			/* Calculate the new attenuation values. */
			bbatt = phy->bbatt.att;
			bbatt += bbatt_delta;
			rfatt = phy->rfatt.att;
			rfatt += rfatt_delta;

			b43_put_attenuation_into_ranges(dev, &bbatt, &rfatt);
			tx_control = phy->tx_control;
			if ((phy->radio_ver == 0x2050) && (phy->radio_rev == 2)) {
				if (rfatt <= 1) {
					if (tx_control == 0) {
						tx_control =
						    B43_TXCTL_PA2DB |
						    B43_TXCTL_TXMIX;
						rfatt += 2;
						bbatt += 2;
					} else if (dev->dev->bus->sprom.
						   boardflags_lo &
						   B43_BFL_PACTRL) {
						bbatt += 4 * (rfatt - 2);
						rfatt = 2;
					}
				} else if (rfatt > 4 && tx_control) {
					tx_control = 0;
					if (bbatt < 3) {
						rfatt -= 3;
						bbatt += 2;
					} else {
						rfatt -= 2;
						bbatt -= 2;
					}
				}
			}
			/* Save the control values */
			phy->tx_control = tx_control;
			b43_put_attenuation_into_ranges(dev, &bbatt, &rfatt);
			phy->rfatt.att = rfatt;
			phy->bbatt.att = bbatt;

			/* Adjust the hardware */
			b43_phy_lock(dev);
			b43_radio_lock(dev);
			b43_set_txpower_g(dev, &phy->bbatt, &phy->rfatt,
					  phy->tx_control);
			b43_lo_g_ctl_mark_cur_used(dev);
			b43_radio_unlock(dev);
			b43_phy_unlock(dev);
			break;
		}
	case B43_PHYTYPE_N:
		b43_nphy_xmitpower(dev);
		break;
	default:
		B43_WARN_ON(1);
	}
}

static inline s32 b43_tssi2dbm_ad(s32 num, s32 den)
{
	if (num < 0)
		return num / den;
	else
		return (num + den / 2) / den;
}

static inline
    s8 b43_tssi2dbm_entry(s8 entry[], u8 index, s16 pab0, s16 pab1, s16 pab2)
{
	s32 m1, m2, f = 256, q, delta;
	s8 i = 0;

	m1 = b43_tssi2dbm_ad(16 * pab0 + index * pab1, 32);
	m2 = max(b43_tssi2dbm_ad(32768 + index * pab2, 256), 1);
	do {
		if (i > 15)
			return -EINVAL;
		q = b43_tssi2dbm_ad(f * 4096 -
				    b43_tssi2dbm_ad(m2 * f, 16) * f, 2048);
		delta = abs(q - f);
		f = q;
		i++;
	} while (delta >= 2);
	entry[index] = limit_value(b43_tssi2dbm_ad(m1 * f, 8192), -127, 128);
	return 0;
}

/* http://bcm-specs.sipsolutions.net/TSSI_to_DBM_Table */
int b43_phy_init_tssi2dbm_table(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	s16 pab0, pab1, pab2;
	u8 idx;
	s8 *dyn_tssi2dbm;

	if (phy->type == B43_PHYTYPE_A) {
		pab0 = (s16) (dev->dev->bus->sprom.pa1b0);
		pab1 = (s16) (dev->dev->bus->sprom.pa1b1);
		pab2 = (s16) (dev->dev->bus->sprom.pa1b2);
	} else {
		pab0 = (s16) (dev->dev->bus->sprom.pa0b0);
		pab1 = (s16) (dev->dev->bus->sprom.pa0b1);
		pab2 = (s16) (dev->dev->bus->sprom.pa0b2);
	}

	if ((dev->dev->bus->chip_id == 0x4301) && (phy->radio_ver != 0x2050)) {
		phy->tgt_idle_tssi = 0x34;
		phy->tssi2dbm = b43_tssi2dbm_b_table;
		return 0;
	}

	if (pab0 != 0 && pab1 != 0 && pab2 != 0 &&
	    pab0 != -1 && pab1 != -1 && pab2 != -1) {
		/* The pabX values are set in SPROM. Use them. */
		if (phy->type == B43_PHYTYPE_A) {
			if ((s8) dev->dev->bus->sprom.itssi_a != 0 &&
			    (s8) dev->dev->bus->sprom.itssi_a != -1)
				phy->tgt_idle_tssi =
				    (s8) (dev->dev->bus->sprom.itssi_a);
			else
				phy->tgt_idle_tssi = 62;
		} else {
			if ((s8) dev->dev->bus->sprom.itssi_bg != 0 &&
			    (s8) dev->dev->bus->sprom.itssi_bg != -1)
				phy->tgt_idle_tssi =
				    (s8) (dev->dev->bus->sprom.itssi_bg);
			else
				phy->tgt_idle_tssi = 62;
		}
		dyn_tssi2dbm = kmalloc(64, GFP_KERNEL);
		if (dyn_tssi2dbm == NULL) {
			b43err(dev->wl, "Could not allocate memory "
			       "for tssi2dbm table\n");
			return -ENOMEM;
		}
		for (idx = 0; idx < 64; idx++)
			if (b43_tssi2dbm_entry
			    (dyn_tssi2dbm, idx, pab0, pab1, pab2)) {
				phy->tssi2dbm = NULL;
				b43err(dev->wl, "Could not generate "
				       "tssi2dBm table\n");
				kfree(dyn_tssi2dbm);
				return -ENODEV;
			}
		phy->tssi2dbm = dyn_tssi2dbm;
		phy->dyn_tssi_tbl = 1;
	} else {
		/* pabX values not set in SPROM. */
		switch (phy->type) {
		case B43_PHYTYPE_A:
			/* APHY needs a generated table. */
			phy->tssi2dbm = NULL;
			b43err(dev->wl, "Could not generate tssi2dBm "
			       "table (wrong SPROM info)!\n");
			return -ENODEV;
		case B43_PHYTYPE_B:
			phy->tgt_idle_tssi = 0x34;
			phy->tssi2dbm = b43_tssi2dbm_b_table;
			break;
		case B43_PHYTYPE_G:
			phy->tgt_idle_tssi = 0x34;
			phy->tssi2dbm = b43_tssi2dbm_g_table;
			break;
		}
	}

	return 0;
}

int b43_phy_init(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	bool unsupported = 0;
	int err = 0;

	switch (phy->type) {
	case B43_PHYTYPE_A:
		if (phy->rev == 2 || phy->rev == 3)
			b43_phy_inita(dev);
		else
			unsupported = 1;
		break;
	case B43_PHYTYPE_B:
		switch (phy->rev) {
		case 2:
			b43_phy_initb2(dev);
			break;
		case 4:
			b43_phy_initb4(dev);
			break;
		case 5:
			b43_phy_initb5(dev);
			break;
		case 6:
			b43_phy_initb6(dev);
			break;
		default:
			unsupported = 1;
		}
		break;
	case B43_PHYTYPE_G:
		b43_phy_initg(dev);
		break;
	case B43_PHYTYPE_N:
		err = b43_phy_initn(dev);
		break;
	default:
		unsupported = 1;
	}
	if (unsupported)
		b43err(dev->wl, "Unknown PHYTYPE found\n");

	return err;
}

void b43_set_rx_antenna(struct b43_wldev *dev, int antenna)
{
	struct b43_phy *phy = &dev->phy;
	u64 hf;
	u16 tmp;
	int autodiv = 0;

	if (antenna == B43_ANTENNA_AUTO0 || antenna == B43_ANTENNA_AUTO1)
		autodiv = 1;

	hf = b43_hf_read(dev);
	hf &= ~B43_HF_ANTDIVHELP;
	b43_hf_write(dev, hf);

	switch (phy->type) {
	case B43_PHYTYPE_A:
	case B43_PHYTYPE_G:
		tmp = b43_phy_read(dev, B43_PHY_BBANDCFG);
		tmp &= ~B43_PHY_BBANDCFG_RXANT;
		tmp |= (autodiv ? B43_ANTENNA_AUTO0 : antenna)
		    << B43_PHY_BBANDCFG_RXANT_SHIFT;
		b43_phy_write(dev, B43_PHY_BBANDCFG, tmp);

		if (autodiv) {
			tmp = b43_phy_read(dev, B43_PHY_ANTDWELL);
			if (antenna == B43_ANTENNA_AUTO0)
				tmp &= ~B43_PHY_ANTDWELL_AUTODIV1;
			else
				tmp |= B43_PHY_ANTDWELL_AUTODIV1;
			b43_phy_write(dev, B43_PHY_ANTDWELL, tmp);
		}
		if (phy->type == B43_PHYTYPE_G) {
			tmp = b43_phy_read(dev, B43_PHY_ANTWRSETT);
			if (autodiv)
				tmp |= B43_PHY_ANTWRSETT_ARXDIV;
			else
				tmp &= ~B43_PHY_ANTWRSETT_ARXDIV;
			b43_phy_write(dev, B43_PHY_ANTWRSETT, tmp);
			if (phy->rev >= 2) {
				tmp = b43_phy_read(dev, B43_PHY_OFDM61);
				tmp |= B43_PHY_OFDM61_10;
				b43_phy_write(dev, B43_PHY_OFDM61, tmp);

				tmp =
				    b43_phy_read(dev, B43_PHY_DIVSRCHGAINBACK);
				tmp = (tmp & 0xFF00) | 0x15;
				b43_phy_write(dev, B43_PHY_DIVSRCHGAINBACK,
					      tmp);

				if (phy->rev == 2) {
					b43_phy_write(dev, B43_PHY_ADIVRELATED,
						      8);
				} else {
					tmp =
					    b43_phy_read(dev,
							 B43_PHY_ADIVRELATED);
					tmp = (tmp & 0xFF00) | 8;
					b43_phy_write(dev, B43_PHY_ADIVRELATED,
						      tmp);
				}
			}
			if (phy->rev >= 6)
				b43_phy_write(dev, B43_PHY_OFDM9B, 0xDC);
		} else {
			if (phy->rev < 3) {
				tmp = b43_phy_read(dev, B43_PHY_ANTDWELL);
				tmp = (tmp & 0xFF00) | 0x24;
				b43_phy_write(dev, B43_PHY_ANTDWELL, tmp);
			} else {
				tmp = b43_phy_read(dev, B43_PHY_OFDM61);
				tmp |= 0x10;
				b43_phy_write(dev, B43_PHY_OFDM61, tmp);
				if (phy->analog == 3) {
					b43_phy_write(dev, B43_PHY_CLIPPWRDOWNT,
						      0x1D);
					b43_phy_write(dev, B43_PHY_ADIVRELATED,
						      8);
				} else {
					b43_phy_write(dev, B43_PHY_CLIPPWRDOWNT,
						      0x3A);
					tmp =
					    b43_phy_read(dev,
							 B43_PHY_ADIVRELATED);
					tmp = (tmp & 0xFF00) | 8;
					b43_phy_write(dev, B43_PHY_ADIVRELATED,
						      tmp);
				}
			}
		}
		break;
	case B43_PHYTYPE_B:
		tmp = b43_phy_read(dev, B43_PHY_CCKBBANDCFG);
		tmp &= ~B43_PHY_BBANDCFG_RXANT;
		tmp |= (autodiv ? B43_ANTENNA_AUTO0 : antenna)
		    << B43_PHY_BBANDCFG_RXANT_SHIFT;
		b43_phy_write(dev, B43_PHY_CCKBBANDCFG, tmp);
		break;
	case B43_PHYTYPE_N:
		b43_nphy_set_rxantenna(dev, antenna);
		break;
	default:
		B43_WARN_ON(1);
	}

	hf |= B43_HF_ANTDIVHELP;
	b43_hf_write(dev, hf);
}

/* Get the freq, as it has to be written to the device. */
static inline u16 channel2freq_bg(u8 channel)
{
	B43_WARN_ON(!(channel >= 1 && channel <= 14));

	return b43_radio_channel_codes_bg[channel - 1];
}

/* Get the freq, as it has to be written to the device. */
static inline u16 channel2freq_a(u8 channel)
{
	B43_WARN_ON(channel > 200);

	return (5000 + 5 * channel);
}

void b43_radio_lock(struct b43_wldev *dev)
{
	u32 macctl;

	macctl = b43_read32(dev, B43_MMIO_MACCTL);
	B43_WARN_ON(macctl & B43_MACCTL_RADIOLOCK);
	macctl |= B43_MACCTL_RADIOLOCK;
	b43_write32(dev, B43_MMIO_MACCTL, macctl);
	/* Commit the write and wait for the device
	 * to exit any radio register access. */
	b43_read32(dev, B43_MMIO_MACCTL);
	udelay(10);
}

void b43_radio_unlock(struct b43_wldev *dev)
{
	u32 macctl;

	/* Commit any write */
	b43_read16(dev, B43_MMIO_PHY_VER);
	/* unlock */
	macctl = b43_read32(dev, B43_MMIO_MACCTL);
	B43_WARN_ON(!(macctl & B43_MACCTL_RADIOLOCK));
	macctl &= ~B43_MACCTL_RADIOLOCK;
	b43_write32(dev, B43_MMIO_MACCTL, macctl);
}

u16 b43_radio_read16(struct b43_wldev *dev, u16 offset)
{
	struct b43_phy *phy = &dev->phy;

	/* Offset 1 is a 32-bit register. */
	B43_WARN_ON(offset == 1);

	switch (phy->type) {
	case B43_PHYTYPE_A:
		offset |= 0x40;
		break;
	case B43_PHYTYPE_B:
		if (phy->radio_ver == 0x2053) {
			if (offset < 0x70)
				offset += 0x80;
			else if (offset < 0x80)
				offset += 0x70;
		} else if (phy->radio_ver == 0x2050) {
			offset |= 0x80;
		} else
			B43_WARN_ON(1);
		break;
	case B43_PHYTYPE_G:
		offset |= 0x80;
		break;
	case B43_PHYTYPE_N:
		offset |= 0x100;
		break;
	case B43_PHYTYPE_LP:
		/* No adjustment required. */
		break;
	default:
		B43_WARN_ON(1);
	}

	b43_write16(dev, B43_MMIO_RADIO_CONTROL, offset);
	return b43_read16(dev, B43_MMIO_RADIO_DATA_LOW);
}

void b43_radio_write16(struct b43_wldev *dev, u16 offset, u16 val)
{
	/* Offset 1 is a 32-bit register. */
	B43_WARN_ON(offset == 1);

	b43_write16(dev, B43_MMIO_RADIO_CONTROL, offset);
	b43_write16(dev, B43_MMIO_RADIO_DATA_LOW, val);
}

void b43_radio_mask(struct b43_wldev *dev, u16 offset, u16 mask)
{
	b43_radio_write16(dev, offset,
			  b43_radio_read16(dev, offset) & mask);
}

void b43_radio_set(struct b43_wldev *dev, u16 offset, u16 set)
{
	b43_radio_write16(dev, offset,
			  b43_radio_read16(dev, offset) | set);
}

void b43_radio_maskset(struct b43_wldev *dev, u16 offset, u16 mask, u16 set)
{
	b43_radio_write16(dev, offset,
			  (b43_radio_read16(dev, offset) & mask) | set);
}

static void b43_set_all_gains(struct b43_wldev *dev,
			      s16 first, s16 second, s16 third)
{
	struct b43_phy *phy = &dev->phy;
	u16 i;
	u16 start = 0x08, end = 0x18;
	u16 tmp;
	u16 table;

	if (phy->rev <= 1) {
		start = 0x10;
		end = 0x20;
	}

	table = B43_OFDMTAB_GAINX;
	if (phy->rev <= 1)
		table = B43_OFDMTAB_GAINX_R1;
	for (i = 0; i < 4; i++)
		b43_ofdmtab_write16(dev, table, i, first);

	for (i = start; i < end; i++)
		b43_ofdmtab_write16(dev, table, i, second);

	if (third != -1) {
		tmp = ((u16) third << 14) | ((u16) third << 6);
		b43_phy_write(dev, 0x04A0,
			      (b43_phy_read(dev, 0x04A0) & 0xBFBF) | tmp);
		b43_phy_write(dev, 0x04A1,
			      (b43_phy_read(dev, 0x04A1) & 0xBFBF) | tmp);
		b43_phy_write(dev, 0x04A2,
			      (b43_phy_read(dev, 0x04A2) & 0xBFBF) | tmp);
	}
	b43_dummy_transmission(dev);
}

static void b43_set_original_gains(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 i, tmp;
	u16 table;
	u16 start = 0x0008, end = 0x0018;

	if (phy->rev <= 1) {
		start = 0x0010;
		end = 0x0020;
	}

	table = B43_OFDMTAB_GAINX;
	if (phy->rev <= 1)
		table = B43_OFDMTAB_GAINX_R1;
	for (i = 0; i < 4; i++) {
		tmp = (i & 0xFFFC);
		tmp |= (i & 0x0001) << 1;
		tmp |= (i & 0x0002) >> 1;

		b43_ofdmtab_write16(dev, table, i, tmp);
	}

	for (i = start; i < end; i++)
		b43_ofdmtab_write16(dev, table, i, i - start);

	b43_phy_write(dev, 0x04A0,
		      (b43_phy_read(dev, 0x04A0) & 0xBFBF) | 0x4040);
	b43_phy_write(dev, 0x04A1,
		      (b43_phy_read(dev, 0x04A1) & 0xBFBF) | 0x4040);
	b43_phy_write(dev, 0x04A2,
		      (b43_phy_read(dev, 0x04A2) & 0xBFBF) | 0x4000);
	b43_dummy_transmission(dev);
}

/* Synthetic PU workaround */
static void b43_synth_pu_workaround(struct b43_wldev *dev, u8 channel)
{
	struct b43_phy *phy = &dev->phy;

	might_sleep();

	if (phy->radio_ver != 0x2050 || phy->radio_rev >= 6) {
		/* We do not need the workaround. */
		return;
	}

	if (channel <= 10) {
		b43_write16(dev, B43_MMIO_CHANNEL,
			    channel2freq_bg(channel + 4));
	} else {
		b43_write16(dev, B43_MMIO_CHANNEL, channel2freq_bg(1));
	}
	msleep(1);
	b43_write16(dev, B43_MMIO_CHANNEL, channel2freq_bg(channel));
}

u8 b43_radio_aci_detect(struct b43_wldev *dev, u8 channel)
{
	struct b43_phy *phy = &dev->phy;
	u8 ret = 0;
	u16 saved, rssi, temp;
	int i, j = 0;

	saved = b43_phy_read(dev, 0x0403);
	b43_radio_selectchannel(dev, channel, 0);
	b43_phy_write(dev, 0x0403, (saved & 0xFFF8) | 5);
	if (phy->aci_hw_rssi)
		rssi = b43_phy_read(dev, 0x048A) & 0x3F;
	else
		rssi = saved & 0x3F;
	/* clamp temp to signed 5bit */
	if (rssi > 32)
		rssi -= 64;
	for (i = 0; i < 100; i++) {
		temp = (b43_phy_read(dev, 0x047F) >> 8) & 0x3F;
		if (temp > 32)
			temp -= 64;
		if (temp < rssi)
			j++;
		if (j >= 20)
			ret = 1;
	}
	b43_phy_write(dev, 0x0403, saved);

	return ret;
}

u8 b43_radio_aci_scan(struct b43_wldev * dev)
{
	struct b43_phy *phy = &dev->phy;
	u8 ret[13];
	unsigned int channel = phy->channel;
	unsigned int i, j, start, end;

	if (!((phy->type == B43_PHYTYPE_G) && (phy->rev > 0)))
		return 0;

	b43_phy_lock(dev);
	b43_radio_lock(dev);
	b43_phy_write(dev, 0x0802, b43_phy_read(dev, 0x0802) & 0xFFFC);
	b43_phy_write(dev, B43_PHY_G_CRS,
		      b43_phy_read(dev, B43_PHY_G_CRS) & 0x7FFF);
	b43_set_all_gains(dev, 3, 8, 1);

	start = (channel - 5 > 0) ? channel - 5 : 1;
	end = (channel + 5 < 14) ? channel + 5 : 13;

	for (i = start; i <= end; i++) {
		if (abs(channel - i) > 2)
			ret[i - 1] = b43_radio_aci_detect(dev, i);
	}
	b43_radio_selectchannel(dev, channel, 0);
	b43_phy_write(dev, 0x0802,
		      (b43_phy_read(dev, 0x0802) & 0xFFFC) | 0x0003);
	b43_phy_write(dev, 0x0403, b43_phy_read(dev, 0x0403) & 0xFFF8);
	b43_phy_write(dev, B43_PHY_G_CRS,
		      b43_phy_read(dev, B43_PHY_G_CRS) | 0x8000);
	b43_set_original_gains(dev);
	for (i = 0; i < 13; i++) {
		if (!ret[i])
			continue;
		end = (i + 5 < 13) ? i + 5 : 13;
		for (j = i; j < end; j++)
			ret[j] = 1;
	}
	b43_radio_unlock(dev);
	b43_phy_unlock(dev);

	return ret[channel - 1];
}

/* http://bcm-specs.sipsolutions.net/NRSSILookupTable */
void b43_nrssi_hw_write(struct b43_wldev *dev, u16 offset, s16 val)
{
	b43_phy_write(dev, B43_PHY_NRSSILT_CTRL, offset);
	mmiowb();
	b43_phy_write(dev, B43_PHY_NRSSILT_DATA, (u16) val);
}

/* http://bcm-specs.sipsolutions.net/NRSSILookupTable */
s16 b43_nrssi_hw_read(struct b43_wldev *dev, u16 offset)
{
	u16 val;

	b43_phy_write(dev, B43_PHY_NRSSILT_CTRL, offset);
	val = b43_phy_read(dev, B43_PHY_NRSSILT_DATA);

	return (s16) val;
}

/* http://bcm-specs.sipsolutions.net/NRSSILookupTable */
void b43_nrssi_hw_update(struct b43_wldev *dev, u16 val)
{
	u16 i;
	s16 tmp;

	for (i = 0; i < 64; i++) {
		tmp = b43_nrssi_hw_read(dev, i);
		tmp -= val;
		tmp = limit_value(tmp, -32, 31);
		b43_nrssi_hw_write(dev, i, tmp);
	}
}

/* http://bcm-specs.sipsolutions.net/NRSSILookupTable */
void b43_nrssi_mem_update(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	s16 i, delta;
	s32 tmp;

	delta = 0x1F - phy->nrssi[0];
	for (i = 0; i < 64; i++) {
		tmp = (i - delta) * phy->nrssislope;
		tmp /= 0x10000;
		tmp += 0x3A;
		tmp = limit_value(tmp, 0, 0x3F);
		phy->nrssi_lt[i] = tmp;
	}
}

static void b43_calc_nrssi_offset(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 backup[20] = { 0 };
	s16 v47F;
	u16 i;
	u16 saved = 0xFFFF;

	backup[0] = b43_phy_read(dev, 0x0001);
	backup[1] = b43_phy_read(dev, 0x0811);
	backup[2] = b43_phy_read(dev, 0x0812);
	if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
		backup[3] = b43_phy_read(dev, 0x0814);
		backup[4] = b43_phy_read(dev, 0x0815);
	}
	backup[5] = b43_phy_read(dev, 0x005A);
	backup[6] = b43_phy_read(dev, 0x0059);
	backup[7] = b43_phy_read(dev, 0x0058);
	backup[8] = b43_phy_read(dev, 0x000A);
	backup[9] = b43_phy_read(dev, 0x0003);
	backup[10] = b43_radio_read16(dev, 0x007A);
	backup[11] = b43_radio_read16(dev, 0x0043);

	b43_phy_write(dev, 0x0429, b43_phy_read(dev, 0x0429) & 0x7FFF);
	b43_phy_write(dev, 0x0001,
		      (b43_phy_read(dev, 0x0001) & 0x3FFF) | 0x4000);
	b43_phy_write(dev, 0x0811, b43_phy_read(dev, 0x0811) | 0x000C);
	b43_phy_write(dev, 0x0812,
		      (b43_phy_read(dev, 0x0812) & 0xFFF3) | 0x0004);
	b43_phy_write(dev, 0x0802, b43_phy_read(dev, 0x0802) & ~(0x1 | 0x2));
	if (phy->rev >= 6) {
		backup[12] = b43_phy_read(dev, 0x002E);
		backup[13] = b43_phy_read(dev, 0x002F);
		backup[14] = b43_phy_read(dev, 0x080F);
		backup[15] = b43_phy_read(dev, 0x0810);
		backup[16] = b43_phy_read(dev, 0x0801);
		backup[17] = b43_phy_read(dev, 0x0060);
		backup[18] = b43_phy_read(dev, 0x0014);
		backup[19] = b43_phy_read(dev, 0x0478);

		b43_phy_write(dev, 0x002E, 0);
		b43_phy_write(dev, 0x002F, 0);
		b43_phy_write(dev, 0x080F, 0);
		b43_phy_write(dev, 0x0810, 0);
		b43_phy_write(dev, 0x0478, b43_phy_read(dev, 0x0478) | 0x0100);
		b43_phy_write(dev, 0x0801, b43_phy_read(dev, 0x0801) | 0x0040);
		b43_phy_write(dev, 0x0060, b43_phy_read(dev, 0x0060) | 0x0040);
		b43_phy_write(dev, 0x0014, b43_phy_read(dev, 0x0014) | 0x0200);
	}
	b43_radio_write16(dev, 0x007A, b43_radio_read16(dev, 0x007A) | 0x0070);
	b43_radio_write16(dev, 0x007A, b43_radio_read16(dev, 0x007A) | 0x0080);
	udelay(30);

	v47F = (s16) ((b43_phy_read(dev, 0x047F) >> 8) & 0x003F);
	if (v47F >= 0x20)
		v47F -= 0x40;
	if (v47F == 31) {
		for (i = 7; i >= 4; i--) {
			b43_radio_write16(dev, 0x007B, i);
			udelay(20);
			v47F =
			    (s16) ((b43_phy_read(dev, 0x047F) >> 8) & 0x003F);
			if (v47F >= 0x20)
				v47F -= 0x40;
			if (v47F < 31 && saved == 0xFFFF)
				saved = i;
		}
		if (saved == 0xFFFF)
			saved = 4;
	} else {
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) & 0x007F);
		if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
			b43_phy_write(dev, 0x0814,
				      b43_phy_read(dev, 0x0814) | 0x0001);
			b43_phy_write(dev, 0x0815,
				      b43_phy_read(dev, 0x0815) & 0xFFFE);
		}
		b43_phy_write(dev, 0x0811, b43_phy_read(dev, 0x0811) | 0x000C);
		b43_phy_write(dev, 0x0812, b43_phy_read(dev, 0x0812) | 0x000C);
		b43_phy_write(dev, 0x0811, b43_phy_read(dev, 0x0811) | 0x0030);
		b43_phy_write(dev, 0x0812, b43_phy_read(dev, 0x0812) | 0x0030);
		b43_phy_write(dev, 0x005A, 0x0480);
		b43_phy_write(dev, 0x0059, 0x0810);
		b43_phy_write(dev, 0x0058, 0x000D);
		if (phy->rev == 0) {
			b43_phy_write(dev, 0x0003, 0x0122);
		} else {
			b43_phy_write(dev, 0x000A, b43_phy_read(dev, 0x000A)
				      | 0x2000);
		}
		if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
			b43_phy_write(dev, 0x0814,
				      b43_phy_read(dev, 0x0814) | 0x0004);
			b43_phy_write(dev, 0x0815,
				      b43_phy_read(dev, 0x0815) & 0xFFFB);
		}
		b43_phy_write(dev, 0x0003, (b43_phy_read(dev, 0x0003) & 0xFF9F)
			      | 0x0040);
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) | 0x000F);
		b43_set_all_gains(dev, 3, 0, 1);
		b43_radio_write16(dev, 0x0043, (b43_radio_read16(dev, 0x0043)
						& 0x00F0) | 0x000F);
		udelay(30);
		v47F = (s16) ((b43_phy_read(dev, 0x047F) >> 8) & 0x003F);
		if (v47F >= 0x20)
			v47F -= 0x40;
		if (v47F == -32) {
			for (i = 0; i < 4; i++) {
				b43_radio_write16(dev, 0x007B, i);
				udelay(20);
				v47F =
				    (s16) ((b43_phy_read(dev, 0x047F) >> 8) &
					   0x003F);
				if (v47F >= 0x20)
					v47F -= 0x40;
				if (v47F > -31 && saved == 0xFFFF)
					saved = i;
			}
			if (saved == 0xFFFF)
				saved = 3;
		} else
			saved = 0;
	}
	b43_radio_write16(dev, 0x007B, saved);

	if (phy->rev >= 6) {
		b43_phy_write(dev, 0x002E, backup[12]);
		b43_phy_write(dev, 0x002F, backup[13]);
		b43_phy_write(dev, 0x080F, backup[14]);
		b43_phy_write(dev, 0x0810, backup[15]);
	}
	if (phy->rev != 1) {	/* Not in specs, but needed to prevent PPC machine check */
		b43_phy_write(dev, 0x0814, backup[3]);
		b43_phy_write(dev, 0x0815, backup[4]);
	}
	b43_phy_write(dev, 0x005A, backup[5]);
	b43_phy_write(dev, 0x0059, backup[6]);
	b43_phy_write(dev, 0x0058, backup[7]);
	b43_phy_write(dev, 0x000A, backup[8]);
	b43_phy_write(dev, 0x0003, backup[9]);
	b43_radio_write16(dev, 0x0043, backup[11]);
	b43_radio_write16(dev, 0x007A, backup[10]);
	b43_phy_write(dev, 0x0802, b43_phy_read(dev, 0x0802) | 0x1 | 0x2);
	b43_phy_write(dev, 0x0429, b43_phy_read(dev, 0x0429) | 0x8000);
	b43_set_original_gains(dev);
	if (phy->rev >= 6) {
		b43_phy_write(dev, 0x0801, backup[16]);
		b43_phy_write(dev, 0x0060, backup[17]);
		b43_phy_write(dev, 0x0014, backup[18]);
		b43_phy_write(dev, 0x0478, backup[19]);
	}
	b43_phy_write(dev, 0x0001, backup[0]);
	b43_phy_write(dev, 0x0812, backup[2]);
	b43_phy_write(dev, 0x0811, backup[1]);
}

void b43_calc_nrssi_slope(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	u16 backup[18] = { 0 };
	u16 tmp;
	s16 nrssi0, nrssi1;

	switch (phy->type) {
	case B43_PHYTYPE_B:
		backup[0] = b43_radio_read16(dev, 0x007A);
		backup[1] = b43_radio_read16(dev, 0x0052);
		backup[2] = b43_radio_read16(dev, 0x0043);
		backup[3] = b43_phy_read(dev, 0x0030);
		backup[4] = b43_phy_read(dev, 0x0026);
		backup[5] = b43_phy_read(dev, 0x0015);
		backup[6] = b43_phy_read(dev, 0x002A);
		backup[7] = b43_phy_read(dev, 0x0020);
		backup[8] = b43_phy_read(dev, 0x005A);
		backup[9] = b43_phy_read(dev, 0x0059);
		backup[10] = b43_phy_read(dev, 0x0058);
		backup[11] = b43_read16(dev, 0x03E2);
		backup[12] = b43_read16(dev, 0x03E6);
		backup[13] = b43_read16(dev, B43_MMIO_CHANNEL_EXT);

		tmp = b43_radio_read16(dev, 0x007A);
		tmp &= (phy->rev >= 5) ? 0x007F : 0x000F;
		b43_radio_write16(dev, 0x007A, tmp);
		b43_phy_write(dev, 0x0030, 0x00FF);
		b43_write16(dev, 0x03EC, 0x7F7F);
		b43_phy_write(dev, 0x0026, 0x0000);
		b43_phy_write(dev, 0x0015, b43_phy_read(dev, 0x0015) | 0x0020);
		b43_phy_write(dev, 0x002A, 0x08A3);
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) | 0x0080);

		nrssi0 = (s16) b43_phy_read(dev, 0x0027);
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) & 0x007F);
		if (phy->rev >= 2) {
			b43_write16(dev, 0x03E6, 0x0040);
		} else if (phy->rev == 0) {
			b43_write16(dev, 0x03E6, 0x0122);
		} else {
			b43_write16(dev, B43_MMIO_CHANNEL_EXT,
				    b43_read16(dev,
					       B43_MMIO_CHANNEL_EXT) & 0x2000);
		}
		b43_phy_write(dev, 0x0020, 0x3F3F);
		b43_phy_write(dev, 0x0015, 0xF330);
		b43_radio_write16(dev, 0x005A, 0x0060);
		b43_radio_write16(dev, 0x0043,
				  b43_radio_read16(dev, 0x0043) & 0x00F0);
		b43_phy_write(dev, 0x005A, 0x0480);
		b43_phy_write(dev, 0x0059, 0x0810);
		b43_phy_write(dev, 0x0058, 0x000D);
		udelay(20);

		nrssi1 = (s16) b43_phy_read(dev, 0x0027);
		b43_phy_write(dev, 0x0030, backup[3]);
		b43_radio_write16(dev, 0x007A, backup[0]);
		b43_write16(dev, 0x03E2, backup[11]);
		b43_phy_write(dev, 0x0026, backup[4]);
		b43_phy_write(dev, 0x0015, backup[5]);
		b43_phy_write(dev, 0x002A, backup[6]);
		b43_synth_pu_workaround(dev, phy->channel);
		if (phy->rev != 0)
			b43_write16(dev, 0x03F4, backup[13]);

		b43_phy_write(dev, 0x0020, backup[7]);
		b43_phy_write(dev, 0x005A, backup[8]);
		b43_phy_write(dev, 0x0059, backup[9]);
		b43_phy_write(dev, 0x0058, backup[10]);
		b43_radio_write16(dev, 0x0052, backup[1]);
		b43_radio_write16(dev, 0x0043, backup[2]);

		if (nrssi0 == nrssi1)
			phy->nrssislope = 0x00010000;
		else
			phy->nrssislope = 0x00400000 / (nrssi0 - nrssi1);

		if (nrssi0 <= -4) {
			phy->nrssi[0] = nrssi0;
			phy->nrssi[1] = nrssi1;
		}
		break;
	case B43_PHYTYPE_G:
		if (phy->radio_rev >= 9)
			return;
		if (phy->radio_rev == 8)
			b43_calc_nrssi_offset(dev);

		b43_phy_write(dev, B43_PHY_G_CRS,
			      b43_phy_read(dev, B43_PHY_G_CRS) & 0x7FFF);
		b43_phy_write(dev, 0x0802, b43_phy_read(dev, 0x0802) & 0xFFFC);
		backup[7] = b43_read16(dev, 0x03E2);
		b43_write16(dev, 0x03E2, b43_read16(dev, 0x03E2) | 0x8000);
		backup[0] = b43_radio_read16(dev, 0x007A);
		backup[1] = b43_radio_read16(dev, 0x0052);
		backup[2] = b43_radio_read16(dev, 0x0043);
		backup[3] = b43_phy_read(dev, 0x0015);
		backup[4] = b43_phy_read(dev, 0x005A);
		backup[5] = b43_phy_read(dev, 0x0059);
		backup[6] = b43_phy_read(dev, 0x0058);
		backup[8] = b43_read16(dev, 0x03E6);
		backup[9] = b43_read16(dev, B43_MMIO_CHANNEL_EXT);
		if (phy->rev >= 3) {
			backup[10] = b43_phy_read(dev, 0x002E);
			backup[11] = b43_phy_read(dev, 0x002F);
			backup[12] = b43_phy_read(dev, 0x080F);
			backup[13] = b43_phy_read(dev, B43_PHY_G_LO_CONTROL);
			backup[14] = b43_phy_read(dev, 0x0801);
			backup[15] = b43_phy_read(dev, 0x0060);
			backup[16] = b43_phy_read(dev, 0x0014);
			backup[17] = b43_phy_read(dev, 0x0478);
			b43_phy_write(dev, 0x002E, 0);
			b43_phy_write(dev, B43_PHY_G_LO_CONTROL, 0);
			switch (phy->rev) {
			case 4:
			case 6:
			case 7:
				b43_phy_write(dev, 0x0478,
					      b43_phy_read(dev, 0x0478)
					      | 0x0100);
				b43_phy_write(dev, 0x0801,
					      b43_phy_read(dev, 0x0801)
					      | 0x0040);
				break;
			case 3:
			case 5:
				b43_phy_write(dev, 0x0801,
					      b43_phy_read(dev, 0x0801)
					      & 0xFFBF);
				break;
			}
			b43_phy_write(dev, 0x0060, b43_phy_read(dev, 0x0060)
				      | 0x0040);
			b43_phy_write(dev, 0x0014, b43_phy_read(dev, 0x0014)
				      | 0x0200);
		}
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) | 0x0070);
		b43_set_all_gains(dev, 0, 8, 0);
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) & 0x00F7);
		if (phy->rev >= 2) {
			b43_phy_write(dev, 0x0811,
				      (b43_phy_read(dev, 0x0811) & 0xFFCF) |
				      0x0030);
			b43_phy_write(dev, 0x0812,
				      (b43_phy_read(dev, 0x0812) & 0xFFCF) |
				      0x0010);
		}
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) | 0x0080);
		udelay(20);

		nrssi0 = (s16) ((b43_phy_read(dev, 0x047F) >> 8) & 0x003F);
		if (nrssi0 >= 0x0020)
			nrssi0 -= 0x0040;

		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) & 0x007F);
		if (phy->rev >= 2) {
			b43_phy_write(dev, 0x0003, (b43_phy_read(dev, 0x0003)
						    & 0xFF9F) | 0x0040);
		}

		b43_write16(dev, B43_MMIO_CHANNEL_EXT,
			    b43_read16(dev, B43_MMIO_CHANNEL_EXT)
			    | 0x2000);
		b43_radio_write16(dev, 0x007A,
				  b43_radio_read16(dev, 0x007A) | 0x000F);
		b43_phy_write(dev, 0x0015, 0xF330);
		if (phy->rev >= 2) {
			b43_phy_write(dev, 0x0812,
				      (b43_phy_read(dev, 0x0812) & 0xFFCF) |
				      0x0020);
			b43_phy_write(dev, 0x0811,
				      (b43_phy_read(dev, 0x0811) & 0xFFCF) |
				      0x0020);
		}

		b43_set_all_gains(dev, 3, 0, 1);
		if (phy->radio_rev == 8) {
			b43_radio_write16(dev, 0x0043, 0x001F);
		} else {
			tmp = b43_radio_read16(dev, 0x0052) & 0xFF0F;
			b43_radio_write16(dev, 0x0052, tmp | 0x0060);
			tmp = b43_radio_read16(dev, 0x0043) & 0xFFF0;
			b43_radio_write16(dev, 0x0043, tmp | 0x0009);
		}
		b43_phy_write(dev, 0x005A, 0x0480);
		b43_phy_write(dev, 0x0059, 0x0810);
		b43_phy_write(dev, 0x0058, 0x000D);
		udelay(20);
		nrssi1 = (s16) ((b43_phy_read(dev, 0x047F) >> 8) & 0x003F);
		if (nrssi1 >= 0x0020)
			nrssi1 -= 0x0040;
		if (nrssi0 == nrssi1)
			phy->nrssislope = 0x00010000;
		else
			phy->nrssislope = 0x00400000 / (nrssi0 - nrssi1);
		if (nrssi0 >= -4) {
			phy->nrssi[0] = nrssi1;
			phy->nrssi[1] = nrssi0;
		}
		if (phy->rev >= 3) {
			b43_phy_write(dev, 0x002E, backup[10]);
			b43_phy_write(dev, 0x002F, backup[11]);
			b43_phy_write(dev, 0x080F, backup[12]);
			b43_phy_write(dev, B43_PHY_G_LO_CONTROL, backup[13]);
		}
		if (phy->rev >= 2) {
			b43_phy_write(dev, 0x0812,
				      b43_phy_read(dev, 0x0812) & 0xFFCF);
			b43_phy_write(dev, 0x0811,
				      b43_phy_read(dev, 0x0811) & 0xFFCF);
		}

		b43_radio_write16(dev, 0x007A, backup[0]);
		b43_radio_write16(dev, 0x0052, backup[1]);
		b43_radio_write16(dev, 0x0043, backup[2]);
		b43_write16(dev, 0x03E2, backup[7]);
		b43_write16(dev, 0x03E6, backup[8]);
		b43_write16(dev, B43_MMIO_CHANNEL_EXT, backup[9]);
		b43_phy_write(dev, 0x0015, backup[3]);
		b43_phy_write(dev, 0x005A, backup[4]);
		b43_phy_write(dev, 0x0059, backup[5]);
		b43_phy_write(dev, 0x0058, backup[6]);
		b43_synth_pu_workaround(dev, phy->channel);
		b43_phy_write(dev, 0x0802,
			      b43_phy_read(dev, 0x0802) | (0x0001 | 0x0002));
		b43_set_original_gains(dev);
		b43_phy_write(dev, B43_PHY_G_CRS,
			      b43_phy_read(dev, B43_PHY_G_CRS) | 0x8000);
		if (phy->rev >= 3) {
			b43_phy_write(dev, 0x0801, backup[14]);
			b43_phy_write(dev, 0x0060, backup[15]);
			b43_phy_write(dev, 0x0014, backup[16]);
			b43_phy_write(dev, 0x0478, backup[17]);
		}
		b43_nrssi_mem_update(dev);
		b43_calc_nrssi_threshold(dev);
		break;
	default:
		B43_WARN_ON(1);
	}
}

void b43_calc_nrssi_threshold(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	s32 threshold;
	s32 a, b;
	s16 tmp16;
	u16 tmp_u16;

	switch (phy->type) {
	case B43_PHYTYPE_B:{
			if (phy->radio_ver != 0x2050)
				return;
			if (!
			    (dev->dev->bus->sprom.
			     boardflags_lo & B43_BFL_RSSI))
				return;

			if (phy->radio_rev >= 6) {
				threshold =
				    (phy->nrssi[1] - phy->nrssi[0]) * 32;
				threshold += 20 * (phy->nrssi[0] + 1);
				threshold /= 40;
			} else
				threshold = phy->nrssi[1] - 5;

			threshold = limit_value(threshold, 0, 0x3E);
			b43_phy_read(dev, 0x0020);	/* dummy read */
			b43_phy_write(dev, 0x0020,
				      (((u16) threshold) << 8) | 0x001C);

			if (phy->radio_rev >= 6) {
				b43_phy_write(dev, 0x0087, 0x0E0D);
				b43_phy_write(dev, 0x0086, 0x0C0B);
				b43_phy_write(dev, 0x0085, 0x0A09);
				b43_phy_write(dev, 0x0084, 0x0808);
				b43_phy_write(dev, 0x0083, 0x0808);
				b43_phy_write(dev, 0x0082, 0x0604);
				b43_phy_write(dev, 0x0081, 0x0302);
				b43_phy_write(dev, 0x0080, 0x0100);
			}
			break;
		}
	case B43_PHYTYPE_G:
		if (!phy->gmode ||
		    !(dev->dev->bus->sprom.boardflags_lo & B43_BFL_RSSI)) {
			tmp16 = b43_nrssi_hw_read(dev, 0x20);
			if (tmp16 >= 0x20)
				tmp16 -= 0x40;
			if (tmp16 < 3) {
				b43_phy_write(dev, 0x048A,
					      (b43_phy_read(dev, 0x048A)
					       & 0xF000) | 0x09EB);
			} else {
				b43_phy_write(dev, 0x048A,
					      (b43_phy_read(dev, 0x048A)
					       & 0xF000) | 0x0AED);
			}
		} else {
			if (phy->interfmode == B43_INTERFMODE_NONWLAN) {
				a = 0xE;
				b = 0xA;
			} else if (!phy->aci_wlan_automatic && phy->aci_enable) {
				a = 0x13;
				b = 0x12;
			} else {
				a = 0xE;
				b = 0x11;
			}

			a = a * (phy->nrssi[1] - phy->nrssi[0]);
			a += (phy->nrssi[0] << 6);
			if (a < 32)
				a += 31;
			else
				a += 32;
			a = a >> 6;
			a = limit_value(a, -31, 31);

			b = b * (phy->nrssi[1] - phy->nrssi[0]);
			b += (phy->nrssi[0] << 6);
			if (b < 32)
				b += 31;
			else
				b += 32;
			b = b >> 6;
			b = limit_value(b, -31, 31);

			tmp_u16 = b43_phy_read(dev, 0x048A) & 0xF000;
			tmp_u16 |= ((u32) b & 0x0000003F);
			tmp_u16 |= (((u32) a & 0x0000003F) << 6);
			b43_phy_write(dev, 0x048A, tmp_u16);
		}
		break;
	default:
		B43_WARN_ON(1);
	}
}

/* Stack implementation to save/restore values from the
 * interference mitigation code.
 * It is save to restore values in random order.
 */
static void _stack_save(u32 * _stackptr, size_t * stackidx,
			u8 id, u16 offset, u16 value)
{
	u32 *stackptr = &(_stackptr[*stackidx]);

	B43_WARN_ON(offset & 0xF000);
	B43_WARN_ON(id & 0xF0);
	*stackptr = offset;
	*stackptr |= ((u32) id) << 12;
	*stackptr |= ((u32) value) << 16;
	(*stackidx)++;
	B43_WARN_ON(*stackidx >= B43_INTERFSTACK_SIZE);
}

static u16 _stack_restore(u32 * stackptr, u8 id, u16 offset)
{
	size_t i;

	B43_WARN_ON(offset & 0xF000);
	B43_WARN_ON(id & 0xF0);
	for (i = 0; i < B43_INTERFSTACK_SIZE; i++, stackptr++) {
		if ((*stackptr & 0x00000FFF) != offset)
			continue;
		if (((*stackptr & 0x0000F000) >> 12) != id)
			continue;
		return ((*stackptr & 0xFFFF0000) >> 16);
	}
	B43_WARN_ON(1);

	return 0;
}

#define phy_stacksave(offset)					\
	do {							\
		_stack_save(stack, &stackidx, 0x1, (offset),	\
			    b43_phy_read(dev, (offset)));	\
	} while (0)
#define phy_stackrestore(offset)				\
	do {							\
		b43_phy_write(dev, (offset),		\
				  _stack_restore(stack, 0x1,	\
						 (offset)));	\
	} while (0)
#define radio_stacksave(offset)						\
	do {								\
		_stack_save(stack, &stackidx, 0x2, (offset),		\
			    b43_radio_read16(dev, (offset)));	\
	} while (0)
#define radio_stackrestore(offset)					\
	do {								\
		b43_radio_write16(dev, (offset),			\
				      _stack_restore(stack, 0x2,	\
						     (offset)));	\
	} while (0)
#define ofdmtab_stacksave(table, offset)			\
	do {							\
		_stack_save(stack, &stackidx, 0x3, (offset)|(table),	\
			    b43_ofdmtab_read16(dev, (table), (offset)));	\
	} while (0)
#define ofdmtab_stackrestore(table, offset)			\
	do {							\
		b43_ofdmtab_write16(dev, (table),	(offset),	\
				  _stack_restore(stack, 0x3,	\
						 (offset)|(table)));	\
	} while (0)

static void
b43_radio_interference_mitigation_enable(struct b43_wldev *dev, int mode)
{
	struct b43_phy *phy = &dev->phy;
	u16 tmp, flipped;
	size_t stackidx = 0;
	u32 *stack = phy->interfstack;

	switch (mode) {
	case B43_INTERFMODE_NONWLAN:
		if (phy->rev != 1) {
			b43_phy_write(dev, 0x042B,
				      b43_phy_read(dev, 0x042B) | 0x0800);
			b43_phy_write(dev, B43_PHY_G_CRS,
				      b43_phy_read(dev,
						   B43_PHY_G_CRS) & ~0x4000);
			break;
		}
		radio_stacksave(0x0078);
		tmp = (b43_radio_read16(dev, 0x0078) & 0x001E);
		flipped = flip_4bit(tmp);
		if (flipped < 10 && flipped >= 8)
			flipped = 7;
		else if (flipped >= 10)
			flipped -= 3;
		flipped = flip_4bit(flipped);
		flipped = (flipped << 1) | 0x0020;
		b43_radio_write16(dev, 0x0078, flipped);

		b43_calc_nrssi_threshold(dev);

		phy_stacksave(0x0406);
		b43_phy_write(dev, 0x0406, 0x7E28);

		b43_phy_write(dev, 0x042B, b43_phy_read(dev, 0x042B) | 0x0800);
		b43_phy_write(dev, B43_PHY_RADIO_BITFIELD,
			      b43_phy_read(dev,
					   B43_PHY_RADIO_BITFIELD) | 0x1000);

		phy_stacksave(0x04A0);
		b43_phy_write(dev, 0x04A0,
			      (b43_phy_read(dev, 0x04A0) & 0xC0C0) | 0x0008);
		phy_stacksave(0x04A1);
		b43_phy_write(dev, 0x04A1,
			      (b43_phy_read(dev, 0x04A1) & 0xC0C0) | 0x0605);
		phy_stacksave(0x04A2);
		b43_phy_write(dev, 0x04A2,
			      (b43_phy_read(dev, 0x04A2) & 0xC0C0) | 0x0204);
		phy_stacksave(0x04A8);
		b43_phy_write(dev, 0x04A8,
			      (b43_phy_read(dev, 0x04A8) & 0xC0C0) | 0x0803);
		phy_stacksave(0x04AB);
		b43_phy_write(dev, 0x04AB,
			      (b43_phy_read(dev, 0x04AB) & 0xC0C0) | 0x0605);

		phy_stacksave(0x04A7);
		b43_phy_write(dev, 0x04A7, 0x0002);
		phy_stacksave(0x04A3);
		b43_phy_write(dev, 0x04A3, 0x287A);
		phy_stacksave(0x04A9);
		b43_phy_write(dev, 0x04A9, 0x2027);
		phy_stacksave(0x0493);
		b43_phy_write(dev, 0x0493, 0x32F5);
		phy_stacksave(0x04AA);
		b43_phy_write(dev, 0x04AA, 0x2027);
		phy_stacksave(0x04AC);
		b43_phy_write(dev, 0x04AC, 0x32F5);
		break;
	case B43_INTERFMODE_MANUALWLAN:
		if (b43_phy_read(dev, 0x0033) & 0x0800)
			break;

		phy->aci_enable = 1;

		phy_stacksave(B43_PHY_RADIO_BITFIELD);
		phy_stacksave(B43_PHY_G_CRS);
		if (phy->rev < 2) {
			phy_stacksave(0x0406);
		} else {
			phy_stacksave(0x04C0);
			phy_stacksave(0x04C1);
		}
		phy_stacksave(0x0033);
		phy_stacksave(0x04A7);
		phy_stacksave(0x04A3);
		phy_stacksave(0x04A9);
		phy_stacksave(0x04AA);
		phy_stacksave(0x04AC);
		phy_stacksave(0x0493);
		phy_stacksave(0x04A1);
		phy_stacksave(0x04A0);
		phy_stacksave(0x04A2);
		phy_stacksave(0x048A);
		phy_stacksave(0x04A8);
		phy_stacksave(0x04AB);
		if (phy->rev == 2) {
			phy_stacksave(0x04AD);
			phy_stacksave(0x04AE);
		} else if (phy->rev >= 3) {
			phy_stacksave(0x04AD);
			phy_stacksave(0x0415);
			phy_stacksave(0x0416);
			phy_stacksave(0x0417);
			ofdmtab_stacksave(0x1A00, 0x2);
			ofdmtab_stacksave(0x1A00, 0x3);
		}
		phy_stacksave(0x042B);
		phy_stacksave(0x048C);

		b43_phy_write(dev, B43_PHY_RADIO_BITFIELD,
			      b43_phy_read(dev, B43_PHY_RADIO_BITFIELD)
			      & ~0x1000);
		b43_phy_write(dev, B43_PHY_G_CRS,
			      (b43_phy_read(dev, B43_PHY_G_CRS)
			       & 0xFFFC) | 0x0002);

		b43_phy_write(dev, 0x0033, 0x0800);
		b43_phy_write(dev, 0x04A3, 0x2027);
		b43_phy_write(dev, 0x04A9, 0x1CA8);
		b43_phy_write(dev, 0x0493, 0x287A);
		b43_phy_write(dev, 0x04AA, 0x1CA8);
		b43_phy_write(dev, 0x04AC, 0x287A);

		b43_phy_write(dev, 0x04A0, (b43_phy_read(dev, 0x04A0)
					    & 0xFFC0) | 0x001A);
		b43_phy_write(dev, 0x04A7, 0x000D);

		if (phy->rev < 2) {
			b43_phy_write(dev, 0x0406, 0xFF0D);
		} else if (phy->rev == 2) {
			b43_phy_write(dev, 0x04C0, 0xFFFF);
			b43_phy_write(dev, 0x04C1, 0x00A9);
		} else {
			b43_phy_write(dev, 0x04C0, 0x00C1);
			b43_phy_write(dev, 0x04C1, 0x0059);
		}

		b43_phy_write(dev, 0x04A1, (b43_phy_read(dev, 0x04A1)
					    & 0xC0FF) | 0x1800);
		b43_phy_write(dev, 0x04A1, (b43_phy_read(dev, 0x04A1)
					    & 0xFFC0) | 0x0015);
		b43_phy_write(dev, 0x04A8, (b43_phy_read(dev, 0x04A8)
					    & 0xCFFF) | 0x1000);
		b43_phy_write(dev, 0x04A8, (b43_phy_read(dev, 0x04A8)
					    & 0xF0FF) | 0x0A00);
		b43_phy_write(dev, 0x04AB, (b43_phy_read(dev, 0x04AB)
					    & 0xCFFF) | 0x1000);
		b43_phy_write(dev, 0x04AB, (b43_phy_read(dev, 0x04AB)
					    & 0xF0FF) | 0x0800);
		b43_phy_write(dev, 0x04AB, (b43_phy_read(dev, 0x04AB)
					    & 0xFFCF) | 0x0010);
		b43_phy_write(dev, 0x04AB, (b43_phy_read(dev, 0x04AB)
					    & 0xFFF0) | 0x0005);
		b43_phy_write(dev, 0x04A8, (b43_phy_read(dev, 0x04A8)
					    & 0xFFCF) | 0x0010);
		b43_phy_write(dev, 0x04A8, (b43_phy_read(dev, 0x04A8)
					    & 0xFFF0) | 0x0006);
		b43_phy_write(dev, 0x04A2, (b43_phy_read(dev, 0x04A2)
					    & 0xF0FF) | 0x0800);
		b43_phy_write(dev, 0x04A0, (b43_phy_read(dev, 0x04A0)
					    & 0xF0FF) | 0x0500);
		b43_phy_write(dev, 0x04A2, (b43_phy_read(dev, 0x04A2)
					    & 0xFFF0) | 0x000B);

		if (phy->rev >= 3) {
			b43_phy_write(dev, 0x048A, b43_phy_read(dev, 0x048A)
				      & ~0x8000);
			b43_phy_write(dev, 0x0415, (b43_phy_read(dev, 0x0415)
						    & 0x8000) | 0x36D8);
			b43_phy_write(dev, 0x0416, (b43_phy_read(dev, 0x0416)
						    & 0x8000) | 0x36D8);
			b43_phy_write(dev, 0x0417, (b43_phy_read(dev, 0x0417)
						    & 0xFE00) | 0x016D);
		} else {
			b43_phy_write(dev, 0x048A, b43_phy_read(dev, 0x048A)
				      | 0x1000);
			b43_phy_write(dev, 0x048A, (b43_phy_read(dev, 0x048A)
						    & 0x9FFF) | 0x2000);
			b43_hf_write(dev, b43_hf_read(dev) | B43_HF_ACIW);
		}
		if (phy->rev >= 2) {
			b43_phy_write(dev, 0x042B, b43_phy_read(dev, 0x042B)
				      | 0x0800);
		}
		b43_phy_write(dev, 0x048C, (b43_phy_read(dev, 0x048C)
					    & 0xF0FF) | 0x0200);
		if (phy->rev == 2) {
			b43_phy_write(dev, 0x04AE, (b43_phy_read(dev, 0x04AE)
						    & 0xFF00) | 0x007F);
			b43_phy_write(dev, 0x04AD, (b43_phy_read(dev, 0x04AD)
						    & 0x00FF) | 0x1300);
		} else if (phy->rev >= 6) {
			b43_ofdmtab_write16(dev, 0x1A00, 0x3, 0x007F);
			b43_ofdmtab_write16(dev, 0x1A00, 0x2, 0x007F);
			b43_phy_write(dev, 0x04AD, b43_phy_read(dev, 0x04AD)
				      & 0x00FF);
		}
		b43_calc_nrssi_slope(dev);
		break;
	default:
		B43_WARN_ON(1);
	}
}

static void
b43_radio_interference_mitigation_disable(struct b43_wldev *dev, int mode)
{
	struct b43_phy *phy = &dev->phy;
	u32 *stack = phy->interfstack;

	switch (mode) {
	case B43_INTERFMODE_NONWLAN:
		if (phy->rev != 1) {
			b43_phy_write(dev, 0x042B,
				      b43_phy_read(dev, 0x042B) & ~0x0800);
			b43_phy_write(dev, B43_PHY_G_CRS,
				      b43_phy_read(dev,
						   B43_PHY_G_CRS) | 0x4000);
			break;
		}
		radio_stackrestore(0x0078);
		b43_calc_nrssi_threshold(dev);
		phy_stackrestore(0x0406);
		b43_phy_write(dev, 0x042B, b43_phy_read(dev, 0x042B) & ~0x0800);
		if (!dev->bad_frames_preempt) {
			b43_phy_write(dev, B43_PHY_RADIO_BITFIELD,
				      b43_phy_read(dev, B43_PHY_RADIO_BITFIELD)
				      & ~(1 << 11));
		}
		b43_phy_write(dev, B43_PHY_G_CRS,
			      b43_phy_read(dev, B43_PHY_G_CRS) | 0x4000);
		phy_stackrestore(0x04A0);
		phy_stackrestore(0x04A1);
		phy_stackrestore(0x04A2);
		phy_stackrestore(0x04A8);
		phy_stackrestore(0x04AB);
		phy_stackrestore(0x04A7);
		phy_stackrestore(0x04A3);
		phy_stackrestore(0x04A9);
		phy_stackrestore(0x0493);
		phy_stackrestore(0x04AA);
		phy_stackrestore(0x04AC);
		break;
	case B43_INTERFMODE_MANUALWLAN:
		if (!(b43_phy_read(dev, 0x0033) & 0x0800))
			break;

		phy->aci_enable = 0;

		phy_stackrestore(B43_PHY_RADIO_BITFIELD);
		phy_stackrestore(B43_PHY_G_CRS);
		phy_stackrestore(0x0033);
		phy_stackrestore(0x04A3);
		phy_stackrestore(0x04A9);
		phy_stackrestore(0x0493);
		phy_stackrestore(0x04AA);
		phy_stackrestore(0x04AC);
		phy_stackrestore(0x04A0);
		phy_stackrestore(0x04A7);
		if (phy->rev >= 2) {
			phy_stackrestore(0x04C0);
			phy_stackrestore(0x04C1);
		} else
			phy_stackrestore(0x0406);
		phy_stackrestore(0x04A1);
		phy_stackrestore(0x04AB);
		phy_stackrestore(0x04A8);
		if (phy->rev == 2) {
			phy_stackrestore(0x04AD);
			phy_stackrestore(0x04AE);
		} else if (phy->rev >= 3) {
			phy_stackrestore(0x04AD);
			phy_stackrestore(0x0415);
			phy_stackrestore(0x0416);
			phy_stackrestore(0x0417);
			ofdmtab_stackrestore(0x1A00, 0x2);
			ofdmtab_stackrestore(0x1A00, 0x3);
		}
		phy_stackrestore(0x04A2);
		phy_stackrestore(0x048A);
		phy_stackrestore(0x042B);
		phy_stackrestore(0x048C);
		b43_hf_write(dev, b43_hf_read(dev) & ~B43_HF_ACIW);
		b43_calc_nrssi_slope(dev);
		break;
	default:
		B43_WARN_ON(1);
	}
}

#undef phy_stacksave
#undef phy_stackrestore
#undef radio_stacksave
#undef radio_stackrestore
#undef ofdmtab_stacksave
#undef ofdmtab_stackrestore

int b43_radio_set_interference_mitigation(struct b43_wldev *dev, int mode)
{
	struct b43_phy *phy = &dev->phy;
	int currentmode;

	if ((phy->type != B43_PHYTYPE_G) || (phy->rev == 0) || (!phy->gmode))
		return -ENODEV;

	phy->aci_wlan_automatic = 0;
	switch (mode) {
	case B43_INTERFMODE_AUTOWLAN:
		phy->aci_wlan_automatic = 1;
		if (phy->aci_enable)
			mode = B43_INTERFMODE_MANUALWLAN;
		else
			mode = B43_INTERFMODE_NONE;
		break;
	case B43_INTERFMODE_NONE:
	case B43_INTERFMODE_NONWLAN:
	case B43_INTERFMODE_MANUALWLAN:
		break;
	default:
		return -EINVAL;
	}

	currentmode = phy->interfmode;
	if (currentmode == mode)
		return 0;
	if (currentmode != B43_INTERFMODE_NONE)
		b43_radio_interference_mitigation_disable(dev, currentmode);

	if (mode == B43_INTERFMODE_NONE) {
		phy->aci_enable = 0;
		phy->aci_hw_rssi = 0;
	} else
		b43_radio_interference_mitigation_enable(dev, mode);
	phy->interfmode = mode;

	return 0;
}

static u16 b43_radio_core_calibration_value(struct b43_wldev *dev)
{
	u16 reg, index, ret;

	static const u8 rcc_table[] = {
		0x02, 0x03, 0x01, 0x0F,
		0x06, 0x07, 0x05, 0x0F,
		0x0A, 0x0B, 0x09, 0x0F,
		0x0E, 0x0F, 0x0D, 0x0F,
	};

	reg = b43_radio_read16(dev, 0x60);
	index = (reg & 0x001E) >> 1;
	ret = rcc_table[index] << 1;
	ret |= (reg & 0x0001);
	ret |= 0x0020;

	return ret;
}

#define LPD(L, P, D)	(((L) << 2) | ((P) << 1) | ((D) << 0))
static u16 radio2050_rfover_val(struct b43_wldev *dev,
				u16 phy_register, unsigned int lpd)
{
	struct b43_phy *phy = &dev->phy;
	struct ssb_sprom *sprom = &(dev->dev->bus->sprom);

	if (!phy->gmode)
		return 0;

	if (has_loopback_gain(phy)) {
		int max_lb_gain = phy->max_lb_gain;
		u16 extlna;
		u16 i;

		if (phy->radio_rev == 8)
			max_lb_gain += 0x3E;
		else
			max_lb_gain += 0x26;
		if (max_lb_gain >= 0x46) {
			extlna = 0x3000;
			max_lb_gain -= 0x46;
		} else if (max_lb_gain >= 0x3A) {
			extlna = 0x1000;
			max_lb_gain -= 0x3A;
		} else if (max_lb_gain >= 0x2E) {
			extlna = 0x2000;
			max_lb_gain -= 0x2E;
		} else {
			extlna = 0;
			max_lb_gain -= 0x10;
		}

		for (i = 0; i < 16; i++) {
			max_lb_gain -= (i * 6);
			if (max_lb_gain < 6)
				break;
		}

		if ((phy->rev < 7) ||
		    !(sprom->boardflags_lo & B43_BFL_EXTLNA)) {
			if (phy_register == B43_PHY_RFOVER) {
				return 0x1B3;
			} else if (phy_register == B43_PHY_RFOVERVAL) {
				extlna |= (i << 8);
				switch (lpd) {
				case LPD(0, 1, 1):
					return 0x0F92;
				case LPD(0, 0, 1):
				case LPD(1, 0, 1):
					return (0x0092 | extlna);
				case LPD(1, 0, 0):
					return (0x0093 | extlna);
				}
				B43_WARN_ON(1);
			}
			B43_WARN_ON(1);
		} else {
			if (phy_register == B43_PHY_RFOVER) {
				return 0x9B3;
			} else if (phy_register == B43_PHY_RFOVERVAL) {
				if (extlna)
					extlna |= 0x8000;
				extlna |= (i << 8);
				switch (lpd) {
				case LPD(0, 1, 1):
					return 0x8F92;
				case LPD(0, 0, 1):
					return (0x8092 | extlna);
				case LPD(1, 0, 1):
					return (0x2092 | extlna);
				case LPD(1, 0, 0):
					return (0x2093 | extlna);
				}
				B43_WARN_ON(1);
			}
			B43_WARN_ON(1);
		}
	} else {
		if ((phy->rev < 7) ||
		    !(sprom->boardflags_lo & B43_BFL_EXTLNA)) {
			if (phy_register == B43_PHY_RFOVER) {
				return 0x1B3;
			} else if (phy_register == B43_PHY_RFOVERVAL) {
				switch (lpd) {
				case LPD(0, 1, 1):
					return 0x0FB2;
				case LPD(0, 0, 1):
					return 0x00B2;
				case LPD(1, 0, 1):
					return 0x30B2;
				case LPD(1, 0, 0):
					return 0x30B3;
				}
				B43_WARN_ON(1);
			}
			B43_WARN_ON(1);
		} else {
			if (phy_register == B43_PHY_RFOVER) {
				return 0x9B3;
			} else if (phy_register == B43_PHY_RFOVERVAL) {
				switch (lpd) {
				case LPD(0, 1, 1):
					return 0x8FB2;
				case LPD(0, 0, 1):
					return 0x80B2;
				case LPD(1, 0, 1):
					return 0x20B2;
				case LPD(1, 0, 0):
					return 0x20B3;
				}
				B43_WARN_ON(1);
			}
			B43_WARN_ON(1);
		}
	}
	return 0;
}

struct init2050_saved_values {
	/* Core registers */
	u16 reg_3EC;
	u16 reg_3E6;
	u16 reg_3F4;
	/* Radio registers */
	u16 radio_43;
	u16 radio_51;
	u16 radio_52;
	/* PHY registers */
	u16 phy_pgactl;
	u16 phy_cck_5A;
	u16 phy_cck_59;
	u16 phy_cck_58;
	u16 phy_cck_30;
	u16 phy_rfover;
	u16 phy_rfoverval;
	u16 phy_analogover;
	u16 phy_analogoverval;
	u16 phy_crs0;
	u16 phy_classctl;
	u16 phy_lo_mask;
	u16 phy_lo_ctl;
	u16 phy_syncctl;
};

u16 b43_radio_init2050(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	struct init2050_saved_values sav;
	u16 rcc;
	u16 radio78;
	u16 ret;
	u16 i, j;
	u32 tmp1 = 0, tmp2 = 0;

	memset(&sav, 0, sizeof(sav));	/* get rid of "may be used uninitialized..." */

	sav.radio_43 = b43_radio_read16(dev, 0x43);
	sav.radio_51 = b43_radio_read16(dev, 0x51);
	sav.radio_52 = b43_radio_read16(dev, 0x52);
	sav.phy_pgactl = b43_phy_read(dev, B43_PHY_PGACTL);
	sav.phy_cck_5A = b43_phy_read(dev, B43_PHY_CCK(0x5A));
	sav.phy_cck_59 = b43_phy_read(dev, B43_PHY_CCK(0x59));
	sav.phy_cck_58 = b43_phy_read(dev, B43_PHY_CCK(0x58));

	if (phy->type == B43_PHYTYPE_B) {
		sav.phy_cck_30 = b43_phy_read(dev, B43_PHY_CCK(0x30));
		sav.reg_3EC = b43_read16(dev, 0x3EC);

		b43_phy_write(dev, B43_PHY_CCK(0x30), 0xFF);
		b43_write16(dev, 0x3EC, 0x3F3F);
	} else if (phy->gmode || phy->rev >= 2) {
		sav.phy_rfover = b43_phy_read(dev, B43_PHY_RFOVER);
		sav.phy_rfoverval = b43_phy_read(dev, B43_PHY_RFOVERVAL);
		sav.phy_analogover = b43_phy_read(dev, B43_PHY_ANALOGOVER);
		sav.phy_analogoverval =
		    b43_phy_read(dev, B43_PHY_ANALOGOVERVAL);
		sav.phy_crs0 = b43_phy_read(dev, B43_PHY_CRS0);
		sav.phy_classctl = b43_phy_read(dev, B43_PHY_CLASSCTL);

		b43_phy_write(dev, B43_PHY_ANALOGOVER,
			      b43_phy_read(dev, B43_PHY_ANALOGOVER)
			      | 0x0003);
		b43_phy_write(dev, B43_PHY_ANALOGOVERVAL,
			      b43_phy_read(dev, B43_PHY_ANALOGOVERVAL)
			      & 0xFFFC);
		b43_phy_write(dev, B43_PHY_CRS0, b43_phy_read(dev, B43_PHY_CRS0)
			      & 0x7FFF);
		b43_phy_write(dev, B43_PHY_CLASSCTL,
			      b43_phy_read(dev, B43_PHY_CLASSCTL)
			      & 0xFFFC);
		if (has_loopback_gain(phy)) {
			sav.phy_lo_mask = b43_phy_read(dev, B43_PHY_LO_MASK);
			sav.phy_lo_ctl = b43_phy_read(dev, B43_PHY_LO_CTL);

			if (phy->rev >= 3)
				b43_phy_write(dev, B43_PHY_LO_MASK, 0xC020);
			else
				b43_phy_write(dev, B43_PHY_LO_MASK, 0x8020);
			b43_phy_write(dev, B43_PHY_LO_CTL, 0);
		}

		b43_phy_write(dev, B43_PHY_RFOVERVAL,
			      radio2050_rfover_val(dev, B43_PHY_RFOVERVAL,
						   LPD(0, 1, 1)));
		b43_phy_write(dev, B43_PHY_RFOVER,
			      radio2050_rfover_val(dev, B43_PHY_RFOVER, 0));
	}
	b43_write16(dev, 0x3E2, b43_read16(dev, 0x3E2) | 0x8000);

	sav.phy_syncctl = b43_phy_read(dev, B43_PHY_SYNCCTL);
	b43_phy_write(dev, B43_PHY_SYNCCTL, b43_phy_read(dev, B43_PHY_SYNCCTL)
		      & 0xFF7F);
	sav.reg_3E6 = b43_read16(dev, 0x3E6);
	sav.reg_3F4 = b43_read16(dev, 0x3F4);

	if (phy->analog == 0) {
		b43_write16(dev, 0x03E6, 0x0122);
	} else {
		if (phy->analog >= 2) {
			b43_phy_write(dev, B43_PHY_CCK(0x03),
				      (b43_phy_read(dev, B43_PHY_CCK(0x03))
				       & 0xFFBF) | 0x40);
		}
		b43_write16(dev, B43_MMIO_CHANNEL_EXT,
			    (b43_read16(dev, B43_MMIO_CHANNEL_EXT) | 0x2000));
	}

	rcc = b43_radio_core_calibration_value(dev);

	if (phy->type == B43_PHYTYPE_B)
		b43_radio_write16(dev, 0x78, 0x26);
	if (phy->gmode || phy->rev >= 2) {
		b43_phy_write(dev, B43_PHY_RFOVERVAL,
			      radio2050_rfover_val(dev, B43_PHY_RFOVERVAL,
						   LPD(0, 1, 1)));
	}
	b43_phy_write(dev, B43_PHY_PGACTL, 0xBFAF);
	b43_phy_write(dev, B43_PHY_CCK(0x2B), 0x1403);
	if (phy->gmode || phy->rev >= 2) {
		b43_phy_write(dev, B43_PHY_RFOVERVAL,
			      radio2050_rfover_val(dev, B43_PHY_RFOVERVAL,
						   LPD(0, 0, 1)));
	}
	b43_phy_write(dev, B43_PHY_PGACTL, 0xBFA0);
	b43_radio_write16(dev, 0x51, b43_radio_read16(dev, 0x51)
			  | 0x0004);
	if (phy->radio_rev == 8) {
		b43_radio_write16(dev, 0x43, 0x1F);
	} else {
		b43_radio_write16(dev, 0x52, 0);
		b43_radio_write16(dev, 0x43, (b43_radio_read16(dev, 0x43)
					      & 0xFFF0) | 0x0009);
	}
	b43_phy_write(dev, B43_PHY_CCK(0x58), 0);

	for (i = 0; i < 16; i++) {
		b43_phy_write(dev, B43_PHY_CCK(0x5A), 0x0480);
		b43_phy_write(dev, B43_PHY_CCK(0x59), 0xC810);
		b43_phy_write(dev, B43_PHY_CCK(0x58), 0x000D);
		if (phy->gmode || phy->rev >= 2) {
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      radio2050_rfover_val(dev,
							   B43_PHY_RFOVERVAL,
							   LPD(1, 0, 1)));
		}
		b43_phy_write(dev, B43_PHY_PGACTL, 0xAFB0);
		udelay(10);
		if (phy->gmode || phy->rev >= 2) {
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      radio2050_rfover_val(dev,
							   B43_PHY_RFOVERVAL,
							   LPD(1, 0, 1)));
		}
		b43_phy_write(dev, B43_PHY_PGACTL, 0xEFB0);
		udelay(10);
		if (phy->gmode || phy->rev >= 2) {
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      radio2050_rfover_val(dev,
							   B43_PHY_RFOVERVAL,
							   LPD(1, 0, 0)));
		}
		b43_phy_write(dev, B43_PHY_PGACTL, 0xFFF0);
		udelay(20);
		tmp1 += b43_phy_read(dev, B43_PHY_LO_LEAKAGE);
		b43_phy_write(dev, B43_PHY_CCK(0x58), 0);
		if (phy->gmode || phy->rev >= 2) {
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      radio2050_rfover_val(dev,
							   B43_PHY_RFOVERVAL,
							   LPD(1, 0, 1)));
		}
		b43_phy_write(dev, B43_PHY_PGACTL, 0xAFB0);
	}
	udelay(10);

	b43_phy_write(dev, B43_PHY_CCK(0x58), 0);
	tmp1++;
	tmp1 >>= 9;

	for (i = 0; i < 16; i++) {
		radio78 = ((flip_4bit(i) << 1) | 0x20);
		b43_radio_write16(dev, 0x78, radio78);
		udelay(10);
		for (j = 0; j < 16; j++) {
			b43_phy_write(dev, B43_PHY_CCK(0x5A), 0x0D80);
			b43_phy_write(dev, B43_PHY_CCK(0x59), 0xC810);
			b43_phy_write(dev, B43_PHY_CCK(0x58), 0x000D);
			if (phy->gmode || phy->rev >= 2) {
				b43_phy_write(dev, B43_PHY_RFOVERVAL,
					      radio2050_rfover_val(dev,
								   B43_PHY_RFOVERVAL,
								   LPD(1, 0,
								       1)));
			}
			b43_phy_write(dev, B43_PHY_PGACTL, 0xAFB0);
			udelay(10);
			if (phy->gmode || phy->rev >= 2) {
				b43_phy_write(dev, B43_PHY_RFOVERVAL,
					      radio2050_rfover_val(dev,
								   B43_PHY_RFOVERVAL,
								   LPD(1, 0,
								       1)));
			}
			b43_phy_write(dev, B43_PHY_PGACTL, 0xEFB0);
			udelay(10);
			if (phy->gmode || phy->rev >= 2) {
				b43_phy_write(dev, B43_PHY_RFOVERVAL,
					      radio2050_rfover_val(dev,
								   B43_PHY_RFOVERVAL,
								   LPD(1, 0,
								       0)));
			}
			b43_phy_write(dev, B43_PHY_PGACTL, 0xFFF0);
			udelay(10);
			tmp2 += b43_phy_read(dev, B43_PHY_LO_LEAKAGE);
			b43_phy_write(dev, B43_PHY_CCK(0x58), 0);
			if (phy->gmode || phy->rev >= 2) {
				b43_phy_write(dev, B43_PHY_RFOVERVAL,
					      radio2050_rfover_val(dev,
								   B43_PHY_RFOVERVAL,
								   LPD(1, 0,
								       1)));
			}
			b43_phy_write(dev, B43_PHY_PGACTL, 0xAFB0);
		}
		tmp2++;
		tmp2 >>= 8;
		if (tmp1 < tmp2)
			break;
	}

	/* Restore the registers */
	b43_phy_write(dev, B43_PHY_PGACTL, sav.phy_pgactl);
	b43_radio_write16(dev, 0x51, sav.radio_51);
	b43_radio_write16(dev, 0x52, sav.radio_52);
	b43_radio_write16(dev, 0x43, sav.radio_43);
	b43_phy_write(dev, B43_PHY_CCK(0x5A), sav.phy_cck_5A);
	b43_phy_write(dev, B43_PHY_CCK(0x59), sav.phy_cck_59);
	b43_phy_write(dev, B43_PHY_CCK(0x58), sav.phy_cck_58);
	b43_write16(dev, 0x3E6, sav.reg_3E6);
	if (phy->analog != 0)
		b43_write16(dev, 0x3F4, sav.reg_3F4);
	b43_phy_write(dev, B43_PHY_SYNCCTL, sav.phy_syncctl);
	b43_synth_pu_workaround(dev, phy->channel);
	if (phy->type == B43_PHYTYPE_B) {
		b43_phy_write(dev, B43_PHY_CCK(0x30), sav.phy_cck_30);
		b43_write16(dev, 0x3EC, sav.reg_3EC);
	} else if (phy->gmode) {
		b43_write16(dev, B43_MMIO_PHY_RADIO,
			    b43_read16(dev, B43_MMIO_PHY_RADIO)
			    & 0x7FFF);
		b43_phy_write(dev, B43_PHY_RFOVER, sav.phy_rfover);
		b43_phy_write(dev, B43_PHY_RFOVERVAL, sav.phy_rfoverval);
		b43_phy_write(dev, B43_PHY_ANALOGOVER, sav.phy_analogover);
		b43_phy_write(dev, B43_PHY_ANALOGOVERVAL,
			      sav.phy_analogoverval);
		b43_phy_write(dev, B43_PHY_CRS0, sav.phy_crs0);
		b43_phy_write(dev, B43_PHY_CLASSCTL, sav.phy_classctl);
		if (has_loopback_gain(phy)) {
			b43_phy_write(dev, B43_PHY_LO_MASK, sav.phy_lo_mask);
			b43_phy_write(dev, B43_PHY_LO_CTL, sav.phy_lo_ctl);
		}
	}
	if (i > 15)
		ret = radio78;
	else
		ret = rcc;

	return ret;
}

void b43_radio_init2060(struct b43_wldev *dev)
{
	int err;

	b43_radio_write16(dev, 0x0004, 0x00C0);
	b43_radio_write16(dev, 0x0005, 0x0008);
	b43_radio_write16(dev, 0x0009, 0x0040);
	b43_radio_write16(dev, 0x0005, 0x00AA);
	b43_radio_write16(dev, 0x0032, 0x008F);
	b43_radio_write16(dev, 0x0006, 0x008F);
	b43_radio_write16(dev, 0x0034, 0x008F);
	b43_radio_write16(dev, 0x002C, 0x0007);
	b43_radio_write16(dev, 0x0082, 0x0080);
	b43_radio_write16(dev, 0x0080, 0x0000);
	b43_radio_write16(dev, 0x003F, 0x00DA);
	b43_radio_write16(dev, 0x0005, b43_radio_read16(dev, 0x0005) & ~0x0008);
	b43_radio_write16(dev, 0x0081, b43_radio_read16(dev, 0x0081) & ~0x0010);
	b43_radio_write16(dev, 0x0081, b43_radio_read16(dev, 0x0081) & ~0x0020);
	b43_radio_write16(dev, 0x0081, b43_radio_read16(dev, 0x0081) & ~0x0020);
	msleep(1);		/* delay 400usec */

	b43_radio_write16(dev, 0x0081,
			  (b43_radio_read16(dev, 0x0081) & ~0x0020) | 0x0010);
	msleep(1);		/* delay 400usec */

	b43_radio_write16(dev, 0x0005,
			  (b43_radio_read16(dev, 0x0005) & ~0x0008) | 0x0008);
	b43_radio_write16(dev, 0x0085, b43_radio_read16(dev, 0x0085) & ~0x0010);
	b43_radio_write16(dev, 0x0005, b43_radio_read16(dev, 0x0005) & ~0x0008);
	b43_radio_write16(dev, 0x0081, b43_radio_read16(dev, 0x0081) & ~0x0040);
	b43_radio_write16(dev, 0x0081,
			  (b43_radio_read16(dev, 0x0081) & ~0x0040) | 0x0040);
	b43_radio_write16(dev, 0x0005,
			  (b43_radio_read16(dev, 0x0081) & ~0x0008) | 0x0008);
	b43_phy_write(dev, 0x0063, 0xDDC6);
	b43_phy_write(dev, 0x0069, 0x07BE);
	b43_phy_write(dev, 0x006A, 0x0000);

	err = b43_radio_selectchannel(dev, B43_DEFAULT_CHANNEL_A, 0);
	B43_WARN_ON(err);

	msleep(1);
}

static inline u16 freq_r3A_value(u16 frequency)
{
	u16 value;

	if (frequency < 5091)
		value = 0x0040;
	else if (frequency < 5321)
		value = 0x0000;
	else if (frequency < 5806)
		value = 0x0080;
	else
		value = 0x0040;

	return value;
}

void b43_radio_set_tx_iq(struct b43_wldev *dev)
{
	static const u8 data_high[5] = { 0x00, 0x40, 0x80, 0x90, 0xD0 };
	static const u8 data_low[5] = { 0x00, 0x01, 0x05, 0x06, 0x0A };
	u16 tmp = b43_radio_read16(dev, 0x001E);
	int i, j;

	for (i = 0; i < 5; i++) {
		for (j = 0; j < 5; j++) {
			if (tmp == (data_high[i] << 4 | data_low[j])) {
				b43_phy_write(dev, 0x0069,
					      (i - j) << 8 | 0x00C0);
				return;
			}
		}
	}
}

int b43_radio_selectchannel(struct b43_wldev *dev,
			    u8 channel, int synthetic_pu_workaround)
{
	struct b43_phy *phy = &dev->phy;
	u16 r8, tmp;
	u16 freq;
	u16 channelcookie, savedcookie;
	int err = 0;

	if (channel == 0xFF) {
		switch (phy->type) {
		case B43_PHYTYPE_A:
			channel = B43_DEFAULT_CHANNEL_A;
			break;
		case B43_PHYTYPE_B:
		case B43_PHYTYPE_G:
			channel = B43_DEFAULT_CHANNEL_BG;
			break;
		case B43_PHYTYPE_N:
			//FIXME check if we are on 2.4GHz or 5GHz and set a default channel.
			channel = 1;
			break;
		default:
			B43_WARN_ON(1);
		}
	}

	/* First we set the channel radio code to prevent the
	 * firmware from sending ghost packets.
	 */
	channelcookie = channel;
	if (0 /*FIXME on 5Ghz */)
		channelcookie |= 0x100;
	//FIXME set 40Mhz flag if required
	savedcookie = b43_shm_read16(dev, B43_SHM_SHARED, B43_SHM_SH_CHAN);
	b43_shm_write16(dev, B43_SHM_SHARED, B43_SHM_SH_CHAN, channelcookie);

	switch (phy->type) {
	case B43_PHYTYPE_A:
		if (channel > 200) {
			err = -EINVAL;
			goto out;
		}
		freq = channel2freq_a(channel);

		r8 = b43_radio_read16(dev, 0x0008);
		b43_write16(dev, 0x03F0, freq);
		b43_radio_write16(dev, 0x0008, r8);

		//TODO: write max channel TX power? to Radio 0x2D
		tmp = b43_radio_read16(dev, 0x002E);
		tmp &= 0x0080;
		//TODO: OR tmp with the Power out estimation for this channel?
		b43_radio_write16(dev, 0x002E, tmp);

		if (freq >= 4920 && freq <= 5500) {
			/*
			 * r8 = (((freq * 15 * 0xE1FC780F) >> 32) / 29) & 0x0F;
			 *    = (freq * 0.025862069
			 */
			r8 = 3 * freq / 116;	/* is equal to r8 = freq * 0.025862 */
		}
		b43_radio_write16(dev, 0x0007, (r8 << 4) | r8);
		b43_radio_write16(dev, 0x0020, (r8 << 4) | r8);
		b43_radio_write16(dev, 0x0021, (r8 << 4) | r8);
		b43_radio_write16(dev, 0x0022, (b43_radio_read16(dev, 0x0022)
						& 0x000F) | (r8 << 4));
		b43_radio_write16(dev, 0x002A, (r8 << 4));
		b43_radio_write16(dev, 0x002B, (r8 << 4));
		b43_radio_write16(dev, 0x0008, (b43_radio_read16(dev, 0x0008)
						& 0x00F0) | (r8 << 4));
		b43_radio_write16(dev, 0x0029, (b43_radio_read16(dev, 0x0029)
						& 0xFF0F) | 0x00B0);
		b43_radio_write16(dev, 0x0035, 0x00AA);
		b43_radio_write16(dev, 0x0036, 0x0085);
		b43_radio_write16(dev, 0x003A, (b43_radio_read16(dev, 0x003A)
						& 0xFF20) |
				  freq_r3A_value(freq));
		b43_radio_write16(dev, 0x003D,
				  b43_radio_read16(dev, 0x003D) & 0x00FF);
		b43_radio_write16(dev, 0x0081, (b43_radio_read16(dev, 0x0081)
						& 0xFF7F) | 0x0080);
		b43_radio_write16(dev, 0x0035,
				  b43_radio_read16(dev, 0x0035) & 0xFFEF);
		b43_radio_write16(dev, 0x0035, (b43_radio_read16(dev, 0x0035)
						& 0xFFEF) | 0x0010);
		b43_radio_set_tx_iq(dev);
		//TODO: TSSI2dbm workaround
		b43_phy_xmitpower(dev);	//FIXME correct?
		break;
	case B43_PHYTYPE_G:
		if ((channel < 1) || (channel > 14)) {
			err = -EINVAL;
			goto out;
		}

		if (synthetic_pu_workaround)
			b43_synth_pu_workaround(dev, channel);

		b43_write16(dev, B43_MMIO_CHANNEL, channel2freq_bg(channel));

		if (channel == 14) {
			if (dev->dev->bus->sprom.country_code ==
			    SSB_SPROM1CCODE_JAPAN)
				b43_hf_write(dev,
					     b43_hf_read(dev) & ~B43_HF_ACPR);
			else
				b43_hf_write(dev,
					     b43_hf_read(dev) | B43_HF_ACPR);
			b43_write16(dev, B43_MMIO_CHANNEL_EXT,
				    b43_read16(dev, B43_MMIO_CHANNEL_EXT)
				    | (1 << 11));
		} else {
			b43_write16(dev, B43_MMIO_CHANNEL_EXT,
				    b43_read16(dev, B43_MMIO_CHANNEL_EXT)
				    & 0xF7BF);
		}
		break;
	case B43_PHYTYPE_N:
		err = b43_nphy_selectchannel(dev, channel);
		if (err)
			goto out;
		break;
	default:
		B43_WARN_ON(1);
	}

	phy->channel = channel;
	/* Wait for the radio to tune to the channel and stabilize. */
	msleep(8);
out:
	if (err) {
		b43_shm_write16(dev, B43_SHM_SHARED,
				B43_SHM_SH_CHAN, savedcookie);
	}
	return err;
}

void b43_radio_turn_on(struct b43_wldev *dev)
{
	struct b43_phy *phy = &dev->phy;
	int err;
	u8 channel;

	might_sleep();

	if (phy->radio_on)
		return;

	switch (phy->type) {
	case B43_PHYTYPE_A:
		b43_radio_write16(dev, 0x0004, 0x00C0);
		b43_radio_write16(dev, 0x0005, 0x0008);
		b43_phy_write(dev, 0x0010, b43_phy_read(dev, 0x0010) & 0xFFF7);
		b43_phy_write(dev, 0x0011, b43_phy_read(dev, 0x0011) & 0xFFF7);
		b43_radio_init2060(dev);
		break;
	case B43_PHYTYPE_B:
	case B43_PHYTYPE_G:
		b43_phy_write(dev, 0x0015, 0x8000);
		b43_phy_write(dev, 0x0015, 0xCC00);
		b43_phy_write(dev, 0x0015, (phy->gmode ? 0x00C0 : 0x0000));
		if (phy->radio_off_context.valid) {
			/* Restore the RFover values. */
			b43_phy_write(dev, B43_PHY_RFOVER,
				      phy->radio_off_context.rfover);
			b43_phy_write(dev, B43_PHY_RFOVERVAL,
				      phy->radio_off_context.rfoverval);
			phy->radio_off_context.valid = 0;
		}
		channel = phy->channel;
		err = b43_radio_selectchannel(dev, B43_DEFAULT_CHANNEL_BG, 1);
		err |= b43_radio_selectchannel(dev, channel, 0);
		B43_WARN_ON(err);
		break;
	case B43_PHYTYPE_N:
		b43_nphy_radio_turn_on(dev);
		break;
	default:
		B43_WARN_ON(1);
	}
	phy->radio_on = 1;
}

void b43_radio_turn_off(struct b43_wldev *dev, bool force)
{
	struct b43_phy *phy = &dev->phy;

	if (!phy->radio_on && !force)
		return;

	switch (phy->type) {
	case B43_PHYTYPE_N:
		b43_nphy_radio_turn_off(dev);
		break;
	case B43_PHYTYPE_A:
		b43_radio_write16(dev, 0x0004, 0x00FF);
		b43_radio_write16(dev, 0x0005, 0x00FB);
		b43_phy_write(dev, 0x0010, b43_phy_read(dev, 0x0010) | 0x0008);
		b43_phy_write(dev, 0x0011, b43_phy_read(dev, 0x0011) | 0x0008);
		break;
	case B43_PHYTYPE_G: {
		u16 rfover, rfoverval;

		rfover = b43_phy_read(dev, B43_PHY_RFOVER);
		rfoverval = b43_phy_read(dev, B43_PHY_RFOVERVAL);
		if (!force) {
			phy->radio_off_context.rfover = rfover;
			phy->radio_off_context.rfoverval = rfoverval;
			phy->radio_off_context.valid = 1;
		}
		b43_phy_write(dev, B43_PHY_RFOVER, rfover | 0x008C);
		b43_phy_write(dev, B43_PHY_RFOVERVAL, rfoverval & 0xFF73);
		break;
	}
	default:
		B43_WARN_ON(1);
	}
	phy->radio_on = 0;
}
