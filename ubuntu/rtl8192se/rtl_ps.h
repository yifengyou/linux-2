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
#ifndef _RTL_PS_H
#define _RTL_PS_H

#include <linux/types.h>
struct net_device;

#define RT_CHECK_FOR_HANG_PERIOD 2
#define INIT_DEFAULT_CHAN 	 1

#if defined CONFIG_ASPM_OR_D3
#define RT_DISABLE_ASPM(dev)            PlatformDisableASPM(dev)
#define RT_ENABLE_ASPM(dev)             PlatformEnableASPM(dev)
#define RT_ENTER_D3(dev, _bTempSetting) PlatformSetPMCSR(dev, 0x03, _bTempSetting)
#define RT_LEAVE_D3(dev, _bTempSetting) PlatformSetPMCSR(dev, 0, _bTempSetting)
bool PlatformEnable92CEBackDoor(struct net_device *dev);
void PlatformDisableASPM(struct net_device *dev);
void PlatformEnableASPM(struct net_device *dev);
u32 PlatformResetPciSpace(struct net_device *dev,u8 Value);
#endif

#if defined(RTL8192E) || defined(RTL8192SE) || defined RTL8192CE
void rtl8192_hw_wakeup(struct net_device *dev);
void rtl8192_hw_to_sleep(struct net_device *dev, u32 th, u32 tl);
void rtllib_ips_leave_wq(struct net_device *dev);
void rtllib_ips_leave(struct net_device *dev);
void IPSLeave_wq (void *data);
#endif

#ifdef ENABLE_IPS
void IPSEnter(struct net_device *dev);
void IPSLeave(struct net_device *dev);
#endif

#ifdef ENABLE_LPS
void LeisurePSEnter(struct net_device *dev);
void LeisurePSLeave(struct net_device *dev);
#endif
#endif
