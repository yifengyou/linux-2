/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2007 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/sched.h>

#include "ixgbe_common.h"
#include "ixgbe_phy.h"

static enum ixgbe_phy_type ixgbe_get_phy_type_from_id(u32 phy_id);
static s32 ixgbe_get_phy_id(struct ixgbe_hw *hw);
static bool ixgbe_validate_phy_addr(struct ixgbe_hw *hw, u32 phy_addr);
static s32 ixgbe_write_phy_reg(struct ixgbe_hw *hw, u32 reg_addr,
			       u32 device_type, u16 phy_data);

/**
 *  ixgbe_identify_phy - Get physical layer module
 *  @hw: pointer to hardware structure
 *
 *  Determines the physical layer module found on the current adapter.
 **/
s32 ixgbe_identify_phy(struct ixgbe_hw *hw)
{
	s32 status = IXGBE_ERR_PHY_ADDR_INVALID;
	u32 phy_addr;

	for (phy_addr = 0; phy_addr < IXGBE_MAX_PHY_ADDR; phy_addr++) {
		if (ixgbe_validate_phy_addr(hw, phy_addr)) {
			hw->phy.addr = phy_addr;
			ixgbe_get_phy_id(hw);
			hw->phy.type = ixgbe_get_phy_type_from_id(hw->phy.id);
			status = 0;
			break;
		}
	}
	return status;
}

/**
 *  ixgbe_validate_phy_addr - Determines phy address is valid
 *  @hw: pointer to hardware structure
 *
 **/
static bool ixgbe_validate_phy_addr(struct ixgbe_hw *hw, u32 phy_addr)
{
	u16 phy_id = 0;
	bool valid = false;

	hw->phy.addr = phy_addr;
	ixgbe_read_phy_reg(hw,
			   IXGBE_MDIO_PHY_ID_HIGH,
			   IXGBE_MDIO_PMA_PMD_DEV_TYPE,
			   &phy_id);

	if (phy_id != 0xFFFF && phy_id != 0x0)
		valid = true;

	return valid;
}

/**
 *  ixgbe_get_phy_id - Get the phy type
 *  @hw: pointer to hardware structure
 *
 **/
static s32 ixgbe_get_phy_id(struct ixgbe_hw *hw)
{
	u32 status;
	u16 phy_id_high = 0;
	u16 phy_id_low = 0;

	status = ixgbe_read_phy_reg(hw,
				   IXGBE_MDIO_PHY_ID_HIGH,
				   IXGBE_MDIO_PMA_PMD_DEV_TYPE,
				   &phy_id_high);

	if (status == 0) {
		hw->phy.id = (u32)(phy_id_high << 16);
		status = ixgbe_read_phy_reg(hw,
					   IXGBE_MDIO_PHY_ID_LOW,
					   IXGBE_MDIO_PMA_PMD_DEV_TYPE,
					   &phy_id_low);
		hw->phy.id |= (u32)(phy_id_low & IXGBE_PHY_REVISION_MASK);
		hw->phy.revision = (u32)(phy_id_low & ~IXGBE_PHY_REVISION_MASK);
	}

	return status;
}

/**
 *  ixgbe_get_phy_type_from_id - Get the phy type
 *  @hw: pointer to hardware structure
 *
 **/
static enum ixgbe_phy_type ixgbe_get_phy_type_from_id(u32 phy_id)
{
	enum ixgbe_phy_type phy_type;

	switch (phy_id) {
	case TN1010_PHY_ID:
		phy_type = ixgbe_phy_tn;
		break;
	case QT2022_PHY_ID:
		phy_type = ixgbe_phy_qt;
		break;
	default:
		phy_type = ixgbe_phy_unknown;
		break;
	}

	return phy_type;
}

/**
 *  ixgbe_reset_phy - Performs a PHY reset
 *  @hw: pointer to hardware structure
 **/
s32 ixgbe_reset_phy(struct ixgbe_hw *hw)
{
	/*
	 * Perform soft PHY reset to the PHY_XS.
	 * This will cause a soft reset to the PHY
	 */
	return ixgbe_write_phy_reg(hw, IXGBE_MDIO_PHY_XS_CONTROL,
				   IXGBE_MDIO_PHY_XS_DEV_TYPE,
				   IXGBE_MDIO_PHY_XS_RESET);
}

/**
 *  ixgbe_read_phy_reg - Reads a value from a specified PHY register
 *  @hw: pointer to hardware structure
 *  @reg_addr: 32 bit address of PHY register to read
 *  @phy_data: Pointer to read data from PHY register
 **/
s32 ixgbe_read_phy_reg(struct ixgbe_hw *hw, u32 reg_addr,
		       u32 device_type, u16 *phy_data)
{
	u32 command;
	u32 i;
	u32 timeout = 10;
	u32 data;
	s32 status = 0;
	u16 gssr;

	if (IXGBE_READ_REG(hw, IXGBE_STATUS) & IXGBE_STATUS_LAN_ID_1)
		gssr = IXGBE_GSSR_PHY1_SM;
	else
		gssr = IXGBE_GSSR_PHY0_SM;

	if (ixgbe_acquire_swfw_sync(hw, gssr) != 0)
		status = IXGBE_ERR_SWFW_SYNC;

	if (status == 0) {
		/* Setup and write the address cycle command */
		command = ((reg_addr << IXGBE_MSCA_NP_ADDR_SHIFT)  |
			   (device_type << IXGBE_MSCA_DEV_TYPE_SHIFT) |
			   (hw->phy.addr << IXGBE_MSCA_PHY_ADDR_SHIFT) |
			   (IXGBE_MSCA_ADDR_CYCLE | IXGBE_MSCA_MDI_COMMAND));

		IXGBE_WRITE_REG(hw, IXGBE_MSCA, command);

		/*
		 * Check every 10 usec to see if the address cycle completed.
		 * The MDI Command bit will clear when the operation is
		 * complete
		 */
		for (i = 0; i < timeout; i++) {
			udelay(10);

			command = IXGBE_READ_REG(hw, IXGBE_MSCA);

			if ((command & IXGBE_MSCA_MDI_COMMAND) == 0)
				break;
		}

		if ((command & IXGBE_MSCA_MDI_COMMAND) != 0) {
			hw_dbg(hw, "PHY address command did not complete.\n");
			status = IXGBE_ERR_PHY;
		}

		if (status == 0) {
			/*
			 * Address cycle complete, setup and write the read
			 * command
			 */
			command = ((reg_addr << IXGBE_MSCA_NP_ADDR_SHIFT)  |
				   (device_type << IXGBE_MSCA_DEV_TYPE_SHIFT) |
				   (hw->phy.addr << IXGBE_MSCA_PHY_ADDR_SHIFT) |
				   (IXGBE_MSCA_READ | IXGBE_MSCA_MDI_COMMAND));

			IXGBE_WRITE_REG(hw, IXGBE_MSCA, command);

			/*
			 * Check every 10 usec to see if the address cycle
			 * completed. The MDI Command bit will clear when the
			 * operation is complete
			 */
			for (i = 0; i < timeout; i++) {
				udelay(10);

				command = IXGBE_READ_REG(hw, IXGBE_MSCA);

				if ((command & IXGBE_MSCA_MDI_COMMAND) == 0)
					break;
			}

			if ((command & IXGBE_MSCA_MDI_COMMAND) != 0) {
				hw_dbg(hw,
				       "PHY read command didn't complete\n");
				status = IXGBE_ERR_PHY;
			} else {
				/*
				 * Read operation is complete.  Get the data
				 * from MSRWD
				 */
				data = IXGBE_READ_REG(hw, IXGBE_MSRWD);
				data >>= IXGBE_MSRWD_READ_DATA_SHIFT;
				*phy_data = (u16)(data);
			}
		}

		ixgbe_release_swfw_sync(hw, gssr);
	}
	return status;
}

/**
 *  ixgbe_write_phy_reg - Writes a value to specified PHY register
 *  @hw: pointer to hardware structure
 *  @reg_addr: 32 bit PHY register to write
 *  @device_type: 5 bit device type
 *  @phy_data: Data to write to the PHY register
 **/
static s32 ixgbe_write_phy_reg(struct ixgbe_hw *hw, u32 reg_addr,
			       u32 device_type, u16 phy_data)
{
	u32 command;
	u32 i;
	u32 timeout = 10;
	s32 status = 0;
	u16 gssr;

	if (IXGBE_READ_REG(hw, IXGBE_STATUS) & IXGBE_STATUS_LAN_ID_1)
		gssr = IXGBE_GSSR_PHY1_SM;
	else
		gssr = IXGBE_GSSR_PHY0_SM;

	if (ixgbe_acquire_swfw_sync(hw, gssr) != 0)
		status = IXGBE_ERR_SWFW_SYNC;

	if (status == 0) {
		/* Put the data in the MDI single read and write data register*/
		IXGBE_WRITE_REG(hw, IXGBE_MSRWD, (u32)phy_data);

		/* Setup and write the address cycle command */
		command = ((reg_addr << IXGBE_MSCA_NP_ADDR_SHIFT)  |
			   (device_type << IXGBE_MSCA_DEV_TYPE_SHIFT) |
			   (hw->phy.addr << IXGBE_MSCA_PHY_ADDR_SHIFT) |
			   (IXGBE_MSCA_ADDR_CYCLE | IXGBE_MSCA_MDI_COMMAND));

		IXGBE_WRITE_REG(hw, IXGBE_MSCA, command);

		/*
		 * Check every 10 usec to see if the address cycle completed.
		 * The MDI Command bit will clear when the operation is
		 * complete
		 */
		for (i = 0; i < timeout; i++) {
			udelay(10);

			command = IXGBE_READ_REG(hw, IXGBE_MSCA);

			if ((command & IXGBE_MSCA_MDI_COMMAND) == 0) {
				hw_dbg(hw, "PHY address cmd didn't complete\n");
				break;
			}
		}

		if ((command & IXGBE_MSCA_MDI_COMMAND) != 0)
			status = IXGBE_ERR_PHY;

		if (status == 0) {
			/*
			 * Address cycle complete, setup and write the write
			 * command
			 */
			command = ((reg_addr << IXGBE_MSCA_NP_ADDR_SHIFT)  |
				   (device_type << IXGBE_MSCA_DEV_TYPE_SHIFT) |
				   (hw->phy.addr << IXGBE_MSCA_PHY_ADDR_SHIFT) |
				   (IXGBE_MSCA_WRITE | IXGBE_MSCA_MDI_COMMAND));

			IXGBE_WRITE_REG(hw, IXGBE_MSCA, command);

			/*
			 * Check every 10 usec to see if the address cycle
			 * completed. The MDI Command bit will clear when the
			 * operation is complete
			 */
			for (i = 0; i < timeout; i++) {
				udelay(10);

				command = IXGBE_READ_REG(hw, IXGBE_MSCA);

				if ((command & IXGBE_MSCA_MDI_COMMAND) == 0) {
					hw_dbg(hw, "PHY write command did not "
						  "complete.\n");
					break;
				}
			}

			if ((command & IXGBE_MSCA_MDI_COMMAND) != 0)
				status = IXGBE_ERR_PHY;
		}

		ixgbe_release_swfw_sync(hw, gssr);
	}

	return status;
}

/**
 *  ixgbe_setup_tnx_phy_link - Set and restart autoneg
 *  @hw: pointer to hardware structure
 *
 *  Restart autonegotiation and PHY and waits for completion.
 **/
s32 ixgbe_setup_tnx_phy_link(struct ixgbe_hw *hw)
{
	s32 status = IXGBE_NOT_IMPLEMENTED;
	u32 time_out;
	u32 max_time_out = 10;
	u16 autoneg_speed_selection_register = 0x10;
	u16 autoneg_restart_mask = 0x0200;
	u16 autoneg_complete_mask = 0x0020;
	u16 autoneg_reg = 0;

	/*
	 * Set advertisement settings in PHY based on autoneg_advertised
	 * settings. If autoneg_advertised = 0, then advertise default values
	 * txn devices cannot be "forced" to a autoneg 10G and fail.  But can
	 * for a 1G.
	 */
	ixgbe_read_phy_reg(hw,
		  autoneg_speed_selection_register,
		  IXGBE_MDIO_AUTO_NEG_DEV_TYPE,
		  &autoneg_reg);

	if (hw->phy.autoneg_advertised == IXGBE_LINK_SPEED_1GB_FULL)
		autoneg_reg &= 0xEFFF; /* 0 in bit 12 is 1G operation */
	else
		autoneg_reg |= 0x1000; /* 1 in bit 12 is 10G/1G operation */

	ixgbe_write_phy_reg(hw,
		  autoneg_speed_selection_register,
		  IXGBE_MDIO_AUTO_NEG_DEV_TYPE,
		  autoneg_reg);


	/* Restart PHY autonegotiation and wait for completion */
	ixgbe_read_phy_reg(hw,
		  IXGBE_MDIO_AUTO_NEG_CONTROL,
		  IXGBE_MDIO_AUTO_NEG_DEV_TYPE,
		  &autoneg_reg);

	autoneg_reg |= autoneg_restart_mask;

	ixgbe_write_phy_reg(hw,
		  IXGBE_MDIO_AUTO_NEG_CONTROL,
		  IXGBE_MDIO_AUTO_NEG_DEV_TYPE,
		  autoneg_reg);

	/* Wait for autonegotiation to finish */
	for (time_out = 0; time_out < max_time_out; time_out++) {
		udelay(10);
		/* Restart PHY autonegotiation and wait for completion */
		status = ixgbe_read_phy_reg(hw,
					    IXGBE_MDIO_AUTO_NEG_STATUS,
					    IXGBE_MDIO_AUTO_NEG_DEV_TYPE,
					    &autoneg_reg);

		autoneg_reg &= autoneg_complete_mask;
		if (autoneg_reg == autoneg_complete_mask) {
			status = 0;
			break;
		}
	}

	if (time_out == max_time_out)
		status = IXGBE_ERR_LINK_SETUP;

	return status;
}

/**
 *  ixgbe_check_tnx_phy_link - Determine link and speed status
 *  @hw: pointer to hardware structure
 *
 *  Reads the VS1 register to determine if link is up and the current speed for
 *  the PHY.
 **/
s32 ixgbe_check_tnx_phy_link(struct ixgbe_hw *hw, u32 *speed,
			     bool *link_up)
{
	s32 status = 0;
	u32 time_out;
	u32 max_time_out = 10;
	u16 phy_link = 0;
	u16 phy_speed = 0;
	u16 phy_data = 0;

	/* Initialize speed and link to default case */
	*link_up = false;
	*speed = IXGBE_LINK_SPEED_10GB_FULL;

	/*
	 * Check current speed and link status of the PHY register.
	 * This is a vendor specific register and may have to
	 * be changed for other copper PHYs.
	 */
	for (time_out = 0; time_out < max_time_out; time_out++) {
		udelay(10);
		if (phy_link == IXGBE_MDIO_VENDOR_SPECIFIC_1_LINK_STATUS) {
			*link_up = true;
			if (phy_speed ==
			    IXGBE_MDIO_VENDOR_SPECIFIC_1_SPEED_STATUS)
				*speed = IXGBE_LINK_SPEED_1GB_FULL;
			break;
		} else {
			status = ixgbe_read_phy_reg(hw,
				     IXGBE_MDIO_VENDOR_SPECIFIC_1_STATUS,
				     IXGBE_MDIO_VENDOR_SPECIFIC_1_DEV_TYPE,
				     &phy_data);
			phy_link = phy_data &
				IXGBE_MDIO_VENDOR_SPECIFIC_1_LINK_STATUS;
			phy_speed = phy_data &
				IXGBE_MDIO_VENDOR_SPECIFIC_1_SPEED_STATUS;
		}
	}

	return status;
}

/**
 *  ixgbe_setup_tnx_phy_link_speed - Sets the auto advertised capabilities
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg: true if autonegotiation enabled
 **/
s32 ixgbe_setup_tnx_phy_link_speed(struct ixgbe_hw *hw, u32 speed,
				   bool autoneg,
				   bool autoneg_wait_to_complete)
{
	/*
	 * Clear autoneg_advertised and set new values based on input link
	 * speed.
	 */
	hw->phy.autoneg_advertised = 0;

	if (speed & IXGBE_LINK_SPEED_10GB_FULL)
		hw->phy.autoneg_advertised |= IXGBE_LINK_SPEED_10GB_FULL;
	if (speed & IXGBE_LINK_SPEED_1GB_FULL)
		hw->phy.autoneg_advertised |= IXGBE_LINK_SPEED_1GB_FULL;

	/* Setup link based on the new speed settings */
	ixgbe_setup_tnx_phy_link(hw);

	return 0;
}
