/*
 * ATSTK1002 daughterboard-specific init code
 *
 * Copyright (C) 2005-2006 Atmel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/clk.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/spi/spi.h>
#include <linux/spi/at73c213.h>

#include <video/atmel_lcdc.h>

#include <asm/io.h>
#include <asm/setup.h>
#include <asm/arch/at32ap700x.h>
#include <asm/arch/board.h>
#include <asm/arch/init.h>
#include <asm/arch/portmux.h>

#include "atstk1000.h"


struct eth_addr {
	u8 addr[6];
};

static struct eth_addr __initdata hw_addr[2];
static struct eth_platform_data __initdata eth_data[2] = {
	{
		/*
		 * The MDIO pullups on STK1000 are a bit too weak for
		 * the autodetection to work properly, so we have to
		 * mask out everything but the correct address.
		 */
		.phy_mask	= ~(1U << 16),
	},
	{
		.phy_mask	= ~(1U << 17),
	},
};

#ifdef CONFIG_BOARD_ATSTK1000_EXTDAC
static struct at73c213_board_info at73c213_data = {
	.ssc_id		= 0,
	.shortname	= "AVR32 STK1000 external DAC",
};
#endif

#ifndef CONFIG_BOARD_ATSTK100X_SW1_CUSTOM
static struct spi_board_info spi0_board_info[] __initdata = {
#ifdef CONFIG_BOARD_ATSTK1000_EXTDAC
	{
		/* AT73C213 */
		.modalias	= "at73c213",
		.max_speed_hz	= 200000,
		.chip_select	= 0,
		.mode		= SPI_MODE_1,
		.platform_data	= &at73c213_data,
	},
#endif
	{
		/* QVGA display */
		.modalias	= "ltv350qv",
		.max_speed_hz	= 16000000,
		.chip_select	= 1,
		.mode		= SPI_MODE_3,
	},
};
#endif

#ifdef CONFIG_BOARD_ATSTK100X_SPI1
static struct spi_board_info spi1_board_info[] __initdata = { {
	/* patch in custom entries here */
} };
#endif

/*
 * The next two functions should go away as the boot loader is
 * supposed to initialize the macb address registers with a valid
 * ethernet address. But we need to keep it around for a while until
 * we can be reasonably sure the boot loader does this.
 *
 * The phy_id is ignored as the driver will probe for it.
 */
static int __init parse_tag_ethernet(struct tag *tag)
{
	int i;

	i = tag->u.ethernet.mac_index;
	if (i < ARRAY_SIZE(hw_addr))
		memcpy(hw_addr[i].addr, tag->u.ethernet.hw_address,
		       sizeof(hw_addr[i].addr));

	return 0;
}
__tagtable(ATAG_ETHERNET, parse_tag_ethernet);

static void __init set_hw_addr(struct platform_device *pdev)
{
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	const u8 *addr;
	void __iomem *regs;
	struct clk *pclk;

	if (!res)
		return;
	if (pdev->id >= ARRAY_SIZE(hw_addr))
		return;

	addr = hw_addr[pdev->id].addr;
	if (!is_valid_ether_addr(addr))
		return;

	/*
	 * Since this is board-specific code, we'll cheat and use the
	 * physical address directly as we happen to know that it's
	 * the same as the virtual address.
	 */
	regs = (void __iomem __force *)res->start;
	pclk = clk_get(&pdev->dev, "pclk");
	if (!pclk)
		return;

	clk_enable(pclk);
	__raw_writel((addr[3] << 24) | (addr[2] << 16)
		     | (addr[1] << 8) | addr[0], regs + 0x98);
	__raw_writel((addr[5] << 8) | addr[4], regs + 0x9c);
	clk_disable(pclk);
	clk_put(pclk);
}

#ifdef CONFIG_BOARD_ATSTK1000_EXTDAC
static void __init atstk1002_setup_extdac(void)
{
	struct clk *gclk;
	struct clk *pll;

	gclk = clk_get(NULL, "gclk0");
	if (IS_ERR(gclk))
		goto err_gclk;
	pll = clk_get(NULL, "pll0");
	if (IS_ERR(pll))
		goto err_pll;

	if (clk_set_parent(gclk, pll)) {
		pr_debug("STK1000: failed to set pll0 as parent for DAC clock\n");
		goto err_set_clk;
	}

	at32_select_periph(GPIO_PIN_PA(30), GPIO_PERIPH_A, 0);
	at73c213_data.dac_clk = gclk;

err_set_clk:
	clk_put(pll);
err_pll:
	clk_put(gclk);
err_gclk:
	return;
}
#else
static void __init atstk1002_setup_extdac(void)
{

}
#endif /* CONFIG_BOARD_ATSTK1000_EXTDAC */

void __init setup_board(void)
{
#ifdef	CONFIG_BOARD_ATSTK100X_SW2_CUSTOM
	at32_map_usart(0, 1);	/* USART 0/B: /dev/ttyS1, IRDA */
#else
	at32_map_usart(1, 0);	/* USART 1/A: /dev/ttyS0, DB9 */
#endif
	/* USART 2/unused: expansion connector */
	at32_map_usart(3, 2);	/* USART 3/C: /dev/ttyS2, DB9 */

	at32_setup_serial_console(0);
}

static int __init atstk1002_init(void)
{
	/*
	 * ATSTK1000 uses 32-bit SDRAM interface. Reserve the
	 * SDRAM-specific pins so that nobody messes with them.
	 */
	at32_reserve_pin(GPIO_PIN_PE(0));	/* DATA[16]	*/
	at32_reserve_pin(GPIO_PIN_PE(1));	/* DATA[17]	*/
	at32_reserve_pin(GPIO_PIN_PE(2));	/* DATA[18]	*/
	at32_reserve_pin(GPIO_PIN_PE(3));	/* DATA[19]	*/
	at32_reserve_pin(GPIO_PIN_PE(4));	/* DATA[20]	*/
	at32_reserve_pin(GPIO_PIN_PE(5));	/* DATA[21]	*/
	at32_reserve_pin(GPIO_PIN_PE(6));	/* DATA[22]	*/
	at32_reserve_pin(GPIO_PIN_PE(7));	/* DATA[23]	*/
	at32_reserve_pin(GPIO_PIN_PE(8));	/* DATA[24]	*/
	at32_reserve_pin(GPIO_PIN_PE(9));	/* DATA[25]	*/
	at32_reserve_pin(GPIO_PIN_PE(10));	/* DATA[26]	*/
	at32_reserve_pin(GPIO_PIN_PE(11));	/* DATA[27]	*/
	at32_reserve_pin(GPIO_PIN_PE(12));	/* DATA[28]	*/
	at32_reserve_pin(GPIO_PIN_PE(13));	/* DATA[29]	*/
	at32_reserve_pin(GPIO_PIN_PE(14));	/* DATA[30]	*/
	at32_reserve_pin(GPIO_PIN_PE(15));	/* DATA[31]	*/
	at32_reserve_pin(GPIO_PIN_PE(26));	/* SDCS		*/

	at32_add_system_devices();

#ifdef	CONFIG_BOARD_ATSTK100X_SW2_CUSTOM
	at32_add_device_usart(1);
#else
	at32_add_device_usart(0);
#endif
	at32_add_device_usart(2);

#ifndef CONFIG_BOARD_ATSTK1002_SW6_CUSTOM
	set_hw_addr(at32_add_device_eth(0, &eth_data[0]));
#endif
#ifndef CONFIG_BOARD_ATSTK100X_SW1_CUSTOM
	at32_add_device_spi(0, spi0_board_info, ARRAY_SIZE(spi0_board_info));
#endif
#ifdef CONFIG_BOARD_ATSTK100X_SPI1
	at32_add_device_spi(1, spi1_board_info, ARRAY_SIZE(spi1_board_info));
#endif
#ifdef CONFIG_BOARD_ATSTK1002_SW5_CUSTOM
	set_hw_addr(at32_add_device_eth(1, &eth_data[1]));
#else
	at32_add_device_lcdc(0, &atstk1000_lcdc_data,
			     fbmem_start, fbmem_size);
#endif
	at32_add_device_usba(0, NULL);
#ifndef CONFIG_BOARD_ATSTK100X_SW3_CUSTOM
	at32_add_device_ssc(0, ATMEL_SSC_TX);
#endif

	atstk1000_setup_j2_leds();
	atstk1002_setup_extdac();

	return 0;
}
postcore_initcall(atstk1002_init);
