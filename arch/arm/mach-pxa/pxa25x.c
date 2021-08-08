/*
 *  linux/arch/arm/mach-pxa/pxa25x.c
 *
 *  Author:	Nicolas Pitre
 *  Created:	Jun 15, 2001
 *  Copyright:	MontaVista Software Inc.
 *
 * Code specific to PXA21x/25x/26x variants.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Since this file should be linked before any other machine specific file,
 * the __initcall() here will be executed first.  This serves as default
 * initialization stuff for PXA machines which can be overridden later if
 * need be.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>
#include <linux/sysdev.h>

#include <asm/hardware.h>
#include <asm/arch/irqs.h>
#include <asm/arch/pxa-regs.h>
#include <asm/arch/mfp-pxa25x.h>
#include <asm/arch/pm.h>
#include <asm/arch/dma.h>

#include "generic.h"
#include "devices.h"
#include "clock.h"

/*
 * Various clock factors driven by the CCCR register.
 */

/* Crystal Frequency to Memory Frequency Multiplier (L) */
static unsigned char L_clk_mult[32] = { 0, 27, 32, 36, 40, 45, 0, };

/* Memory Frequency to Run Mode Frequency Multiplier (M) */
static unsigned char M_clk_mult[4] = { 0, 1, 2, 4 };

/* Run Mode Frequency to Turbo Mode Frequency Multiplier (N) */
/* Note: we store the value N * 2 here. */
static unsigned char N2_clk_mult[8] = { 0, 0, 2, 3, 4, 0, 6, 0 };

/* Crystal clock */
#define BASE_CLK	3686400

/*
 * Get the clock frequency as reflected by CCCR and the turbo flag.
 * We assume these values have been applied via a fcs.
 * If info is not 0 we also display the current settings.
 */
unsigned int pxa25x_get_clk_frequency_khz(int info)
{
	unsigned long cccr, turbo;
	unsigned int l, L, m, M, n2, N;

	cccr = CCCR;
	asm( "mrc\tp14, 0, %0, c6, c0, 0" : "=r" (turbo) );

	l  =  L_clk_mult[(cccr >> 0) & 0x1f];
	m  =  M_clk_mult[(cccr >> 5) & 0x03];
	n2 = N2_clk_mult[(cccr >> 7) & 0x07];

	L = l * BASE_CLK;
	M = m * L;
	N = n2 * M / 2;

	if(info)
	{
		L += 5000;
		printk( KERN_INFO "Memory clock: %d.%02dMHz (*%d)\n",
			L / 1000000, (L % 1000000) / 10000, l );
		M += 5000;
		printk( KERN_INFO "Run Mode clock: %d.%02dMHz (*%d)\n",
			M / 1000000, (M % 1000000) / 10000, m );
		N += 5000;
		printk( KERN_INFO "Turbo Mode clock: %d.%02dMHz (*%d.%d, %sactive)\n",
			N / 1000000, (N % 1000000) / 10000, n2 / 2, (n2 % 2) * 5,
			(turbo & 1) ? "" : "in" );
	}

	return (turbo & 1) ? (N/1000) : (M/1000);
}

/*
 * Return the current memory clock frequency in units of 10kHz
 */
unsigned int pxa25x_get_memclk_frequency_10khz(void)
{
	return L_clk_mult[(CCCR >> 0) & 0x1f] * BASE_CLK / 10000;
}

static unsigned long clk_pxa25x_lcd_getrate(struct clk *clk)
{
	return pxa25x_get_memclk_frequency_10khz() * 10000;
}

static const struct clkops clk_pxa25x_lcd_ops = {
	.enable		= clk_cken_enable,
	.disable	= clk_cken_disable,
	.getrate	= clk_pxa25x_lcd_getrate,
};

/*
 * 3.6864MHz -> OST, GPIO, SSP, PWM, PLLs (95.842MHz, 147.456MHz)
 * 95.842MHz -> MMC 19.169MHz, I2C 31.949MHz, FICP 47.923MHz, USB 47.923MHz
 * 147.456MHz -> UART 14.7456MHz, AC97 12.288MHz, I2S 5.672MHz (allegedly)
 */
static struct clk pxa25x_hwuart_clk =
	INIT_CKEN("UARTCLK", HWUART, 14745600, 1, &pxa_device_hwuart.dev)
;

static struct clk pxa25x_clks[] = {
	INIT_CK("LCDCLK", LCD, &clk_pxa25x_lcd_ops, &pxa_device_fb.dev),
	INIT_CKEN("UARTCLK", FFUART, 14745600, 1, &pxa_device_ffuart.dev),
	INIT_CKEN("UARTCLK", BTUART, 14745600, 1, &pxa_device_btuart.dev),
	INIT_CKEN("UARTCLK", STUART, 14745600, 1, NULL),
	INIT_CKEN("UDCCLK", USB, 47923000, 5, &pxa_device_udc.dev),
	INIT_CKEN("MMCCLK", MMC, 19169000, 0, &pxa_device_mci.dev),
	INIT_CKEN("I2CCLK", I2C, 31949000, 0, &pxa_device_i2c.dev),

	INIT_CKEN("SSPCLK",  SSP, 3686400, 0, &pxa25x_device_ssp.dev),
	INIT_CKEN("SSPCLK", NSSP, 3686400, 0, &pxa25x_device_nssp.dev),
	INIT_CKEN("SSPCLK", ASSP, 3686400, 0, &pxa25x_device_assp.dev),

	INIT_CKEN("AC97CLK",     AC97,     24576000, 0, NULL),

	/*
	INIT_CKEN("PWMCLK",  PWM0, 3686400,  0, NULL),
	INIT_CKEN("PWMCLK",  PWM0, 3686400,  0, NULL),
	INIT_CKEN("I2SCLK",  I2S,  14745600, 0, NULL),
	*/
	INIT_CKEN("FICPCLK", FICP, 47923000, 0, NULL),
};

#ifdef CONFIG_PM

#define SAVE(x)		sleep_save[SLEEP_SAVE_##x] = x
#define RESTORE(x)	x = sleep_save[SLEEP_SAVE_##x]

/*
 * List of global PXA peripheral registers to preserve.
 * More ones like CP and general purpose register values are preserved
 * with the stack pointer in sleep.S.
 */
enum {	SLEEP_SAVE_PGSR0, SLEEP_SAVE_PGSR1, SLEEP_SAVE_PGSR2,

	SLEEP_SAVE_GAFR0_L, SLEEP_SAVE_GAFR0_U,
	SLEEP_SAVE_GAFR1_L, SLEEP_SAVE_GAFR1_U,
	SLEEP_SAVE_GAFR2_L, SLEEP_SAVE_GAFR2_U,

	SLEEP_SAVE_PSTR,

	SLEEP_SAVE_CKEN,

	SLEEP_SAVE_COUNT
};


static void pxa25x_cpu_pm_save(unsigned long *sleep_save)
{
	SAVE(PGSR0); SAVE(PGSR1); SAVE(PGSR2);

	SAVE(GAFR0_L); SAVE(GAFR0_U);
	SAVE(GAFR1_L); SAVE(GAFR1_U);
	SAVE(GAFR2_L); SAVE(GAFR2_U);

	SAVE(CKEN);
	SAVE(PSTR);

	/* Clear GPIO transition detect bits */
	GEDR0 = GEDR0; GEDR1 = GEDR1; GEDR2 = GEDR2;
}

static void pxa25x_cpu_pm_restore(unsigned long *sleep_save)
{
	/* ensure not to come back here if it wasn't intended */
	PSPR = 0;

	/* restore registers */
	RESTORE(GAFR0_L); RESTORE(GAFR0_U);
	RESTORE(GAFR1_L); RESTORE(GAFR1_U);
	RESTORE(GAFR2_L); RESTORE(GAFR2_U);
	RESTORE(PGSR0); RESTORE(PGSR1); RESTORE(PGSR2);

	PSSR = PSSR_RDH | PSSR_PH;

	RESTORE(CKEN);
	RESTORE(PSTR);
}

static void pxa25x_cpu_pm_enter(suspend_state_t state)
{
	/* Clear reset status */
	RCSR = RCSR_HWR | RCSR_WDR | RCSR_SMR | RCSR_GPR;

	switch (state) {
	case PM_SUSPEND_MEM:
		/* set resume return address */
		PSPR = virt_to_phys(pxa_cpu_resume);
		pxa25x_cpu_suspend(PWRMODE_SLEEP);
		break;
	}
}

static struct pxa_cpu_pm_fns pxa25x_cpu_pm_fns = {
	.save_count	= SLEEP_SAVE_COUNT,
	.valid		= suspend_valid_only_mem,
	.save		= pxa25x_cpu_pm_save,
	.restore	= pxa25x_cpu_pm_restore,
	.enter		= pxa25x_cpu_pm_enter,
};

static void __init pxa25x_init_pm(void)
{
	pxa_cpu_pm_fns = &pxa25x_cpu_pm_fns;
}
#else
static inline void pxa25x_init_pm(void) {}
#endif

/* PXA25x: supports wakeup from GPIO0..GPIO15 and RTC alarm
 */

static int pxa25x_set_wake(unsigned int irq, unsigned int on)
{
	int gpio = IRQ_TO_GPIO(irq);
	uint32_t mask = 0;

	if (gpio >= 0 && gpio < 85)
		return gpio_set_wake(gpio, on);

	if (irq == IRQ_RTCAlrm) {
		mask = PWER_RTC;
		goto set_pwer;
	}

	return -EINVAL;

set_pwer:
	if (on)
		PWER |= mask;
	else
		PWER &=~mask;

	return 0;
}

void __init pxa25x_init_irq(void)
{
	pxa_init_irq(32, pxa25x_set_wake);
	pxa_init_gpio(85, pxa25x_set_wake);
}

static struct platform_device *pxa25x_devices[] __initdata = {
	&pxa_device_udc,
	&pxa_device_ffuart,
	&pxa_device_btuart,
	&pxa_device_stuart,
	&pxa_device_i2s,
	&pxa_device_rtc,
	&pxa25x_device_ssp,
	&pxa25x_device_nssp,
	&pxa25x_device_assp,
};

static struct sys_device pxa25x_sysdev[] = {
	{
		.cls	= &pxa_irq_sysclass,
	}, {
		.cls	= &pxa_gpio_sysclass,
	},
};

static int __init pxa25x_init(void)
{
	int i, ret = 0;

	/* Only add HWUART for PXA255/26x; PXA210/250/27x do not have it. */
	if (cpu_is_pxa25x())
		clks_register(&pxa25x_hwuart_clk, 1);

	if (cpu_is_pxa21x() || cpu_is_pxa25x()) {
		clks_register(pxa25x_clks, ARRAY_SIZE(pxa25x_clks));

		if ((ret = pxa_init_dma(16)))
			return ret;

		pxa25x_init_pm();

		for (i = 0; i < ARRAY_SIZE(pxa25x_sysdev); i++) {
			ret = sysdev_register(&pxa25x_sysdev[i]);
			if (ret)
				pr_err("failed to register sysdev[%d]\n", i);
		}

		ret = platform_add_devices(pxa25x_devices,
					   ARRAY_SIZE(pxa25x_devices));
		if (ret)
			return ret;
	}

	/* Only add HWUART for PXA255/26x; PXA210/250/27x do not have it. */
	if (cpu_is_pxa25x())
		ret = platform_device_register(&pxa_device_hwuart);

	return ret;
}

postcore_initcall(pxa25x_init);
