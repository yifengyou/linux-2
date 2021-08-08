#ifndef _ASM_X86_NMI_H_
#define _ASM_X86_NMI_H_

#include <linux/pm.h>
#include <asm/irq.h>
#include <asm/io.h>

#ifdef ARCH_HAS_NMI_WATCHDOG

/**
 * do_nmi_callback
 *
 * Check to see if a callback exists and execute it.  Return 1
 * if the handler exists and was handled successfully.
 */
int do_nmi_callback(struct pt_regs *regs, int cpu);

#ifdef CONFIG_PM

/** Replace the PM callback routine for NMI. */
struct pm_dev *set_nmi_pm_callback(pm_callback callback);

/** Unset the PM callback routine back to the default. */
void unset_nmi_pm_callback(struct pm_dev *dev);

#else

static inline struct pm_dev *set_nmi_pm_callback(pm_callback callback)
{
	return 0;
}

static inline void unset_nmi_pm_callback(struct pm_dev *dev)
{
}

#endif /* CONFIG_PM */

#ifdef CONFIG_X86_64
extern void default_do_nmi(struct pt_regs *);
extern void die_nmi(char *str, struct pt_regs *regs, int do_panic);
extern void nmi_watchdog_default(void);
#else
#define nmi_watchdog_default() do {} while (0)
#endif

extern int check_nmi_watchdog(void);
extern int nmi_watchdog_enabled;
extern int unknown_nmi_panic;
extern int avail_to_resrv_perfctr_nmi_bit(unsigned int);
extern int avail_to_resrv_perfctr_nmi(unsigned int);
extern int reserve_perfctr_nmi(unsigned int);
extern void release_perfctr_nmi(unsigned int);
extern int reserve_evntsel_nmi(unsigned int);
extern void release_evntsel_nmi(unsigned int);

extern void setup_apic_nmi_watchdog(void *);
extern void stop_apic_nmi_watchdog(void *);
extern void disable_timer_nmi_watchdog(void);
extern void enable_timer_nmi_watchdog(void);
extern int nmi_watchdog_tick(struct pt_regs *regs, unsigned reason);

extern atomic_t nmi_active;
extern unsigned int nmi_watchdog;
#define NMI_DISABLED    -1
#define NMI_NONE	0
#define NMI_IO_APIC	1
#define NMI_LOCAL_APIC	2
#define NMI_INVALID	3
#define NMI_DEFAULT	NMI_DISABLED

struct ctl_table;
struct file;
extern int proc_nmi_enabled(struct ctl_table *, int , struct file *,
			void __user *, size_t *, loff_t *);
extern int unknown_nmi_panic;

void __trigger_all_cpu_backtrace(void);
#define trigger_all_cpu_backtrace() __trigger_all_cpu_backtrace()

#endif

void lapic_watchdog_stop(void);
int lapic_watchdog_init(unsigned nmi_hz);
int lapic_wd_event(unsigned nmi_hz);
unsigned lapic_adjust_nmi_hz(unsigned hz);
int lapic_watchdog_ok(void);
void disable_lapic_nmi_watchdog(void);
void enable_lapic_nmi_watchdog(void);
void stop_nmi(void);
void restart_nmi(void);

#endif
