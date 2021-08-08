/*
 *  arch/s390/kernel/early.c
 *
 *    Copyright IBM Corp. 2007
 *    Author(s): Hongjie Yang <hongjie@us.ibm.com>,
 *		 Heiko Carstens <heiko.carstens@de.ibm.com>
 */

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/pfn.h>
#include <linux/uaccess.h>
#include <asm/ipl.h>
#include <asm/lowcore.h>
#include <asm/processor.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/cpcmd.h>
#include <asm/sclp.h>
#include "entry.h"

/*
 * Create a Kernel NSS if the SAVESYS= parameter is defined
 */
#define DEFSYS_CMD_SIZE		96
#define SAVESYS_CMD_SIZE	32

char kernel_nss_name[NSS_NAME_SIZE + 1];

#ifdef CONFIG_SHARED_KERNEL
static noinline __init void create_kernel_nss(void)
{
	unsigned int i, stext_pfn, eshared_pfn, end_pfn, min_size;
#ifdef CONFIG_BLK_DEV_INITRD
	unsigned int sinitrd_pfn, einitrd_pfn;
#endif
	int response;
	char *savesys_ptr;
	char upper_command_line[COMMAND_LINE_SIZE];
	char defsys_cmd[DEFSYS_CMD_SIZE];
	char savesys_cmd[SAVESYS_CMD_SIZE];

	/* Do nothing if we are not running under VM */
	if (!MACHINE_IS_VM)
		return;

	/* Convert COMMAND_LINE to upper case */
	for (i = 0; i < strlen(COMMAND_LINE); i++)
		upper_command_line[i] = toupper(COMMAND_LINE[i]);

	savesys_ptr = strstr(upper_command_line, "SAVESYS=");

	if (!savesys_ptr)
		return;

	savesys_ptr += 8;    /* Point to the beginning of the NSS name */
	for (i = 0; i < NSS_NAME_SIZE; i++) {
		if (savesys_ptr[i] == ' ' || savesys_ptr[i] == '\0')
			break;
		kernel_nss_name[i] = savesys_ptr[i];
	}

	stext_pfn = PFN_DOWN(__pa(&_stext));
	eshared_pfn = PFN_DOWN(__pa(&_eshared));
	end_pfn = PFN_UP(__pa(&_end));
	min_size = end_pfn << 2;

	sprintf(defsys_cmd, "DEFSYS %s 00000-%.5X EW %.5X-%.5X SR %.5X-%.5X",
		kernel_nss_name, stext_pfn - 1, stext_pfn, eshared_pfn - 1,
		eshared_pfn, end_pfn);

#ifdef CONFIG_BLK_DEV_INITRD
	if (INITRD_START && INITRD_SIZE) {
		sinitrd_pfn = PFN_DOWN(__pa(INITRD_START));
		einitrd_pfn = PFN_UP(__pa(INITRD_START + INITRD_SIZE));
		min_size = einitrd_pfn << 2;
		sprintf(defsys_cmd, "%s EW %.5X-%.5X", defsys_cmd,
		sinitrd_pfn, einitrd_pfn);
	}
#endif

	sprintf(defsys_cmd, "%s EW MINSIZE=%.7iK", defsys_cmd, min_size);
	sprintf(savesys_cmd, "SAVESYS %s \n IPL %s",
		kernel_nss_name, kernel_nss_name);

	__cpcmd(defsys_cmd, NULL, 0, &response);

	if (response != 0) {
		kernel_nss_name[0] = '\0';
		return;
	}

	__cpcmd(savesys_cmd, NULL, 0, &response);

	if (response != strlen(savesys_cmd)) {
		kernel_nss_name[0] = '\0';
		return;
	}

	ipl_flags = IPL_NSS_VALID;
}

#else /* CONFIG_SHARED_KERNEL */

static inline void create_kernel_nss(void) { }

#endif /* CONFIG_SHARED_KERNEL */

/*
 * Clear bss memory
 */
static noinline __init void clear_bss_section(void)
{
	memset(__bss_start, 0, __bss_stop - __bss_start);
}

/*
 * Initialize storage key for kernel pages
 */
static noinline __init void init_kernel_storage_key(void)
{
	unsigned long end_pfn, init_pfn;

	end_pfn = PFN_UP(__pa(&_end));

	for (init_pfn = 0 ; init_pfn < end_pfn; init_pfn++)
		page_set_storage_key(init_pfn << PAGE_SHIFT, PAGE_DEFAULT_KEY);
}

static noinline __init void detect_machine_type(void)
{
	struct cpuinfo_S390 *cpuinfo = &S390_lowcore.cpu_data;

	get_cpu_id(&S390_lowcore.cpu_data.cpu_id);

	/* Running under z/VM ? */
	if (cpuinfo->cpu_id.version == 0xff)
		machine_flags |= MACHINE_FLAG_VM;

	/* Running on a P/390 ? */
	if (cpuinfo->cpu_id.machine == 0x7490)
		machine_flags |= MACHINE_FLAG_P390;

	/* Running under KVM ? */
	if (cpuinfo->cpu_id.version == 0xfe)
		machine_flags |= MACHINE_FLAG_KVM;
}

#ifdef CONFIG_64BIT
static noinline __init int memory_fast_detect(void)
{
	unsigned long val0 = 0;
	unsigned long val1 = 0xc;
	int ret = -ENOSYS;

	if (ipl_flags & IPL_NSS_VALID)
		return -ENOSYS;

	asm volatile(
		"	diag	%1,%2,0x260\n"
		"0:	lhi	%0,0\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "+d" (ret), "+d" (val0), "+d" (val1) : : "cc");

	if (ret || val0 != val1)
		return -ENOSYS;

	memory_chunk[0].size = val0 + 1;
	return 0;
}
#else
static inline int memory_fast_detect(void)
{
	return -ENOSYS;
}
#endif

static inline __init unsigned long __tprot(unsigned long addr)
{
	int cc = -1;

	asm volatile(
		"	tprot	0(%1),0\n"
		"0:	ipm	%0\n"
		"	srl	%0,28\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "+d" (cc) : "a" (addr) : "cc");
	return (unsigned long)cc;
}

/* Checking memory in 128KB increments. */
#define CHUNK_INCR	(1UL << 17)
#define ADDR2G		(1UL << 31)

static noinline __init void find_memory_chunks(unsigned long memsize)
{
	unsigned long addr = 0, old_addr = 0;
	unsigned long old_cc = CHUNK_READ_WRITE;
	unsigned long cc;
	int chunk = 0;

	while (chunk < MEMORY_CHUNKS) {
		cc = __tprot(addr);
		while (cc == old_cc) {
			addr += CHUNK_INCR;
			if (memsize && addr >= memsize)
				break;
#ifndef CONFIG_64BIT
			if (addr == ADDR2G)
				break;
#endif
			cc = __tprot(addr);
		}

		if (old_addr != addr &&
		    (old_cc == CHUNK_READ_WRITE || old_cc == CHUNK_READ_ONLY)) {
			memory_chunk[chunk].addr = old_addr;
			memory_chunk[chunk].size = addr - old_addr;
			memory_chunk[chunk].type = old_cc;
			chunk++;
		}

		old_addr = addr;
		old_cc = cc;

#ifndef CONFIG_64BIT
		if (addr == ADDR2G)
			break;
#endif
		/*
		 * Finish memory detection at the first hole
		 * if storage size is unknown.
		 */
		if (cc == -1UL && !memsize)
			break;
		if (memsize && addr >= memsize)
			break;
	}
}

static __init void early_pgm_check_handler(void)
{
	unsigned long addr;
	const struct exception_table_entry *fixup;

	addr = S390_lowcore.program_old_psw.addr;
	fixup = search_exception_tables(addr & PSW_ADDR_INSN);
	if (!fixup)
		disabled_wait(0);
	S390_lowcore.program_old_psw.addr = fixup->fixup | PSW_ADDR_AMODE;
}

static noinline __init void setup_lowcore_early(void)
{
	psw_t psw;

	psw.mask = PSW_BASE_BITS | PSW_DEFAULT_KEY;
	psw.addr = PSW_ADDR_AMODE | (unsigned long) s390_base_ext_handler;
	S390_lowcore.external_new_psw = psw;
	psw.addr = PSW_ADDR_AMODE | (unsigned long) s390_base_pgm_handler;
	S390_lowcore.program_new_psw = psw;
	s390_base_pgm_handler_fn = early_pgm_check_handler;
}

static noinline __init void setup_hpage(void)
{
#ifndef CONFIG_DEBUG_PAGEALLOC
	unsigned int facilities;

	facilities = stfl();
	if (!(facilities & (1UL << 23)) || !(facilities & (1UL << 29)))
		return;
	machine_flags |= MACHINE_FLAG_HPAGE;
	__ctl_set_bit(0, 23);
#endif
}

static __init void detect_mvpg(void)
{
#ifndef CONFIG_64BIT
	int rc;

	asm volatile(
		"	la	0,0\n"
		"	mvpg	%2,%2\n"
		"0:	la	%0,0\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "=d" (rc) : "0" (-EOPNOTSUPP), "a" (0) : "memory", "cc", "0");
	if (!rc)
		machine_flags |= MACHINE_FLAG_MVPG;
#endif
}

static __init void detect_ieee(void)
{
#ifndef CONFIG_64BIT
	int rc, tmp;

	asm volatile(
		"	efpc	%1,0\n"
		"0:	la	%0,0\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "=d" (rc), "=d" (tmp): "0" (-EOPNOTSUPP) : "cc");
	if (!rc)
		machine_flags |= MACHINE_FLAG_IEEE;
#endif
}

static __init void detect_csp(void)
{
#ifndef CONFIG_64BIT
	int rc;

	asm volatile(
		"	la	0,0\n"
		"	la	1,0\n"
		"	la	2,4\n"
		"	csp	0,2\n"
		"0:	la	%0,0\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "=d" (rc) : "0" (-EOPNOTSUPP) : "cc", "0", "1", "2");
	if (!rc)
		machine_flags |= MACHINE_FLAG_CSP;
#endif
}

static __init void detect_diag9c(void)
{
	unsigned int cpu_address;
	int rc;

	cpu_address = stap();
	asm volatile(
		"	diag	%2,0,0x9c\n"
		"0:	la	%0,0\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "=d" (rc) : "0" (-EOPNOTSUPP), "d" (cpu_address) : "cc");
	if (!rc)
		machine_flags |= MACHINE_FLAG_DIAG9C;
}

static __init void detect_diag44(void)
{
#ifdef CONFIG_64BIT
	int rc;

	asm volatile(
		"	diag	0,0,0x44\n"
		"0:	la	%0,0\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "=d" (rc) : "0" (-EOPNOTSUPP) : "cc");
	if (!rc)
		machine_flags |= MACHINE_FLAG_DIAG44;
#endif
}

static __init void detect_machine_facilities(void)
{
#ifdef CONFIG_64BIT
	unsigned int facilities;

	facilities = stfl();
	if (facilities & (1 << 28))
		machine_flags |= MACHINE_FLAG_IDTE;
	if (facilities & (1 << 23))
		machine_flags |= MACHINE_FLAG_PFMF;
	if (facilities & (1 << 4))
		machine_flags |= MACHINE_FLAG_MVCOS;
#endif
}

/*
 * Save ipl parameters, clear bss memory, initialize storage keys
 * and create a kernel NSS at startup if the SAVESYS= parm is defined
 */
void __init startup_init(void)
{
	unsigned long long memsize;

	ipl_save_parameters();
	clear_bss_section();
	init_kernel_storage_key();
	lockdep_init();
	lockdep_off();
	detect_machine_type();
	create_kernel_nss();
	sort_main_extable();
	setup_lowcore_early();
	detect_mvpg();
	detect_ieee();
	detect_csp();
	detect_diag9c();
	detect_diag44();
	detect_machine_facilities();
	setup_hpage();
	sclp_read_info_early();
	sclp_facilities_detect();
	memsize = sclp_memory_detect();
#ifndef CONFIG_64BIT
	/*
	 * Can't deal with more than 2G in 31 bit addressing mode, so
	 * limit the value in order to avoid strange side effects.
	 */
	if (memsize > ADDR2G)
		memsize = ADDR2G;
#endif
	if (memory_fast_detect() < 0)
		find_memory_chunks((unsigned long) memsize);
	lockdep_on();
}
