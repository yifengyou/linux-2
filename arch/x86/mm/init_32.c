/*
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 */

#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pfn.h>
#include <linux/poison.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/memory_hotplug.h>
#include <linux/initrd.h>
#include <linux/cpumask.h>

#include <asm/asm.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/dma.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/apic.h>
#include <asm/bugs.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>
#include <asm/paravirt.h>
#include <asm/setup.h>
#include <asm/cacheflush.h>

unsigned int __VMALLOC_RESERVE = 128 << 20;

unsigned long max_pfn_mapped;

DEFINE_PER_CPU(struct mmu_gather, mmu_gathers);
unsigned long highstart_pfn, highend_pfn;

static noinline int do_test_wp_bit(void);

/*
 * Creates a middle page table and puts a pointer to it in the
 * given global directory entry. This only returns the gd entry
 * in non-PAE compilation mode, since the middle layer is folded.
 */
static pmd_t * __init one_md_table_init(pgd_t *pgd)
{
	pud_t *pud;
	pmd_t *pmd_table;

#ifdef CONFIG_X86_PAE
	if (!(pgd_val(*pgd) & _PAGE_PRESENT)) {
		pmd_table = (pmd_t *) alloc_bootmem_low_pages(PAGE_SIZE);

		paravirt_alloc_pmd(&init_mm, __pa(pmd_table) >> PAGE_SHIFT);
		set_pgd(pgd, __pgd(__pa(pmd_table) | _PAGE_PRESENT));
		pud = pud_offset(pgd, 0);
		BUG_ON(pmd_table != pmd_offset(pud, 0));
	}
#endif
	pud = pud_offset(pgd, 0);
	pmd_table = pmd_offset(pud, 0);

	return pmd_table;
}

/*
 * Create a page table and place a pointer to it in a middle page
 * directory entry:
 */
static pte_t * __init one_page_table_init(pmd_t *pmd)
{
	if (!(pmd_val(*pmd) & _PAGE_PRESENT)) {
		pte_t *page_table = NULL;

#ifdef CONFIG_DEBUG_PAGEALLOC
		page_table = (pte_t *) alloc_bootmem_pages(PAGE_SIZE);
#endif
		if (!page_table) {
			page_table =
				(pte_t *)alloc_bootmem_low_pages(PAGE_SIZE);
		}

		paravirt_alloc_pte(&init_mm, __pa(page_table) >> PAGE_SHIFT);
		set_pmd(pmd, __pmd(__pa(page_table) | _PAGE_TABLE));
		BUG_ON(page_table != pte_offset_kernel(pmd, 0));
	}

	return pte_offset_kernel(pmd, 0);
}

/*
 * This function initializes a certain range of kernel virtual memory
 * with new bootmem page tables, everywhere page tables are missing in
 * the given range.
 *
 * NOTE: The pagetables are allocated contiguous on the physical space
 * so we can cache the place of the first one and move around without
 * checking the pgd every time.
 */
static void __init
page_table_range_init(unsigned long start, unsigned long end, pgd_t *pgd_base)
{
	int pgd_idx, pmd_idx;
	unsigned long vaddr;
	pgd_t *pgd;
	pmd_t *pmd;

	vaddr = start;
	pgd_idx = pgd_index(vaddr);
	pmd_idx = pmd_index(vaddr);
	pgd = pgd_base + pgd_idx;

	for ( ; (pgd_idx < PTRS_PER_PGD) && (vaddr != end); pgd++, pgd_idx++) {
		pmd = one_md_table_init(pgd);
		pmd = pmd + pmd_index(vaddr);
		for (; (pmd_idx < PTRS_PER_PMD) && (vaddr != end);
							pmd++, pmd_idx++) {
			one_page_table_init(pmd);

			vaddr += PMD_SIZE;
		}
		pmd_idx = 0;
	}
}

static inline int is_kernel_text(unsigned long addr)
{
	if (addr >= PAGE_OFFSET && addr <= (unsigned long)__init_end)
		return 1;
	return 0;
}

/*
 * This maps the physical memory to kernel virtual address space, a total
 * of max_low_pfn pages, by creating page tables starting from address
 * PAGE_OFFSET:
 */
static void __init kernel_physical_mapping_init(pgd_t *pgd_base)
{
	int pgd_idx, pmd_idx, pte_ofs;
	unsigned long pfn;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;

	pgd_idx = pgd_index(PAGE_OFFSET);
	pgd = pgd_base + pgd_idx;
	pfn = 0;

	for (; pgd_idx < PTRS_PER_PGD; pgd++, pgd_idx++) {
		pmd = one_md_table_init(pgd);
		if (pfn >= max_low_pfn)
			continue;

		for (pmd_idx = 0;
		     pmd_idx < PTRS_PER_PMD && pfn < max_low_pfn;
		     pmd++, pmd_idx++) {
			unsigned int addr = pfn * PAGE_SIZE + PAGE_OFFSET;

			/*
			 * Map with big pages if possible, otherwise
			 * create normal page tables:
			 *
			 * Don't use a large page for the first 2/4MB of memory
			 * because there are often fixed size MTRRs in there
			 * and overlapping MTRRs into large pages can cause
			 * slowdowns.
			 */
			if (cpu_has_pse && !(pgd_idx == 0 && pmd_idx == 0)) {
				unsigned int addr2;
				pgprot_t prot = PAGE_KERNEL_LARGE;

				addr2 = (pfn + PTRS_PER_PTE-1) * PAGE_SIZE +
					PAGE_OFFSET + PAGE_SIZE-1;

				if (is_kernel_text(addr) ||
				    is_kernel_text(addr2))
					prot = PAGE_KERNEL_LARGE_EXEC;

				set_pmd(pmd, pfn_pmd(pfn, prot));

				pfn += PTRS_PER_PTE;
				max_pfn_mapped = pfn;
				continue;
			}
			pte = one_page_table_init(pmd);

			for (pte_ofs = 0;
			     pte_ofs < PTRS_PER_PTE && pfn < max_low_pfn;
			     pte++, pfn++, pte_ofs++, addr += PAGE_SIZE) {
				pgprot_t prot = PAGE_KERNEL;

				if (is_kernel_text(addr))
					prot = PAGE_KERNEL_EXEC;

				set_pte(pte, pfn_pte(pfn, prot));
			}
			max_pfn_mapped = pfn;
		}
	}
}

static inline int page_kills_ppro(unsigned long pagenr)
{
	if (pagenr >= 0x70000 && pagenr <= 0x7003F)
		return 1;
	return 0;
}

/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address
 * is valid. The argument is a physical page number.
 *
 *
 * On x86, access has to be given to the first megabyte of ram because that area
 * contains bios code and data regions used by X and dosemu and similar apps.
 * Access has to be given to non-kernel-ram areas as well, these contain the PCI
 * mmio resources as well as potential bios/acpi data regions.
 */
int devmem_is_allowed(unsigned long pagenr)
{
	if (pagenr <= 256)
		return 1;
	if (!page_is_ram(pagenr))
		return 1;
	return 0;
}

#ifdef CONFIG_HIGHMEM
pte_t *kmap_pte;
pgprot_t kmap_prot;

static inline pte_t *kmap_get_fixmap_pte(unsigned long vaddr)
{
	return pte_offset_kernel(pmd_offset(pud_offset(pgd_offset_k(vaddr),
			vaddr), vaddr), vaddr);
}

static void __init kmap_init(void)
{
	unsigned long kmap_vstart;

	/*
	 * Cache the first kmap pte:
	 */
	kmap_vstart = __fix_to_virt(FIX_KMAP_BEGIN);
	kmap_pte = kmap_get_fixmap_pte(kmap_vstart);

	kmap_prot = PAGE_KERNEL;
}

static void __init permanent_kmaps_init(pgd_t *pgd_base)
{
	unsigned long vaddr;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	vaddr = PKMAP_BASE;
	page_table_range_init(vaddr, vaddr + PAGE_SIZE*LAST_PKMAP, pgd_base);

	pgd = swapper_pg_dir + pgd_index(vaddr);
	pud = pud_offset(pgd, vaddr);
	pmd = pmd_offset(pud, vaddr);
	pte = pte_offset_kernel(pmd, vaddr);
	pkmap_page_table = pte;
}

void __init add_one_highpage_init(struct page *page, int pfn, int bad_ppro)
{
	if (page_is_ram(pfn) && !(bad_ppro && page_kills_ppro(pfn))) {
		ClearPageReserved(page);
		init_page_count(page);
		__free_page(page);
		totalhigh_pages++;
	} else
		SetPageReserved(page);
}

#ifndef CONFIG_NUMA
static void __init set_highmem_pages_init(int bad_ppro)
{
	int pfn;

	for (pfn = highstart_pfn; pfn < highend_pfn; pfn++) {
		/*
		 * Holes under sparsemem might not have no mem_map[]:
		 */
		if (pfn_valid(pfn))
			add_one_highpage_init(pfn_to_page(pfn), pfn, bad_ppro);
	}
	totalram_pages += totalhigh_pages;
}
#endif /* !CONFIG_NUMA */

#else
# define kmap_init()				do { } while (0)
# define permanent_kmaps_init(pgd_base)		do { } while (0)
# define set_highmem_pages_init(bad_ppro)	do { } while (0)
#endif /* CONFIG_HIGHMEM */

pteval_t __PAGE_KERNEL = _PAGE_KERNEL;
EXPORT_SYMBOL(__PAGE_KERNEL);

pteval_t __PAGE_KERNEL_EXEC = _PAGE_KERNEL_EXEC;

void __init native_pagetable_setup_start(pgd_t *base)
{
	unsigned long pfn, va;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/*
	 * Remove any mappings which extend past the end of physical
	 * memory from the boot time page table:
	 */
	for (pfn = max_low_pfn + 1; pfn < 1<<(32-PAGE_SHIFT); pfn++) {
		va = PAGE_OFFSET + (pfn<<PAGE_SHIFT);
		pgd = base + pgd_index(va);
		if (!pgd_present(*pgd))
			break;

		pud = pud_offset(pgd, va);
		pmd = pmd_offset(pud, va);
		if (!pmd_present(*pmd))
			break;

		pte = pte_offset_kernel(pmd, va);
		if (!pte_present(*pte))
			break;

		pte_clear(NULL, va, pte);
	}
	paravirt_alloc_pmd(&init_mm, __pa(base) >> PAGE_SHIFT);
}

void __init native_pagetable_setup_done(pgd_t *base)
{
}

/*
 * Build a proper pagetable for the kernel mappings.  Up until this
 * point, we've been running on some set of pagetables constructed by
 * the boot process.
 *
 * If we're booting on native hardware, this will be a pagetable
 * constructed in arch/x86/kernel/head_32.S.  The root of the
 * pagetable will be swapper_pg_dir.
 *
 * If we're booting paravirtualized under a hypervisor, then there are
 * more options: we may already be running PAE, and the pagetable may
 * or may not be based in swapper_pg_dir.  In any case,
 * paravirt_pagetable_setup_start() will set up swapper_pg_dir
 * appropriately for the rest of the initialization to work.
 *
 * In general, pagetable_init() assumes that the pagetable may already
 * be partially populated, and so it avoids stomping on any existing
 * mappings.
 */
static void __init pagetable_init(void)
{
	pgd_t *pgd_base = swapper_pg_dir;
	unsigned long vaddr, end;

	paravirt_pagetable_setup_start(pgd_base);

	/* Enable PSE if available */
	if (cpu_has_pse)
		set_in_cr4(X86_CR4_PSE);

	/* Enable PGE if available */
	if (cpu_has_pge) {
		set_in_cr4(X86_CR4_PGE);
		__PAGE_KERNEL |= _PAGE_GLOBAL;
		__PAGE_KERNEL_EXEC |= _PAGE_GLOBAL;
	}

	kernel_physical_mapping_init(pgd_base);
	remap_numa_kva();

	/*
	 * Fixed mappings, only the page table structure has to be
	 * created - mappings will be set by set_fixmap():
	 */
	early_ioremap_clear();
	vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
	end = (FIXADDR_TOP + PMD_SIZE - 1) & PMD_MASK;
	page_table_range_init(vaddr, end, pgd_base);
	early_ioremap_reset();

	permanent_kmaps_init(pgd_base);

	paravirt_pagetable_setup_done(pgd_base);
}

#ifdef CONFIG_ACPI_SLEEP
/*
 * ACPI suspend needs this for resume, because things like the intel-agp
 * driver might have split up a kernel 4MB mapping.
 */
char swsusp_pg_dir[PAGE_SIZE]
	__attribute__ ((aligned(PAGE_SIZE)));

static inline void save_pg_dir(void)
{
	memcpy(swsusp_pg_dir, swapper_pg_dir, PAGE_SIZE);
}
#else /* !CONFIG_ACPI_SLEEP */
static inline void save_pg_dir(void)
{
}
#endif /* !CONFIG_ACPI_SLEEP */

void zap_low_mappings(void)
{
	int i;

	/*
	 * Zap initial low-memory mappings.
	 *
	 * Note that "pgd_clear()" doesn't do it for
	 * us, because pgd_clear() is a no-op on i386.
	 */
	for (i = 0; i < KERNEL_PGD_BOUNDARY; i++) {
#ifdef CONFIG_X86_PAE
		set_pgd(swapper_pg_dir+i, __pgd(1 + __pa(empty_zero_page)));
#else
		set_pgd(swapper_pg_dir+i, __pgd(0));
#endif
	}
	flush_tlb_all();
}

int nx_enabled;

pteval_t __supported_pte_mask __read_mostly = ~_PAGE_NX;
EXPORT_SYMBOL_GPL(__supported_pte_mask);

#ifdef CONFIG_X86_PAE

static int disable_nx __initdata;

/*
 * noexec = on|off
 *
 * Control non executable mappings.
 *
 * on      Enable
 * off     Disable
 */
static int __init noexec_setup(char *str)
{
	if (!str || !strcmp(str, "on")) {
		if (cpu_has_nx) {
			__supported_pte_mask |= _PAGE_NX;
			disable_nx = 0;
		}
	} else {
		if (!strcmp(str, "off")) {
			disable_nx = 1;
			__supported_pte_mask &= ~_PAGE_NX;
		} else {
			return -EINVAL;
		}
	}

	return 0;
}
early_param("noexec", noexec_setup);

static void __init set_nx(void)
{
	unsigned int v[4], l, h;

	if (cpu_has_pae && (cpuid_eax(0x80000000) > 0x80000001)) {
		cpuid(0x80000001, &v[0], &v[1], &v[2], &v[3]);

		if ((v[3] & (1 << 20)) && !disable_nx) {
			rdmsr(MSR_EFER, l, h);
			l |= EFER_NX;
			wrmsr(MSR_EFER, l, h);
			nx_enabled = 1;
			__supported_pte_mask |= _PAGE_NX;
		}
	}
}
#endif

/*
 * paging_init() sets up the page tables - note that the first 8MB are
 * already mapped by head.S.
 *
 * This routines also unmaps the page at virtual kernel address 0, so
 * that we can trap those pesky NULL-reference errors in the kernel.
 */
void __init paging_init(void)
{
#ifdef CONFIG_X86_PAE
	set_nx();
	if (nx_enabled)
		printk(KERN_INFO "NX (Execute Disable) protection: active\n");
#endif
	pagetable_init();

	load_cr3(swapper_pg_dir);

	__flush_tlb_all();

	kmap_init();
}

/*
 * Test if the WP bit works in supervisor mode. It isn't supported on 386's
 * and also on some strange 486's. All 586+'s are OK. This used to involve
 * black magic jumps to work around some nasty CPU bugs, but fortunately the
 * switch to using exceptions got rid of all that.
 */
static void __init test_wp_bit(void)
{
	printk(KERN_INFO
  "Checking if this processor honours the WP bit even in supervisor mode...");

	/* Any page-aligned address will do, the test is non-destructive */
	__set_fixmap(FIX_WP_TEST, __pa(&swapper_pg_dir), PAGE_READONLY);
	boot_cpu_data.wp_works_ok = do_test_wp_bit();
	clear_fixmap(FIX_WP_TEST);

	if (!boot_cpu_data.wp_works_ok) {
		printk(KERN_CONT "No.\n");
#ifdef CONFIG_X86_WP_WORKS_OK
		panic(
  "This kernel doesn't support CPU's with broken WP. Recompile it for a 386!");
#endif
	} else {
		printk(KERN_CONT "Ok.\n");
	}
}

static struct kcore_list kcore_mem, kcore_vmalloc;

void __init mem_init(void)
{
	int codesize, reservedpages, datasize, initsize;
	int tmp, bad_ppro;

#ifdef CONFIG_FLATMEM
	BUG_ON(!mem_map);
#endif
	bad_ppro = ppro_with_ram_bug();

#ifdef CONFIG_HIGHMEM
	/* check that fixmap and pkmap do not overlap */
	if (PKMAP_BASE + LAST_PKMAP*PAGE_SIZE >= FIXADDR_START) {
		printk(KERN_ERR
			"fixmap and kmap areas overlap - this will crash\n");
		printk(KERN_ERR "pkstart: %lxh pkend: %lxh fixstart %lxh\n",
				PKMAP_BASE, PKMAP_BASE + LAST_PKMAP*PAGE_SIZE,
				FIXADDR_START);
		BUG();
	}
#endif
	/* this will put all low memory onto the freelists */
	totalram_pages += free_all_bootmem();

	reservedpages = 0;
	for (tmp = 0; tmp < max_low_pfn; tmp++)
		/*
		 * Only count reserved RAM pages:
		 */
		if (page_is_ram(tmp) && PageReserved(pfn_to_page(tmp)))
			reservedpages++;

	set_highmem_pages_init(bad_ppro);

	codesize =  (unsigned long) &_etext - (unsigned long) &_text;
	datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

	kclist_add(&kcore_mem, __va(0), max_low_pfn << PAGE_SHIFT);
	kclist_add(&kcore_vmalloc, (void *)VMALLOC_START,
		   VMALLOC_END-VMALLOC_START);

	printk(KERN_INFO "Memory: %luk/%luk available (%dk kernel code, "
			"%dk reserved, %dk data, %dk init, %ldk highmem)\n",
		(unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
		num_physpages << (PAGE_SHIFT-10),
		codesize >> 10,
		reservedpages << (PAGE_SHIFT-10),
		datasize >> 10,
		initsize >> 10,
		(unsigned long) (totalhigh_pages << (PAGE_SHIFT-10))
	       );

#if 1 /* double-sanity-check paranoia */
	printk(KERN_INFO "virtual kernel memory layout:\n"
		"    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HIGHMEM
		"    pkmap   : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
		"    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
		"    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
		"      .init : 0x%08lx - 0x%08lx   (%4ld kB)\n"
		"      .data : 0x%08lx - 0x%08lx   (%4ld kB)\n"
		"      .text : 0x%08lx - 0x%08lx   (%4ld kB)\n",
		FIXADDR_START, FIXADDR_TOP,
		(FIXADDR_TOP - FIXADDR_START) >> 10,

#ifdef CONFIG_HIGHMEM
		PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE,
		(LAST_PKMAP*PAGE_SIZE) >> 10,
#endif

		VMALLOC_START, VMALLOC_END,
		(VMALLOC_END - VMALLOC_START) >> 20,

		(unsigned long)__va(0), (unsigned long)high_memory,
		((unsigned long)high_memory - (unsigned long)__va(0)) >> 20,

		(unsigned long)&__init_begin, (unsigned long)&__init_end,
		((unsigned long)&__init_end -
		 (unsigned long)&__init_begin) >> 10,

		(unsigned long)&_etext, (unsigned long)&_edata,
		((unsigned long)&_edata - (unsigned long)&_etext) >> 10,

		(unsigned long)&_text, (unsigned long)&_etext,
		((unsigned long)&_etext - (unsigned long)&_text) >> 10);

#ifdef CONFIG_HIGHMEM
	BUG_ON(PKMAP_BASE + LAST_PKMAP*PAGE_SIZE	> FIXADDR_START);
	BUG_ON(VMALLOC_END				> PKMAP_BASE);
#endif
	BUG_ON(VMALLOC_START				> VMALLOC_END);
	BUG_ON((unsigned long)high_memory		> VMALLOC_START);
#endif /* double-sanity-check paranoia */

	if (boot_cpu_data.wp_works_ok < 0)
		test_wp_bit();

	cpa_init();
	save_pg_dir();
	zap_low_mappings();
}

#ifdef CONFIG_MEMORY_HOTPLUG
int arch_add_memory(int nid, u64 start, u64 size)
{
	struct pglist_data *pgdata = NODE_DATA(nid);
	struct zone *zone = pgdata->node_zones + ZONE_HIGHMEM;
	unsigned long start_pfn = start >> PAGE_SHIFT;
	unsigned long nr_pages = size >> PAGE_SHIFT;

	return __add_pages(zone, start_pfn, nr_pages);
}
#endif

/*
 * This function cannot be __init, since exceptions don't work in that
 * section.  Put this after the callers, so that it cannot be inlined.
 */
static noinline int do_test_wp_bit(void)
{
	char tmp_reg;
	int flag;

	__asm__ __volatile__(
		"	movb %0, %1	\n"
		"1:	movb %1, %0	\n"
		"	xorl %2, %2	\n"
		"2:			\n"
		_ASM_EXTABLE(1b,2b)
		:"=m" (*(char *)fix_to_virt(FIX_WP_TEST)),
		 "=q" (tmp_reg),
		 "=r" (flag)
		:"2" (1)
		:"memory");

	return flag;
}

#ifdef CONFIG_DEBUG_RODATA
const int rodata_test_data = 0xC3;
EXPORT_SYMBOL_GPL(rodata_test_data);

void mark_rodata_ro(void)
{
	unsigned long start = PFN_ALIGN(_text);
	unsigned long size = PFN_ALIGN(_etext) - start;

	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
	printk(KERN_INFO "Write protecting the kernel text: %luk\n",
		size >> 10);

#ifdef CONFIG_CPA_DEBUG
	printk(KERN_INFO "Testing CPA: Reverting %lx-%lx\n",
		start, start+size);
	set_pages_rw(virt_to_page(start), size>>PAGE_SHIFT);

	printk(KERN_INFO "Testing CPA: write protecting again\n");
	set_pages_ro(virt_to_page(start), size>>PAGE_SHIFT);
#endif
	start += size;
	size = (unsigned long)__end_rodata - start;
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
	printk(KERN_INFO "Write protecting the kernel read-only data: %luk\n",
		size >> 10);
	rodata_test();

#ifdef CONFIG_CPA_DEBUG
	printk(KERN_INFO "Testing CPA: undo %lx-%lx\n", start, start + size);
	set_pages_rw(virt_to_page(start), size >> PAGE_SHIFT);

	printk(KERN_INFO "Testing CPA: write protecting again\n");
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
#endif
}
#endif

void free_init_pages(char *what, unsigned long begin, unsigned long end)
{
#ifdef CONFIG_DEBUG_PAGEALLOC
	/*
	 * If debugging page accesses then do not free this memory but
	 * mark them not present - any buggy init-section access will
	 * create a kernel page fault:
	 */
	printk(KERN_INFO "debug: unmapping init memory %08lx..%08lx\n",
		begin, PAGE_ALIGN(end));
	set_memory_np(begin, (end - begin) >> PAGE_SHIFT);
#else
	unsigned long addr;

	/*
	 * We just marked the kernel text read only above, now that
	 * we are going to free part of that, we need to make that
	 * writeable first.
	 */
	set_memory_rw(begin, (end - begin) >> PAGE_SHIFT);

	for (addr = begin; addr < end; addr += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(addr));
		init_page_count(virt_to_page(addr));
		memset((void *)addr, POISON_FREE_INITMEM, PAGE_SIZE);
		free_page(addr);
		totalram_pages++;
	}
	printk(KERN_INFO "Freeing %s: %luk freed\n", what, (end - begin) >> 10);
#endif
}

void free_initmem(void)
{
	free_init_pages("unused kernel memory",
			(unsigned long)(&__init_begin),
			(unsigned long)(&__init_end));
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
	free_init_pages("initrd memory", start, end);
}
#endif
