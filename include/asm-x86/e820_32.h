/*
 * structures and definitions for the int 15, ax=e820 memory map
 * scheme.
 *
 * In a nutshell, arch/i386/boot/setup.S populates a scratch table
 * in the empty_zero_block that contains a list of usable address/size
 * duples.   In arch/i386/kernel/setup.c, this information is
 * transferred into the e820map, and in arch/i386/mm/init.c, that
 * new information is used to mark pages reserved or not.
 *
 */
#ifndef __E820_HEADER
#define __E820_HEADER

#include <linux/ioport.h>

#define HIGH_MEMORY	(1024*1024)

#ifndef __ASSEMBLY__

extern struct e820map e820;
extern void update_e820(void);

extern int e820_all_mapped(unsigned long start, unsigned long end,
			   unsigned type);
extern int e820_any_mapped(u64 start, u64 end, unsigned type);
extern void propagate_e820_map(void);
extern void register_bootmem_low_pages(unsigned long max_low_pfn);
extern void add_memory_region(unsigned long long start,
			      unsigned long long size, int type);
extern void update_memory_range(u64 start, u64 size, unsigned old_type,
				unsigned new_type);
extern void e820_register_memory(void);
extern void limit_regions(unsigned long long size);
extern void print_memory_map(char *who);
extern void init_iomem_resources(struct resource *code_resource,
				 struct resource *data_resource,
				 struct resource *bss_resource);

#if defined(CONFIG_PM) && defined(CONFIG_HIBERNATION)
extern void e820_mark_nosave_regions(void);
#else
static inline void e820_mark_nosave_regions(void)
{
}
#endif


#endif/*!__ASSEMBLY__*/
#endif/*__E820_HEADER*/
