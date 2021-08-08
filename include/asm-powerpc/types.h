#ifndef _ASM_POWERPC_TYPES_H
#define _ASM_POWERPC_TYPES_H

#ifdef __powerpc64__
# include <asm-generic/int-l64.h>
#else
# include <asm-generic/int-ll64.h>
#endif

#ifndef __ASSEMBLY__

/*
 * This file is never included by application software unless
 * explicitly requested (e.g., via linux/types.h) in which case the
 * application is Linux specific so (user-) name space pollution is
 * not a major issue.  However, for interoperability, libraries still
 * need to be careful to avoid a name clashes.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifdef __powerpc64__
typedef unsigned int umode_t;
#else
typedef unsigned short umode_t;
#endif

typedef struct {
	__u32 u[4];
} __attribute__((aligned(16))) __vector128;

#endif /* __ASSEMBLY__ */

#ifdef __KERNEL__
/*
 * These aren't exported outside the kernel to avoid name space clashes
 */
#ifdef __powerpc64__
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif

#ifndef __ASSEMBLY__

typedef __vector128 vector128;

/* Physical address used by some IO functions */
#if defined(CONFIG_PPC64) || defined(CONFIG_PHYS_64BIT)
typedef u64 phys_addr_t;
#else
typedef u32 phys_addr_t;
#endif

#ifdef __powerpc64__
typedef u64 dma_addr_t;
#else
typedef u32 dma_addr_t;
#endif
typedef u64 dma64_addr_t;

typedef struct {
	unsigned long entry;
	unsigned long toc;
	unsigned long env;
} func_descr_t;

#endif /* __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _ASM_POWERPC_TYPES_H */
