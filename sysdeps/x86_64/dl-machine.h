/* Machine-dependent ELF dynamic relocation inline functions.  x86-64 version.
   Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Andreas Jaeger <aj@suse.de>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef dl_machine_h
#define dl_machine_h

#define ELF_MACHINE_NAME "x86_64"

#include <sys/param.h>
#include <sysdep.h>
#include <tls.h>

/* Return nonzero iff ELF header is compatible with the running host.  */
static inline int __attribute__ ((unused))
elf_machine_matches_host (const Elf64_Ehdr *ehdr)
{
  return ehdr->e_machine == EM_X86_64;
}


/* Return the link-time address of _DYNAMIC.  Conveniently, this is the
   first element of the GOT.  This must be inlined in a function which
   uses global data.  */
static inline Elf64_Addr __attribute__ ((unused))
elf_machine_dynamic (void)
{
  Elf64_Addr addr;

  /* This works because we have our GOT address available in the small PIC
     model.  */
  addr = (Elf64_Addr) &_DYNAMIC;

  return addr;
}


/* Return the run-time load address of the shared object.  */
static inline Elf64_Addr __attribute__ ((unused))
elf_machine_load_address (void)
{
  register Elf64_Addr addr, tmp;

  /* The easy way is just the same as on x86:
       leaq _dl_start, %0
       leaq _dl_start(%%rip), %1
       subq %0, %1
     but this does not work with binutils since we then have
     a R_X86_64_32S relocation in a shared lib.

     Instead we store the address of _dl_start in the data section
     and compare it with the current value that we can get via
     an RIP relative addressing mode.  */

  asm ("movq 1f(%%rip), %1\n"
       "0:\tleaq _dl_start(%%rip), %0\n\t"
       "subq %1, %0\n\t"
       ".section\t.data\n"
       "1:\t.quad _dl_start\n\t"
       ".previous\n\t"
       : "=r" (addr), "=r" (tmp) : : "cc");

  return addr;
}

/* Set up the loaded object described by L so its unrelocated PLT
   entries will jump to the on-demand fixup code in dl-runtime.c.  */

static inline int __attribute__ ((unused, always_inline))
elf_machine_runtime_setup (struct link_map *l, int lazy, int profile)
{
  Elf64_Addr *got;
  extern void _dl_runtime_resolve (Elf64_Word) attribute_hidden;
  extern void _dl_runtime_profile (Elf64_Word) attribute_hidden;

  if (l->l_info[DT_JMPREL] && lazy)
    {
      /* The GOT entries for functions in the PLT have not yet been filled
	 in.  Their initial contents will arrange when called to push an
	 offset into the .rel.plt section, push _GLOBAL_OFFSET_TABLE_[1],
	 and then jump to _GLOBAL_OFFSET_TABLE[2].  */
      got = (Elf64_Addr *) D_PTR (l, l_info[DT_PLTGOT]);
      /* If a library is prelinked but we have to relocate anyway,
	 we have to be able to undo the prelinking of .got.plt.
	 The prelinker saved us here address of .plt + 0x16.  */
      if (got[1])
	{
	  l->l_mach.plt = got[1] + l->l_addr;
	  l->l_mach.gotplt = (Elf64_Addr) &got[3];
	}
      got[1] = (Elf64_Addr) l;	/* Identify this shared object.  */

      /* The got[2] entry contains the address of a function which gets
	 called to get the address of a so far unresolved function and
	 jump to it.  The profiling extension of the dynamic linker allows
	 to intercept the calls to collect information.  In this case we
	 don't store the address in the GOT so that all future calls also
	 end in this function.  */
      if (__builtin_expect (profile, 0))
	{
	  got[2] = (Elf64_Addr) &_dl_runtime_profile;

	  if (_dl_name_match_p (GLRO(dl_profile), l))
	    /* This is the object we are looking for.  Say that we really
	       want profiling and the timers are started.  */
	    GL(dl_profile_map) = l;
	}
      else
	/* This function will get called to fix up the GOT entry indicated by
	   the offset on the stack, and then jump to the resolved address.  */
	got[2] = (Elf64_Addr) &_dl_runtime_resolve;
    }

  return lazy;
}

/* This code is used in dl-runtime.c to call the `fixup' function
   and then redirect to the address it returns.  */
#ifndef PROF
# define ELF_MACHINE_RUNTIME_TRAMPOLINE asm ("\n\
	.text\n\
	.globl _dl_runtime_resolve\n\
	.type _dl_runtime_resolve, @function\n\
	.align 16\n\
	" CFI_STARTPROC "\n\
_dl_runtime_resolve:\n\
	subq $56,%rsp\n\
	" CFI_ADJUST_CFA_OFFSET(72)" # Incorporate PLT\n\
	movq %rax,(%rsp)	# Preserve registers otherwise clobbered.\n\
	movq %rcx,8(%rsp)\n\
	movq %rdx,16(%rsp)\n\
	movq %rsi,24(%rsp)\n\
	movq %rdi,32(%rsp)\n\
	movq %r8,40(%rsp)\n\
	movq %r9,48(%rsp)\n\
	movq 64(%rsp), %rsi	# Copy args pushed by PLT in register.\n\
	movq %rsi,%r11		# Multiply by 24\n\
	addq %r11,%rsi\n\
	addq %r11,%rsi\n\
	shlq $3, %rsi\n\
	movq 56(%rsp), %rdi	# %rdi: link_map, %rsi: reloc_offset\n\
	call fixup		# Call resolver.\n\
	movq %rax, %r11		# Save return value\n\
	movq 48(%rsp),%r9	# Get register content back.\n\
	movq 40(%rsp),%r8\n\
	movq 32(%rsp),%rdi\n\
	movq 24(%rsp),%rsi\n\
	movq 16(%rsp),%rdx\n\
	movq 8(%rsp),%rcx\n\
	movq (%rsp),%rax\n\
	addq $72,%rsp		# Adjust stack(PLT did 2 pushes)\n\
	" CFI_ADJUST_CFA_OFFSET(-72)" \n\
	jmp *%r11		# Jump to function address.\n\
	" CFI_ENDPROC "\n\
	.size _dl_runtime_resolve, .-_dl_runtime_resolve\n\
\n\
	.globl _dl_runtime_profile\n\
	.type _dl_runtime_profile, @function\n\
	.align 16\n\
	" CFI_STARTPROC "\n\
_dl_runtime_profile:\n\
	subq $56,%rsp\n\
	" CFI_ADJUST_CFA_OFFSET(72)" # Incorporate PLT\n\
	movq %rax,(%rsp)	# Preserve registers otherwise clobbered.\n\
	movq %rcx,8(%rsp)\n\
	movq %rdx,16(%rsp)\n\
	movq %rsi,24(%rsp)\n\
	movq %rdi,32(%rsp)\n\
	movq %r8,40(%rsp)\n\
	movq %r9,48(%rsp)\n\
	movq 72(%rsp), %rdx	# Load return address if needed\n\
	movq 64(%rsp), %rsi	# Copy args pushed by PLT in register.\n\
	movq %rsi,%r11		# Multiply by 24\n\
	addq %r11,%rsi\n\
	addq %r11,%rsi\n\
	shlq $3, %rsi\n\
	movq 56(%rsp), %rdi	# %rdi: link_map, %rsi: reloc_offset\n\
	call profile_fixup	# Call resolver.\n\
	movq %rax, %r11		# Save return value\n\
	movq 48(%rsp),%r9	# Get register content back.\n\
	movq 40(%rsp),%r8\n\
	movq 32(%rsp),%rdi\n\
	movq 24(%rsp),%rsi\n\
	movq 16(%rsp),%rdx\n\
	movq 8(%rsp),%rcx\n\
	movq (%rsp),%rax\n\
	addq $72,%rsp		# Adjust stack\n\
	" CFI_ADJUST_CFA_OFFSET(-72)"\n\
	jmp *%r11		# Jump to function address.\n\
	" CFI_ENDPROC "\n\
	.size _dl_runtime_profile, .-_dl_runtime_profile\n\
	.previous\n\
");
#else
# define ELF_MACHINE_RUNTIME_TRAMPOLINE asm ("\n\
	.text\n\
	.globl _dl_runtime_resolve\n\
	.globl _dl_runtime_profile\n\
	.type _dl_runtime_resolve, @function\n\
	.type _dl_runtime_profile, @function\n\
	.align 16\n\
	" CFI_STARTPROC "\n\
_dl_runtime_resolve:\n\
_dl_runtime_profile:\n\
	subq $56,%rsp\n\
	" CFI_ADJUST_CFA_OFFSET(72)" # Incorporate PLT\n\
	movq %rax,(%rsp)	# Preserve registers otherwise clobbered.\n\
	movq %rcx,8(%rsp)\n\
	movq %rdx,16(%rsp)\n\
	movq %rsi,24(%rsp)\n\
	movq %rdi,32(%rsp)\n\
	movq %r8,40(%rsp)\n\
	movq %r9,48(%rsp)\n\
	movq 64(%rsp), %rsi	# Copy args pushed by PLT in register.\n\
	movq %rsi,%r11		# Multiply by 24\n\
	addq %r11,%rsi\n\
	addq %r11,%rsi\n\
	shlq $3, %rsi\n\
	movq 56(%rsp), %rdi	# %rdi: link_map, %rsi: reloc_offset\n\
	call fixup		# Call resolver.\n\
	movq %rax, %r11		# Save return value\n\
	movq 48(%rsp),%r9	# Get register content back.\n\
	movq 40(%rsp),%r8\n\
	movq 32(%rsp),%rdi\n\
	movq 24(%rsp),%rsi\n\
	movq 16(%rsp),%rdx\n\
	movq 8(%rsp),%rcx\n\
	movq (%rsp),%rax\n\
	addq $72,%rsp		# Adjust stack\n\
	" CFI_ADJUST_CFA_OFFSET(-72)"\n\
	jmp *%r11		# Jump to function address.\n\
	" CFI_ENDPROC "\n\
	.size _dl_runtime_resolve, .-_dl_runtime_resolve\n\
	.size _dl_runtime_profile, .-_dl_runtime_profile\n\
	.previous\n\
");
#endif

/* Initial entry point code for the dynamic linker.
   The C function `_dl_start' is the real entry point;
   its return value is the user program's entry point.  */
#define RTLD_START asm ("\n\
.text\n\
	.align 16\n\
.globl _start\n\
.globl _dl_start_user\n\
_start:\n\
	movq %rsp, %rdi\n\
	call _dl_start\n\
_dl_start_user:\n\
	# Save the user entry point address in %r12.\n\
	movq %rax, %r12\n\
	# See if we were run as a command with the executable file\n\
	# name as an extra leading argument.\n\
	movl _dl_skip_args(%rip), %eax\n\
	# Pop the original argument count.\n\
	popq %rdx\n\
	# Adjust the stack pointer to skip _dl_skip_args words.\n\
	leaq (%rsp,%rax,8), %rsp\n\
	# Subtract _dl_skip_args from argc.\n\
	subl %eax, %edx\n\
	# Push argc back on the stack.\n\
	pushq %rdx\n\
	# Call _dl_init (struct link_map *main_map, int argc, char **argv, char **env)\n\
	# argc -> rsi\n\
	movq %rdx, %rsi\n\
	# Save %rsp value in %r13.\n\
	movq %rsp, %r13\n\
	# And align stack for the _dl_init_internal call. \n\
	andq $-16, %rsp\n\
	# _dl_loaded -> rdi\n\
	movq _rtld_local(%rip), %rdi\n\
	# env -> rcx\n\
	leaq 16(%r13,%rdx,8), %rcx\n\
	# argv -> rdx\n\
	leaq 8(%r13), %rdx\n\
	# Clear %rbp to mark outermost frame obviously even for constructors.\n\
	xorq %rbp, %rbp\n\
	# Call the function to run the initializers.\n\
	call _dl_init_internal@PLT\n\
	# Pass our finalizer function to the user in %rdx, as per ELF ABI.\n\
	leaq _dl_fini(%rip), %rdx\n\
	# And make sure %rsp points to argc stored on the stack.\n\
	movq %r13, %rsp\n\
	# Jump to the user's entry point.\n\
	jmp *%r12\n\
.previous\n\
");

/* ELF_RTYPE_CLASS_PLT iff TYPE describes relocation of a PLT entry or
   TLS variable, so undefined references should not be allowed to
   define the value.
   ELF_RTYPE_CLASS_NOCOPY iff TYPE should not be allowed to resolve to one
   of the main executable's symbols, as for a COPY reloc.  */
#if defined USE_TLS && (!defined RTLD_BOOTSTRAP || USE___THREAD)
# define elf_machine_type_class(type)					      \
  ((((type) == R_X86_64_JUMP_SLOT					      \
     || (type) == R_X86_64_DTPMOD64					      \
     || (type) == R_X86_64_DTPOFF64 || (type) == R_X86_64_TPOFF64)	      \
    * ELF_RTYPE_CLASS_PLT)						      \
   | (((type) == R_X86_64_COPY) * ELF_RTYPE_CLASS_COPY))
#else
# define elf_machine_type_class(type) \
  ((((type) == R_X86_64_JUMP_SLOT) * ELF_RTYPE_CLASS_PLT) \
   | (((type) == R_X86_64_COPY) * ELF_RTYPE_CLASS_COPY))
#endif

/* A reloc type used for ld.so cmdline arg lookups to reject PLT entries.  */
#define ELF_MACHINE_JMP_SLOT	R_X86_64_JUMP_SLOT

/* The x86-64 never uses Elf64_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1

/* We define an initialization functions.  This is called very early in
   _dl_sysdep_start.  */
#define DL_PLATFORM_INIT dl_platform_init ()

static inline void __attribute__ ((unused))
dl_platform_init (void)
{
  if (GLRO(dl_platform) != NULL && *GLRO(dl_platform) == '\0')
    /* Avoid an empty string which would disturb us.  */
    GLRO(dl_platform) = NULL;
}

static inline Elf64_Addr
elf_machine_fixup_plt (struct link_map *map, lookup_t t,
		       const Elf64_Rela *reloc,
		       Elf64_Addr *reloc_addr, Elf64_Addr value)
{
  return *reloc_addr = value;
}

/* Return the final value of a plt relocation.  On x86-64 the
   JUMP_SLOT relocation ignores the addend. */
static inline Elf64_Addr
elf_machine_plt_value (struct link_map *map, const Elf64_Rela *reloc,
		       Elf64_Addr value)
{
  return value;
}

#endif /* !dl_machine_h */

#ifdef RESOLVE

/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

auto inline void
__attribute__ ((always_inline))
elf_machine_rela (struct link_map *map, const Elf64_Rela *reloc,
		  const Elf64_Sym *sym, const struct r_found_version *version,
		  void *const reloc_addr_arg)
{
  Elf64_Addr *const reloc_addr = reloc_addr_arg;
  const unsigned long int r_type = ELF64_R_TYPE (reloc->r_info);

#if !defined RTLD_BOOTSTRAP || !defined HAVE_Z_COMBRELOC
  if (__builtin_expect (r_type == R_X86_64_RELATIVE, 0))
    {
# if !defined RTLD_BOOTSTRAP && !defined HAVE_Z_COMBRELOC
      /* This is defined in rtld.c, but nowhere in the static libc.a;
	 make the reference weak so static programs can still link.
	 This declaration cannot be done when compiling rtld.c
	 (i.e. #ifdef RTLD_BOOTSTRAP) because rtld.c contains the
	 common defn for _dl_rtld_map, which is incompatible with a
	 weak decl in the same file.  */
#  ifndef SHARED
      weak_extern (GL(dl_rtld_map));
#  endif
      if (map != &GL(dl_rtld_map)) /* Already done in rtld itself.  */
# endif
	*reloc_addr = map->l_addr + reloc->r_addend;
    }
  else
#endif
  if (__builtin_expect (r_type == R_X86_64_NONE, 0))
    return;
  else
    {
#ifndef RTLD_BOOTSTRAP
      const Elf64_Sym *const refsym = sym;
#endif
#if defined USE_TLS && !defined RTLD_BOOTSTRAP
      struct link_map *sym_map = RESOLVE_MAP (&sym, version, r_type);
      Elf64_Addr value = (sym == NULL ? 0
			  : (Elf64_Addr) sym_map->l_addr + sym->st_value);
#else
      Elf64_Addr value = RESOLVE (&sym, version, r_type);

# ifndef RTLD_BOOTSTRAP
      if (sym != NULL)
# endif
	value += sym->st_value;
#endif

#if defined RTLD_BOOTSTRAP && !USE___THREAD
      assert (r_type == R_X86_64_GLOB_DAT || r_type == R_X86_64_JUMP_SLOT);
      *reloc_addr = value + reloc->r_addend;
#else
      switch (r_type)
	{
	case R_X86_64_GLOB_DAT:
	case R_X86_64_JUMP_SLOT:
	  *reloc_addr = value + reloc->r_addend;
	  break;

#if defined USE_TLS && !defined RESOLVE_CONFLICT_FIND_MAP
	case R_X86_64_DTPMOD64:
# ifdef RTLD_BOOTSTRAP
	  /* During startup the dynamic linker is always the module
	     with index 1.
	     XXX If this relocation is necessary move before RESOLVE
	     call.  */
	  *reloc_addr = 1;
# else
	  /* Get the information from the link map returned by the
	     resolve function.  */
	  if (sym_map != NULL)
	    *reloc_addr = sym_map->l_tls_modid;
# endif
	  break;
	case R_X86_64_DTPOFF64:
# ifndef RTLD_BOOTSTRAP
	  /* During relocation all TLS symbols are defined and used.
	     Therefore the offset is already correct.  */
	  if (sym != NULL)
	    *reloc_addr = sym->st_value + reloc->r_addend;
# endif
	  break;
	case R_X86_64_TPOFF64:
	  /* The offset is negative, forward from the thread pointer.  */
# ifndef RTLD_BOOTSTRAP
	  if (sym != NULL)
# endif
	    {
# ifndef RTLD_BOOTSTRAP
	      CHECK_STATIC_TLS (map, sym_map);
# endif
	      /* We know the offset of the object the symbol is contained in.
		 It is a negative value which will be added to the
		 thread pointer.  */
	      *reloc_addr = (sym->st_value + reloc->r_addend
			     - sym_map->l_tls_offset);
	    }
	  break;
#endif	/* use TLS */

#ifndef RTLD_BOOTSTRAP
	case R_X86_64_64:
	  *reloc_addr = value + reloc->r_addend;
	  break;
	case R_X86_64_32:
	  *(unsigned int *) reloc_addr = value + reloc->r_addend;
	  if (value + reloc->r_addend > UINT_MAX)
	    {
	      const char *strtab;

	      strtab = (const char *) D_PTR (map, l_info[DT_STRTAB]);

	      _dl_error_printf ("\
%s: Symbol `%s' causes overflow in R_X86_64_32 relocation\n",
				rtld_progname ?: "<program name unknown>",
				strtab + refsym->st_name);
	    }
	  break;
# ifndef RESOLVE_CONFLICT_FIND_MAP
	  /* Not needed for dl-conflict.c.  */
	case R_X86_64_PC32:
	  *(unsigned int *) reloc_addr = value + reloc->r_addend
	    - (Elf64_Addr) reloc_addr;
	  if (value + reloc->r_addend - (Elf64_Addr) reloc_addr
	      != (int)(value + reloc->r_addend - (Elf64_Addr) reloc_addr))
	    {
	      const char *strtab;

	      strtab = (const char *) D_PTR (map, l_info[DT_STRTAB]);

	      _dl_error_printf ("\
%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation\n",
				rtld_progname ?: "<program name unknown>",
				strtab + refsym->st_name);
	    }
	  break;
	case R_X86_64_COPY:
	  if (sym == NULL)
	    /* This can happen in trace mode if an object could not be
	       found.  */
	    break;
	  if (__builtin_expect (sym->st_size > refsym->st_size, 0)
	      || (__builtin_expect (sym->st_size < refsym->st_size, 0)
		  && GLRO(dl_verbose)))
	    {
	      const char *strtab;

	      strtab = (const char *) D_PTR (map, l_info[DT_STRTAB]);
	      _dl_error_printf ("\
%s: Symbol `%s' has different size in shared object, consider re-linking\n",
				rtld_progname ?: "<program name unknown>",
				strtab + refsym->st_name);
	    }
	  memcpy (reloc_addr_arg, (void *) value,
		  MIN (sym->st_size, refsym->st_size));
	  break;
# endif
	default:
	  _dl_reloc_bad_type (map, r_type, 0);
	  break;
#endif
	}
#endif
    }
}

auto inline void
__attribute ((always_inline))
elf_machine_rela_relative (Elf64_Addr l_addr, const Elf64_Rela *reloc,
			   void *const reloc_addr_arg)
{
  Elf64_Addr *const reloc_addr = reloc_addr_arg;
  assert (ELF64_R_TYPE (reloc->r_info) == R_X86_64_RELATIVE);
  *reloc_addr = l_addr + reloc->r_addend;
}

auto inline void
__attribute ((always_inline))
elf_machine_lazy_rel (struct link_map *map,
		      Elf64_Addr l_addr, const Elf64_Rela *reloc)
{
  Elf64_Addr *const reloc_addr = (void *) (l_addr + reloc->r_offset);
  const unsigned long int r_type = ELF64_R_TYPE (reloc->r_info);

  /* Check for unexpected PLT reloc type.  */
  if (__builtin_expect (r_type == R_X86_64_JUMP_SLOT, 1))
    {
      if (__builtin_expect (map->l_mach.plt, 0) == 0)
	*reloc_addr += l_addr;
      else
	*reloc_addr =
	  map->l_mach.plt
	  + (((Elf64_Addr) reloc_addr) - map->l_mach.gotplt) * 2;
    }
  else
    _dl_reloc_bad_type (map, r_type, 1);
}

#endif /* RESOLVE */
