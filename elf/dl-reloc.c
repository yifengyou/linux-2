/* Relocate a shared object and resolve its references to other loaded objects.
   Copyright (C) 1995-2002, 2003, 2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

#include <errno.h>
#include <libintl.h>
#include <stdlib.h>
#include <unistd.h>
#include <ldsodefs.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include "dynamic-link.h"

/* Statistics function.  */
#ifdef SHARED
# define bump_num_cache_relocations() ++GL(dl_num_cache_relocations)
#else
# define bump_num_cache_relocations() ((void) 0)
#endif


#ifdef USE_TLS
/* We are trying to perform a static TLS relocation in MAP, but it was
   dynamically loaded.  This can only work if there is enough surplus in
   the static TLS area already allocated for each running thread.  If this
   object's TLS segment is too big to fit, we fail.  If it fits,
   we set MAP->l_tls_offset and return.
   This function intentionally does not return any value but signals error
   directly, as static TLS should be rare and code handling it should
   not be inlined as much as possible.  */
void
internal_function __attribute_noinline__
_dl_allocate_static_tls (struct link_map *map)
{
  size_t offset;

  /* If the alignment requirements are too high fail.  */
  if (map->l_tls_align > GL(dl_tls_static_align))
    {
    fail:
      _dl_signal_error (0, map->l_name, NULL, N_("\
cannot allocate memory in static TLS block"));
    }

# if TLS_TCB_AT_TP
  size_t freebytes;
  size_t n;
  size_t blsize;

  freebytes = GL(dl_tls_static_size) - GL(dl_tls_static_used) - TLS_TCB_SIZE;

  blsize = map->l_tls_blocksize + map->l_tls_firstbyte_offset;
  if (freebytes < blsize)
    goto fail;

  n = (freebytes - blsize) / map->l_tls_align;

  offset = GL(dl_tls_static_used) + (freebytes - n * map->l_tls_align
				     - map->l_tls_firstbyte_offset);

  map->l_tls_offset = GL(dl_tls_static_used) = offset;
# elif TLS_DTV_AT_TP
  size_t used;
  size_t check;

  offset = roundup (GL(dl_tls_static_used), map->l_tls_align);
  used = offset + map->l_tls_blocksize;
  check = used;
  /* dl_tls_static_used includes the TCB at the beginning.  */

  if (check > GL(dl_tls_static_size))
    goto fail;

  map->l_tls_offset = offset;
  GL(dl_tls_static_used) = used;
# else
#  error "Either TLS_TCB_AT_TP or TLS_DTV_AT_TP must be defined"
# endif

  if (map->l_relocated)
    GL(dl_init_static_tls) (map);
  else
    map->l_need_tls_init = 1;
}

/* Initialize static TLS area and DTV for current (only) thread.
   libpthread implementations should provide their own hook
   to handle all threads.  */
void
_dl_nothread_init_static_tls (struct link_map *map)
{
# if TLS_TCB_AT_TP
  void *dest = (char *) THREAD_SELF - map->l_tls_offset;
# elif TLS_DTV_AT_TP
  void *dest = (char *) THREAD_SELF + map->l_tls_offset + TLS_PRE_TCB_SIZE;
# else
#  error "Either TLS_TCB_AT_TP or TLS_DTV_AT_TP must be defined"
# endif

  /* Fill in the DTV slot so that a later LD/GD access will find it.  */
  dtv_t *dtv = THREAD_DTV ();
  assert (map->l_tls_modid <= dtv[-1].counter);
  dtv[map->l_tls_modid].pointer = dest;

  /* Initialize the memory.  */
  memset (__mempcpy (dest, map->l_tls_initimage, map->l_tls_initimage_size),
	  '\0', map->l_tls_blocksize - map->l_tls_initimage_size);
}
#endif


void
_dl_relocate_object (struct link_map *l, struct r_scope_elem *scope[],
		     int lazy, int consider_profiling)
{
  struct textrels
  {
    caddr_t start;
    size_t len;
    int prot;
    struct textrels *next;
  } *textrels = NULL;
  /* Initialize it to make the compiler happy.  */
  const char *errstring = NULL;

  if (l->l_relocated)
    return;

  /* If DT_BIND_NOW is set relocate all references in this object.  We
     do not do this if we are profiling, of course.  */
  if (!consider_profiling
      && __builtin_expect (l->l_info[DT_BIND_NOW] != NULL, 0))
    lazy = 0;

  if (__builtin_expect (GLRO(dl_debug_mask) & DL_DEBUG_RELOC, 0))
    _dl_debug_printf ("\nrelocation processing: %s%s\n",
		      l->l_name[0] ? l->l_name : rtld_progname,
		      lazy ? " (lazy)" : "");

  /* DT_TEXTREL is now in level 2 and might phase out at some time.
     But we rewrite the DT_FLAGS entry to a DT_TEXTREL entry to make
     testing easier and therefore it will be available at all time.  */
  if (__builtin_expect (l->l_info[DT_TEXTREL] != NULL, 0))
    {
      /* Bletch.  We must make read-only segments writable
	 long enough to relocate them.  */
      const ElfW(Phdr) *ph;
      for (ph = l->l_phdr; ph < &l->l_phdr[l->l_phnum]; ++ph)
	if (ph->p_type == PT_LOAD && (ph->p_flags & PF_W) == 0)
	  {
	    struct textrels *newp;

	    newp = (struct textrels *) alloca (sizeof (*newp));
	    newp->len = (((ph->p_vaddr + ph->p_memsz + GLRO(dl_pagesize) - 1)
			  & ~(GLRO(dl_pagesize) - 1))
			 - (ph->p_vaddr & ~(GLRO(dl_pagesize) - 1)));
	    newp->start = ((ph->p_vaddr & ~(GLRO(dl_pagesize) - 1))
			   + (caddr_t) l->l_addr);

	    if (__mprotect (newp->start, newp->len, PROT_READ|PROT_WRITE) < 0)
	      {
		errstring = N_("cannot make segment writable for relocation");
	      call_error:
		_dl_signal_error (errno, l->l_name, NULL, errstring);
	      }

#if (PF_R | PF_W | PF_X) == 7 && (PROT_READ | PROT_WRITE | PROT_EXEC) == 7
	    newp->prot = (PF_TO_PROT
			  >> ((ph->p_flags & (PF_R | PF_W | PF_X)) * 4)) & 0xf;
#else
	    newp->prot = 0;
	    if (ph->p_flags & PF_R)
	      newp->prot |= PROT_READ;
	    if (ph->p_flags & PF_W)
	      newp->prot |= PROT_WRITE;
	    if (ph->p_flags & PF_X)
	      newp->prot |= PROT_EXEC;
#endif
	    newp->next = textrels;
	    textrels = newp;
	  }
    }

  {
    /* Do the actual relocation of the object's GOT and other data.  */

    /* String table object symbols.  */
    const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

    /* This macro is used as a callback from the ELF_DYNAMIC_RELOCATE code.  */
#define RESOLVE_MAP(ref, version, r_type) \
    (ELFW(ST_BIND) ((*ref)->st_info) != STB_LOCAL			      \
     ? ((__builtin_expect ((*ref) == l->l_lookup_cache.sym, 0)		      \
	 && elf_machine_type_class (r_type) == l->l_lookup_cache.type_class)  \
	? (bump_num_cache_relocations (),				      \
	   (*ref) = l->l_lookup_cache.ret,				      \
	   l->l_lookup_cache.value)					      \
	: ({ lookup_t _lr;						      \
	     int _tc = elf_machine_type_class (r_type);			      \
	     l->l_lookup_cache.type_class = _tc;			      \
	     l->l_lookup_cache.sym = (*ref);				      \
	     const struct r_found_version *v = NULL;			      \
	     int flags = DL_LOOKUP_ADD_DEPENDENCY;			      \
	     if ((version) != NULL && (version)->hash != 0)		      \
	       {							      \
		 v = (version);						      \
		 flags = 0;						      \
	       }							      \
	     _lr = _dl_lookup_symbol_x (strtab + (*ref)->st_name, l, (ref),   \
					scope, v, _tc, flags, NULL);	      \
	     l->l_lookup_cache.ret = (*ref);				      \
	     l->l_lookup_cache.value = _lr; }))				      \
     : l)
#define RESOLVE(ref, version, r_type) \
    (ELFW(ST_BIND) ((*ref)->st_info) != STB_LOCAL			      \
     ? ((__builtin_expect ((*ref) == l->l_lookup_cache.sym, 0)		      \
	 && elf_machine_type_class (r_type) == l->l_lookup_cache.type_class)  \
		? (bump_num_cache_relocations (),			      \
	   (*ref) = l->l_lookup_cache.ret,				      \
	   l->l_lookup_cache.value)					      \
	: ({ lookup_t _lr;						      \
	     int _tc = elf_machine_type_class (r_type);			      \
	     l->l_lookup_cache.type_class = _tc;			      \
	     l->l_lookup_cache.sym = (*ref);				      \
	     const struct r_found_version *v = NULL;			      \
	     int flags = DL_LOOKUP_ADD_DEPENDENCY;			      \
	     if ((version) != NULL && (version)->hash != 0)		      \
	       {							      \
		 v = (version);						      \
		 flags = 0;						      \
	       }							      \
	     _lr = _dl_lookup_symbol_x (strtab + (*ref)->st_name, l, (ref),   \
					scope, v, _tc, flags, NULL);	      \
	     l->l_lookup_cache.ret = (*ref);				      \
	     l->l_lookup_cache.value = _lr; }))				      \
     : l->l_addr)

    /* This macro is used as a callback from elf_machine_rel{a,} when a
       static TLS reloc is about to be performed.  Since (in dl-load.c) we
       permit dynamic loading of objects that might use such relocs, we
       have to check whether each use is actually doable.  If the object
       whose TLS segment the reference resolves to was allocated space in
       the static TLS block at startup, then it's ok.  Otherwise, we make
       an attempt to allocate it in surplus space on the fly.  If that
       can't be done, we fall back to the error that DF_STATIC_TLS is
       intended to produce.  */
#define CHECK_STATIC_TLS(map, sym_map)					      \
    do {								      \
      if (__builtin_expect ((sym_map)->l_tls_offset == NO_TLS_OFFSET, 0))     \
	_dl_allocate_static_tls (sym_map);				      \
    } while (0)

#include "dynamic-link.h"

    ELF_DYNAMIC_RELOCATE (l, lazy, consider_profiling);

    if (__builtin_expect (consider_profiling, 0))
      {
	/* Allocate the array which will contain the already found
	   relocations.  If the shared object lacks a PLT (for example
	   if it only contains lead function) the l_info[DT_PLTRELSZ]
	   will be NULL.  */
	if (l->l_info[DT_PLTRELSZ] == NULL)
	  {
	    errstring = N_("%s: profiler found no PLTREL in object %s\n");
	  fatal:
	    _dl_fatal_printf (errstring,
			      rtld_progname ?: "<program name unknown>",
			      l->l_name);
	  }

	l->l_reloc_result =
	  (ElfW(Addr) *) calloc (sizeof (ElfW(Addr)),
				 l->l_info[DT_PLTRELSZ]->d_un.d_val);
	if (l->l_reloc_result == NULL)
	  {
	    errstring = N_("\
%s: profiler out of memory shadowing PLTREL of %s\n");
	    goto fatal;
	  }
      }
  }

  /* Mark the object so we know this work has been done.  */
  l->l_relocated = 1;

  /* Undo the segment protection changes.  */
  while (__builtin_expect (textrels != NULL, 0))
    {
      if (__mprotect (textrels->start, textrels->len, textrels->prot) < 0)
	{
	  errstring = N_("cannot restore segment prot after reloc");
	  goto call_error;
	}

      textrels = textrels->next;
    }

  /* In case we can protect the data now that the relocations are
     done, do it.  */
  if (l->l_relro_size != 0)
    _dl_protect_relro (l);
}


void internal_function
_dl_protect_relro (struct link_map *l)
{
  ElfW(Addr) start = ((l->l_addr + l->l_relro_addr)
		      & ~(GLRO(dl_pagesize) - 1));
  ElfW(Addr) end = ((l->l_addr + l->l_relro_addr + l->l_relro_size)
		    & ~(GLRO(dl_pagesize) - 1));

  if (start != end
      && __mprotect ((void *) start, end - start, PROT_READ) < 0)
    {
      static const char errstring[] = N_("\
cannot apply additional memory protection after relocation");
      _dl_signal_error (errno, l->l_name, NULL, errstring);
    }
}

void
internal_function __attribute_noinline__
_dl_reloc_bad_type (struct link_map *map, unsigned int type, int plt)
{
  extern const char INTUSE(_itoa_lower_digits)[] attribute_hidden;
#define DIGIT(b)	INTUSE(_itoa_lower_digits)[(b) & 0xf];

  /* XXX We cannot translate these messages.  */
  static const char msg[2][32
#if __ELF_NATIVE_CLASS == 64
			   + 6
#endif
  ] = { "unexpected reloc type 0x",
	"unexpected PLT reloc type 0x" };
  char msgbuf[sizeof (msg[0])];
  char *cp;

  cp = __stpcpy (msgbuf, msg[plt]);
#if __ELF_NATIVE_CLASS == 64
  if (__builtin_expect(type > 0xff, 0))
    {
      *cp++ = DIGIT (type >> 28);
      *cp++ = DIGIT (type >> 24);
      *cp++ = DIGIT (type >> 20);
      *cp++ = DIGIT (type >> 16);
      *cp++ = DIGIT (type >> 12);
      *cp++ = DIGIT (type >> 8);
    }
#endif
  *cp++ = DIGIT (type >> 4);
  *cp++ = DIGIT (type);
  *cp = '\0';

  _dl_signal_error (0, map->l_name, NULL, msgbuf);
}
