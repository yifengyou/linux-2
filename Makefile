# Copyright (C) 1991-2002, 2003, 2004, 2005 Free Software Foundation, Inc.
# This file is part of the GNU C Library.

# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with the GNU C Library; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
# 02111-1307 USA.

#
#	Master Makefile for the GNU C library
#
ifneq (,)
This makefile requires GNU Make.
endif

include Makeconfig


# This is the default target; it makes everything except the tests.
.PHONY: all
all: lib others

ifneq ($(AUTOCONF),no)

ifeq ($(with-cvs),yes)
define autoconf-it-cvs
test ! -d CVS || cvs $(CVSOPTS) commit -m'Regenerated: autoconf $(ACFLAGS) $<' $@
endef
else
autoconf-it-cvs =
endif

define autoconf-it
@-rm -f $@.new
$(AUTOCONF) $(ACFLAGS) $< > $@.new
chmod a-w,a+x $@.new
mv -f $@.new $@
$(autoconf-it-cvs)
endef

configure: configure.in aclocal.m4; $(autoconf-it)
%/configure: %/configure.in aclocal.m4; $(autoconf-it)

endif # $(AUTOCONF) = no


# We don't want to run anything here in parallel.
.NOTPARALLEL:

# These are the targets that are made by making them in each subdirectory.
+subdir_targets	:= subdir_lib objects objs others subdir_mostlyclean	\
		   subdir_clean subdir_distclean subdir_realclean	\
		   tests xtests subdir_lint.out				\
		   subdir_update-abi subdir_check-abi 			\
		   subdir_echo-headers 					\
		   subdir_install					\
		   subdir_testclean					\
		   $(addprefix install-, no-libc.a bin lib data headers others)

headers := limits.h values.h features.h gnu-versions.h bits/libc-lock.h \
	   bits/xopen_lim.h gnu/libc-version.h

echo-headers: subdir_echo-headers

# The headers are in the include directory.
subdir-dirs = include
vpath %.h $(subdir-dirs)

# What to install.
install-others = $(inst_includedir)/gnu/stubs.h
install-bin-script =

ifeq (yes,$(build-shared))
headers += gnu/lib-names.h
endif

include Makerules

ifeq ($(build-programs),yes)
others: $(addprefix $(objpfx),$(install-bin-script))
endif

# Install from subdirectories too.
install: subdir_install

# Explicit dependency so that `make install-headers' works
install-headers: install-headers-nosubdir

# Make sure that the dynamic linker is installed before libc.
$(inst_slibdir)/libc-$(version).so: elf/ldso_install

.PHONY: elf/ldso_install
elf/ldso_install:
	$(MAKE) -C $(@D) $(@F)

# Create links for shared libraries using the `ldconfig' program if possible.
# Ignore the error if we cannot update /etc/ld.so.cache.
ifeq (no,$(cross-compiling))
ifeq (yes,$(build-shared))
install: install-symbolic-link
.PHONY: install-symbolic-link
install-symbolic-link: subdir_install
	$(symbolic-link-prog) $(symbolic-link-list)
	rm -f $(symbolic-link-list)

install:
	-test ! -x $(common-objpfx)elf/ldconfig || LC_ALL=C LANGUAGE=C \
	  $(common-objpfx)elf/ldconfig $(addprefix -r ,$(install_root)) \
				       $(slibdir) $(libdir)
ifneq (no,$(PERL))
ifeq (/usr,$(prefix))
ifeq (,$(install_root))
	CC="$(CC)" $(PERL) scripts/test-installation.pl $(common-objpfx)
endif
endif
endif
endif
endif

# Build subdirectory lib objects.
lib-noranlib: subdir_lib

ifeq (yes,$(build-shared))
# Build the shared object from the PIC object library.
lib: $(common-objpfx)libc.so
endif


# This is a handy script for running any dynamically linked program against
# the current libc build for testing.
$(common-objpfx)testrun.sh: $(common-objpfx)config.make \
			    $(..)Makeconfig $(..)Makefile
	(echo '#!/bin/sh'; \
	 echo "GCONV_PATH='$(common-objpfx)iconvdata' \\"; \
	 echo 'exec $(run-program-prefix) $${1+"$$@"}'; \
	) > $@T
	chmod a+x $@T
	mv -f $@T $@
postclean-generated += testrun.sh

others: $(common-objpfx)testrun.sh

# Makerules creates a file `stubs' in each subdirectory, which
# contains `#define __stub_FUNCTION' for each function defined in that
# directory which is a stub.
# Here we paste all of these together into <gnu/stubs.h>.

subdir-stubs := $(foreach dir,$(subdirs),$(common-objpfx)$(dir)/stubs)

# Since stubs.h is never needed when building the library, we simplify the
# hairy installation process by producing it in place only as the last part
# of the top-level `make install'.  It depends on subdir_install, which
# iterates over all the subdirs; subdir_install in each subdir depends on
# the subdir's stubs file.  Having more direct dependencies would result in
# extra iterations over the list for subdirs and many recursive makes.
$(inst_includedir)/gnu/stubs.h: include/stubs-prologue.h subdir_install
	$(make-target-directory)
	@rm -f $(objpfx)stubs.h
	(sed '/^@/d' $<; LC_ALL=C sort $(subdir-stubs)) > $(objpfx)stubs.h
	if test -r $@ && cmp -s $(objpfx)stubs.h $@; \
	then echo 'stubs.h unchanged'; \
	else $(INSTALL_DATA) $(objpfx)stubs.h $@; fi
	rm -f $(objpfx)stubs.h

# This makes the Info or DVI file of the documentation from the Texinfo source.
.PHONY: info dvi pdf html
info dvi pdf html:
	$(MAKE) $(PARALLELMFLAGS) -C manual $@

# This makes all the subdirectory targets.

# For each target, make it depend on DIR/target for each subdirectory DIR.
$(+subdir_targets): %: $(addsuffix /%,$(subdirs))

# Compute a list of all those targets.
all-subdirs-targets := $(foreach dir,$(subdirs),\
				 $(addprefix $(dir)/,$(+subdir_targets)))

# The action for each of those is to cd into the directory and make the
# target there.
$(all-subdirs-targets):
	$(MAKE) $(PARALLELMFLAGS) -C $(@D) $(@F)

.PHONY: $(+subdir_targets) $(all-subdirs-targets)

# Targets to clean things up to various degrees.

.PHONY: clean realclean distclean distclean-1 parent-clean parent-mostlyclean \
	tests-clean

# Subroutines of all cleaning targets.
parent-mostlyclean: common-mostlyclean # common-mostlyclean is in Makerules.
	-rm -f $(foreach o,$(object-suffixes-for-libc),\
		   $(common-objpfx)$(patsubst %,$(libtype$o),c)) \
	       $(addprefix $(objpfx),$(install-lib))
parent-clean: parent-mostlyclean common-clean

postclean = $(addprefix $(common-objpfx),$(postclean-generated)) \
	    $(addprefix $(objpfx),sysd-dirs sysd-rules) \
	    $(addprefix $(objpfx),sysd-sorted soversions.mk soversions.i)

clean: parent-clean
# This is done this way rather than having `subdir_clean' be a
# dependency of this target so that libc.a will be removed before the
# subdirectories are dealt with and so they won't try to remove object
# files from it when it's going to be removed anyway.
	@$(MAKE) subdir_clean no_deps=t
	-rm -f $(postclean)
mostlyclean: parent-mostlyclean
	@$(MAKE) subdir_mostlyclean no_deps=t
	-rm -f $(postclean)

tests-clean:
	@$(MAKE) subdir_testclean no_deps=t

tests: $(objpfx)c++-types-check.out
ifneq ($(CXX),no)
check-data := $(firstword $(wildcard \
	        $(foreach M,$(config-machine) $(base-machine),\
			  scripts/data/c++-types-$M-$(config-os).data)))
ifneq (,$(check-data))
$(objpfx)c++-types-check.out: $(check-data)
	scripts/check-c++-types.sh $^ $(CXX) $(filter-out -std=gnu99 -Wstrict-prototypes,$(CFLAGS)) $(CPPFLAGS) > $@
else
$(objpfx)c++-types-check.out:
	@echo 'WARNING C++ tests not run; create a c++-types-XXX file'
	@echo "not run" > $@
endif
endif

# The realclean target is just like distclean for the parent, but we want
# the subdirs to know the difference in case they care.
realclean distclean: parent-clean
# This is done this way rather than having `subdir_distclean' be a
# dependency of this target so that libc.a will be removed before the
# subdirectories are dealt with and so they won't try to remove object
# files from it when it's going to be removed anyway.
	@$(MAKE) distclean-1 no_deps=t distclean-1=$@ avoid-generated=yes \
		 sysdep-subdirs="$(sysdep-subdirs)"
	-rm -f $(postclean)

# Subroutine of distclean and realclean.
distclean-1: subdir_$(distclean-1)
	-rm -f $(config-generated)
	-rm -f $(addprefix $(objpfx),config.status config.cache config.log)
	-rm -f $(addprefix $(objpfx),config.make config-name.h config.h)
ifdef objdir
	-rm -f $(objpfx)Makefile
endif
	-rm -f $(sysdep-$(distclean-1))

# Make the distribution tarfile.
.PHONY: dist tag-for-dist

generated := $(generated) stubs.h

README: README.template version.h
	-rm -f $@
	sed -e 's/RELEASE/$(release)/' -e 's/VERSION/$(version)/' < $< > $@
# Make it unwritable so I won't change it by mistake.
	chmod 444 $@
ifeq ($(with-cvs),yes)
	test ! -d CVS || cvs $(CVSOPTS) commit -m'Remade for $(release)-$(version)' $@
endif

files-for-dist := README FAQ INSTALL NOTES configure

tag-of-stem = glibc-$(subst .,_,$*)

# Add-ons in the main repository but distributed in their own tar files.
dist-separate = libidn linuxthreads

# Directories in each add-on.
dist-separate-libidn = libidn
dist-separate-linuxthreads = linuxthreads linuxthreads_db

glibc-%.tar $(dist-separate:%=glibc-%-%.tar): $(files-for-dist) \
					      $(foreach D,$(dist-separate),\
							$D/configure)
	@rm -fr glibc-$*
	$(MAKE) -q `find sysdeps $(addsuffix /sysdeps,$(add-ons)) \
			 -name configure`
	cvs $(CVSOPTS) -Q export -d glibc-$* -r $(tag-of-stem) libc
# Touch all the configure scripts going into the tarball since cvs export
# might have delivered configure.in newer than configure.
	find glibc-$* -name configure -print | xargs touch
	$(dist-do-separate-dirs)
	tar cf glibc-$*.tar glibc-$*
	rm -fr glibc-$*
define dist-do-separate-dirs
$(foreach dir,$(dist-separate),
	tar cf glibc-$(dir)-$*.tar -C glibc-$* $(dist-separate-$(dir))
	rm -rf $(addprefix glibc-$*/,$(dist-separate-$(dir)))
)
endef

# Do `make dist dist-version=X.Y.Z' to make tar files of an older version.
dist-version = $(version)

dist: $(foreach Z,.bz2 .gz,glibc-$(dist-version).tar$Z \
		           $(foreach D,$(dist-separate),\
				     glibc-$D-$(dist-version).tar$Z))
	md5sum $^

tag-for-dist: tag-$(dist-version)
tag-%: $(files-for-dist)
	cvs $(CVSOPTS) -Q tag -c $(tag-of-stem)

define format-me
@rm -f $@
makeinfo --no-validate --no-warn --no-headers $< -o $@
-chmod a-w $@
endef
INSTALL: manual/install.texi; $(format-me)
NOTES: manual/creature.texi; $(format-me)
manual/dir-add.texi manual/dir-add.info: FORCE
	$(MAKE) $(PARALLELMFLAGS) -C $(@D) $(@F)
FAQ: scripts/gen-FAQ.pl FAQ.in
	$(PERL) $^ > $@.new && rm -f $@ && mv $@.new $@ && chmod a-w $@
ifeq ($(with-cvs),yes)
	test ! -d CVS || cvs $(CVSOPTS) commit -m'Regenerated:  $(PERL) $^' $@
endif
FORCE:

iconvdata/% localedata/% po/% manual/%:
	$(MAKE) $(PARALLELMFLAGS) -C $(@D) $(@F)

# glibc 2.0 contains some header files which aren't used with glibc 2.1
# anymore.
# These rules should remove those headers
ifeq (,$(install_root))
ifeq ($(old-glibc-headers),yes)
install: remove-old-headers
endif
endif

headers2_0 := 	__math.h bytesex.h confname.h direntry.h elfclass.h  	\
		errnos.h fcntlbits.h huge_val.h ioctl-types.h 		\
		ioctls.h iovec.h jmp_buf.h libc-lock.h local_lim.h 	\
		mathcalls.h mpool.h nan.h ndbm.h posix1_lim.h  		\
		posix2_lim.h posix_opt.h resourcebits.h schedbits.h 	\
		selectbits.h semaphorebits.h sigaction.h sigcontext.h 	\
		signum.h sigset.h sockaddrcom.h socketbits.h stab.def 	\
		statbuf.h statfsbuf.h stdio-lock.h stdio_lim.h 		\
		syscall-list.h termbits.h timebits.h ustatbits.h 	\
		utmpbits.h utsnamelen.h waitflags.h waitstatus.h 	\
		xopen_lim.h gnu/types.h sys/ipc_buf.h 			\
		sys/kernel_termios.h sys/msq_buf.h sys/sem_buf.h 	\
		sys/shm_buf.h sys/socketcall.h sigstack.h

.PHONY: remove-old-headers
remove-old-headers:
	rm -f $(addprefix $(inst_includedir)/, $(headers2_0))
