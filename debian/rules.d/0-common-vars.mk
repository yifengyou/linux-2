#
# The source package name will be the first token from $(DEBIAN)/changelog
#
src_pkg_name=$(shell sed -n '1s/^\(.*\) (.*).*$$/\1/p' $(DEBIAN)/changelog)

# Get some version info
series := lucid
release := $(shell sed -n '1s/^$(src_pkg_name).*(\(.*\)-.*).*$$/\1/p' $(DEBIAN)/changelog)
revisions := $(shell sed -n 's/^$(src_pkg_name)\ .*($(release)-\(.*\)).*$$/\1/p' $(DEBIAN)/changelog | tac)
revision ?= $(word $(words $(revisions)),$(revisions))
prev_revisions := $(filter-out $(revision),0.0 $(revisions))
prev_revision := $(word $(words $(prev_revisions)),$(prev_revisions))

family=ubuntu

# This is an internally used mechanism for the daily kernel builds. It
# creates packages whose ABI is suffixed with a minimal representation of
# the current git HEAD sha. If .git/HEAD is not present, then it uses the
# uuidgen program,
#
# AUTOBUILD can also be used by anyone wanting to build a custom kernel
# image, or rebuild the entire set of Ubuntu packages using custom patches
# or configs.
AUTOBUILD=

#
# This is a way to support some external variables. A good example is
# a local setup for ccache and distcc See LOCAL_ENV_CC and
# LOCAL_ENV_DISTCC_HOSTS in the definition of kmake.
# For example:
#      LOCAL_ENV_CC="ccache distcc"
#      LOCAL_ENV_DISTCC_HOSTS="localhost 10.0.2.5 10.0.2.221"
#
-include $(CURDIR)/../.$(series)-env

ifneq ($(AUTOBUILD),)
skipabi		= true
skipmodule	= true
skipdbg		= true
gitver=$(shell if test -f .git/HEAD; then cat .git/HEAD; else uuidgen; fi)
gitverpre=$(shell echo $(gitver) | cut -b -3)
gitverpost=$(shell echo $(gitver) | cut -b 38-40)
abi_suffix = -$(gitverpre)$(gitverpost)
endif

ifneq ($(NOKERNLOG),)
ubuntu_log_opts += --no-kern-log
endif
ifneq ($(PRINTSHAS),)
ubuntu_log_opts += --print-shas
endif

# Get the kernels own extra version to be added to the release signature.
extraversion=$(shell awk '/EXTRAVERSION =/ { print $$3 }' <Makefile)

#
# full_build -- are we doing a full buildd style build
#
ifeq ($(wildcard /CurrentlyBuilding),)
full_build?=false
else
full_build?=true
endif

#
# The debug packages are ginormous, so you probably want to skip
# building them (as a developer).
#
ifeq ($(full_build),false)
skipdbg=true
endif

abinum		:= $(shell echo $(revision) | sed -e 's/\..*//')$(abi_suffix)
prev_abinum	:= $(shell echo $(prev_revision) | sed -e 's/\..*//')$(abi_suffix)
abi_release	:= $(release)-$(abinum)

uploadnum	:= $(shell echo $(revision) | sed -e 's/.*\.//')
ifneq ($(full_build),false)
  uploadnum	:= $(uploadnum)-Ubuntu
endif

# We force the sublevel to be exactly what we want. The actual source may
# be an in development git tree. We want to force it here instead of
# committing changes to the top level Makefile
SUBLEVEL	:= $(shell echo $(release) | awk -F. '{print $$3}')

arch		:= $(shell dpkg-architecture -qDEB_HOST_ARCH)
abidir		:= $(CURDIR)/$(DEBIAN)/abi/$(release)-$(revision)/$(arch)
prev_abidir	:= $(CURDIR)/$(DEBIAN)/abi/$(release)-$(prev_revision)/$(arch)
commonconfdir	:= $(CURDIR)/$(DEBIAN)/config
archconfdir	:= $(CURDIR)/$(DEBIAN)/config/$(arch)
sharedconfdir	:= $(CURDIR)/debian.master/config
builddir	:= $(CURDIR)/debian/build
stampdir	:= $(CURDIR)/debian/stamps

#
# The binary package name always starts with linux-image-$KVER-$ABI.$UPLOAD_NUM. There
# are places that you'll find linux-image hard coded, but I guess thats OK since the
# assumption that the binary package always starts with linux-image will never change.
#
bin_pkg_name=linux-image-$(abi_release)
hdrs_pkg_name=linux-headers-$(abi_release)
#
# The generation of content in the doc package depends on both 'AUTOBUILD=' and
# 'do_doc_package_content=true'. There are usually build errors during the development
# cycle, so its OK to leave 'do_doc_package_content=false' until those build
# failures get sorted out. Finally, the doc package doesn't really need to be built
# for developer testing (its kind of slow), so only do it if on a buildd.
do_doc_package=true
do_doc_package_content=true
ifeq ($(full_build),false)
do_doc_package_content=false
endif
doc_pkg_name=$(src_pkg_name)-doc

#
# Similarly with the linux-source package, you need not build it as a developer. Its
# somewhat I/O intensive and utterly useless.
#
do_source_package=true
do_source_package_content=true
ifeq ($(full_build),false)
do_source_package_content=false
endif

# linux-libc-dev may not be needed, default to building it.
do_libc_dev_package=true

# common headers normally is built as an indep package, but may be arch
do_common_headers_indep=true

# add a 'full source' mode
do_full_source=false

# build tools
ifneq ($(wildcard $(CURDIR)/tools),)
do_tools?=true
else
do_tools?=false
endif
tools_pkg_name=$(src_pkg_name)-tools-$(abi_release)
tools_common_pkg_name=$(src_pkg_name)-tools-common

# Support parallel=<n> in DEB_BUILD_OPTIONS (see #209008)
#
# These 2 environment variables set the -j value of the kernel build. For example,
# CONCURRENCY_LEVEL=16 fakeroot $(DEBIAN)/rules binary-debs
# or
# DEB_BUILD_OPTIONS=parallel=16 fakeroot $(DEBIAN)/rules binary-debs
#
# The default is to use the number of CPUs.
#
COMMA=,
DEB_BUILD_OPTIONS_PARA = $(subst parallel=,,$(filter parallel=%,$(subst $(COMMA), ,$(DEB_BUILD_OPTIONS))))
ifneq (,$(DEB_BUILD_OPTIONS_PARA))
  CONCURRENCY_LEVEL := $(DEB_BUILD_OPTIONS_PARA)
endif

ifeq ($(CONCURRENCY_LEVEL),)
  # Check the environment
  CONCURRENCY_LEVEL := $(shell echo $$CONCURRENCY_LEVEL)
  # No? Then build with the number of CPUs on the host.
  ifeq ($(CONCURRENCY_LEVEL),)
      CONCURRENCY_LEVEL := $(shell expr `getconf _NPROCESSORS_ONLN` \* 1)
  endif
  # Oh hell, give 'em one
  ifeq ($(CONCURRENCY_LEVEL),)
    CONCURRENCY_LEVEL := 1
  endif
endif

conc_level		= -j$(CONCURRENCY_LEVEL)

# target_flavour is filled in for each step
kmake = make ARCH=$(build_arch) \
	EXTRAVERSION=-$(abinum)-$(target_flavour) \
	CONFIG_DEBUG_SECTION_MISMATCH=y SUBLEVEL=$(SUBLEVEL) \
	KBUILD_BUILD_VERSION="$(uploadnum)" \
	LOCALVERSION=
ifneq ($(LOCAL_ENV_CC),)
kmake += CC=$(LOCAL_ENV_CC) DISTCC_HOSTS=$(LOCAL_ENV_DISTCC_HOSTS)
endif
