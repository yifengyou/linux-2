# We don't want make removing intermediary stamps
.SECONDARY :

# Prepare the out-of-tree build directory

prepare-%: $(stampdir)/stamp-prepare-%
	@# Empty for make to be happy
$(stampdir)/stamp-prepare-%: $(stampdir)/stamp-prepare-tree-% prepare-checks-%
	@touch $@
$(stampdir)/stamp-prepare-tree-%: target_flavour = $*
$(stampdir)/stamp-prepare-tree-%: $(commonconfdir)/config.common.$(family) $(archconfdir)/config.common.$(arch) $(archconfdir)/config.flavour.%
	@echo "Preparing $*..."
	install -d $(builddir)/build-$*
	touch $(builddir)/build-$*/ubuntu-build
	cat $^ | sed -e 's/.*CONFIG_VERSION_SIGNATURE.*/CONFIG_VERSION_SIGNATURE="Ubuntu $(release)-$(revision)-$*"/' > $(builddir)/build-$*/.config
	find $(builddir)/build-$* -name "*.ko" | xargs rm -f
	$(kmake) O=$(builddir)/build-$* silentoldconfig prepare scripts
	touch $@


# Do the actual build, including image and modules
build-%: $(stampdir)/stamp-build-%
	@# Empty for make to be happy
$(stampdir)/stamp-build-%: target_flavour = $*
$(stampdir)/stamp-build-%: prepare-%
	@echo "Building $*..."
	$(kmake) O=$(builddir)/build-$* $(conc_level) $(build_image)
	$(kmake) O=$(builddir)/build-$* $(conc_level) modules
	@touch $@

# Install the finished build
install-%: pkgdir = $(CURDIR)/debian/$(bin_pkg_name)-$*
install-%: bindoc = $(pkgdir)/usr/share/doc/$(bin_pkg_name)-$*
install-%: dbgpkgdir = $(CURDIR)/debian/$(dbg_pkg_name)-$*
install-%: basepkg = $(hdrs_pkg_name)
install-%: hdrdir = $(CURDIR)/debian/$(basepkg)-$*/usr/src/$(basepkg)-$*
install-%: target_flavour = $*
install-%: $(stampdir)/stamp-build-% checks-%
	dh_testdir
	dh_testroot
	dh_clean -k -p$(bin_pkg_name)-$*
	dh_clean -k -p$(hdrs_pkg_name)-$*
	dh_clean -k -p$(dbg_pkg_name)-$*

	# The main image
	# compress_file logic required because not all architectures
	# generate a zImage automatically out of the box
ifeq ($(compress_file),)
	install -m644 -D $(builddir)/build-$*/$(kernel_file) \
		$(pkgdir)/boot/$(install_file)-$(abi_release)-$*
else
	install -d $(pkgdir)/boot
	gzip -c9v $(builddir)/build-$*/$(kernel_file) > \
		$(pkgdir)/boot/$(install_file)-$(abi_release)-$*
	chmod 644 $(pkgdir)/boot/$(install_file)-$(abi_release)-$*
endif

	install -m644 $(builddir)/build-$*/.config \
		$(pkgdir)/boot/config-$(abi_release)-$*
	install -m644 $(abidir)/$* \
		$(pkgdir)/boot/abi-$(abi_release)-$*
	install -m644 $(builddir)/build-$*/System.map \
		$(pkgdir)/boot/System.map-$(abi_release)-$*
ifeq ($(no_dumpfile),)
	makedumpfile -g $(pkgdir)/boot/vmcoreinfo-$(abi_release)-$* \
		-x $(builddir)/build-$*/vmlinux
endif

	$(kmake) O=$(builddir)/build-$* modules_install \
		INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=$(pkgdir)/ \
		INSTALL_FW_PATH=$(pkgdir)/lib/firmware/$(abi_release)-$*

ifeq ($(no_dumpfile),)
	makedumpfile -g $(pkgdir)/boot/vmcoreinfo-$(abi_release)-$* \
		-x $(builddir)/build-$*/vmlinux
endif
	rm -f $(pkgdir)/lib/modules/$(abi_release)-$*/build
	rm -f $(pkgdir)/lib/modules/$(abi_release)-$*/source

	# Some initramfs-tools specific modules
	install -d $(pkgdir)/lib/modules/$(abi_release)-$*/initrd
	if [ -f $(pkgdir)/lib/modules/$(abi_release)-$*/kernel/drivers/video/vesafb.ko ]; then\
	  ln -f $(pkgdir)/lib/modules/$(abi_release)-$*/kernel/drivers/video/vesafb.ko \
		$(pkgdir)/lib/modules/$(abi_release)-$*/initrd/; \
	fi

	# Now the image scripts
	install -d $(pkgdir)/DEBIAN
	for script in postinst postrm preinst prerm; do				\
	  sed -e 's/=V/$(abi_release)-$*/g' -e 's/=K/$(install_file)/g'		\
	      -e 's/=L/$(loader)/g'         -e 's@=B@$(build_arch)@g'		\
	       $(DEBIAN)/control-scripts/$$script > $(pkgdir)/DEBIAN/$$script;	\
	  chmod 755 $(pkgdir)/DEBIAN/$$script;					\
	done

	# Install the full changelog.
ifeq ($(do_doc_package),true)
	install -d $(bindoc)
	cat $(DEBIAN)/changelog $(DEBIAN)/changelog.historical | \
		gzip -9 >$(bindoc)/changelog.Debian.old.gz
	chmod 644 $(bindoc)/changelog.Debian.old.gz
endif

ifneq ($(skipsub),true)
	for sub in $($(*)_sub); do					\
		if ! (TO=$$sub FROM=$* ABI_RELEASE=$(abi_release) $(SHELL)		\
			$(DEBIAN)/scripts/sub-flavour); then exit 1; fi;		\
		/sbin/depmod -b debian/$(bin_pkg_name)-$$sub		\
			-ea -F debian/$(bin_pkg_name)-$$sub/boot/System.map-$(abi_release)-$* \
			$(abi_release)-$*;					\
		install -d debian/$(bin_pkg_name)-$$sub/DEBIAN;	\
		for script in postinst postrm preinst prerm; do			\
			sed -e 's/=V/$(abi_release)-$*/g'			\
			    -e 's/=K/$(install_file)/g'				\
			    -e 's/=L/$(loader)/g'				\
			    -e 's@=B@$(build_arch)@g'				\
				$(DEBIAN)/control-scripts/$$script >		\
				debian/$(bin_pkg_name)-$$sub/DEBIAN/$$script;\
			chmod 755  debian/$(bin_pkg_name)-$$sub/DEBIAN/$$script;\
		done;								\
	done
endif

ifneq ($(skipdbg),true)
	# Debug image is simple
	install -m644 -D $(builddir)/build-$*/vmlinux \
		$(dbgpkgdir)/usr/lib/debug/boot/vmlinux-$(abi_release)-$*
	$(kmake) O=$(builddir)/build-$* modules_install \
		INSTALL_MOD_PATH=$(dbgpkgdir)/usr/lib/debug
	rm -f $(dbgpkgdir)/usr/lib/debug/lib/modules/$(abi_release)-$*/build
	rm -f $(dbgpkgdir)/usr/lib/debug/lib/modules/$(abi_release)-$*/source
	rm -f $(dbgpkgdir)/usr/lib/debug/lib/modules/$(abi_release)-$*/modules.*
	rm -fr $(dbgpkgdir)/usr/lib/debug/lib/firmware
endif

	# The flavour specific headers image
	# TODO: Would be nice if we didn't have to dupe the original builddir
	install -d -m755 $(hdrdir)
	cat $(builddir)/build-$*/.config | \
		sed -e 's/.*CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/g' > \
		$(hdrdir)/.config
	chmod 644 $(hdrdir)/.config
	$(kmake) O=$(hdrdir) silentoldconfig prepare scripts
	# We'll symlink this stuff
	rm -f $(hdrdir)/Makefile
	rm -rf $(hdrdir)/include2
	# powerpc seems to need some .o files for external module linking. Add them in.
ifeq ($(arch),powerpc)
	mkdir -p $(hdrdir)/arch/powerpc/lib
	cp $(builddir)/build-$*/arch/powerpc/lib/*.o $(hdrdir)/arch/powerpc/lib
endif
	# Script to symlink everything up
	$(SHELL) $(DEBIAN)/scripts/link-headers "$(hdrdir)" "$(basepkg)" "$*"
	# Setup the proper asm symlink
	rm -f $(hdrdir)/include/asm
	ln -s asm-$(asm_link) $(hdrdir)/include/asm
	# The build symlink
	install -d debian/$(basepkg)-$*/lib/modules/$(abi_release)-$*
	ln -s /usr/src/$(basepkg)-$* \
		debian/$(basepkg)-$*/lib/modules/$(abi_release)-$*/build
	# And finally the symvers
	install -m644 $(builddir)/build-$*/Module.symvers \
		$(hdrdir)/Module.symvers

	# Now the header scripts
	install -d $(CURDIR)/debian/$(basepkg)-$*/DEBIAN
	for script in postinst; do						\
	  sed -e 's/=V/$(abi_release)-$*/g' -e 's/=K/$(install_file)/g'	\
		$(DEBIAN)/control-scripts/headers-$$script > 			\
			$(CURDIR)/debian/$(basepkg)-$*/DEBIAN/$$script;		\
	  chmod 755 $(CURDIR)/debian/$(basepkg)-$*/DEBIAN/$$script;		\
	done

	# At the end of the package prep, call the tests
	DPKG_ARCH="$(arch)" KERN_ARCH="$(build_arch)" FLAVOUR="$*"	\
	 VERSION="$(abi_release)" REVISION="$(revision)"		\
	 PREV_REVISION="$(prev_revision)" ABI_NUM="$(abinum)"		\
	 PREV_ABI_NUM="$(prev_abinum)" BUILD_DIR="$(builddir)/build-$*"	\
	 INSTALL_DIR="$(pkgdir)" SOURCE_DIR="$(CURDIR)"			\
	 run-parts -v $(DEBIAN)/tests

	#
	# Remove files which are generated at installation by postinst,
	# except for modules.order and modules.builtin
	#
	mv $(pkgdir)/lib/modules/$(abi_release)-$*/modules.order \
		$(pkgdir)/lib/modules/$(abi_release)-$*/_modules.order
	mv $(pkgdir)/lib/modules/$(abi_release)-$*/modules.builtin \
		$(pkgdir)/lib/modules/$(abi_release)-$*/_modules.builtin
	rm -f $(pkgdir)/lib/modules/$(abi_release)-$*/modules.*
	mv $(pkgdir)/lib/modules/$(abi_release)-$*/_modules.builtin \
		$(pkgdir)/lib/modules/$(abi_release)-$*/modules.builtin
	mv $(pkgdir)/lib/modules/$(abi_release)-$*/_modules.order \
		$(pkgdir)/lib/modules/$(abi_release)-$*/modules.order

headers_tmp := $(CURDIR)/debian/tmp-headers
headers_dir := $(CURDIR)/debian/linux-libc-dev

hmake := $(MAKE) -C $(CURDIR) O=$(headers_tmp) SUBLEVEL=$(SUBLEVEL) \
	EXTRAVERSION=-$(abinum) INSTALL_HDR_PATH=$(headers_tmp)/install \
	SHELL="$(SHELL)" ARCH=$(header_arch)

install-arch-headers:
	dh_testdir
	dh_testroot
	dh_clean -k -plinux-libc-dev

	rm -rf $(headers_tmp)
	install -d $(headers_tmp) $(headers_dir)/usr/include/

	$(hmake) $(defconfig)
	mv $(headers_tmp)/.config $(headers_tmp)/.config.old
	sed -e 's/^# \(CONFIG_MODVERSIONS\) is not set$$/\1=y/' \
	  -e 's/.*CONFIG_LOCALVERSION_AUTO.*/# CONFIG_LOCALVERSION_AUTO is not set/' \
	  $(headers_tmp)/.config.old > $(headers_tmp)/.config
	$(hmake) silentoldconfig
	$(hmake) headers_install

	( cd $(headers_tmp)/install/include/ && \
		find . -name '.' -o -name '.*' -prune -o -print | \
                cpio -pvd --preserve-modification-time \
			$(headers_dir)/usr/include/ )

	rm -rf $(headers_tmp)

binary-arch-headers: install-arch-headers
	dh_testdir
	dh_testroot
ifeq ($(do_libc_dev_package),true)
	dh_installchangelogs -plinux-libc-dev
	dh_installdocs -plinux-libc-dev
	dh_compress -plinux-libc-dev
	dh_fixperms -plinux-libc-dev
	dh_installdeb -plinux-libc-dev
	dh_gencontrol -plinux-libc-dev
	dh_md5sums -plinux-libc-dev
	dh_builddeb -plinux-libc-dev
endif

binary-%: pkgimg = $(bin_pkg_name)-$*
binary-%: pkghdr = $(hdrs_pkg_name)-$*
binary-%: dbgpkg = $(dbg_pkg_name)-$*
binary-%: install-%
	dh_testdir
	dh_testroot

	dh_installchangelogs -p$(pkgimg)
	dh_installdocs -p$(pkgimg)
	dh_compress -p$(pkgimg)
	dh_fixperms -p$(pkgimg)
	dh_installdeb -p$(pkgimg)
	dh_gencontrol -p$(pkgimg)
	dh_md5sums -p$(pkgimg)
	dh_builddeb -p$(pkgimg) -- -Zbzip2 -z9

	dh_installchangelogs -p$(pkghdr)
	dh_installdocs -p$(pkghdr)
	dh_compress -p$(pkghdr)
	dh_fixperms -p$(pkghdr)
	dh_shlibdeps -p$(pkghdr)
	dh_installdeb -p$(pkghdr)
	dh_gencontrol -p$(pkghdr)
	dh_md5sums -p$(pkghdr)
	dh_builddeb -p$(pkghdr)

ifneq ($(skipsub),true)
	@set -e; for sub in $($(*)_sub); do		\
		pkg=$(bin_pkg_name)-$$sub;	\
		dh_installchangelogs -p$$pkg;		\
		dh_installdocs -p$$pkg;			\
		dh_compress -p$$pkg;			\
		dh_fixperms -p$$pkg;			\
		dh_shlibdeps -p$$pkg;			\
		dh_installdeb -p$$pkg;			\
		dh_gencontrol -p$$pkg;			\
		dh_md5sums -p$$pkg;			\
		dh_builddeb -p$$pkg;			\
	done
endif

ifneq ($(skipdbg),true)
	dh_installchangelogs -p$(dbgpkg)
	dh_installdocs -p$(dbgpkg)
	dh_compress -p$(dbgpkg)
	dh_fixperms -p$(dbgpkg)
	dh_installdeb -p$(dbgpkg)
	dh_gencontrol -p$(dbgpkg)
	dh_md5sums -p$(dbgpkg)
	dh_builddeb -p$(dbgpkg)

	# Hokay...here's where we do a little twiddling...
	# Renaming the debug package prevents it from getting into
	# the primary archive, and therefore prevents this very large
	# package from being mirrored. It is instead, through some
	# archive admin hackery, copied to http://ddebs.ubuntu.com.
	#
	mv ../$(dbgpkg)_$(release)-$(revision)_$(arch).deb \
		../$(dbgpkg)_$(release)-$(revision)_$(arch).ddeb
	grep -v '^$(dbgpkg)_.*$$' debian/files > debian/files.new
	mv debian/files.new debian/files
	# Now, the package wont get into the archive, but it will get put
	# into the debug system.
endif

$(stampdir)/stamp-flavours:
	@echo $(flavours) > $@

binary-debs: $(stampdir)/stamp-flavours $(addprefix binary-,$(flavours))

build-arch:  $(addprefix build-,$(flavours))

binary-arch-deps = binary-debs
ifeq ($(AUTOBUILD),)
binary-arch-deps += binary-udebs
endif
ifeq ($(do_libc_dev_package),true)
binary-arch-deps += binary-arch-headers
endif
ifneq ($(do_common_headers_indep),true)
binary-arch-deps += binary-headers
endif
binary-arch: $(binary-arch-deps)
