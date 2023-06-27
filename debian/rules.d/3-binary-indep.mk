build-indep:

docpkg = $(doc_pkg_name)
docdir = $(CURDIR)/debian/$(docpkg)/usr/share/doc/$(docpkg)
install-doc: install-headers
ifeq ($(do_doc_package),true)
	dh_testdir
	dh_testroot
	dh_clean -k -p$(docpkg)

	install -d $(docdir)
ifeq ($(do_doc_package_content),true)
	# First the html docs. We skip these for autobuilds
	if [ -z "$(AUTOBUILD)" ]; then \
		install -d $(docdir)/$(doc_pkg_name)-tmp; \
		$(kmake) O=$(docdir)/$(doc_pkg_name)-tmp htmldocs; \
		install -d $(docdir)/html; \
		rsync -aL $(docdir)/$(doc_pkg_name)-tmp/Documentation/DocBook/ \
			$(docdir)/html/; \
		rm -rf $(docdir)/$(doc_pkg_name)-tmp; \
	fi
endif
	# Copy the rest
	cp -a Documentation/* $(docdir)
	rm -rf $(docdir)/DocBook
	find $(docdir) -name .gitignore | xargs rm -f
endif

indep_hdrpkg = $(hdrs_pkg_name)
indep_hdrdir = $(CURDIR)/debian/$(indep_hdrpkg)/usr/src/$(indep_hdrpkg)
install-headers:
ifeq ($(do_common_headers_indep),true)
	dh_testdir
	dh_testroot
	dh_clean -k -p$(indep_hdrpkg)

	install -d $(indep_hdrdir)
	find . -path './debian' -prune -o -path './$(DEBIAN)' -prune \
	  -o -path './include/*' -prune \
	  -o -path './scripts/*' -prune -o -type f \
	  \( -name 'Makefile*' -o -name 'Kconfig*' -o -name 'Kbuild*' -o \
	     -name '*.sh' -o -name '*.pl' -o -name '*.lds' \) \
	  -print | cpio -pd --preserve-modification-time $(indep_hdrdir)
	cp -a drivers/media/dvb/dvb-core/*.h $(indep_hdrdir)/drivers/media/dvb/dvb-core
	cp -a drivers/media/video/*.h $(indep_hdrdir)/drivers/media/video
	cp -a drivers/media/dvb/frontends/*.h $(indep_hdrdir)/drivers/media/dvb/frontends
	cp -a scripts include $(indep_hdrdir)
	(find arch -name include -type d -print | \
		xargs -n1 -i: find : -type f) | \
		cpio -pd --preserve-modification-time $(indep_hdrdir)
endif

srcpkg = $(src_pkg_name)-source-$(release)
srcdir = $(CURDIR)/debian/$(srcpkg)/usr/src/$(srcpkg)
install-source: install-doc
ifeq ($(do_source_package),true)
	dh_testdir
	dh_testroot
	dh_clean -k -p$(srcpkg)

	install -d $(srcdir)
ifeq ($(do_source_package_content),true)
	find . -path './debian' -prune -o -path './$(DEBIAN)' -prune -o \
		-path './.*' -prune -o -print | \
		cpio -pd --preserve-modification-time $(srcdir)
	(cd $(srcdir)/..; tar cf - $(srcpkg)) | bzip2 -9c > \
		$(srcdir).tar.bz2
	rm -rf $(srcdir)
endif
endif

install-tools: toolspkg = $(tools_common_pkg_name)
install-tools: toolsbin = $(CURDIR)/debian/$(toolspkg)/usr/bin
install-tools: toolsman = $(CURDIR)/debian/$(toolspkg)/usr/share/man
install-tools: install-source
ifeq ($(do_tools),true)
	dh_testdir
	dh_testroot
	dh_clean -k -p$(toolspkg)

	install -d $(toolsbin)
	install -d $(toolsman)/man1

	install -m755 debian/tools/perf $(toolsbin)/perf

	install -d $(builddir)/tools
	for i in *; do ln -s $(CURDIR)/$$i $(builddir)/tools/; done
	rm $(builddir)/tools/tools
	rsync -a tools/ $(builddir)/tools/tools/

	cd $(builddir)/tools/tools/perf && make man
	install -m644 $(builddir)/tools/tools/perf/Documentation/*.1 \
		$(toolsman)/man1
endif

install-indep: install-tools

# This is just to make it easy to call manually. Normally done in
# binary-indep target during builds.
binary-headers: install-headers
	dh_testdir
	dh_testroot
	dh_installchangelogs -p$(indep_hdrpkg)
	dh_installdocs -p$(indep_hdrpkg)
	dh_compress -p$(indep_hdrpkg)
	dh_fixperms -p$(indep_hdrpkg)
	dh_installdeb -p$(indep_hdrpkg)
	dh_gencontrol -p$(indep_hdrpkg)
	dh_md5sums -p$(indep_hdrpkg)
	dh_builddeb -p$(indep_hdrpkg)

binary-indep: install-indep
	dh_testdir
	dh_testroot

	dh_installchangelogs -i
	dh_installdocs -i
	dh_compress -i
	dh_fixperms -i
	dh_installdeb -i
	dh_gencontrol -i
	dh_md5sums -i
	dh_builddeb -i
