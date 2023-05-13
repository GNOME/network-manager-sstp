AUTOMAKE_OPTIONS = subdir-objects

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes

libexec_PROGRAMS =

noinst_LTLIBRARIES =

EXTRA_DIST =

CLEANFILES =

noinst_PROGRAMS =

SUBDIRS = \
	 . \
	 po

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

dbusservicedir = $(datadir)/dbus-1/system.d
dbusservice_DATA = nm-sstp-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-sstp-service.name

BUILT_SOURCES =

###############################################################################

shared_sources = \
	shared/nm-default.h \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-shared-utils.c

EXTRA_DIST += \
	shared/README

src_cppflags = \
	-DNM_SSTP_LOCALEDIR=\"$(datadir)/locale\" \
	-DNM_SSTP_STATEDIR=\"$(sstp_statedir)\" \
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" \
	-DG_LOG_DOMAIN=\"nm-sstp\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT \
	-I$(builddir)/src \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(GNUTLS_CFLAGS) \
	$(SSTPC_CFLAGS)

###############################################################################

noinst_LTLIBRARIES += src/libnm-sstp-pppd-service-dbus.la

nodist_src_libnm_sstp_pppd_service_dbus_la_SOURCES = \
	src/nm-sstp-pppd-service-dbus.c \
	src/nm-sstp-pppd-service-dbus.h

src_libnm_sstp_pppd_service_dbus_la_CPPFLAGS = \
	$(src_cppflags) \
	$(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

src/nm-sstp-pppd-service-dbus.h: $(top_srcdir)/src/nm-sstp-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

src/nm-sstp-pppd-service-dbus.c: src/nm-sstp-pppd-service-dbus.h
	@true

BUILT_SOURCES += \
	src/nm-sstp-pppd-service-dbus.h \
	src/nm-sstp-pppd-service-dbus.c

CLEANFILES += \
	src/nm-sstp-pppd-service-dbus.h \
	src/nm-sstp-pppd-service-dbus.c

EXTRA_DIST += \
	src/nm-sstp-pppd-service.xml

###############################################################################

libexec_PROGRAMS += src/nm-sstp-service

src_nm_sstp_service_SOURCES = \
	$(shared_sources) \
	shared/utils.c \
	shared/utils.h \
	shared/nm-service-defines.h \
	src/nm-sstp-pppd-status.h \
	src/nm-sstp-service.h \
	src/nm-sstp-service.c
src_nm_sstp_service_CPPFLAGS = \
	$(src_cppflags)
src_nm_sstp_service_LDADD = \
	src/libnm-sstp-pppd-service-dbus.la \
	$(LIBNM_LIBS) \
	$(GNUTLS_LIBS)

###############################################################################

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = src/nm-sstp-pppd-plugin.la

src_nm_sstp_pppd_plugin_la_SOURCES = \
	shared/nm-utils/nm-shared-utils.c \
	src/nm-sstp-pppd-plugin.c \
	src/nm-sstp-pppd-mppe.h \
	src/nm-sstp-pppd-compat.h \
	src/nm-sstp-pppd-status.h
if !WITH_PPP_MPPE_KEYS
src_nm_sstp_pppd_plugin_la_SOURCES += \
	src/nm-sstp-pppd-mppe.c
endif
src_nm_sstp_pppd_plugin_la_CPPFLAGS = \
	$(src_cppflags)
src_nm_sstp_pppd_plugin_la_LDFLAGS = \
	-module -avoid-version
src_nm_sstp_pppd_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(SSTPC_LIBS)

###############################################################################

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal

gtk4/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --generate-dependencies $(srcdir)/properties/gresource.xml |sed "s,^,$(builddir)/gtk4/,")
	@mkdir -p $(builddir)/gtk4
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/gtk4 --sourcedir=$(builddir)/gtk4 --generate-source --internal

gtk4/%.ui: properties/%.ui
	@mkdir -p $(builddir)/gtk4
	gtk4-builder-tool simplify --3to4 $< |grep -v can-default >$@

# Include a prebuilt file in tarball, to avoid hitting
# https://gitlab.gnome.org/GNOME/gtk/-/merge_requests/4415
EXTRA_DIST += \
	gtk4/nm-sstp-dialog.ui

plugin_sources = \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	properties/nm-sstp-editor-plugin.c \
	properties/nm-sstp-editor-plugin.h

editor_sources = \
	$(shared_sources) \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/utils.h \
	shared/utils.c \
	properties/advanced-dialog.c \
	properties/advanced-dialog.h \
	properties/nm-sstp-editor.c \
	properties/nm-sstp-editor.h

properties_cppflags = \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(top_srcdir)/shared

CLEANFILES += \
	properties/resources.c \
	properties/resources.h \
	gtk4/resources.c \
	gtk4/nm-sstp-dialog.ui

EXTRA_DIST += \
	properties/nm-sstp-dialog.ui \
	properties/gresource.xml \
	properties/libnm-sstp-properties.ver \
	properties/libnm-vpn-plugin-sstp.ver \
	properties/libnm-vpn-plugin-sstp-editor.ver

###############################################################################

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-sstp.la

properties_libnm_vpn_plugin_sstp_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	$(plugin_sources)
properties_libnm_vpn_plugin_sstp_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS)
properties_libnm_vpn_plugin_sstp_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	$(properties_cppflags)
properties_libnm_vpn_plugin_sstp_la_LIBADD = \
	$(LIBNM_LIBS)
properties_libnm_vpn_plugin_sstp_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-sstp.ver"

###############################################################################

if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-sstp-editor.la
endif

properties_libnm_vpn_plugin_sstp_editor_la_SOURCES = \
	$(editor_sources)

nodist_properties_libnm_vpn_plugin_sstp_editor_la_SOURCES = \
	properties/resources.c \
	properties/resources.h

properties_libnm_vpn_plugin_sstp_editor_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(GNUTLS_CFLAGS)

properties_libnm_vpn_plugin_sstp_editor_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags)

properties_libnm_vpn_plugin_sstp_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(GNUTLS_LIBS)

properties_libnm_vpn_plugin_sstp_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-sstp-editor.ver"

###############################################################################

if WITH_GTK4
plugin_LTLIBRARIES += properties/libnm-gtk4-vpn-plugin-sstp-editor.la
endif

properties_libnm_gtk4_vpn_plugin_sstp_editor_la_SOURCES = \
	$(editor_sources)

nodist_properties_libnm_gtk4_vpn_plugin_sstp_editor_la_SOURCES = \
	gtk4/resources.c \
	properties/resources.h

properties_libnm_gtk4_vpn_plugin_sstp_editor_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS) \
	$(GNUTLS_CFLAGS)

properties_libnm_gtk4_vpn_plugin_sstp_editor_la_CPPFLAGS = \
	$(properties_libnm_vpn_plugin_sstp_editor_la_CPPFLAGS)

properties_libnm_gtk4_vpn_plugin_sstp_editor_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS) \
	$(GNUTLS_LIBS)

properties_libnm_gtk4_vpn_plugin_sstp_editor_la_LDFLAGS = \
	$(properties_libnm_vpn_plugin_sstp_editor_la_LDFLAGS)

###############################################################################

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-sstp-auth-dialog
endif

auth_dialog_nm_sstp_auth_dialog_SOURCES = \
	$(shared_sources) \
	auth-dialog/main.c

auth_dialog_nm_sstp_auth_dialog_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS)

auth_dialog_nm_sstp_auth_dialog_CPPFLAGS = \
	-I$(top_srcdir)/shared

auth_dialog_nm_sstp_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS) \
	$(GNUTLS_LIBS)

###############################################################################

appdatadir = $(datadir)/metainfo
appdata_in_files = appdata/network-manager-sstp.metainfo.xml.in
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
$(appdata_DATA): $(appdata_in_files)
	$(AM_V_GEN)$(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@
endif

nm-sstp-service.name: $(srcdir)/nm-sstp-service.name.in
	$(AM_V_GEN) sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

EXTRA_DIST += \
	nm-sstp-service.name.in \
	$(dbusservice_DATA) \
	$(appdata_in_files) \
	$(appdata_files)

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

ACLOCAL_AMFLAGS = -I m4
