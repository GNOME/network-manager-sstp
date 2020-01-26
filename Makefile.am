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

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-sstp-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-sstp-service.name

BUILT_SOURCES =

###############################################################################

shared_sources = \
	shared/nm-default.h \
	shared/nm-utils/nm-errno.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-secret-utils.h \
	shared/nm-utils/nm-shared-utils.h

EXTRA_DIST += \
	shared/README

src_cppflags = \
	-DNM_SSTP_LOCALEDIR=\"$(datadir)/locale\" \
	-DNM_SSTP_STATEDIR=\"$(sstp_statedir)\" \
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" \
	-DG_LOG_DOMAIN=\"nm-sstp\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT \
	-I$(builddir)/src \
	-I$(top_srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
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

noinst_LTLIBRARIES += shared/nm-utils/libnm-utils.la
shared_nm_utils_libnm_utils_la_SOURCES = \
	$(shared_sources) \
	shared/nm-utils/nm-errno.c \
	shared/nm-utils/nm-io-utils.c \
	shared/nm-utils/nm-secret-utils.c \
	shared/nm-utils/nm-shared-utils.c
shared_nm_utils_libnm_utils_la_CPPFLAGS = \
	$(src_cppflags)
shared_nm_utils_libnm_utils_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GNUTLS_LIBS)

libexec_PROGRAMS += src/nm-sstp-service

src_nm_sstp_service_SOURCES = \
	$(shared_sources) \
	shared/utils.c \
	shared/utils.h \
	shared/nm-service-defines.h \
	src/nm-ppp-status.h \
	src/nm-sstp-service.h \
	src/nm-sstp-service.c
src_nm_sstp_service_CPPFLAGS = $(src_cppflags)
src_nm_sstp_service_LDADD = \
	src/libnm-sstp-pppd-service-dbus.la \
	shared/nm-utils/libnm-utils.la \
	$(LIBNM_LIBS)

###############################################################################

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = src/nm-sstp-pppd-plugin.la

src_nm_sstp_pppd_plugin_la_SOURCES = \
	$(shared_sources) \
	src/nm-sstp-pppd-plugin.c \
	src/nm-ppp-status.h
src_nm_sstp_pppd_plugin_la_CPPFLAGS = $(src_cppflags)
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

plugin_sources = \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	properties/nm-sstp-editor-plugin.c \
	properties/nm-sstp-editor-plugin.h

editor_sources = \
	$(shared_sources) \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/utils.h \
	shared/utils.c \
	properties/resources.c \
	properties/resources.h \
	properties/advanced-dialog.c \
	properties/advanced-dialog.h \
	properties/nm-sstp-editor.c \
	properties/nm-sstp-editor.h

properties_cppflags = \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(top_srcdir)/shared

CLEANFILES += \
	properties/resources.c \
	properties/resources.h

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
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(properties_cppflags)
properties_libnm_vpn_plugin_sstp_la_LIBADD = \
	shared/nm-utils/libnm-utils.la \
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
properties_libnm_vpn_plugin_sstp_editor_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)
properties_libnm_vpn_plugin_sstp_editor_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags)
properties_libnm_vpn_plugin_sstp_editor_la_LIBADD = \
	shared/nm-utils/libnm-utils.la \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)
properties_libnm_vpn_plugin_sstp_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-sstp-editor.ver"

###############################################################################

if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += properties/libnm-sstp-properties.la
endif

properties_libnm_sstp_properties_la_SOURCES = \
	shared/nm-utils/nm-glib.h \
	$(plugin_sources) \
	$(editor_sources)

properties_libnm_sstp_properties_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

properties_libnm_sstp_properties_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION='NM_NETWORKMANAGER_COMPILATION_LIB|NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL' \
	$(properties_cppflags)

properties_libnm_sstp_properties_la_LIBADD = \
	shared/nm-utils/libnm-utils.la \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GLIB_LIBS)

properties_libnm_sstp_properties_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-sstp-properties.ver"

###############################################################################

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-sstp-auth-dialog
endif

auth_dialog_nm_sstp_auth_dialog_SOURCES = \
	$(shared_sources) \
	shared/utils.c \
	shared/utils.h \
	properties/resources.c \
	properties/resources.h \
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
	shared/nm-utils/libnm-utils.la \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS) \
	$(GNUTLS_LIBS)

###############################################################################

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-sstp-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-sstp-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-sstp-service.name
endif

appdatadir = $(datadir)/appdata
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
endif
appdata_in_files = appdata/network-manager-sstp.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-sstp-service.name: $(srcdir)/nm-sstp-service.name.in
	$(AM_V_GEN) sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

EXTRA_DIST += \
	nm-sstp-service.name.in \
	$(dbusservice_DATA) \
	$(appdata_in_files) \
	$(appdata_files) \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update

ACLOCAL_AMFLAGS = -I m4
