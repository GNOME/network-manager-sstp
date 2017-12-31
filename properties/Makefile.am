plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-sstp.la
if WITH_GNOME
plugin_LTLIBRARIES += libnm-vpn-plugin-sstp-editor.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-sstp-properties.la
endif
endif

AM_CPPFLAGS = -I${top_srcdir}

plugin_sources = \
    nm-sstp-editor-plugin.c \
    nm-sstp-editor-plugin.h

editor_sources = \
    advanced-dialog.c \
    advanced-dialog.h \
    nm-sstp-editor.c \
    nm-sstp-editor.h

uidir = $(datadir)/gnome-vpn-properties/sstp
if WITH_GNOME
ui_DATA = nm-sstp-dialog.ui
endif

common_CFLAGS = \
    $(GLIB_CFLAGS) \
    -I"$(top_srcdir)/shared" \
    -DICONDIR=\""$(datadir)/pixmaps"\" \
    -DUIDIR=\""$(uidir)"\" \
    -DLOCALEDIR=\""$(datadir)/locale"\"

###############################################################################

libnm_vpn_plugin_sstp_la_SOURCES = \
    $(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.c \
    $(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.h \
    $(plugin_sources)

libnm_vpn_plugin_sstp_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
    -DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
    $(common_CFLAGS) \
    $(LIBNM_CFLAGS)

libnm_vpn_plugin_sstp_la_LIBADD = \
    $(LIBNM_LIBS) \
    $(DL_LIBS) \
    $(NULL)

libnm_vpn_plugin_sstp_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-vpn-plugin-sstp.ver"

###############################################################################

libnm_vpn_plugin_sstp_editor_la_SOURCES = \
    $(editor_sources)

libnm_vpn_plugin_sstp_editor_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
    $(common_CFLAGS) \
    $(GTK_CFLAGS) \
    $(LIBNMA_CFLAGS) \
    $(LIBNM_CFLAGS)

libnm_vpn_plugin_sstp_editor_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNMA_LIBS) \
    $(LIBNM_LIBS)

libnm_vpn_plugin_sstp_editor_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-vpn-plugin-sstp-editor.ver"

###############################################################################

libnm_sstp_properties_la_SOURCES = \
    $(plugin_sources) \
    $(editor_sources)

libnm_sstp_properties_la_CFLAGS = \
    -DNM_VPN_OLD \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
    $(common_CFLAGS) \
    $(GTK_CFLAGS) \
    $(LIBNM_GLIB_CFLAGS) \
    $(LIBNM_GTK_CFLAGS)

libnm_sstp_properties_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_GLIB_LIBS) \
    $(LIBNM_GTK_LIBS)

libnm_sstp_properties_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-sstp-properties.ver"

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
    libnm-sstp-properties.ver \
    libnm-vpn-plugin-sstp.ver \
    libnm-vpn-plugin-sstp-editor.ver \
    nm-sstp-dialog.ui
