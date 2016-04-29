plugindir = $(libdir)/NetworkManager

plugin_LTLIBRARIES = libnm-vpn-plugin-sstp.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-sstp-properties.la
endif

AM_CPPFLAGS = -I${top_srcdir}

libnm_vpn_plugin_sstp_la_SOURCES = \
	nm-sstp.c \
	nm-sstp.h \
	advanced-dialog.c \
	advanced-dialog.h \
	import-export.c \
	import-export.h

libnm_sstp_properties_la_SOURCES = \
	$(libnm_vpn_plugin_sstp_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/sstp
ui_DATA = nm-sstp-dialog.ui

common_CFLAGS =                                         \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
	-I$(top_srcdir)/src				\
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\""$(datadir)/locale"\"

libnm_vpn_plugin_sstp_la_CFLAGS = \
	$(common_CFLAGS) \
        $(LIBNMA_CFLAGS) \
        $(LIBNM_CFLAGS)

libnm_sstp_properties_la_CFLAGS = \
	-DNM_SSTP_OLD \
	$(common_CFLAGS) \
        $(LIBNM_GLIB_CFLAGS) \
        $(LIBNM_GTK_CFLAGS)

libnm_vpn_plugin_sstp_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNMA_LIBS) \
        $(LIBNM_LIBS)

libnm_sstp_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_GLIB_LIBS) \
        $(LIBNM_GTK_LIBS)

libnm_vpn_plugin_sstp_la_LDFLAGS = \
        -avoid-version

libnm_sstp_properties_la_LDFLAGS = \
	$(libnm_vpn_plugin_sstp_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
