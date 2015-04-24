plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-sstp-properties.la

INCLUDES = -I${top_srcdir}

libnm_sstp_properties_la_SOURCES = \
	nm-sstp.c \
	nm-sstp.h \
	advanced-dialog.c \
	advanced-dialog.h \
	import-export.c \
	import-export.h

uidir = $(datadir)/gnome-vpn-properties/sstp
ui_DATA = nm-sstp-dialog.ui

libnm_sstp_properties_la_CFLAGS =                       \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                                    \
	-I$(top_srcdir)/src				\
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\""$(datadir)/locale"\"             \
        -DG_DISABLE_DEPRECATED                          \
        -DVERSION=\"$(VERSION)\"

libnm_sstp_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS)

libnm_sstp_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
