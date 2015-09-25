INCLUDES = -I${top_srcdir}

AM_CPPFLAGS =							\
	$(DBUS_GLIB_CFLAGS)						\
	$(GLIB_CFLAGS)						\
	$(LIBNM_GLIB_CFLAGS)					\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DNM_VERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\"				\
	-DNM_SSTP_LOCALEDIR=\"$(datadir)/locale\"		\
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" 

libexec_PROGRAMS = nm-sstp-service

nm_sstp_service_SOURCES = \
	nm-sstp-service-defines.h \
	nm-sstp-service.c \
	nm-sstp-service.h

nm-sstp-pppd-service-glue.h: $(top_srcdir)/src/nm-sstp-pppd-service.xml
	dbus-binding-tool --prefix=nm_sstp_pppd_service --mode=glib-server --output=$@ $<

nm_sstp_service_LDADD = \
	$(DBUS_GLIB_LIBS) \
	$(GLIB_LIBS) \
	$(LIBNM_GLIB_LIBS)

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-sstp-pppd-plugin.la

nm_sstp_pppd_plugin_la_SOURCES = \
	nm-sstp-pppd-plugin.c \
	nm-ppp-status.h

nm_sstp_pppd_plugin_la_CPPFLAGS = \
	$(DBUS_GLIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
    $(SSTPC_CFLAGS)

nm_sstp_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_sstp_pppd_plugin_la_LIBADD = \
	$(DBUS_GLIB_LIBS) \
	$(GLIB_LIBS) \
	$(LIBNM_GLIB_LIBS) \
    $(SSTPC_LIBS)

BUILT_SOURCES = nm-sstp-pppd-service-glue.h

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = nm-sstp-pppd-service.xml

