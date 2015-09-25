INCLUDES = -I${top_srcdir}

AM_CPPFLAGS =							\
	$(GLIB_CFLAGS)						\
	$(LIBNM_CFLAGS)						\
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

# D-Bus stuff
noinst_LTLIBRARIES = libnm-sstp-pppd-service-dbus.la

nodist_libnm_sstp_pppd_service_dbus_la_SOURCES =		\
	nm-sstp-pppd-service-dbus.c			\
	nm-sstp-pppd-service-dbus.h

libnm_sstp_pppd_service_dbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nm-sstp-pppd-service-dbus.h: $(top_srcdir)/src/nm-sstp-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

nm-sstp-pppd-service-dbus.c:
	@true

nm_sstp_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	libnm-sstp-pppd-service-dbus.la

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-sstp-pppd-plugin.la

nm_sstp_pppd_plugin_la_SOURCES = \
	nm-sstp-pppd-plugin.c \
	nm-ppp-status.h

nm_sstp_pppd_plugin_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
    $(SSTPC_CFLAGS)

nm_sstp_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_sstp_pppd_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
    $(SSTPC_LIBS)

BUILT_SOURCES = \
	nm-sstp-pppd-service-dbus.h \
	nm-sstp-pppd-service-dbus.c

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = nm-sstp-pppd-service.xml

