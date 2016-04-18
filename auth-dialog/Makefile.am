INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-sstp-auth-dialog

nm_sstp_auth_dialog_CPPFLAGS =			\
	$(LIBNM_CFLAGS)			\
	$(GLIB_CFLAGS)				\
	$(GTK_CFLAGS)				\
	$(LIBNMA_CFLAGS)			\
	$(LIBSECRET_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"			\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DVERSION=\"$(VERSION)\"

nm_sstp_auth_dialog_SOURCES = \
	main.c

nm_sstp_auth_dialog_LDADD = \
	$(LIBNM_LIBS) \
	$(GTK_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

CLEANFILES = *~
