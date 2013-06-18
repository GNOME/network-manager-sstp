INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-sstp-auth-dialog

nm_sstp_auth_dialog_CPPFLAGS =			\
	$(NM_CFLAGS)		\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(GNOMEKEYRING_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"			\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DVERSION=\"$(VERSION)\"

nm_sstp_auth_dialog_SOURCES = \
	main.c \
	vpn-password-dialog.c \
	vpn-password-dialog.h

nm_sstp_auth_dialog_LDADD = \
	$(NM_LIBS) \
	$(GTK_LIBS) \
	$(GNOMEKEYRING_LIBS)

CLEANFILES = *~
