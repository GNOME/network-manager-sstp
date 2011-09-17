AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += auth-dialog properties po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-sstp-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-sstp-service.name

desktopfile = nm-sstp.desktop.in
iconfile = gnome-mime-application-x-sstp-settings.png

if WITH_GNOME
# FIXME: uncomment when nmce gets --import support
#desktopdir = $(datadir)/applications
#desktop_in_files = $(desktopfile)
#desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
#@INTLTOOL_DESKTOP_RULE@

#icondir = $(datadir)/icons/hicolor/48x48/apps
#icon_DATA = $(iconfile)
endif

nm-sstp-service.name: $(srcdir)/nm-sstp-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

EXTRA_DIST = nm-sstp-service.name.in \
             $(dbusservice_DATA)  \
             $(desktopfile) \
             $(iconfile) \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
