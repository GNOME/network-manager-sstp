%define nm_version          1:0.8.998
%define dbus_version        1.1
%define gtk3_version        3.0
%define ppp_version         2.4.5
%define shared_mime_version 0.16-3

%define snapshot %{nil}
%define realversion 0.9.0

Summary:   NetworkManager VPN plugin for SSTP
Name:      NetworkManager-sstp
Epoch:     1
Version:   0.9.0
Release:   2%{snapshot}%{?dist}
License:   GPLv2+
Group:     System Environment/Base
URL:       http://www.gnome.org/projects/NetworkManager/
Source:    %{name}-%{realversion}%{snapshot}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-root


BuildRequires: gtk3-devel             >= %{gtk3_version}
BuildRequires: dbus-devel             >= %{dbus_version}
BuildRequires: dbus-glib-devel        >= 0.74
BuildRequires: NetworkManager-devel   >= %{nm_version}
BuildRequires: NetworkManager-glib-devel >= %{nm_version}
BuildRequires: gnome-keyring-devel
BuildRequires: intltool gettext
BuildRequires: ppp-devel = %{ppp_version}

Requires: gtk2             >= %{gtk2_version}
Requires: dbus             >= %{dbus_version}
Requires: NetworkManager   >= %{nm_version}
Requires: ppp              = %{ppp_version}
Requires: shared-mime-info >= %{shared_mime_version}
Requires: sstp-client
Requires: gnome-keyring
Requires(post):   /sbin/ldconfig desktop-file-utils
Requires(postun): /sbin/ldconfig desktop-file-utils


%description
This package contains software for integrating PPTP VPN support with
the NetworkManager and the GNOME desktop.

%prep
%setup -q -n NetworkManager-sstp-%{realversion}


%build
%configure \
	--disable-static \
	--enable-more-warnings=yes \
	--with-pppd-plugin-dir=%{_libdir}/pppd/%{ppp_version}

make %{?_smp_mflags}

%install

make install DESTDIR=$RPM_BUILD_ROOT

rm -f %{buildroot}%{_libdir}/NetworkManager/lib*.la
rm -f %{buildroot}%{_libdir}/NetworkManager/lib*.a

rm -f %{buildroot}%{_libdir}/pppd/2.*/nm-sstp-pppd-plugin.la
rm -f %{buildroot}%{_libdir}/pppd/2.*/nm-sstp-pppd-plugin.a

%find_lang %{name}


%clean
rm -rf $RPM_BUILD_ROOT


%post
/sbin/ldconfig
/usr/bin/update-desktop-database &> /dev/null || :
touch --no-create %{_datadir}/icons/hicolor
if [ -x %{_bindir}/gtk-update-icon-cache ]; then
      %{_bindir}/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi


%postun
/sbin/ldconfig
/usr/bin/update-desktop-database &> /dev/null || :
touch --no-create %{_datadir}/icons/hicolor
if [ -x %{_bindir}/gtk-update-icon-cache ]; then
      %{_bindir}/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi


%files -f %{name}.lang
%defattr(-, root, root)

%doc AUTHORS ChangeLog
%{_libdir}/NetworkManager/lib*.so*
%{_libexecdir}/nm-sstp-auth-dialog
%{_sysconfdir}/dbus-1/system.d/nm-sstp-service.conf
%{_sysconfdir}/NetworkManager/VPN/nm-sstp-service.name
%{_libexecdir}/nm-sstp-service
%{_libdir}/pppd/2.*/nm-sstp-pppd-plugin.so
#%{_datadir}/applications/nm-sstp.desktop
#%{_datadir}/icons/hicolor/48x48/apps/gnome-mime-application-x-sstp-settings.png
%dir %{_datadir}/gnome-vpn-properties/sstp
%{_datadir}/gnome-vpn-properties/sstp/nm-sstp-dialog.ui

%changelog
* Sun Oct 02 2011 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.0-1
- Initial release
