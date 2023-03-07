%global snapshot %{nil}
%global ppp_version %(rpm -q ppp --queryformat '%{VERSION}')

Summary:   NetworkManager VPN plugin for SSTP
Name:      NetworkManager-sstp
Epoch:     1
Version:   0.9.10
Release:   6%{snapshot}%{?dist}
License:   GPLv2+
URL:       https://gitlab.gnome.org/GNOME/network-manager-sstp
Source:    https://downloads.sourceforge.net/sstp-client/%{name}-%{version}%{snapshot}.tar.xz

BuildRequires: gtk3-devel
BuildRequires: dbus-devel
BuildRequires: NetworkManager-glib-devel >= 0.9.10
BuildRequires: sstp-client-devel
BuildRequires: glib2-devel
BuildRequires: ppp-devel >= 2.4.6
BuildRequires: libtool intltool gettext
BuildRequires: libsecret-devel
BuildRequires: libnm-gtk-devel

Requires: dbus
Requires: NetworkManager >= 0.9.10
Requires: sstp-client
Requires: ppp >= 2.4.6
Requires: shared-mime-info
Requires: gnome-keyring

%global _privatelibs libnm-sstp-properties[.]so.*
%global __provides_exclude ^(%{_privatelibs})$
%global __requires_exclude ^(%{_privatelibs})$

%description
This package contains software for integrating VPN capabilities using
the SSTP server with NetworkManager.

%package -n NetworkManager-sstp-gnome
Summary: NetworkManager VPN plugin for SSTP - GNOME files
Group:   System Environment/Base

Requires: NetworkManager-sstp = %{version}-%{release}
Requires: nm-connection-editor

%description -n NetworkManager-sstp-gnome
This package contains software for integrating VPN capabilities with
the SSTP server with NetworkManager (GNOME files).

%prep
%setup -q

%build
%configure \
    --disable-static \
    --enable-more-warnings=yes \
    --with-pppd-plugin-dir=%{_libdir}/pppd/%{ppp_version}
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot} INSTALL="%{__install} -p"

rm -f %{buildroot}%{_libdir}/NetworkManager/lib*.la
rm -f %{buildroot}%{_libdir}/NetworkManager/lib*.a
rm -f %{buildroot}%{_libdir}/pppd/%{ppp_version}/*.la

%find_lang %{name}

%files -f %{name}.lang
%doc AUTHORS README ChangeLog
%license COPYING
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/nm-sstp-service.conf
%config(noreplace) %{_sysconfdir}/NetworkManager/VPN/nm-sstp-service.name
%{_libexecdir}/nm-sstp-service
%{_libexecdir}/nm-sstp-auth-dialog
%{_libdir}/pppd/%{ppp_version}/nm-sstp-pppd-plugin.so

%files -n NetworkManager-sstp-gnome
%doc AUTHORS README ChangeLog
%license COPYING
%{_libdir}/NetworkManager/lib*.so*
%dir %{_datadir}/gnome-vpn-properties/sstp
%{_datadir}/gnome-vpn-properties/sstp/nm-sstp-dialog.ui

%changelog
* Thu Feb 04 2016 Marcin Zajaczkowski <mszpak ATT wp DOTT pl> - 1:0.9.10-6
- Apply remarks after package review by Christopher Meng
- Specify minimal required ppp version to >= 2.4.6

* Wed Jun 24 2015 Marcin Zajaczkowski <mszpak ATT wp DOTT pl> - 1:0.9.10-5
- Change doc macro to license macro for COPYING file
- Change URL to plugin project page instead if NetworkManager itself

* Thu Jun 11 2015 Marcin Zajaczkowski <mszpak ATT wp DOTT pl> - 1:0.9.10-4
- Specify minimum required NetworkManager version - 0.9.10

* Mon Jun 08 2015 Marcin Zajaczkowski <mszpak ATT wp DOTT pl> - 1:0.9.10-3
- Minor changes to adjust configuration to Fedora requirements
- Remove redundant Obsoletes tag 

* Tue Jun 02 2015 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.10-2
- Taking suggested changes for Gateway validation from George Joseph

* Fri May 29 2015 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.10-1
- Upgraded the network-manager-sstp package to reflect mainstream 
  changes made to the network-manager-pptp counter part.

* Fri Oct 12 2012 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.4-2
- Fixed a bug that caused connection to be aborted with the message:
  "Connection was aborted, value of attribute is incorrect"

* Sat May 05 2012 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.4-1
- Compiled against the latest network manager 0.9.4 sources.

* Sat Mar 03 2012 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.1-4
- Added back the 'refuese-eap=yes' by default in the configuration.

* Wed Feb 08 2012 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.1-3
- Changed the pppd plugin to send MPPE keys on ip-up

* Sun Nov 20 2011 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.1-2
- Added proxy support

* Sun Oct 02 2011 Eivind Naess <eivnaes@yahoo.com> - 1:0.9.0-1
- Initial release
