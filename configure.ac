AC_PREREQ([2.69])

AC_INIT([NetworkManager-sstp],[1.3.2],[eivnaes@yahoo.com],[NetworkManager-sstp])
AM_INIT_AUTOMAKE([1.9 no-dist-gzip dist-xz -Wno-portability])
AM_MAINTAINER_MODE
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

dnl Define _SYSTEM_EXTENSIONS for various things like strcasestr()
AC_USE_SYSTEM_EXTENSIONS

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_SED
LT_INIT

AC_PATH_PROG(GLIB_COMPILE_RESOURCES, glib-compile-resources)
PKG_PROG_PKG_CONFIG()

AC_CHECK_PROG([has_file], file, yes, no)
if test x$has_file = xno ; then
    AC_MSG_ERROR(["file" utility not found.])
fi

AC_CHECK_PROG([has_find], find, yes, no)
if test x$has_find = xno ; then
    AC_MSG_ERROR(["find" utility not found.])
fi

AC_CHECK_HEADERS([
      fcntl.h
      paths.h
      syslog.h
      stdarg.h
      stdbool.h
      sys/ioctl.h
      unistd.h])

dnl
dnl Versions >= 2.5.0 will have pkg-config support
PKG_CHECK_EXISTS([pppd],
    [AS_VAR_SET([pppd_pkgconfig_support],[yes])])

dnl
dnl We do require pppd
AC_CHECK_HEADERS(pppd/pppd.h,,
    [AC_MSG_ERROR([pppd.h missing, Hint: apt-get install ppp-dev])])

dnl
dnl Check the presense of other pppd/*.h files
AC_CHECK_HEADERS([
    pppd/chap.h
    pppd/chap-new.h
    pppd/chap_ms.h
    ])

dnl
dnl Check if the version of mppe.h define mppe_keys_isset() functions, this has been backported to 2.4.9 on some Linux distributions
CFLAGS_OLD="$CFLAGS"
CFLAGS="$CFLAGS -Werror"
AC_CACHE_CHECK([for mppe_keys_isset() function], ac_cv_working_mppe_h, [
    AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
            @%:@define MPPE 1
            @%:@include <pppd/pppd.h>
            @%:@include <pppd/chap_ms.h>
            @%:@include <pppd/mppe.h>
        ]], [[
            if (mppe_keys_isset())
                return 0;
        ]]
    )],
    [ac_cv_working_mppe_h=yes],
    [ac_cv_working_mppe_h=no])
])
if test $ac_cv_working_mppe_h = yes; then
    AC_DEFINE(HAVE_MPPE_KEYS_FUNCTIONS, 1,
        [Define to 1 if you have <pppd/mppe.h> and it declares the mppe_keys_xyz() functions])
fi
CFLAGS="$CFLAGS_OLD"
AM_CONDITIONAL(WITH_PPP_MPPE_KEYS, test "x${ac_cv_working_mppe_h}" != "xno")


dnl
dnl Support for the auth notify callback in pppd >= 2.4.9
AC_ARG_WITH([pppd-auth-notify-support],
    [AS_HELP_STRING([--with-pppd-auth-notify-support], [is the auth-notifier supported by pppd])])
if test x"$with_pppd_auth_notify_support" != xyes; then
    if test x"$pppd_pkgconfig_support" = xyes; then
        AS_VAR_SET([with_pppd_auth_notify_support],[yes])
    fi
fi
if test x"$with_pppd_auth_notify_support" = xyes; then
    AC_DEFINE(USE_PPPD_AUTH_HOOK,1,[Define if pppd has support for client side authentication complete notification])
else
    AS_VAR_SET([with_pppd_auth_notify_support],[no])
fi

dnl
dnl Get the version of pppd using pkg-config, assume 2.4.9 if not present
PPPD_VERSION=2.4.9
if test x"$pppd_pkgconfig_support" = xyes; then
    PPPD_VERSION=`$PKG_CONFIG --modversion pppd`
fi

dnl
dnl Enable support for extended tls settings in pppd >= 2.5.0
AC_ARG_WITH([pppd-ext-tls-settings-suppport], [
    AS_HELP_STRING([--with-pppd-ext-tls-settings-support],
                   [is settings such as pkcs12, tls-verify-method, tls-verify-key-usage and max-tls-version supported in by pppd])
    ])
if test x"$with_pppd_ext_tls_settings_support" != xyes; then
    if test x"$pppd_pkgconfig_support" = xyes; then
        AS_VAR_SET([with_pppd_ext_tls_settings_support],[yes])
    fi
fi
if test x"$with_pppd_ext_tls_settings_support" = xyes; then
    AC_DEFINE(USE_PPP_EXT_TLS_SETTINGS,1,[Define if pppd has support for extended tls-settings like pkcs12, tls-verify-method, tls-verify-key-usage, max-tls-version])
else
    AS_VAR_SET([with_pppd_ext_tls_settings_support],[no])
fi

dnl The version of pppd dictates what code can be included, i.e. enable use of
dnl   #if WITH_PPP_VERSION >= PPP_VERSION(2,5,0) in the code
AC_DEFINE_UNQUOTED([PPP_VERSION(x,y,z)],
    [((x & 0xFF) << 16 | (y & 0xFF) << 8 | (z & 0xFF) << 0)],
    [Macro to help determine the particular version of pppd])
PPP_VERSION=$(echo $PPPD_VERSION | sed -e "s/\./\,/g")
AC_DEFINE_UNQUOTED(WITH_PPP_VERSION, PPP_VERSION($PPP_VERSION),
    [The real version of pppd represented as an int])


dnl
dnl Specify the path of the pppd plugin directory
AC_ARG_WITH([pppd-plugin-dir],
        [AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory])])
if test -n "$with_pppd_plugin_dir" ; then
	PPPD_PLUGIN_DIR="$with_pppd_plugin_dir"
else
    if test x"$pppd_pkgconfig_support" = xyes; then
        PKG_CHECK_VAR(PPPD_PLUGIN_DIR, [pppd], [plugindir])
    else
	    PPPD_PLUGIN_DIR="${libdir}/pppd/2.4.7"
    fi
fi
AC_SUBST(PPPD_PLUGIN_DIR)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_MODE_T
AC_TYPE_PID_T

dnl
dnl Checks for library functions.
dnl
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

GIT_SHA_RECORD(NM_GIT_SHA)

AC_SEARCH_LIBS([dlopen], [dl dld], [], [ac_cv_search_dlopen=])
AC_SUBST([DL_LIBS], "$ac_cv_search_dlopen")

dnl
dnl GNOME support
dnl
AC_ARG_WITH(gnome, AS_HELP_STRING([--without-gnome], [Build NetworkManager-sstp without GNOME support, e.g. vpn service only]), [], [with_gnome_specified=no])
AC_ARG_WITH(gtk4, AS_HELP_STRING([--with-gtk4], [Build NetworkManager-sstp with libnma-gtk4 support]), [], [with_gtk4_specified=no])
if test x"$with_gnome" != xno; then
	with_gnome=yes
fi
if test x"$with_gtk4_specified" = xno; then
	with_gtk4=no
fi
if test x"$with_gtk4" != xyes; then
	with_gtk4=no
fi
AM_CONDITIONAL(WITH_GNOME, test x"$with_gnome" != xno)
AM_CONDITIONAL(WITH_GTK4, test x"$with_gtk4" != xno)
AC_ARG_ENABLE(absolute-paths, AS_HELP_STRING([--enable-absolute-paths], [Use absolute paths to in .name files. Useful for development. (default is no)]))

dnl
dnl translation support
dnl
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.20])

GETTEXT_PACKAGE=NetworkManager-sstp
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

PKG_CHECK_MODULES(GNUTLS, [gnutls >= 2.12])
PKG_CHECK_MODULES(SSTPC, [sstp-client-1.0 >= 1.0.10])

# gio-unix will require glib and gio
PKG_CHECK_MODULES(GLIB, [gio-unix-2.0 >= 2.40 gmodule-2.0])
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_44"
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_44"

if test x"$with_gnome" != xno; then
	PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.4)
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_3_4"
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MAX_REQUIRED=GDK_VERSION_3_4"

	PKG_CHECK_MODULES(LIBNMA, libnma >= 1.8.0)
	PKG_CHECK_MODULES(LIBSECRET, libsecret-1 >= 0.18)
fi

if test x"$with_gtk4" != xno; then
	PKG_CHECK_MODULES(GTK4, gtk4 >= 4.0)
	GTK4_CFLAGS="$GTK4_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_4_0"
	GTK4_CFLAGS="$GTK4_CFLAGS -DGDK_VERSION_MAX_ALLOWED=GDK_VERSION_4_0"
	PKG_CHECK_MODULES(LIBNMA_GTK4, libnma-gtk4 >= 1.8.33)
fi

PKG_CHECK_MODULES(LIBNM, libnm >= 1.7.0)
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_8"
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_8"

# system CA certificates path
AC_ARG_WITH(system-ca-path,
            AS_HELP_STRING([--with-system-ca-path=/path/to/ssl/certs], [path to system CA certificates]))
if test "x${with_system_ca_path}" = x; then
    SYSTEM_CA_PATH="${sysconfdir}/ssl/certs"
else
    SYSTEM_CA_PATH="$with_system_ca_path"
fi
AC_DEFINE_UNQUOTED(SYSTEM_CA_PATH, "$SYSTEM_CA_PATH", [Define to path to system CA certificates])
AC_SUBST(SYSTEM_CA_PATH)

NM_VPN_SERVICE_DIR=`$PKG_CONFIG --define-variable prefix='\${prefix}' --variable vpnservicedir libnm`
AC_SUBST(NM_VPN_SERVICE_DIR)

NM_COMPILER_WARNINGS([yes])

NM_PLUGIN_DIR="$libdir/NetworkManager"
AC_SUBST(NM_PLUGIN_DIR)
if test x"$enable_absolute_paths" = x"yes"; then
	NM_PLUGIN_DIR_NAME_FILE="$NM_PLUGIN_DIR/"
else
	enable_absolute_paths=no
	NM_PLUGIN_DIR_NAME_FILE=""
fi
AC_SUBST(NM_PLUGIN_DIR_NAME_FILE)

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<dist-version>], [Define the custom version (like distribution package name and revision)]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

AC_CONFIG_FILES([
Makefile
po/Makefile.in
])
AC_OUTPUT

echo ""
echo "Build configuration: "
echo "  --with-dist-version=$ac_distver"
echo "  --with-gnome=$with_gnome"
echo "  --with-gtk4=$with_gtk4"
echo "  --with-system-ca-path=$SYSTEM_CA_PATH"
echo "  --with-pppd-plugin-dir=$PPPD_PLUGIN_DIR"
echo "  --with-pppd-auth-notify-support=$with_pppd_auth_notify_support"
echo "  --with-pppd-ext-tls-settings-support=$with_pppd_ext_tls_settings_support"
echo "  --enable-absolute-paths=$enable_absolute_paths"
echo "  --enable-more-warnings=$set_more_warnings"
