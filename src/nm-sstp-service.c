/* -*- Mode: C; tab-width: 4; indent-tabs-mode: s; c-basic-offset: 4 -*- */
/* nm-sstp-service - SSTP VPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-sstp-service.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <locale.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "nm-sstp-pppd-status.h"
#include "nm-sstp-pppd-service-dbus.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static struct {
    gboolean debug;
    int log_level;
} gl/*lobal*/;

static void nm_sstp_plugin_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMSstpPlugin, nm_sstp_plugin, NM_TYPE_VPN_SERVICE_PLUGIN,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_sstp_plugin_initable_iface_init));

typedef struct {
    GPid pid;
    guint32 ppp_timeout_handler;
    NMConnection *connection;
    NMDBusSstpPpp *dbus_skeleton;
} NMSstpPluginPrivate;

#define NM_SSTP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSTP_PLUGIN, NMSstpPluginPrivate))

#define NM_SSTP_PPPD_PLUGIN PLUGINDIR "/nm-sstp-pppd-plugin.so"
#define NM_SSTP_WAIT_PPPD 10000 /* 10 seconds */
#define NM_SSTP_MTU_DEFAULT "1400"
#define SSTP_SERVICE_SECRET_TRIES "sstp-service-secret-tries"

/*****************************************************************************/

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (gl.log_level >= (level)) { \
              g_print ("nm-sstp[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                       (long) getpid (), \
                       nm_utils_syslog_to_str (level) \
                       _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

static gboolean
_LOGD_enabled (void)
{
    return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

typedef struct {
    const char *name;
    GType type;
    bool required:1;
} ValidProperty;

static const ValidProperty valid_properties[] = {
    { NM_SSTP_KEY_GATEWAY,                   G_TYPE_STRING,  TRUE  },
    { NM_SSTP_KEY_USER,                      G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_PASSWORD_FLAGS,            G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_DOMAIN,                    G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_CONNECTION_TYPE,           G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_CA_CERT,                   G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_IGN_CERT_WARN,             G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_TLS_EXT_ENABLE,            G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_MTU,                       G_TYPE_UINT,    FALSE },
    { NM_SSTP_KEY_REFUSE_EAP,                G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_REFUSE_PAP,                G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_REFUSE_CHAP,               G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_REFUSE_MSCHAP,             G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_REFUSE_MSCHAPV2,           G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_REQUIRE_MPPE,              G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_REQUIRE_MPPE_40,           G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_REQUIRE_MPPE_128,          G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_MPPE_STATEFUL,             G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_NOBSDCOMP,                 G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_NODEFLATE,                 G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_NO_VJ_COMP,                G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_LCP_ECHO_FAILURE,          G_TYPE_UINT,    FALSE },
    { NM_SSTP_KEY_LCP_ECHO_INTERVAL,         G_TYPE_UINT,    FALSE },
    { NM_SSTP_KEY_UNIT_NUM,                  G_TYPE_UINT,    FALSE },
    { NM_SSTP_KEY_PROXY_SERVER,              G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_PROXY_PORT,                G_TYPE_UINT,    FALSE },
    { NM_SSTP_KEY_PROXY_USER,                G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_PROXY_PASSWORD_FLAGS,      G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_UUID,                      G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_NOSECRET,                  G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_CRL_REVOCATION_FILE,       G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_CA_CERT,               G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_IDENTITY,              G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_SUBJECT_NAME,          G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_USER_CERT,             G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_USER_KEY,              G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_USER_KEY_SECRET_FLAGS, G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_VERIFY_KEY_USAGE,      G_TYPE_BOOLEAN, FALSE },
    { NM_SSTP_KEY_TLS_VERIFY_METHOD,         G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_REMOTENAME,            G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_MAX_VERSION,           G_TYPE_STRING,  FALSE },
    { NULL,                                  G_TYPE_NONE,    FALSE }
};

static const ValidProperty valid_secrets[] = {
    { NM_SSTP_KEY_PASSWORD,                  G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_PROXY_PASSWORD,            G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_TLS_USER_KEY_SECRET,       G_TYPE_STRING,  FALSE },
    { NM_SSTP_KEY_NOSECRET,                  G_TYPE_STRING,  FALSE },
    { NULL,                                  G_TYPE_NONE,    FALSE }
};

static void
args_add_str_take (GPtrArray *args, char *arg)
{
    nm_assert (args);
    nm_assert (arg);

    g_ptr_array_add (args, arg);
}

static const char *
args_add_utf8safe_str (GPtrArray *args, const char *arg)
{
    char *arg_unescaped;

    nm_assert (args);
    nm_assert (arg);

    arg_unescaped = nm_utils_str_utf8safe_unescape_cp (arg);
    args_add_str_take (args, arg_unescaped);
    return arg_unescaped;
}

static gboolean
validate_gateway (const char *gateway)
{
    const char *p = gateway;

    if (!gateway || !strlen (gateway))
        return FALSE;

    /* Ensure it's a valid DNS name or IP address */
    p = gateway;
    while (*p) {
        if (!isalnum (*p) && (*p != '-') && (*p != '.') && (*p != ':'))
            return FALSE;
        p++;
    }
    return TRUE;
}

typedef struct ValidateInfo {
    const ValidProperty *table;
    GError **error;
    gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
    ValidateInfo *info = (ValidateInfo *) user_data;
    int i;

    if (*(info->error))
        return;

    info->have_items = TRUE;

    /* 'name' is the setting name; always allowed but unused */
    if (!strcmp (key, NM_SETTING_NAME))
        return;

    for (i = 0; info->table[i].name; i++) {
        const ValidProperty prop = info->table[i];
        long int tmp;

        if (strcmp (prop.name, key))
            continue;

        switch (prop.type) {
        case G_TYPE_STRING:
            if (   !strcmp (prop.name, NM_SSTP_KEY_GATEWAY)
                && !validate_gateway (value)) {
                g_set_error (info->error,
                             NM_VPN_PLUGIN_ERROR,
                             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                             _("invalid gateway “%s”"),
                             key);
                return;
            }
            return; /* valid */
        case G_TYPE_UINT:
            errno = 0;
            tmp = strtol (value, NULL, 10);
            if (errno == 0)
                return; /* valid */

            g_set_error (info->error,
                         NM_VPN_PLUGIN_ERROR,
                         NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                         _("invalid integer property “%s”"),
                         key);
            break;
        case G_TYPE_BOOLEAN:
            if (!strcmp (value, "yes") || !strcmp (value, "no"))
                return; /* valid */

            g_set_error (info->error,
                         NM_VPN_PLUGIN_ERROR,
                         NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                         _("invalid boolean property “%s” (not yes or no)"),
                         key);
            break;
        default:
            g_set_error (info->error,
                         NM_VPN_PLUGIN_ERROR,
                         NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                         _("unhandled property “%s” type %s"),
                         key, g_type_name (prop.type));
            break;
        }
    }

    /* Did not find the property from valid_properties or the type did not match */
    if (!info->table[i].name) {
        g_set_error (info->error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                     _("property “%s” invalid or not supported"),
                     key);
    }
}

static gboolean
nm_sstp_properties_validate (NMSettingVpn *s_vpn,
                             GError **error)
{
    ValidateInfo info = { &valid_properties[0], error, FALSE };
    int i;

    nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
    if (!info.have_items) {
        g_set_error (error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                     "%s",
                     _("No VPN configuration options."));
        return FALSE;
    }

    if (*error)
        return FALSE;

    /* Ensure required properties exist */
    for (i = 0; valid_properties[i].name; i++) {
        const ValidProperty prop = valid_properties[i];
        const char *value;

        if (!prop.required)
            continue;

        value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
        if (!value || !strlen (value)) {
            g_set_error (error,
                         NM_VPN_PLUGIN_ERROR,
                         NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                         _("Missing required option “%s”."),
                         prop.name);
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
nm_sstp_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
    GError *validate_error = NULL;
    ValidateInfo info = { &valid_secrets[0], &validate_error, FALSE };

    nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
    if (validate_error) {
        g_propagate_error (error, validate_error);
        return FALSE;
    }
    return TRUE;
}

static void
pppd_watch_cb (GPid pid, gint status, gpointer user_data)
{
    NMSstpPlugin *plugin = NM_SSTP_PLUGIN (user_data);
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);
    guint error = 0;

    if (WIFEXITED (status)) {
        error = WEXITSTATUS (status);
        if (error != 0)
            _LOGW ("pppd exited with error code %d", error);
    }
    else if (WIFSTOPPED (status))
        _LOGW ("pppd stopped unexpectedly with signal %d", WSTOPSIG (status));
    else if (WIFSIGNALED (status))
        _LOGW ("pppd died with signal %d", WTERMSIG (status));
    else
        _LOGW ("pppd died from an unknown cause");

    /* Reap child if needed. */
    waitpid (priv->pid, NULL, WNOHANG);
    priv->pid = 0;

    /* Must be after data->state is set since signals use data->state */
    switch (error) {
    case 16:
        /* hangup */
        // FIXME: better failure reason
        nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
        break;
    case 2:
        /* Couldn't log in due to bad user/pass */
        nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
        break;
    case 1:
        /* Other error (couldn't bind to address, etc) */
        nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
        break;
    default:
        nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
        break;
    }
}

static inline const char *
nm_find_pppd (void)
{
    static const char *pppd_binary_paths[] =
        {
            "/sbin/pppd",
            "/usr/sbin/pppd",
            "/usr/local/sbin/pppd",
            NULL
        };

    const char  **pppd_binary = pppd_binary_paths;

    while (*pppd_binary != NULL) {
        if (g_file_test (*pppd_binary, G_FILE_TEST_EXISTS))
            break;
        pppd_binary++;
    }

    return *pppd_binary;
}

static inline const char *
nm_find_sstpc (void)
{
    static const char *sstp_binary_paths[] =
    {
        "/sbin/sstpc",
        "/usr/sbin/sstpc",
        "/usr/local/sbin/sstpc",
        NULL
    };

    const char  **sstp_binary = sstp_binary_paths;

    while (*sstp_binary != NULL) {
        if (g_file_test (*sstp_binary, G_FILE_TEST_EXISTS))
            break;
        sstp_binary++;
    }

    return *sstp_binary;
}

static gboolean
pppd_timed_out (gpointer user_data)
{
    NMSstpPlugin *plugin = NM_SSTP_PLUGIN (user_data);

    _LOGW ("Looks like pppd didn't initialize our dbus module");
    nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

    return FALSE;
}

static gboolean
str_to_int (const char *str, long int *out)
{
    long int tmp_int;

    if (!str)
        return FALSE;

    errno = 0;
    tmp_int = strtol (str, NULL, 10);
    if (errno == 0) {
        *out = tmp_int;
        return TRUE;
    }
    return FALSE;
}

static GPtrArray *
construct_pppd_args (NMSstpPlugin *plugin,
                     NMSettingVpn *s_vpn,
                     const char *pppd,
                     const char *gwaddr,
                     GError **error)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);
    NMConnection *connection = priv->connection;
    NMSettingIPConfig *ip4cfg = NULL;
    NMSettingIPConfig *ip6cfg = NULL;
    GPtrArray *args = NULL;
    const char *value, *sstp_binary;
    const char *proxy_server, *proxy_port;
    gs_free char *ipparam = NULL;
    gs_free char *ca_cert = NULL;
    gs_free char *ca_path = NULL;
    gs_free char *proxy = NULL;
    gs_free char *uuid = NULL;
    gs_free char *pty = NULL;
    gboolean ign_cert = FALSE;
    gboolean tls_ext = FALSE;
    gboolean is_pkcs12 = FALSE;
    gboolean is_local_set = FALSE;

    sstp_binary = nm_find_sstpc ();
    if (!sstp_binary) {
        g_set_error (error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
                     "%s",
                     _("Could not find sstp client binary."));
        return FALSE;
    }

    /* Validate the Gateway option */
    if (!gwaddr || !strlen (gwaddr)) {
        g_set_error (error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                     "%s",
                     _("Missing VPN gateway."));
        goto error;
    }

    /* Create the argument vector for pppd */
    args = g_ptr_array_new ();
    g_ptr_array_add (args, (gpointer) g_strdup (pppd));

    /* Get the CA Certificate (if any) */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_CA_CERT);
    if (value && strlen (value)) {

        ca_path = nm_utils_str_utf8safe_unescape_cp (value);
        ca_cert = g_strdup_printf ("--ca-cert %s", ca_path);
    }

    /*  Set the UUID of the connection */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_UUID);
    if (value && strlen(value)) {
        uuid = g_strdup_printf ("--uuid %s", value);
    }

    /* Ignore any certificate warnings */
    value = nm_setting_vpn_get_data_item(s_vpn, NM_SSTP_KEY_IGN_CERT_WARN);
    if (value && !strcmp(value, "yes")) {
        ign_cert = TRUE;
    }

    /* Enable TLS hostname extensions */
    value = nm_setting_vpn_get_data_item(s_vpn, NM_SSTP_KEY_TLS_EXT_ENABLE);
    if (value && !strcmp(value, "yes")) {
        tls_ext = TRUE;
    }

    /* Get the proxy settings */
    proxy_server = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_SERVER);
    proxy_port = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_PORT);
    if (proxy_server && proxy_port && strlen(proxy_server) && strlen(proxy_port)) {
        const char *proxy_user, *proxy_password;
        long int tmp_int;

        if (!str_to_int (proxy_port, &tmp_int)) {
            tmp_int = 0;
        }

        proxy_user = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_USER);
        proxy_password = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PROXY_PASSWORD);

        proxy = g_strdup_printf("--proxy http://%s%s%s%s%s:%ld",
                                proxy_user     ?     : "",
                                proxy_password ? ":" : "",
                                proxy_password ?     : "",
                                proxy_user     ? "@" : "",
                                proxy_server,
                                tmp_int);
    }

    /* Add the PTY option */
    ipparam = g_strdup_printf ("nm-pptp-service-%d", getpid ());    /* Using "pptp" to avoid having /etc/ppp/ip-up.d/0000usepeerdns replace /etc/resolv.conf */
    pty = g_strdup_printf ("%s %s %s %s --nolaunchpppd %s %s --ipparam %s %s %s",
                           sstp_binary, gwaddr,
                           ign_cert == TRUE ? "--cert-warn" : "",
                           tls_ext == TRUE ? "--tls-ext" : "",
                           gl.debug ? "--log-level 5" : "",
                           proxy ? proxy : "",
                           ipparam,
                           uuid ? uuid : "",
                           ca_cert ? ca_cert : ""
                           );
    g_ptr_array_add (args, (gpointer) g_strdup ("pty"));
    g_ptr_array_add (args, (gpointer) g_strdup (pty));

    /* Enable debug */
    if (_LOGD_enabled ()) {
        g_ptr_array_add (args, (gpointer) g_strdup ("debug"));
    }

    /* PPP options */
    g_ptr_array_add (args, (gpointer) g_strdup ("ipparam"));
    g_ptr_array_add (args, (gpointer) g_strdup (ipparam));
    g_ptr_array_add (args, (gpointer) g_strdup ("nodetach"));
    g_ptr_array_add (args, (gpointer) g_strdup ("lock"));

    /* Any IPv4 configuration options */
    ip4cfg = nm_connection_get_setting_ip4_config (connection);
    if (ip4cfg) {

        value = nm_setting_ip_config_get_method (ip4cfg);
        if (nm_streq0 (value, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
            const char *ipv4_str = NULL;
            const char *gway_str = NULL;
            const char *mask_str = NULL;
            char buf[NM_INET_ADDRSTRLEN];
            NMIPAddress *ipv4 = NULL;

            // IF <local:remote> is specified, the IPCP negotiation will fail unless
            //   - ipcp-accept-local, and/or
            //   - ipcp-accept-remote
            // is specified. That depends on the server, but in any case allow it.
            //
            // The "manual" option is really just a suggestion. "auto" is the default.

            ipv4 = nm_setting_ip_config_get_address (ip4cfg, 0);
            if (ipv4) {
                int prefix = nm_ip_address_get_prefix (ipv4);
                ipv4_str = nm_ip_address_get_address (ipv4);
                mask_str = nm_utils_inet4_ntop(nm_utils_ip4_prefix_to_netmask (prefix), buf);

                gway_str = nm_setting_ip_config_get_gateway (ip4cfg);
                if (ipv4_str && gway_str) {
                    g_ptr_array_add (args, (gpointer) g_strdup_printf ("%s:%s", ipv4_str, gway_str));
                    if (mask_str) {
                        g_ptr_array_add (args, (gpointer) g_strdup ("netmask"));
                        g_ptr_array_add (args, (gpointer) g_strdup (mask_str));
                    }
                    g_ptr_array_add (args, (gpointer) g_strdup ("ipcp-accept-local"));
                    g_ptr_array_add (args, (gpointer) g_strdup ("ipcp-accept-remote"));
                    is_local_set = TRUE;
                }
            }
        }
        if (nm_streq (value, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
            g_ptr_array_add (args, (gpointer) g_strdup ("noip"));
        }
        else {
            // pppd will copy over /etc/resolv.conf which results in an ugly bug when connecting to 
            //    Azure and the private DNS service isn't responding to any queries. Don't use this
            //    option unless it is absolutely necessary (i.e. user can disable this behavior).
            if (!nm_setting_ip_config_get_ignore_auto_dns(ip4cfg)) {
                g_ptr_array_add (args, (gpointer) g_strdup ("usepeerdns"));
            }
        }
    }
    if (!is_local_set) {
        g_ptr_array_add (args, (gpointer) g_strdup ("noipdefault"));
    }
    is_local_set = FALSE;

    /* Any IPv6 configuration options */
    ip6cfg = nm_connection_get_setting_ip6_config (connection);
    if (ip6cfg) {

        value = nm_setting_ip_config_get_method (ip6cfg);
        if (nm_streq0 (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {

            NMIPAddress *ipv6 = nm_setting_ip_config_get_address (ip6cfg, 0);
            if (ipv6) {

                const char *ipv6_str = nm_ip_address_get_address (ipv6);
                const char *gway_str = nm_setting_ip_config_get_gateway (ip6cfg);
                if (ipv6_str && gway_str) {

                    g_ptr_array_add (args, (gpointer) g_strdup ("ipv6"));
                    g_ptr_array_add (args, (gpointer) g_strdup_printf ("%s,%s",
                            ipv6_str, gway_str));
                }
            }
            else {
                // Specified "manual", but no addresses provided??
                g_ptr_array_add (args, (gpointer) g_strdup ("+ipv6"));
            }
        }
        else if (nm_streq0 (value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
            g_ptr_array_add (args, (gpointer) g_strdup ("+ipv6"));
        }
        else if (nm_streq0 (value, NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
            g_ptr_array_add (args, (gpointer) g_strdup ("noipv6"));
        }
    }

    /* Let network-manager handle the routes, tell pppd to not mess with them */
    g_ptr_array_add (args, (gpointer) g_strdup ("nodefaultroute"));
    g_ptr_array_add (args, (gpointer) g_strdup ("nodefaultroute6"));

    /* Don't need to auth the SSTP server */
    g_ptr_array_add (args, (gpointer) g_strdup ("noauth"));

    /* Username; try SSTP specific username first, then generic username */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_CONNECTION_TYPE);
    if (value == NULL || nm_streq0(value, NM_SSTP_CONTYPE_PASSWORD)) {

        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_USER);
        if (!value || !*value)
            value = nm_setting_vpn_get_user_name (s_vpn);
        if (value && *value) {
            g_ptr_array_add (args, (gpointer) g_strdup ("user"));
            g_ptr_array_add (args, (gpointer) g_strdup (value));
        }

        /* Pass the remotename */
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_GATEWAY);
        if (value && *value) {
            g_ptr_array_add (args, (gpointer) g_strdup ("remotename"));
            g_ptr_array_add (args, (gpointer) g_strdup (value));
        }
    }
    else if (nm_streq0(value, NM_SSTP_CONTYPE_TLS)) {

        /* This is usually the certificate's subject name, but user can specify an override in
         *   the advanced settings dialog
         *
         * NOTE: that the Microsoft OID for username has presidence (OID: 1.2.840.113549.1.9.1),
         *   over the subject name for the user's convenience.
         */
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_IDENTITY);
        if (value && *value) {
            g_ptr_array_add (args, (gpointer) g_strdup ("name"));
            args_add_utf8safe_str(args, value);
        }
        else {
            /* Automatically extracted from the certificate when password is correct */
            value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_SUBJECT_NAME);
            if (value && *value) {
                g_ptr_array_add (args, (gpointer) g_strdup ("name"));
                args_add_utf8safe_str (args, value);
            }
        }

        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_CERT);
        if (value && *value) {
#ifdef USE_PPP_EXT_TLS_SETTINGS
            // "pkcs12" is only available in pppd > 2.4.9
            is_pkcs12 = nm_utils_file_is_pkcs12 (value);
#endif // USE_PPP_EXT_TLS_SETTINGS
            g_ptr_array_add (args, (gpointer) g_strdup (is_pkcs12 ? "pkcs12" : "cert"));
            args_add_utf8safe_str (args, value);
        }

        if (!is_pkcs12) {
            value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_KEY);
            if (value && *value) {
                g_ptr_array_add (args, (gpointer) g_strdup ("key"));
                args_add_utf8safe_str(args, value);
            }
        }

        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_CA_CERT);
        if (value && *value) {
            g_ptr_array_add (args, (gpointer) g_strdup ("ca"));
            args_add_utf8safe_str(args, value);
        }
        else {
            g_ptr_array_add (args, (gpointer) g_strdup ("capath"));
            args_add_utf8safe_str(args, g_strdup (SYSTEM_CA_PATH));
        }

        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_CRL_REVOCATION_FILE);
        if (value && *value) {
            g_ptr_array_add (args, (gpointer) g_strdup ("crl"));
            g_ptr_array_add (args, g_strdup (value));
        }

#ifdef USE_PPP_EXT_TLS_SETTINGS
        // "max-tls-version" is only in pppd > 2.4.9
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_MAX_VERSION);
        if (value && *value) {
            g_ptr_array_add (args, (gpointer) g_strdup ("max-tls-version"));
            g_ptr_array_add (args, g_strdup (value));
        }

        // "tls-verify-key-usage" is only in pppd > 2.4.9
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_VERIFY_KEY_USAGE);
        if (value && *value) {
            g_ptr_array_add (args, (gpointer) g_strdup ("tls-verify-key-usage"));
        }

        // "tls-verify-method" is only in pppd > 2.4.9
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_VERIFY_METHOD);
        if (value && *value) {

            const char *remote = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_REMOTENAME);
            if (remote && *remote) {

                g_ptr_array_add (args, (gpointer) g_strdup ("tls-verify-method"));
                g_ptr_array_add (args, g_strdup (value));

                // If one specify (ca or capath), cert, key and password, then remote name isn't
                //    used to look up the secret in /etc/ppp/eaptls-client
                g_ptr_array_add (args, (gpointer) g_strdup ("remotename"));
                g_ptr_array_add (args, g_strdup (remote));
            }
        }
#endif // USE_PPP_EXT_TLS_SETTINGS

        g_ptr_array_add (args, (gpointer) g_strdup ("need-peer-eap"));
    }

    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_MTU) ? : NM_SSTP_MTU_DEFAULT;
    if (value && *value) {
        long int tmp_int;
        if (str_to_int (value, &tmp_int)) {
            g_ptr_array_add (args, (gpointer) g_strdup ("mtu"));
            g_ptr_array_add (args, (gpointer) g_strdup_printf("%ld", tmp_int));
        } else
            _LOGW ("failed to convert mtu value “%s”", value);
    }

    /* Allow EAP */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REFUSE_EAP);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("refuse-eap"));

    /* Allow plain text passwords */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REFUSE_PAP);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("refuse-pap"));

    /* Allow CHAP-MD5 */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REFUSE_CHAP);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("refuse-chap"));

    /* Allow MSCHAP */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REFUSE_MSCHAP);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap"));

    /* Allow MSCHAP-v2 */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REFUSE_MSCHAPV2);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap-v2"));

    /* Require MPPE */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REQUIRE_MPPE);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe"));

    /* Use MPPE-40 bit */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REQUIRE_MPPE_40);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-40"));

    /* Use MPPE-128 bit */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_REQUIRE_MPPE_128);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-128"));

    /* Use stateful MPPE */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_MPPE_STATEFUL);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("mppe-stateful"));

    /* No BSD Compression */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_NOBSDCOMP);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("nobsdcomp"));

    /* No Deflate */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_NODEFLATE);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("nodeflate"));

    /* No Compression */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_NO_VJ_COMP);
    if (value && !strcmp (value, "yes"))
        g_ptr_array_add (args, (gpointer) g_strdup ("novj"));

    /* LCP Echo Failure */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_LCP_ECHO_FAILURE);
    if (value && strlen (value)) {
        long int tmp_int;

        /* Convert to integer and then back to string for security's sake
         * because strtol ignores some leading and trailing characters.
         */
        if (str_to_int (value, &tmp_int)) {
            g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
            g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
        } else {
            _LOGW ("failed to convert lcp-echo-failure value “%s”", value);
        }
    } else {
        g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
        g_ptr_array_add (args, (gpointer) g_strdup ("0"));
    }

    /* LCP Echo Interval */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_LCP_ECHO_INTERVAL);
    if (value && strlen (value)) {
        long int tmp_int;

        /* Convert to integer and then back to string for security's sake
         * because strtol ignores some leading and trailing characters.
         */
        if (str_to_int (value, &tmp_int)) {
            g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
            g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
        } else {
            _LOGW ("failed to convert lcp-echo-interval value “%s”", value);
        }
    } else {
        g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
        g_ptr_array_add (args, (gpointer) g_strdup ("0"));
    }

    /* Unit Number */
    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_UNIT_NUM);
    if (value && *value) {
        long int tmp_int;
        if (str_to_int (value, &tmp_int)) {
            g_ptr_array_add (args, (gpointer) g_strdup ("unit"));
            g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
        } else
            _LOGW ("failed to convert unit value “%s”", value);
    }

    /* Add the SSTP PPP Plugin */
    g_ptr_array_add (args, (gpointer) g_strdup ("plugin"));
    g_ptr_array_add (args, (gpointer) g_strdup (NM_SSTP_PPPD_PLUGIN));

    /* Terminate pointer array with NULL */
    g_ptr_array_add (args, NULL);

    return args;

error:
    g_ptr_array_free (args, TRUE);
    return FALSE;
}

static void
nm_sstp_dump_ptr_array(gpointer data, gpointer ctx)
{
    _LOGD("%s", (gchar *) data);
}

static gboolean
nm_sstp_start_pppd_binary (NMSstpPlugin *plugin,
                           NMSettingVpn *s_vpn,
                           const char *gwaddr,
                           GError **error)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);
    GPid pid;
    const char *pppd_binary;
    GPtrArray *pppd_argv;

    pppd_binary = nm_find_pppd ();
    if (!pppd_binary) {
        g_set_error (error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
                     "%s",
                     _("Could not find the pppd binary."));
        return FALSE;
    }

    pppd_argv = construct_pppd_args (plugin, s_vpn, pppd_binary, gwaddr, error);
    if (!pppd_argv)
        return FALSE;

    if (gl.debug)
        g_ptr_array_foreach (pppd_argv, nm_sstp_dump_ptr_array, NULL);

    if (!g_spawn_async (NULL, (char **) pppd_argv->pdata, NULL,
                        G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
        g_ptr_array_free (pppd_argv, TRUE);
        return FALSE;
    }
    g_ptr_array_free (pppd_argv, TRUE);

    _LOGI ("pppd started with pid %d", pid);

    NM_SSTP_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
    g_child_watch_add (pid, pppd_watch_cb, plugin);

    priv->ppp_timeout_handler = g_timeout_add (NM_SSTP_WAIT_PPPD, pppd_timed_out, plugin);

    return TRUE;
}

static void
remove_timeout_handler (NMSstpPlugin *plugin)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);

    if (priv->ppp_timeout_handler) {
        g_source_remove (priv->ppp_timeout_handler);
        priv->ppp_timeout_handler = 0;
    }
}

static gboolean
handle_need_secrets (NMDBusSstpPpp *object,
                     GDBusMethodInvocation *invocation,
                     gpointer user_data)
{
    NMSstpPlugin *self = NM_SSTP_PLUGIN (user_data);
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (self);
    NMSettingVpn *s_vpn;
    const char *user = NULL, *password = NULL, *domain, *value;
    gchar *username;
    gboolean is_encr;

    remove_timeout_handler (NM_SSTP_PLUGIN (user_data));

    s_vpn = nm_connection_get_setting_vpn (priv->connection);
    g_assert (s_vpn);

    value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_CONNECTION_TYPE);
    if (value == NULL || nm_streq0 (value, NM_SSTP_CONTYPE_PASSWORD)) {
        /* Username; try SSTP specific username first, then generic username */
        user = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_USER);
        if (!user || !strlen (user))
            user = nm_setting_vpn_get_user_name (s_vpn);
        if (!user || !strlen (user)) {
            g_dbus_method_invocation_return_error_literal (invocation,
                                                           NM_VPN_PLUGIN_ERROR,
                                                           NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                                                           _("Missing VPN username."));
            return FALSE;
        }
        password = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PASSWORD);
        if (!password || !strlen (password)) {
            g_dbus_method_invocation_return_error_literal (invocation,
                                                           NM_VPN_PLUGIN_ERROR,
                                                           NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                                                           _("Missing or invalid VPN password."));
            return FALSE;
        }

        /* Domain is optional */
        domain = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_DOMAIN);

        /* Success */
        if (domain && strlen (domain))
            username = g_strdup_printf ("%s\\%s", domain, user);
        else
            username = g_strdup (user);

        nmdbus_sstp_ppp_complete_need_secrets (object, invocation, username, password);
        g_free (username);

        return TRUE;
    }
    else {
        /* In case of certificates, the username is the certificate file */
        user = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_KEY);
        if (!user || !strlen (user)) {
            g_dbus_method_invocation_return_error_literal (invocation,
                                                           NM_VPN_PLUGIN_ERROR,
                                                           NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                                                           _("Missing VPN username."));
            return FALSE;
        }

        if (nm_utils_file_is_private_key(user, &is_encr)) {
            if (is_encr) {
                password = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_TLS_USER_KEY_SECRET);
                if (!password || !strlen (password)) {
                    g_dbus_method_invocation_return_error_literal (invocation,
                                                                   NM_VPN_PLUGIN_ERROR,
                                                                   NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                                                                   _("Missing or invalid VPN password."));
                    return FALSE;
                }
            } else {
                password = "";
            }
        }
        else {
            g_dbus_method_invocation_return_error_literal (invocation,
                                                           NM_VPN_PLUGIN_ERROR,
                                                           NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                                                           _("Invalid private key file"));
            return FALSE;
        }

        nmdbus_sstp_ppp_complete_need_secrets (object, invocation, user, password);
        return TRUE;
    }
}

static gboolean
handle_set_state (NMDBusSstpPpp *object,
                  GDBusMethodInvocation *invocation,
                  guint arg_state,
                  gpointer user_data)
{
    g_message("handle_set_state");
    remove_timeout_handler (NM_SSTP_PLUGIN (user_data));
    if (arg_state == NM_PPP_STATUS_DEAD || arg_state == NM_PPP_STATUS_DISCONNECT)
        nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (user_data), NULL);

    g_dbus_method_invocation_return_value (invocation, NULL);
    return TRUE;
}

static gboolean
handle_set_config (NMDBusSstpPpp *object,
                   GDBusMethodInvocation *invocation,
                   GVariant *arg_config,
                   gpointer user_data)
{
    NMSstpPlugin *plugin = NM_SSTP_PLUGIN (user_data);
    GVariantIter iter;
    const char *key;
    GVariant *value;
    GVariantBuilder builder;
    GVariant *new_config;

    remove_timeout_handler (plugin);
    g_message("handle_set_config");

    g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
    g_variant_iter_init (&iter, arg_config);
    while (g_variant_iter_next (&iter, "{&sv}", &key, &value)) {
        g_variant_builder_add (&builder, "{sv}", key, value);
        g_variant_unref (value);
    }
    new_config = g_variant_builder_end (&builder);
    g_variant_ref_sink (new_config);

    nm_vpn_service_plugin_set_config (NM_VPN_SERVICE_PLUGIN (plugin), new_config);
    g_variant_unref (new_config);

    g_dbus_method_invocation_return_value (invocation, NULL);
    return TRUE;
}

static gboolean
handle_set_ip4_config (NMDBusSstpPpp *object,
                       GDBusMethodInvocation *invocation,
                       GVariant *arg_config,
                       gpointer user_data)
{
    NMSstpPlugin *plugin = NM_SSTP_PLUGIN (user_data);
    GVariantIter iter;
    const char *key;
    GVariant *value;
    GVariantBuilder builder;
    GVariant *new_config;

    remove_timeout_handler (plugin);
    g_message("handle_set_ip4_config");

    g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
    g_variant_iter_init (&iter, arg_config);
    while (g_variant_iter_next (&iter, "{&sv}", &key, &value)) {
        g_variant_builder_add (&builder, "{sv}", key, value);
        g_variant_unref (value);
    }
    new_config = g_variant_builder_end (&builder);
    g_variant_ref_sink (new_config);

    nm_vpn_service_plugin_set_ip4_config (NM_VPN_SERVICE_PLUGIN (plugin), new_config);
    g_variant_unref (new_config);

    g_dbus_method_invocation_return_value (invocation, NULL);
    return TRUE;
}

static gboolean
handle_set_ip6_config (NMDBusSstpPpp *object,
                       GDBusMethodInvocation *invocation,
                       GVariant *arg_config,
                       gpointer user_data)
{
    NMSstpPlugin *plugin = NM_SSTP_PLUGIN (user_data);
    GVariantIter iter;
    const char *key;
    GVariant *value;
    GVariantBuilder builder;
    GVariant *new_config;

    remove_timeout_handler (plugin);
    g_message("handle_set_ipv6_config");

    g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
    g_variant_iter_init (&iter, arg_config);
    while (g_variant_iter_next (&iter, "{&sv}", &key, &value)) {
        g_variant_builder_add (&builder, "{sv}", key, value);
        g_variant_unref (value);
    }
    new_config = g_variant_builder_end (&builder);
    g_variant_ref_sink (new_config);

    nm_vpn_service_plugin_set_ip6_config (NM_VPN_SERVICE_PLUGIN (plugin), new_config);
    g_variant_unref (new_config);

    g_dbus_method_invocation_return_value (invocation, NULL);
    return TRUE;
}

static gboolean
real_connect (NMVpnServicePlugin   *plugin,
              NMConnection         *connection,
              GError              **error)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);
    NMSettingVpn *s_vpn;
    const char *gwaddr;
    const char *value;

    s_vpn = nm_connection_get_setting_vpn (connection);
    g_assert (s_vpn);

    gwaddr = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_GATEWAY);
    if (!gwaddr || !strlen (gwaddr)) {
        g_set_error_literal (error,
                             NM_VPN_PLUGIN_ERROR,
                             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
                             _("Invalid or missing SSTP gateway."));
        return FALSE;
    }

    /*  Set the UUID of the connection */
    value = nm_connection_get_uuid(connection);
    if (value && strlen(value)) {
        nm_setting_vpn_add_data_item(s_vpn, NM_SSTP_KEY_UUID, value);
    }

    if (!nm_sstp_properties_validate (s_vpn, error)) {
        return FALSE;
    }

    if (!nm_sstp_secrets_validate (s_vpn, error)) {
        return FALSE;
    }

    g_clear_object (&priv->connection);
    priv->connection = g_object_ref (connection);

    if (   getenv ("NM_PPP_DUMP_CONNECTION")
        || _LOGD_enabled ())
        nm_connection_dump (connection);

    return nm_sstp_start_pppd_binary (NM_SSTP_PLUGIN (plugin),
                                      s_vpn,
                                      gwaddr,
                                      error);
}

/*
 * Callback from NetworkManager having us check if we need secrets
 *
 * The auth-dialog is being displayed after we indicate it is needed.
 */
static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
    NMSettingVpn *s_vpn;
    NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
    const char *ctype, *key;
    gs_free char *key_free = NULL;
    gboolean encrypted = FALSE;

    g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
    g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

    if (   getenv ("NM_PPP_DUMP_CONNECTION")
        || _LOGD_enabled ()) {
        nm_connection_dump (connection);
    }

    s_vpn = nm_connection_get_setting_vpn (connection);
    if (!s_vpn) {
        g_set_error_literal (error,
                             NM_VPN_PLUGIN_ERROR,
                             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                             _("Could not process the request because the VPN connection settings were invalid."));
        return FALSE;
    }

    ctype = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_CONNECTION_TYPE);
    if (ctype == NULL || nm_streq0 (ctype, NM_SSTP_CONTYPE_PASSWORD)) {

        /* Don't need the password if we already have one */
        if (nm_setting_vpn_get_secret (NM_SETTING_VPN (s_vpn), NM_SSTP_KEY_PASSWORD))
            return FALSE;

        /* Don't need the password if it's not required */
        nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_SSTP_KEY_PASSWORD, &flags, NULL);
        if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
            return FALSE;

        *setting_name = NM_SETTING_VPN_SETTING_NAME;
        return TRUE;
    }
    else if (nm_streq0 (ctype, NM_SSTP_CONTYPE_TLS)) {

        /* The private key may require a password */
        key = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_KEY);
        key = nm_utils_str_utf8safe_unescape (key, &key_free);
        if (nm_utils_file_is_private_key (key, &encrypted) && encrypted &&
            !nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_TLS_USER_KEY_SECRET)) {

            *setting_name = NM_SETTING_VPN_SETTING_NAME;
            return TRUE;
        }
    }
    else {
        g_set_error_literal (error,
                             NM_VPN_PLUGIN_ERROR,
                             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                             _("Invalid connection type."));
        return FALSE;
    }

    /* Proxy might require a password; assume so if there's an proxy username */
    if (nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_SERVER) &&
        nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_USER)) {

        if (!nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PROXY_PASSWORD)) {
            *setting_name = NM_SETTING_VPN_SETTING_NAME;
            return TRUE;
        }
    }

    return FALSE;
}

static gboolean
ensure_killed (gpointer data)
{
    int pid = GPOINTER_TO_INT (data);

    if (kill (pid, 0) == 0)
        kill (pid, SIGKILL);

    return FALSE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **err)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);

    if (priv->pid) {
        if (kill (priv->pid, SIGTERM) == 0)
            g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
        else
            kill (priv->pid, SIGKILL);

        _LOGI ("Terminated ppp daemon with PID %d.", priv->pid);
        priv->pid = 0;
    }

    g_clear_object (&priv->connection);
    return TRUE;
}

static void
state_changed_cb (GObject *object, NMVpnServiceState state, gpointer user_data)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (object);

    switch (state) {
    case NM_VPN_SERVICE_STATE_STARTED:
        remove_timeout_handler (NM_SSTP_PLUGIN (object));
        break;
    case NM_VPN_SERVICE_STATE_UNKNOWN:
    case NM_VPN_SERVICE_STATE_INIT:
    case NM_VPN_SERVICE_STATE_SHUTDOWN:
    case NM_VPN_SERVICE_STATE_STOPPING:
    case NM_VPN_SERVICE_STATE_STOPPED:
        remove_timeout_handler (NM_SSTP_PLUGIN (object));
        g_clear_object (&priv->connection);
        break;
    default:
        break;
    }
}

static void
dispose (GObject *object)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (object);
    GDBusInterfaceSkeleton *skeleton = NULL;

    if (priv->dbus_skeleton)
        skeleton = G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton);

    if (skeleton) {
        if (g_dbus_interface_skeleton_get_object_path (skeleton))
            g_dbus_interface_skeleton_unexport (skeleton);
        g_signal_handlers_disconnect_by_func (skeleton, handle_need_secrets, object);
        g_signal_handlers_disconnect_by_func (skeleton, handle_set_state, object);
        g_signal_handlers_disconnect_by_func (skeleton, handle_set_config, object);
        g_signal_handlers_disconnect_by_func (skeleton, handle_set_ip4_config, object);
        g_signal_handlers_disconnect_by_func (skeleton, handle_set_ip6_config, object);
    }

    g_clear_object (&priv->connection);
    G_OBJECT_CLASS (nm_sstp_plugin_parent_class)->dispose (object);
}

static void
nm_sstp_plugin_init (NMSstpPlugin *plugin)
{
}

static void
nm_sstp_plugin_class_init (NMSstpPluginClass *sstp_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (sstp_class);
    NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (sstp_class);

    g_type_class_add_private (object_class, sizeof (NMSstpPluginPrivate));

    /* virtual methods */
    object_class->dispose = dispose;
    parent_class->connect = real_connect;
    parent_class->need_secrets = real_need_secrets;
    parent_class->disconnect = real_disconnect;
}

static GInitableIface *ginitable_parent_iface = NULL;

static gboolean
init_sync (GInitable *object, GCancellable *cancellable, GError **error)
{
    NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (object);
    GDBusConnection *bus;

    if (!ginitable_parent_iface->init (object, cancellable, error))
        return FALSE;

    g_signal_connect (G_OBJECT (object), "state-changed", G_CALLBACK (state_changed_cb), NULL);

    bus = nm_vpn_service_plugin_get_connection (NM_VPN_SERVICE_PLUGIN (object)),
    priv->dbus_skeleton = nmdbus_sstp_ppp_skeleton_new ();
    if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton),
                                           bus,
                                           NM_DBUS_PATH_SSTP_PPP,
                                           error)) {
        g_prefix_error (error, "Failed to export helper interface: ");
        g_object_unref (bus);
        return FALSE;
    }

    g_dbus_connection_register_object (bus, NM_DBUS_PATH_SSTP_PPP,
                                       nmdbus_sstp_ppp_interface_info (),
                                       NULL, NULL, NULL, NULL);

    g_signal_connect (priv->dbus_skeleton, "handle-need-secrets", G_CALLBACK (handle_need_secrets), object);
    g_signal_connect (priv->dbus_skeleton, "handle-set-state", G_CALLBACK (handle_set_state), object);
    g_signal_connect (priv->dbus_skeleton, "handle-set-config", G_CALLBACK (handle_set_config), object);
    g_signal_connect (priv->dbus_skeleton, "handle-set-ip4-config", G_CALLBACK (handle_set_ip4_config), object);
    g_signal_connect (priv->dbus_skeleton, "handle-set-ip6-config", G_CALLBACK (handle_set_ip6_config), object);

    g_object_unref (bus);
    return TRUE;
}

static void
nm_sstp_plugin_initable_iface_init (GInitableIface *iface)
{
    ginitable_parent_iface = g_type_interface_peek_parent (iface);
    iface->init = init_sync;
}

NMSstpPlugin *
nm_sstp_plugin_new (const char *bus_name)
{
    NMSstpPlugin *plugin;
    GError *error = NULL;

    plugin = g_initable_new (NM_TYPE_SSTP_PLUGIN, NULL, &error,
                             NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
                             NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
                             NULL);
    if (!plugin) {
        _LOGW ("Failed to initialize a plugin instance: %s", error->message);
        g_error_free (error);
    }

    return plugin;
}

static void
quit_mainloop (NMSstpPlugin *plugin, gpointer user_data)
{
    g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
    NMSstpPlugin *plugin;
    GMainLoop *main_loop;
    gboolean persist = FALSE;
    GOptionContext *opt_ctx = NULL;
    GError *error = NULL;
    gs_free char *bus_name_free = NULL;
    const char *bus_name;
    char sbuf[30];

    GOptionEntry options[] = {
        { "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
        { "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
        { "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name_free, N_("D-Bus name to use for this instance"), NULL },
        {NULL}
    };

    nm_g_type_init ();

    /* locale will be set according to environment LC_* variables */
    setlocale (LC_ALL, "");

    bindtextdomain (GETTEXT_PACKAGE, NM_SSTP_LOCALEDIR);
    bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
    textdomain (GETTEXT_PACKAGE);

    /* Parse options */
    opt_ctx = g_option_context_new (NULL);
    g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
    g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
    g_option_context_set_help_enabled (opt_ctx, TRUE);
    g_option_context_add_main_entries (opt_ctx, options, NULL);

    g_option_context_set_summary (opt_ctx,
        _("nm-sstp-service provides integrated SSTP VPN capability (compatible with Microsoft and other implementations) to NetworkManager."));

    if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
        g_printerr ("Error parsing the command line options: %s\n", error->message);
        g_option_context_free (opt_ctx);
        g_error_free (error);
        return EXIT_FAILURE;
    }
    g_option_context_free (opt_ctx);

    bus_name = bus_name_free ?: NM_DBUS_SERVICE_SSTP;

    if (getenv ("NM_PPP_DEBUG"))
        gl.debug = TRUE;

    gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
                                                 10, 0, LOG_DEBUG,
                                                 gl.debug ? LOG_INFO : LOG_NOTICE);

    _LOGD ("nm-sstp-service (version " DIST_VERSION ") starting...");
    _LOGD ("   uses%s --bus-name \"%s\"", bus_name_free ? "" : " default", bus_name);

    setenv ("NM_VPN_LOG_LEVEL", nm_sprintf_buf (sbuf, "%d", gl.log_level), TRUE);
    setenv ("NM_VPN_LOG_PREFIX_TOKEN", nm_sprintf_buf (sbuf, "%ld", (long) getpid ()), TRUE);
    setenv ("NM_DBUS_SERVICE_SSTP", bus_name, 0);

    plugin = nm_sstp_plugin_new (bus_name);
    if (!plugin)
        exit (EXIT_FAILURE);

    main_loop = g_main_loop_new (NULL, FALSE);

    if (!persist)
        g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), main_loop);

    g_main_loop_run (main_loop);

    g_main_loop_unref (main_loop);
    g_object_unref (plugin);

    return EXIT_SUCCESS;
}
