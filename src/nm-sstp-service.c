/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * (C) Copyright 2008 - 2014 Red Hat, Inc.
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

#include "nm-ppp-status.h"
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

	/* IP of SStP gateway in numeric and string format */
	guint32 naddr;
	char *saddr;
} NMSstpPluginPrivate;

#define NM_SSTP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSTP_PLUGIN, NMSstpPluginPrivate))

#define NM_SSTP_PPPD_PLUGIN PLUGINDIR "/nm-sstp-pppd-plugin.so"
#define NM_SSTP_WAIT_PPPD 10000 /* 10 seconds */
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
	{ NM_SSTP_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_SSTP_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_DOMAIN,            G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_CA_CERT,           G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_IGN_CERT_WARN,     G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_TLS_EXT_ENABLE,    G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REFUSE_EAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REFUSE_PAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REFUSE_CHAP,       G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REFUSE_MSCHAP,     G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REFUSE_MSCHAPV2,   G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REQUIRE_MPPE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REQUIRE_MPPE_40,   G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_REQUIRE_MPPE_128,  G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_MPPE_STATEFUL,     G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_NOBSDCOMP,         G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_NODEFLATE,         G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_NO_VJ_COMP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_SSTP_KEY_LCP_ECHO_FAILURE,  G_TYPE_UINT, FALSE },
	{ NM_SSTP_KEY_LCP_ECHO_INTERVAL, G_TYPE_UINT, FALSE },
	{ NM_SSTP_KEY_UNIT_NUM,          G_TYPE_UINT, FALSE },
	{ NM_SSTP_KEY_PASSWORD_FLAGS,    G_TYPE_UINT, FALSE },
	{ NM_SSTP_KEY_PROXY_SERVER,      G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_PROXY_PORT,        G_TYPE_UINT, FALSE },
	{ NM_SSTP_KEY_PROXY_USER,        G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_PROXY_PASSWORD_FLAGS, G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_UUID,              G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE, FALSE }
};

static const ValidProperty valid_secrets[] = {
	{ NM_SSTP_KEY_PASSWORD,          G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_PROXY_PASSWORD,    G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

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
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
	}

	return *error ? FALSE : TRUE;
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

static void
free_pppd_args (GPtrArray *args)
{
	int i;

	if (!args)
		return;

	for (i = 0; i < args->len; i++)
		g_free (g_ptr_array_index (args, i));
	g_ptr_array_free (args, TRUE);
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
	GPtrArray *args = NULL;
	const char *value, *sstp_binary;
	char *ipparam, *tmp, *ca_cert = NULL, *proxy = NULL, *uuid = NULL;
	const char *proxy_server, *proxy_port;
	gboolean ign_cert;
	gboolean tls_ext;


	/* Get the proxy settings */
	proxy_server = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_SERVER);
	proxy_port = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_PORT);
	if (proxy_server && proxy_port && strlen(proxy_server) && strlen(proxy_port)) {
		const char *proxy_user, *proxy_password;
		long int tmp_int;

		if (!str_to_int (proxy_port, &tmp_int))
			tmp_int = 0;

		proxy_user = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_USER);
		proxy_password = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PROXY_PASSWORD);

		proxy = g_strdup_printf("--proxy http://%s%s%s@%s:%ld",
		                        proxy_user,
		                        proxy_password ? ":" : "",
		                        proxy_password ?     : "",
		                        proxy_server,
		                        tmp_int);
	}

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
	g_ptr_array_add (args, (gpointer) g_strdup ("pty"));

	/* Get the CA Certificate (if any) */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_CA_CERT);
	if (value && strlen (value))
		ca_cert = g_strdup_printf ("--ca-cert %s", value);

	/*  Set the UUID of the connection */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_UUID);
	if (value && strlen(value))
		uuid = g_strdup_printf ("--uuid %s", value);

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

	/* Prepare the PTY option */
	ipparam = g_strdup_printf ("nm-sstp-service-%d", getpid ());
	tmp = g_strdup_printf ("%s %s %s %s --nolaunchpppd %s %s --ipparam %s %s %s",
						   sstp_binary, gwaddr,
						   ign_cert == TRUE ? "--cert-warn" : "",
						   tls_ext == TRUE ? "--tls-ext" : "",
						   gl.debug ? "--log-level 5" : "",
						   proxy ? proxy : "",
						   ipparam,
						   uuid ? uuid : "",
						   ca_cert ? ca_cert : ""
						   );

	g_ptr_array_add (args, (gpointer) tmp);
	if (ca_cert)
		g_free(ca_cert);
	if (uuid)
		g_free(uuid);

	/* Enable debug */
	if (_LOGD_enabled ())
		g_ptr_array_add (args, (gpointer) g_strdup ("debug"));

	/* PPP options */
	g_ptr_array_add (args, (gpointer) g_strdup ("noipv6"));
	g_ptr_array_add (args, (gpointer) g_strdup ("ipparam"));
	g_ptr_array_add (args, (gpointer) ipparam);

	g_ptr_array_add (args, (gpointer) g_strdup ("nodetach"));
	g_ptr_array_add (args, (gpointer) g_strdup ("lock"));
	g_ptr_array_add (args, (gpointer) g_strdup ("usepeerdns"));
	g_ptr_array_add (args, (gpointer) g_strdup ("noipdefault"));
	g_ptr_array_add (args, (gpointer) g_strdup ("nodefaultroute"));

	/* Don't need to auth the SSTP server */
	g_ptr_array_add (args, (gpointer) g_strdup ("noauth"));

	/* Username; try SSTP specific username first, then generic username */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_USER);
	if (!value || !*value)
		value = nm_setting_vpn_get_user_name (s_vpn);
	if (!value || !*value) {
 		g_ptr_array_add (args, (gpointer) g_strdup ("user"));
		g_ptr_array_add (args, (gpointer) g_strdup (value));
	}

	/* Allow EAP (currently not supported */
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
	free_pppd_args (args);
	return FALSE;
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

	if (!g_spawn_async (NULL, (char **) pppd_argv->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
		g_ptr_array_free (pppd_argv, TRUE);
		return FALSE;
	}
	free_pppd_args (pppd_argv);

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
	const char *user, *password, *domain;
	gchar *username;

	remove_timeout_handler (NM_SSTP_PLUGIN (user_data));

	s_vpn = nm_connection_get_setting_vpn (priv->connection);
	g_assert (s_vpn);

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
		return FALSE;;
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

static gboolean
handle_set_state (NMDBusSstpPpp *object,
                  GDBusMethodInvocation *invocation,
                  guint arg_state,
                  gpointer user_data)
{
	remove_timeout_handler (NM_SSTP_PLUGIN (user_data));
	if (arg_state == NM_PPP_STATUS_DEAD || arg_state == NM_PPP_STATUS_DISCONNECT)
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (user_data), NULL);

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
	NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);
	GVariantIter iter;
	const char *key;
	GVariant *value;
	GVariantBuilder builder;
	GVariant *new_config;

	remove_timeout_handler (plugin);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_iter_init (&iter, arg_config);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &value)) {
		g_variant_builder_add (&builder, "{sv}", key, value);
		g_variant_unref (value);
	}

	/* Insert the external VPN gateway into the table, which the pppd plugin
	 * simply doesn't know about.
	 */
	g_variant_builder_add (&builder, "{sv}", NM_SSTP_KEY_GATEWAY, g_variant_new_uint32 (priv->naddr));
	new_config = g_variant_builder_end (&builder);
	g_variant_ref_sink (new_config);

	nm_vpn_service_plugin_set_ip4_config (NM_VPN_SERVICE_PLUGIN (plugin), new_config);
	g_variant_unref (new_config);

	g_dbus_method_invocation_return_value (invocation, NULL);
	return TRUE;
}

#if 0
/* SSTP-NOTE:
 * We need to pass the real server ip/fqdn for sstpc to validate the server certificate
 *  though, the nm-sstp-pppd-plugin.c will use sstp-api to get the server adddress before ip-up.
 */
static gboolean
lookup_gateway (NMSstpPlugin *self,
                const char *src,
                GError **error)
{
	NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (self);
	const char *p = src;
	gboolean is_name = FALSE;
	struct in_addr naddr;
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int err;
	char buf[INET_ADDRSTRLEN];

	g_return_val_if_fail (src != NULL, FALSE);

	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

	while (*p) {
		if (*p != '.' && !isdigit (*p)) {
			is_name = TRUE;
			break;
		}
		p++;
	}

	if (is_name == FALSE) {
		errno = 0;
		if (inet_pton (AF_INET, src, &naddr) <= 0) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			             _("couldn't convert SSTP VPN gateway IP address “%s” (%d)"),
			             src, errno);
			return FALSE;
		}
		priv->naddr = naddr.s_addr;
		priv->saddr = g_strdup (src);
		return TRUE;
	}

	/* It's a hostname, resolve it */
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_ADDRCONFIG;
	err = getaddrinfo (src, NULL, &hints, &result);
	if (err != 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("couldn't look up SSTP VPN gateway IP address “%s” (%d)"),
		             src, err);
		return FALSE;
	}

	/* If the hostname resolves to multiple IP addresses, use the first one.
	 * FIXME: maybe we just want to use a random one instead?
	 */
	memset (&naddr, 0, sizeof (naddr));
	for (rp = result; rp; rp = rp->ai_next) {
		if (   (rp->ai_family == AF_INET)
		    && (rp->ai_addrlen == sizeof (struct sockaddr_in))) {
			struct sockaddr_in *inptr = (struct sockaddr_in *) rp->ai_addr;

			memcpy (&naddr, &(inptr->sin_addr), sizeof (struct in_addr));
			break;
		}
	}
	freeaddrinfo (result);

	if (naddr.s_addr == 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("no usable addresses returned for SSTP VPN gateway “%s”"),
		             src);
		return FALSE;
	}

	priv->naddr = naddr.s_addr;
	priv->saddr = g_strdup (inet_ntop (AF_INET, &naddr, buf, sizeof (buf)));

	return TRUE;
}
#endif

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
	if (value && strlen(value))
		nm_setting_vpn_add_data_item(s_vpn, NM_SSTP_KEY_UUID, value);


	/* SSTP-NOTE:
     * We need to pass the real server ip/fqdn for sstpc to validate the server certificate
     *  though, the nm-sstp-pppd-plugin.c will use sstp-api to get the server adddress before ip-up.
     *
     * Look up the IP address of the PPtP server; if the server has multiple
	 * addresses, because we can't get the actual IP used back from sstp itself,
	 * we need to do name->addr conversion here and only pass the IP address
	 * down to pppd/sstp.  If only sstp could somehow return the IP address it's
	 * using for the connection, we wouldn't need to do this...
     *
	if (!lookup_gateway (NM_SSTP_PLUGIN (plugin), gwaddr, error))
		return FALSE;
	 */


	if (!nm_sstp_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_sstp_secrets_validate (s_vpn, error))
		return FALSE;

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


static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);

	nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_SSTP_KEY_PASSWORD, &flags, NULL);

	/* Don't need the password if it's not required */
	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		return FALSE;

	/* Don't need the password if we already have one */
	if (nm_setting_vpn_get_secret (NM_SETTING_VPN (s_vpn), NM_SSTP_KEY_PASSWORD))
		return FALSE;

	/* Otherwise we need a password */
	*setting_name = NM_SETTING_VPN_SETTING_NAME;
	return TRUE;
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
	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

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
		if (priv->saddr) {
			g_free (priv->saddr);
			priv->saddr = NULL;
		}
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
		g_signal_handlers_disconnect_by_func (skeleton, handle_set_ip4_config, object);
	}

	g_clear_object (&priv->connection);
	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

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
	g_signal_connect (priv->dbus_skeleton, "handle-set-ip4-config", G_CALLBACK (handle_set_ip4_config), object);

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
