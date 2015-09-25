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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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

#include <glib/gi18n.h>

//#include <nm-setting-vpn.h>
//#include <nm-utils.h>

#include "nm-sstp-service.h"
#include "nm-ppp-status.h"
#include "nm-sstp-pppd-service-dbus.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;

/********************************************************/
/* ppp plugin <-> sstp-service object                   */
/********************************************************/

/* We have a separate object to handle ppp plugin requests from
 * historical reason, because dbus-glib didn't allow multiple
 * interfaces registed on one GObject.
 *
 * Majority of the differences to nm-sstp-service from the pptp version here
 * are made to:
 *   - Add HTTP Proxy Settings
 *   - SSTP takes the FQDN, but will call back with the correct addresses as
 *     it resolved it.
 */

#define NM_TYPE_SSTP_PPP_SERVICE            (nm_sstp_ppp_service_get_type ())
#define NM_SSTP_PPP_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SSTP_PPP_SERVICE, NMSstpPppService))
#define NM_SSTP_PPP_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SSTP_PPP_SERVICE, NMSstpPppServiceClass))
#define NM_IS_SSTP_PPP_SERVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SSTP_PPP_SERVICE))
#define NM_IS_SSTP_PPP_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SSTP_PPP_SERVICE))
#define NM_SSTP_PPP_SERVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SSTP_PPP_SERVICE, NMSstpPppServiceClass))

typedef struct {
	GObject parent;
} NMSstpPppService;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*plugin_alive) (NMSstpPppService *self);
	void (*ppp_state) (NMSstpPppService *self, guint32 state);
	void (*ip4_config) (NMSstpPppService *self, GVariant *config);
} NMSstpPppServiceClass;

GType nm_sstp_ppp_service_get_type (void);

G_DEFINE_TYPE (NMSstpPppService, nm_sstp_ppp_service, G_TYPE_OBJECT)

static gboolean handle_need_secrets (NMDBusSstpPpp *object,
                                     GDBusMethodInvocation *invocation,
                                     gpointer user_data);

static gboolean handle_set_state (NMDBusSstpPpp *object,
                                  GDBusMethodInvocation *invocation,
                                  guint arg_state,
                                  gpointer user_data);

static gboolean handle_set_ip4_config (NMDBusSstpPpp *object,
                                       GDBusMethodInvocation *invocation,
                                       GVariant *arg_config,
                                       gpointer user_data);

#define NM_SSTP_PPP_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSTP_PPP_SERVICE, NMSstpPppServicePrivate))

typedef struct {
	char *server;       // Proxy Server
	char *username;     // Proxy User Name
	char *password;     // Proxy Password
	unsigned short port;// Proxy Port
} NMSstpPluginProxy;

typedef struct {
	char *username;
	char *domain;
	char *password;
	char *ca_cert;
	gboolean ign_cert;
	NMSstpPluginProxy proxy;
	NMDBusSstpPpp *dbus_skeleton;
} NMSstpPppServicePrivate;

enum {
	PLUGIN_ALIVE,
	PPP_STATE,
	IP4_CONFIG,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };
static gboolean str_to_int (const char *str, long int *out);

static gboolean
_service_cache_credentials (NMSstpPppService *self,
                            NMConnection *connection,
                            GError **error)
{
	NMSstpPppServicePrivate *priv = NM_SSTP_PPP_SERVICE_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *username, *password, *domain, *ca_cert, *server, *port, *temp;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not find secrets (connection invalid, no vpn setting)."));
		return FALSE;
	}

	/* Username; try SSTP specific username first, then generic username */
	username = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_USER);
	if (username && strlen (username)) {
		/* FIXME: This check makes about 0 sense. */
		if (!username || !strlen (username)) {
			g_set_error_literal (error,
			                     NM_VPN_PLUGIN_ERROR,
			                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
			                    _("Invalid VPN username."));
			return FALSE;
		}
	} else {
		username = nm_setting_vpn_get_user_name (s_vpn);
		if (!username || !strlen (username)) {
			g_set_error_literal (error,
			                     NM_VPN_PLUGIN_ERROR,
			                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
			                     _("Missing VPN username."));
			return FALSE;
		}
	}

	/* We need password */
	password = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PASSWORD);
	if (!password || !strlen (password)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Missing or invalid VPN password."));
		return FALSE;
	}

	/* CA Certificate is optional */
	ca_cert = nm_setting_vpn_get_data_item(s_vpn, NM_SSTP_KEY_CA_CERT);
	if (ca_cert && strlen (ca_cert))
		priv->ca_cert = g_strdup (ca_cert);

	/* Ignore any certificate warnings */
	temp = nm_setting_vpn_get_data_item(s_vpn, NM_SSTP_KEY_IGN_CERT_WARN);
	if (temp && !strcmp(temp, "yes")) {
		priv->ign_cert = TRUE;
	}

	/* Domain is optional */
	domain = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_DOMAIN);
	if (domain && strlen (domain))
		priv->domain = g_strdup (domain);
	
	/* Username and password */
	priv->username = g_strdup (username);
	priv->password = g_strdup (password);

	/* Get the proxy settings */
	server = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_SERVER);
	port   = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_PORT);
	if (server && port && strlen(server) && strlen(port))
	{
		long int tmp_int;
		
		if (!str_to_int (port, &tmp_int))
			tmp_int = 0;
		
		priv->proxy.server = g_strdup(server);
		priv->proxy.port   = tmp_int;
		
		temp = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_PROXY_USER);
		if (temp && strlen(temp))
			priv->proxy.username = g_strdup(temp);
		
		temp = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PROXY_PASSWORD);
		if (temp && strlen(temp))
			priv->proxy.password = g_strdup(temp);
	}

	return TRUE;
}

static NMSstpPppService *
nm_sstp_ppp_service_new (const char *gwaddr,
                         NMConnection *connection,
                         GError **error)
{

	NMSstpPppService *self = NULL;
	NMSstpPppServicePrivate *priv;
	GDBusConnection *bus;
	GDBusProxy *proxy;
	GVariant *ret;

	bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, error);
	if (!bus)
		return NULL;
	proxy = g_dbus_proxy_new_sync (bus,
				       G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
				       G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
				       NULL,
				       "org.freedesktop.DBus",
				       "/org/freedesktop/DBus",
				       "org.freedesktop.DBus",
				       NULL, error);
	g_assert (proxy);
	ret = g_dbus_proxy_call_sync (proxy,
				      "RequestName",
				      g_variant_new ("(su)", NM_DBUS_SERVICE_SSTP_PPP, 0),
				      G_DBUS_CALL_FLAGS_NONE, -1,
				      NULL, error);
	g_object_unref (proxy);
	if (!ret) {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		goto out;
	}
	g_variant_unref (ret);

	self = (NMSstpPppService *) g_object_new (NM_TYPE_SSTP_PPP_SERVICE, NULL);
	g_assert (self);
	priv = NM_SSTP_PPP_SERVICE_GET_PRIVATE (self);

	/* Cache the username and password so we can relay the secrets to the pppd
	 * plugin when it asks for them.
	 */
	if (!_service_cache_credentials (self, connection, error)) {
		g_object_unref (self);
		self = NULL;
		goto out;
	}

	priv->dbus_skeleton = nmdbus_sstp_ppp_skeleton_new ();
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton),
	                                       bus,
	                                       NM_DBUS_PATH_SSTP_PPP,
	                                       error))
		goto out;

	g_dbus_connection_register_object (bus, NM_DBUS_PATH_SSTP_PPP,
	                                   nmdbus_sstp_ppp_interface_info (),
	                                   NULL, NULL, NULL, NULL);

	g_signal_connect (priv->dbus_skeleton, "handle-need-secrets", G_CALLBACK (handle_need_secrets), self);
	g_signal_connect (priv->dbus_skeleton, "handle-set-state", G_CALLBACK (handle_set_state), self);
	g_signal_connect (priv->dbus_skeleton, "handle-set-ip4-config", G_CALLBACK (handle_set_ip4_config), self);

out:
	g_clear_object (&bus);
	return self;
}

static void
nm_sstp_ppp_service_init (NMSstpPppService *self)
{
}

static void
nm_sstp_ppp_service_dispose (GObject *object)
{
	NMSstpPppServicePrivate *priv = NM_SSTP_PPP_SERVICE_GET_PRIVATE (object);

	g_signal_handlers_disconnect_by_func (priv->dbus_skeleton, handle_need_secrets, object);
	g_signal_handlers_disconnect_by_func (priv->dbus_skeleton, handle_set_state, object);
	g_signal_handlers_disconnect_by_func (priv->dbus_skeleton, handle_set_ip4_config, object);

	G_OBJECT_CLASS (nm_sstp_ppp_service_parent_class)->dispose (object);
}

static void
nm_sstp_ppp_service_finalize (GObject *object)
{
	NMSstpPppServicePrivate *priv = NM_SSTP_PPP_SERVICE_GET_PRIVATE (object);

	/* Get rid of the cached username and password */
	g_free (priv->username);
	if (priv->password) {
		memset (priv->password, 0, strlen (priv->password));
		g_free (priv->password);
	}
	g_free (priv->domain);
	g_free (priv->ca_cert);

	if (priv->proxy.server)
		g_free (priv->proxy.server);
	
	if (priv->proxy.username)
		g_free (priv->proxy.username);
	
	if (priv->proxy.password) {
		memset (priv->proxy.password, 0, strlen(priv->proxy.password));
		g_free(priv->proxy.password);
	}

	G_OBJECT_CLASS (nm_sstp_ppp_service_parent_class)->finalize (object);
}

static void
nm_sstp_ppp_service_class_init (NMSstpPppServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NMSstpPppServicePrivate));

	/* virtual methods */
	object_class->dispose = nm_sstp_ppp_service_dispose;
	object_class->finalize = nm_sstp_ppp_service_finalize;

	/* Signals */
	signals[PLUGIN_ALIVE] = 
		g_signal_new ("plugin-alive", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMSstpPppServiceClass, plugin_alive),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[PPP_STATE] = 
		g_signal_new ("ppp-state", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMSstpPppServiceClass, ppp_state),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[IP4_CONFIG] = 
		g_signal_new ("ip4-config", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMSstpPppServiceClass, ip4_config),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static gboolean
handle_need_secrets (NMDBusSstpPpp *object,
                     GDBusMethodInvocation *invocation,
                     gpointer user_data)
{
	NMSstpPppService *self = NM_SSTP_PPP_SERVICE (user_data);
	NMSstpPppServicePrivate *priv = NM_SSTP_PPP_SERVICE_GET_PRIVATE (self);
	gchar *username;

	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	if (!strlen (priv->username) || !strlen (priv->password)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_VPN_PLUGIN_ERROR,
		                                               NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                                               _("No cached credentials."));
		return FALSE;;
	}

	/* Success */
	if (priv->domain && strlen (priv->domain))
		username = g_strdup_printf ("%s\\%s", priv->domain, priv->username);
	else
		username = g_strdup (priv->username);

	nmdbus_sstp_ppp_complete_need_secrets (object, invocation, username, priv->password);
	g_free (username);

	return TRUE;
}

static gboolean
handle_set_state (NMDBusSstpPpp *object,
                  GDBusMethodInvocation *invocation,
                  guint arg_state,
                  gpointer user_data)
{
	NMSstpPppService *self = NM_SSTP_PPP_SERVICE (user_data);

	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);
	g_signal_emit (G_OBJECT (self), signals[PPP_STATE], 0, arg_state);
	g_dbus_method_invocation_return_value (invocation, NULL);
	return TRUE;
}

static gboolean
handle_set_ip4_config (NMDBusSstpPpp *object,
                       GDBusMethodInvocation *invocation,
                       GVariant *arg_config,
                       gpointer user_data)
{
	NMSstpPppService *self = NM_SSTP_PPP_SERVICE (user_data);

	g_message ("SSTP service (IP Config Get) reply received.");
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	/* Just forward the pppd plugin config up to our superclass; no need to modify it */
	g_signal_emit (G_OBJECT (self), signals[IP4_CONFIG], 0, arg_config);

	return TRUE;
}


/********************************************************/
/* The VPN plugin service                               */
/********************************************************/

G_DEFINE_TYPE (NMSstpPlugin, nm_sstp_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

typedef struct {
	GPid pid;
	guint32 ppp_timeout_handler;
	NMSstpPppService *service;
	NMConnection *connection;
} NMSstpPluginPrivate;

#define NM_SSTP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSTP_PLUGIN, NMSstpPluginPrivate))

#define NM_SSTP_PPPD_PLUGIN PLUGINDIR "/nm-sstp-pppd-plugin.so"
#define NM_SSTP_WAIT_PPPD 10000 /* 10 seconds */
#define SSTP_SERVICE_SECRET_TRIES "sstp-service-secret-tries"

typedef struct {
	const char *name;
	GType type;
	gboolean required;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_SSTP_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_SSTP_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_DOMAIN,            G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_CA_CERT,           G_TYPE_STRING, FALSE },
	{ NM_SSTP_KEY_IGN_CERT_WARN,     G_TYPE_BOOLEAN, FALSE },
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

static ValidProperty valid_secrets[] = {
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
	ValidProperty *table;
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
		ValidProperty prop = info->table[i];
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
				             _("invalid gateway '%s'"),
				             value);
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
			             _("invalid integer property '%s'"),
			             key);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid boolean property '%s' (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property '%s' type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property '%s' invalid or not supported"),
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
		ValidProperty prop = valid_properties[i];
		const char *value;

		if (!prop.required)
			continue;

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value || !strlen (value)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Missing required option '%s'."),
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
			g_warning ("pppd exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		g_warning ("pppd stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning ("pppd died with signal %d", WTERMSIG (status));
	else
		g_warning ("pppd died from an unknown cause");

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

	g_warning ("Looks like pppd didn't initialize our dbus module");
	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);

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
	NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);
	NMSstpPppServicePrivate *service_priv = NULL;
	GPtrArray *args = NULL;
	const char *value, *sstp_binary;
	char *ipparam, *tmp, *ca_cert = NULL, *proxy = NULL, *uuid = NULL;

	if (priv->service)
		service_priv = NM_SSTP_PPP_SERVICE_GET_PRIVATE (priv->service);

	if (service_priv) {
		if (service_priv->proxy.server && service_priv->proxy.port != 0) {
			proxy = g_strdup_printf("--proxy http://%s%s%s@%s:%d",
									service_priv->proxy.username,
									service_priv->proxy.password ? ":" : "",
									service_priv->proxy.password ?     : "",
									service_priv->proxy.server,
									service_priv->proxy.port);
		}
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
	
	/* Prepare the PTY option */
	ipparam = g_strdup_printf ("nm-sstp-service-%d", getpid ());
	tmp = g_strdup_printf ("%s %s %s --nolaunchpppd %s %s --ipparam %s %s %s",
						   sstp_binary, gwaddr,
						   service_priv->ign_cert == TRUE ? "--cert-warn" : "",
						   debug ? "--log-level 4" : "",
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
	if (debug)
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

	/* Set the username */
	if (service_priv && strlen (service_priv->username)) {
		g_ptr_array_add (args, (gpointer) g_strdup ("user"));
		g_ptr_array_add (args, (gpointer) g_strdup (service_priv->username));
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
			g_warning ("failed to convert lcp-echo-failure value '%s'", value);
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
			g_warning ("failed to convert lcp-echo-interval value '%s'", value);
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
			g_warning ("failed to convert unit value '%s'", value);
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

	g_message ("pppd started with pid %d", pid);

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

static void
service_plugin_alive_cb (NMSstpPppService *service,
                         NMSstpPlugin *plugin)
{
	remove_timeout_handler (plugin);
}

static void
service_ppp_state_cb (NMSstpPppService *service,
                      guint32 ppp_state,
                      NMSstpPlugin *plugin)
{
	if (ppp_state == NM_PPP_STATUS_DEAD || ppp_state == NM_PPP_STATUS_DISCONNECT)
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
}

static void
service_ip4_config_cb (NMSstpPppService *service,
                       GVariant *config,
                       NMVpnServicePlugin *plugin)
{
	nm_vpn_service_plugin_set_ip4_config (plugin, config);
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
	if (value && strlen(value))
		nm_setting_vpn_add_data_item(s_vpn, NM_SSTP_KEY_UUID, value);

	if (!nm_sstp_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_sstp_secrets_validate (s_vpn, error))
		return FALSE;

	/* Start our pppd plugin helper service */
	if (priv->service)
		g_object_unref (priv->service);
	if (priv->connection) {
		g_object_unref (priv->connection);
		priv->connection = NULL;
	}

	/* Start our helper D-Bus service that the pppd plugin sends state changes to */
	priv->service = nm_sstp_ppp_service_new (gwaddr, connection, error);
	if (!priv->service)
		return FALSE;

	priv->connection = g_object_ref (connection);

	g_signal_connect (G_OBJECT (priv->service), "plugin-alive", G_CALLBACK (service_plugin_alive_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ppp-state", G_CALLBACK (service_ppp_state_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ip4-config", G_CALLBACK (service_ip4_config_cb), plugin);

	if (getenv ("NM_PPP_DUMP_CONNECTION") || debug)
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
real_disconnect (NMVpnServicePlugin   *plugin,
                 GError              **err)
{
	NMSstpPluginPrivate *priv = NM_SSTP_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		g_message ("Terminated ppp daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	if (priv->connection) {
		g_object_unref (priv->connection);
		priv->connection = NULL;
	}

	if (priv->service) {
		g_object_unref (priv->service);
		priv->service = NULL;
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
		if (priv->connection) {
			g_object_unref (priv->connection);
			priv->connection = NULL;
		}
		if (priv->service) {
			g_object_unref (priv->service);
			priv->service = NULL;
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

	if (priv->connection)
		g_object_unref (priv->connection);

	if (priv->service)
		g_object_unref (priv->service);

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

NMSstpPlugin *
nm_sstp_plugin_new (void)
{
	NMSstpPlugin *plugin;
	GError *error = NULL;

	plugin = (NMSstpPlugin *) g_initable_new (NM_TYPE_SSTP_PLUGIN, NULL, &error,
	                                          NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME,
	                                          NM_DBUS_SERVICE_SSTP,
	                                          NULL);
	if (plugin) {
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (state_changed_cb), NULL);
	} else {
		g_warning ("Failed to initialize a plugin instance: %s", error->message);
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

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

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

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("NM_PPP_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("nm-sstp-service (version " DIST_VERSION ") starting...");

	plugin = nm_sstp_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
