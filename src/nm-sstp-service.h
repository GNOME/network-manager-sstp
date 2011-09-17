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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef NM_SSTP_PLUGIN_H
#define NM_SSTP_PLUGIN_H

#include <glib.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_SSTP_MAX_BUFLEN             (255)
#define NM_TYPE_SSTP_PLUGIN            (nm_sstp_plugin_get_type ())
#define NM_SSTP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SSTP_PLUGIN, NMSstpPlugin))
#define NM_SSTP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SSTP_PLUGIN, NMSstpPluginClass))
#define NM_IS_SSTP_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SSTP_PLUGIN))
#define NM_IS_SSTP_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SSTP_PLUGIN))
#define NM_SSTP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SSTP_PLUGIN, NMSstpPluginClass))

/* For the pppd plugin <-> VPN plugin service */
#define DBUS_TYPE_G_MAP_OF_VARIANT (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))

#define NM_DBUS_SERVICE_SSTP_PPP    "org.freedesktop.NetworkManager.sstp-ppp"
#define NM_DBUS_PATH_SSTP_PPP       "/org/freedesktop/NetworkManager/sstp/ppp"
#define NM_DBUS_INTERFACE_SSTP_PPP  "org.freedesktop.NetworkManager.sstp.ppp"


/* For the NM <-> VPN plugin service */
#define NM_DBUS_SERVICE_SSTP    "org.freedesktop.NetworkManager.sstp"
#define NM_DBUS_INTERFACE_SSTP  "org.freedesktop.NetworkManager.sstp"
#define NM_DBUS_PATH_SSTP       "/org/freedesktop/NetworkManager/sstp"

#define NM_SSTP_KEY_GATEWAY           "gateway"
#define NM_SSTP_KEY_USER              "user"
#define NM_SSTP_KEY_PASSWORD          "password"
#define NM_SSTP_KEY_PASSWORD_FLAGS    "password-flags"
#define NM_SSTP_KEY_DOMAIN            "domain"
#define NM_SSTP_KEY_CA_CERT           "ca-cert"
#define NM_SSTP_KEY_REFUSE_EAP        "refuse-eap"
#define NM_SSTP_KEY_REFUSE_PAP        "refuse-pap"
#define NM_SSTP_KEY_REFUSE_CHAP       "refuse-chap"
#define NM_SSTP_KEY_REFUSE_MSCHAP     "refuse-mschap"
#define NM_SSTP_KEY_REFUSE_MSCHAPV2   "refuse-mschapv2"
#define NM_SSTP_KEY_REQUIRE_MPPE      "require-mppe"
#define NM_SSTP_KEY_REQUIRE_MPPE_40   "require-mppe-40"
#define NM_SSTP_KEY_REQUIRE_MPPE_128  "require-mppe-128"
#define NM_SSTP_KEY_MPPE_STATEFUL     "mppe-stateful"
#define NM_SSTP_KEY_NOBSDCOMP         "nobsdcomp"
#define NM_SSTP_KEY_NODEFLATE         "nodeflate"
#define NM_SSTP_KEY_NO_VJ_COMP        "no-vj-comp"
#define NM_SSTP_KEY_LCP_ECHO_FAILURE  "lcp-echo-failure"
#define NM_SSTP_KEY_LCP_ECHO_INTERVAL "lcp-echo-interval"


typedef struct {
	NMVPNPlugin parent;
} NMSstpPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMSstpPluginClass;

GType nm_sstp_plugin_get_type (void);

NMSstpPlugin *nm_sstp_plugin_new (void);

#endif /* NM_SSTP_PLUGIN_H */
