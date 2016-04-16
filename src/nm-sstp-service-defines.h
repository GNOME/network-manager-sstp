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
 * Copyright 2008, 2014 Red Hat, Inc.
 */

#ifndef NM_SSTP_SERVICE_DEFINES_H
#define NM_SSTP_SERVICE_DEFINES_H

#define NM_SSTP_MAX_BUFLEN             (255)

#define NM_DBUS_SERVICE_SSTP_PPP    "org.freedesktop.NetworkManager.sstp-ppp"
#define NM_DBUS_PATH_SSTP_PPP       "/org/freedesktop/NetworkManager/sstp/ppp"
#define NM_DBUS_INTERFACE_SSTP_PPP  "org.freedesktop.NetworkManager.sstp.ppp"

/* For the NM <-> VPN plugin service */
#define NM_DBUS_SERVICE_SSTP    "org.freedesktop.NetworkManager.sstp"
#define NM_DBUS_INTERFACE_SSTP  "org.freedesktop.NetworkManager.sstp"
#define NM_DBUS_PATH_SSTP       "/org/freedesktop/NetworkManager/sstp"

#define NM_SSTP_KEY_GATEWAY           "gateway"
#define NM_SSTP_KEY_UUID              "uuid"
#define NM_SSTP_KEY_USER              "user"
#define NM_SSTP_KEY_PASSWORD          "password"
#define NM_SSTP_KEY_PASSWORD_FLAGS    "password-flags"
#define NM_SSTP_KEY_DOMAIN            "domain"
#define NM_SSTP_KEY_CA_CERT           "ca-cert"
#define NM_SSTP_KEY_IGN_CERT_WARN     "ignore-cert-warn"
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
#define NM_SSTP_KEY_UNIT_NUM          "unit"
#define NM_SSTP_KEY_PROXY_SERVER      "proxy-server"
#define NM_SSTP_KEY_PROXY_PORT        "proxy-port"
#define NM_SSTP_KEY_PROXY_USER        "proxy-user"
#define NM_SSTP_KEY_PROXY_PASSWORD    "proxy-password"
#define NM_SSTP_KEY_PROXY_PASSWORD_FLAGS "proxy-password-flags"

// TODO: We need to eliminate the password-flags and proxy-password-flags

#endif /* NM_SSTP_SERVICE_DEFINES_H */
