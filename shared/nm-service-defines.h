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

#ifndef __NM_SERVICE_DEFINES_H__
#define __NM_SERVICE_DEFINES_H__

#define NM_SSTP_MAX_BUFLEN                      (255)

#define NM_DBUS_SERVICE_SSTP                    "org.freedesktop.NetworkManager.sstp"

/* For the NM <-> VPN plugin service */
#define NM_DBUS_INTERFACE_SSTP                  "org.freedesktop.NetworkManager.sstp"
#define NM_DBUS_PATH_SSTP                       "/org/freedesktop/NetworkManager/sstp"

/* For the VPN plugin service <-> PPP plugin */
#define NM_DBUS_INTERFACE_SSTP_PPP              "org.freedesktop.NetworkManager.sstp.ppp"
#define NM_DBUS_PATH_SSTP_PPP                   "/org/freedesktop/NetworkManager/sstp/ppp"

#define NM_SSTP_KEY_GATEWAY                     "gateway"
#define NM_SSTP_KEY_UUID                        "uuid"
#define NM_SSTP_KEY_USER                        "user"
#define NM_SSTP_KEY_PASSWORD                    "password"
#define NM_SSTP_KEY_DOMAIN                      "domain"
#define NM_SSTP_KEY_CA_CERT                     "ca-cert"
#define NM_SSTP_KEY_CONNECTION_TYPE             "connection-type"
#define NM_SSTP_KEY_IGN_CERT_WARN               "ignore-cert-warn"
#define NM_SSTP_KEY_NOSECRET                    "no-secret"
#define NM_SSTP_KEY_REFUSE_EAP                  "refuse-eap"
#define NM_SSTP_KEY_REFUSE_PAP                  "refuse-pap"
#define NM_SSTP_KEY_REFUSE_CHAP                 "refuse-chap"
#define NM_SSTP_KEY_REFUSE_MSCHAP               "refuse-mschap"
#define NM_SSTP_KEY_REFUSE_MSCHAPV2             "refuse-mschapv2"
#define NM_SSTP_KEY_REQUIRE_MPPE                "require-mppe"
#define NM_SSTP_KEY_REQUIRE_MPPE_40             "require-mppe-40"
#define NM_SSTP_KEY_REQUIRE_MPPE_128            "require-mppe-128"
#define NM_SSTP_KEY_MPPE_STATEFUL               "mppe-stateful"
#define NM_SSTP_KEY_NOBSDCOMP                   "nobsdcomp"
#define NM_SSTP_KEY_NODEFLATE                   "nodeflate"
#define NM_SSTP_KEY_NO_VJ_COMP                  "no-vj-comp"
#define NM_SSTP_KEY_LCP_ECHO_FAILURE            "lcp-echo-failure"
#define NM_SSTP_KEY_LCP_ECHO_INTERVAL           "lcp-echo-interval"
#define NM_SSTP_KEY_UNIT_NUM                    "unit"
#define NM_SSTP_KEY_MTU                         "mtu"
#define NM_SSTP_KEY_PROXY_SERVER                "proxy-server"
#define NM_SSTP_KEY_PROXY_PORT                  "proxy-port"
#define NM_SSTP_KEY_PROXY_USER                  "proxy-user"
#define NM_SSTP_KEY_PROXY_PASSWORD              "proxy-password"
#define NM_SSTP_KEY_CRL_REVOCATION_FILE         "crl-file"

#define NM_SSTP_KEY_TLS_EXT_ENABLE              "tls-ext"
#define NM_SSTP_KEY_TLS_CA_CERT                 "tls-ca-cert"
#define NM_SSTP_KEY_TLS_IDENTITY                "tls-identity"
#define NM_SSTP_KEY_TLS_SUBJECT_NAME            "tls-subject-name"
#define NM_SSTP_KEY_TLS_USER_CERT               "tls-user-cert"
#define NM_SSTP_KEY_TLS_USER_KEY                "tls-user-key"
#define NM_SSTP_KEY_TLS_USER_KEY_SECRET         "tls-user-key-secret"
#define NM_SSTP_KEY_TLS_VERIFY_KEY_USAGE        "tls-verify-key-usage"
#define NM_SSTP_KEY_TLS_VERIFY_METHOD           "tls-verify-method"
#define NM_SSTP_KEY_TLS_REMOTENAME              "tls-remotename"
#define NM_SSTP_KEY_TLS_MAX_VERSION             "tls-max-version"

#define NM_SSTP_KEY_TLS_USER_KEY_SECRET_FLAGS   "tls-user-key-secret-flags"
#define NM_SSTP_KEY_PASSWORD_FLAGS              "password-flags"
#define NM_SSTP_KEY_PROXY_PASSWORD_FLAGS        "proxy-password-flags"

#define NM_SSTP_CONTYPE_PASSWORD                "password"
#define NM_SSTP_CONTYPE_TLS                     "tls"

#define NM_SSTP_VERIFY_MODE_NONE                "none"
#define NM_SSTP_VERIFY_MODE_SUBJECT             "subject"
#define NM_SSTP_VERIFY_MODE_NAME                "name"
#define NM_SSTP_VERIFY_MODE_NAME_SUFFIX         "suffix"

#define NM_SSTP_TLS_1_0_SUPPORT                 "1.0"
#define NM_SSTP_TLS_1_1_SUPPORT                 "1.1"
#define NM_SSTP_TLS_1_2_SUPPORT                 "1.2"
#define NM_SSTP_TLS_1_3_SUPPORT                 "1.3"


#endif /* __NM_SERVICE_DEFINES_H__ */
