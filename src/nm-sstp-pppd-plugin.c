/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-sstp-service - sstp (and other pppd) integration with NetworkManager
 *
 * (C) 2007 - 2008 Novell, Inc.
 * (C) 2008 - 2009 Red Hat, Inc.
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
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/un.h>
#include <paths.h>
#include <unistd.h>

#include <sstp-client/sstp-api.h>

#include "nm-sstp-pppd-compat.h"
#include "nm-sstp-pppd-status.h"
#include "nm-sstp-pppd-mppe.h"

#include "nm-default.h"
#include "nm-sstp-service.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#ifndef USE_PPPD_AUTH_HOOK
static int sstp_notify_sent = 0;
#endif  /* USE_PPPD_AUTH_HOOK */

int plugin_init (void);


char pppd_version[] = PPPD_VERSION;

/*****************************************************************************/
typedef void (*protrej_fn)(int unit);

struct {
    int log_level;
    const char *log_prefix_token;
    GDBusProxy *proxy;
    bool is_ip_up;
    bool is_ip6_up;
    bool is_ip6_rej;
    protrej_fn old_protrej;
} gl/*lobal*/;

/*****************************************************************************/

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (gl.log_level >= (level)) { \
             syslog (nm_utils_syslog_coerce_from_nm (level), \
                     "nm-sstp[%s] %-7s [helper-%ld] " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                     gl.log_prefix_token, \
                     nm_utils_syslog_to_str (level), \
                     (long) getpid () \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)
#define _LOGE(...) _NMLOG(LOG_ERR, __VA_ARGS__)

/*****************************************************************************/

/**
 * Notify Network Manager of phase changes
 */
static void
nm_phasechange (void *data, int arg)
{
    NMPPPStatus ppp_status = NM_PPP_STATUS_UNKNOWN;
    char *ppp_phase;

    g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));
    switch (arg) {
    case PHASE_DEAD:
        ppp_status = NM_PPP_STATUS_DEAD;
        ppp_phase = "dead";
        break;
    case PHASE_INITIALIZE:
        ppp_status = NM_PPP_STATUS_INITIALIZE;
        ppp_phase = "initialize";
        break;
    case PHASE_SERIALCONN:
        ppp_status = NM_PPP_STATUS_SERIALCONN;
        ppp_phase = "serial connection";
        break;
    case PHASE_DORMANT:
        ppp_status = NM_PPP_STATUS_DORMANT;
        ppp_phase = "dormant";
        break;
    case PHASE_ESTABLISH:
        ppp_status = NM_PPP_STATUS_ESTABLISH;
        ppp_phase = "establish";
        break;
    case PHASE_AUTHENTICATE:
        ppp_status = NM_PPP_STATUS_AUTHENTICATE;
        ppp_phase = "authenticate";
        break;
    case PHASE_CALLBACK:
        ppp_status = NM_PPP_STATUS_CALLBACK;
        ppp_phase = "callback";
        break;
    case PHASE_NETWORK:
        ppp_status = NM_PPP_STATUS_NETWORK;
        ppp_phase = "network";
        break;
    case PHASE_RUNNING:
        ppp_status = NM_PPP_STATUS_RUNNING;
        ppp_phase = "running";
        break;
    case PHASE_TERMINATE:
        ppp_status = NM_PPP_STATUS_TERMINATE;
        ppp_phase = "terminate";
        break;
    case PHASE_DISCONNECT:
        ppp_status = NM_PPP_STATUS_DISCONNECT;
        ppp_phase = "disconnect";
        break;
    case PHASE_HOLDOFF:
        ppp_status = NM_PPP_STATUS_HOLDOFF;
        ppp_phase = "holdoff";
        break;
    case PHASE_MASTER:
        ppp_status = NM_PPP_STATUS_MASTER;
        ppp_phase = "master";
        break;

    default:
        ppp_phase = "unknown";
        break;
    }

    _LOGI ("phasechange: status %d / phase '%s'",
           ppp_status, ppp_phase);

    if (ppp_status != NM_PPP_STATUS_UNKNOWN) {
        g_dbus_proxy_call (gl.proxy,
                           "SetState",
                           g_variant_new ("(u)", ppp_status),
                           G_DBUS_CALL_FLAGS_NONE, -1,
                               NULL,
                               NULL, NULL);
    }
}

/**
 * Create the socket that is used to communicate with SSTPC
 */
static int
nm_sstp_getsock(void)
{
    struct sockaddr_un addr;
    int retval = (-1);
    int sock   = (-1);
    int ret    = (-1);
    int alen   = (sizeof(addr));

    /* Open the socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        _LOGE ("sstp-plugin: could not create a socket to sstpc");
        goto done;
    }

    /* Setup the address */
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/var/run/sstpc/sstpc-%s", ppp_ipparam());

    /* Connect the socket */
    ret = connect(sock, (struct sockaddr*) &addr, alen);
    if (ret < 0) {
        _LOGE ("sstp-plugin: Could not connect to sstpc (%s), %m", addr.sun_path);
        goto done;
    }

    /* Sucess */
    retval = sock;

done:

    if (retval <= 0) {
        close(sock);
    }

    return retval;
}

/**
 * Extract the address SSTPC resolved as the hostname
 */
static int
nm_sstp_getaddr(struct sockaddr_storage *addr)
{
    char *buff = NULL;
    int retval = (-1);
    int sock   = (-1);
    int ret    = (-1);
    int cnt    = (SSTP_API_ATTR_MAX+1);
    char name[255] = {};
    char ipstr[NM_INET_ADDRSTRLEN];
    sstp_api_msg_st msg;
    sstp_api_msg_t  type;
    sstp_api_attr_st *attr;
    sstp_api_attr_st *list[SSTP_API_ATTR_MAX+1];

    /* Get the sstpc socket */
    sock = nm_sstp_getsock();
    if (sock <= 0) {
        goto done;
    }

    /* Create an address request */
    sstp_api_msg_new((unsigned char*)&msg, SSTP_API_MSG_ADDR);

    /* Send the request */
    ret = send(sock, &msg, sizeof(msg), 0);
    if (ret < 0) {
        _LOGE ("sstp-plugin: Could not send data to sstpc");
        goto done;
    }

    /* Wait for the ACK to be received */
    ret = recv(sock, &msg, (sizeof(msg)), 0);
    if (ret < 0 || ret != (sizeof(msg))) {
        _LOGE ("sstp-plugin: Failed to receive ack from sstpc");
        goto done;
    }

    /* Validate message header */
    if (sstp_api_msg_type(&msg, &type) &&
        SSTP_API_MSG_ACK != type) {
        _LOGE ("sstp-plugin: Received invalid response from sstpc");
        goto done;
    }

    /* Allocate memory for response */
    buff = alloca(msg.msg_len);
    if (!buff) {
        _LOGE ("sstp-plugin: Could not allocate space for response");
        goto done;
    }

    /* Read the remainder of the payload */
    ret = read(sock, buff, msg.msg_len);
    if (ret < 0 || ret != msg.msg_len) {
        _LOGE ("sstp-plugin: Could not read the response");
        goto done;
    }

    /* Parse the Attributes */
    ret = sstp_api_attr_parse(buff, msg.msg_len, list, cnt);
    if (ret != 0) {
        _LOGE ("sstp-plugin: Could not parse attributes");
        goto done;
    }

    /* Get the address */
    attr = list[SSTP_API_ATTR_ADDR];
    if (!attr) {
        _LOGE ("sstp-plugin: Could not get resolved address");
        goto done;
    }

    /* Copy the result to the output argument */
    memcpy(addr, attr->attr_data, MIN(attr->attr_len, sizeof(*addr)));
    switch (addr->ss_family)
    {
        case AF_INET:
            nm_utils_inet4_ntop(((struct sockaddr_in*)addr)->sin_addr.s_addr, ipstr);
            break;
        case AF_INET6:
            nm_utils_inet6_ntop(&((struct sockaddr_in6*)addr)->sin6_addr, ipstr);
            break;
    }

    /* Get the gateway name */
    attr = list[SSTP_API_ATTR_GATEWAY];
    if (!attr) {
        _LOGE ("sstp-plugin: Could not get resolved name");
        goto done;
    }

    /* Copy the name */
    memcpy(name, attr->attr_data, attr->attr_len);

    _LOGI ("sstp-plugin: sstpc is connected to %s using %s",
           name, ipstr);

    /* Success */
    retval = 0;

done:

    /* Close socket */
    if (sock > 0) {
        close(sock);
    }

    return retval;
}

/**
 * Notify SSTPC of the MPPE keys
 */
static int
nm_sstp_notify(void)
{
    int ret    = (-1);
    int sock   = (-1);
    int retval = (-1);
    uint8_t buf[NM_SSTP_MAX_BUFLEN+1] = {};
    sstp_api_msg_st  *msg  = NULL;
    unsigned char key[32];
    char key_buf[255];
    int key_len;

    /* Get the sstpc socket */
    sock = nm_sstp_getsock();
    if (sock <= 0) {
        goto done;
    }

    /* Create a new message */
    msg = sstp_api_msg_new((unsigned char*) buf, SSTP_API_MSG_AUTH);
    if (!msg) {
        _LOGE ("sstp-plugin: Could not create message to sstpc");
        goto done;
    }

    /* Add the attributes for the MPPE keys */
    if (mppe_keys_isset()) {

        /* Add the MPPE Send Key */
        key_len = mppe_get_send_key(key, sizeof(key));
        if (key_len > 0) {

            sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_SEND, key_len, key);
            if (debug_on()) {
                slprintf(key_buf, sizeof(key_buf)-1, "%0.*B", key_len, key);
                _LOGI ("The MPPE-Send-Key: %s", key);
            }
        }

        /* Add the MPPE Recv Key */
        key_len = mppe_get_recv_key(key, sizeof(key));
        if (key_len > 0) {

            sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_RECV, key_len, key);
            if (debug_on()) {
                slprintf(key_buf, sizeof(key_buf)-1, "%0.*B", key_len, key);
                _LOGI ("The MPPE-Recv-Key: %s", key);
            }
        }
    }

    /* Send the structure */
    ret = send(sock, msg, sstp_api_msg_len(msg), 0);
    if (ret < 0) {
        _LOGE ("sstp-plugin: Could not send data to sstpc");
        goto done;
    }

    /* Wait for the ACK to be received */
    ret = recv(sock, msg, (sizeof(*msg)), 0);
    if (ret <= 0 || ret != (sizeof(*msg))) {
        _LOGE ("sstp-plugin: Could not wait for ack from sstpc (%d)", ret);
        goto done;
    }

    /* Sent credentials to sstpc */
    _LOGI ("sstp-plugin: Shared authentication details with sstpc");
#ifndef USE_PPPD_AUTH_HOOK
    sstp_notify_sent = 1;
#endif

    /* Success */
    retval = 0;

done:

    /* Close socket */
    if (sock > 0) {
        close(sock);
    }

    return retval;
}

static GVariant* nm_ip6_get_params(void)
{
    GVariantBuilder builder;
    ipv6cp_options *opts = &ipv6cp_gotoptions[0];
    ipv6cp_options *peer_opts = &ipv6cp_hisoptions[0];
    struct in6_addr addr;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    if (gl.is_ip6_rej || eui64_iszero(opts->ourid) || eui64_iszero(peer_opts->hisid)) {
        _LOGI ("No IPv6 addresses negotiated");
        return g_variant_builder_end (&builder);
    }
    if (eui64_equals(opts->ourid, peer_opts->hisid)) {
        _LOGI ("Local and remote addresses are equal");
        return g_variant_builder_end (&builder);
    }

    eui64_copy(addr.s6_addr32[2], opts->ourid);
    g_variant_builder_add (&builder, "{sv}",
                           NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS,
                           g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &addr, 16, 1));

    eui64_copy(addr.s6_addr32[2], peer_opts->hisid);
    g_variant_builder_add (&builder, "{sv}",
                           NM_VPN_PLUGIN_IP6_CONFIG_PTP,
                           g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &addr, 16, 1));

    // IPv6 DNS and DOMAIN is not supported
    // IPv6 WINS is not supported

    return g_variant_builder_end (&builder);
}

static void
nm_ip4_add_route(GVariantBuilder *builder, int network, int gateway, int prefix, int metric) 
{
    GVariantBuilder route;
    g_variant_builder_init (&route, G_VARIANT_TYPE ("au"));
    g_variant_builder_add_value (&route, g_variant_new_uint32 (network));
    g_variant_builder_add_value (&route, g_variant_new_uint32 (prefix));
    g_variant_builder_add_value (&route, g_variant_new_uint32 (gateway));
    g_variant_builder_add_value (&route, g_variant_new_uint32 (metric));
    g_variant_builder_add_value (builder, g_variant_builder_end (&route));
}

static GVariant*
nm_ip4_get_params(void)
{
    guint32 pppd_made_up_address = htonl (0x0a404040 + ppp_ifunit());
    ipcp_options *opts = &ipcp_gotoptions[0];
    ipcp_options *peer_opts = &ipcp_hisoptions[0];
    GVariantBuilder builder;
    GVariantBuilder array;
    GVariant *routes;
    guint32 gateway = 0;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    if (opts->ouraddr != 0) {

        g_variant_builder_add (&builder, "{sv}",
                               NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
                               g_variant_new_uint32 (opts->ouraddr));

        g_variant_builder_add (&builder, "{sv}",
                               NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
                               g_variant_new_uint32 (32));

        /* Prefer the peer options remote address first, _unless_ pppd made the
         * address up, at which point prefer the local options remote address,
         * and if that's not right, use the made-up address as a last resort.
         */
        if (peer_opts->hisaddr && (peer_opts->hisaddr != pppd_made_up_address)) {
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_PTP,
                                   g_variant_new_uint32 (peer_opts->hisaddr));
            gateway = peer_opts->hisaddr;
        } else if (opts->hisaddr) {
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_PTP,
                                   g_variant_new_uint32 (opts->hisaddr));
            gateway = peer_opts->hisaddr;
        } else if (peer_opts->hisaddr == pppd_made_up_address) {
            /* As a last resort, use the made-up address */
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_PTP,
                                   g_variant_new_uint32 (peer_opts->ouraddr));
        }

        g_variant_builder_init (&array, G_VARIANT_TYPE ("aau"));

        /* DNS Servers */
        if (opts->dnsaddr[0] || opts->dnsaddr[1]) {
            guint32 dns[2];
            int len = 0;

            if (opts->dnsaddr[0]) {
                dns[len++] = opts->dnsaddr[0];
                nm_ip4_add_route (&array, opts->dnsaddr[0], gateway, 32, 0);
            }
            if (opts->dnsaddr[1]) {
                dns[len++] = opts->dnsaddr[1];
                nm_ip4_add_route (&array, opts->dnsaddr[0], gateway, 32, 0);
            }

            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_DNS,
                                   g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
                                                              dns, len, sizeof (guint32)));
        }

        /* NetBIOS or WINS server if configured */
        if (opts->winsaddr[0] || opts->winsaddr[1]) {
            guint32 wins[2];
            int len = 0;

            if (opts->winsaddr[0]) {
                wins[len++] = opts->winsaddr[0];
                nm_ip4_add_route (&array, opts->dnsaddr[0], gateway, 32, 0);
            }
            if (opts->winsaddr[1]) {
                wins[len++] = opts->winsaddr[1];
                nm_ip4_add_route (&array, opts->dnsaddr[0], gateway, 32, 0);
            }

            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_NBNS,
                                   g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
                                                              wins, len, sizeof (guint32)));
        }

        routes = g_variant_builder_end (&array);
        if (g_variant_n_children (routes)) {
            g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, routes);
        }
        else {
            g_variant_unref (routes);
            routes = NULL;
        }
    }

    return g_variant_builder_end(&builder);
}

/**
 * Process the ip-up event, and notify Network Manager
 */
static void
nm_send_config (void)
{
    GVariantBuilder builder;
    GVariant *ip4config = NULL, *ip6config = NULL;
    struct sockaddr_storage addr;
    int mtu;

    g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add (&builder, "{sv}",
                           NM_VPN_PLUGIN_CONFIG_TUNDEV,
                           g_variant_new_string (ppp_ifname()));

    mtu = ppp_get_mtu (ppp_ifunit());
    g_variant_builder_add (&builder, "{sv}",
                           NM_VPN_PLUGIN_CONFIG_MTU,
                            g_variant_new_uint32 (mtu));

    /* Request the address of the server sstpc connected to */
    if (0 == nm_sstp_getaddr(&addr)) {

        if (addr.ss_family == AF_INET) {
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY,
                                   g_variant_new_uint32 (((struct sockaddr_in*)&addr)->sin_addr.s_addr));
        }
        if (addr.ss_family == AF_INET6) {
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY,
                                   g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &((struct sockaddr_in6*)&addr)->sin6_addr, 16, 1));
        }
    }

    ip4config = nm_ip4_get_params();
    if (g_variant_n_children (ip4config)) {
        g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4,
                g_variant_new_boolean (TRUE));
    }
    else {
        g_variant_unref (ip4config);
        ip4config = NULL;
    }

    ip6config = nm_ip6_get_params();
    if (g_variant_n_children (ip6config)) {
        g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP6,
                g_variant_new_boolean (TRUE));
    }
    else {
        g_variant_unref (ip6config);
        ip6config = NULL;
    }

    _LOGI ("Sending Config to NetworkManager-sstp...");
    g_dbus_proxy_call (gl.proxy,
                       "SetConfig",
                       g_variant_new ("(*)", g_variant_builder_end (&builder)),
                       G_DBUS_CALL_FLAGS_NONE, -1,
                       NULL,
                       NULL, NULL);

    if (ip4config) {
        _LOGI ("Sending IP4Config to NetworkManager-sstp...");
        g_dbus_proxy_call (gl.proxy,
                           "SetIp4Config",
                           g_variant_new ("(*)", ip4config),
                           G_DBUS_CALL_FLAGS_NONE, -1,
                           NULL,
                           NULL, NULL);
    }

    if (ip6config) {
        _LOGI ("Sending IP6Config to NetworkManager-sstp...");
        g_dbus_proxy_call (gl.proxy,
                           "SetIp6Config",
                           g_variant_new ("(*)", ip6config),
                           G_DBUS_CALL_FLAGS_NONE, -1,
                           NULL, NULL, NULL);
    }
}

/**
 * Check if we have CHAP password (we always do)
 */
static int
nm_get_chap_check (void)
{
    return 1;
}

/**
 * Check if we have a PAP password (we always do)
 */
static int
nm_get_pap_check (void)
{
    return 1;
}

/**
 * Invoke Network Manager to extract the secret saved for this connection
 */
static int
nm_get_credentials (char *username, char *password)
{
    const char *my_username = NULL;
    const char *my_password = NULL;
    GVariant *ret;
    GError *error = NULL;

    if (!password) {
        /* pppd is checking pap support; return 1 for supported */
        g_return_val_if_fail (username, -1);
        return 1;
    }

    g_return_val_if_fail (username, -1);
    g_return_val_if_fail (G_IS_DBUS_PROXY (gl.proxy), -1);

    _LOGI ("passwd-hook: requesting credentials...");

    ret = g_dbus_proxy_call_sync (gl.proxy,
                                  "NeedSecrets",
                                  NULL,
                                  G_DBUS_CALL_FLAGS_NONE, -1,
                                  NULL, &error);
    if (!ret) {
        _LOGW ("passwd-hook: could not get secrets: %s",
                   error->message);
        g_error_free (error);
        return -1;
    }

    _LOGI ("passwd-hook: got credentials from NetworkManager-sstp");

    g_variant_get (ret, "(&s&s)", &my_username, &my_password);

    if (my_username)
        g_strlcpy (username, my_username, MAXNAMELEN);

    if (my_password)
        g_strlcpy (password, my_password, MAXNAMELEN);

    g_variant_unref (ret);

    return 1;
}

#ifndef USE_PPPD_AUTH_HOOK

/**
 * Called on transitions between phases, but only act when pppd has reached state running.
 */
static int
nm_new_phase(int phase)
{
    if (PHASE_RUNNING != phase) {
        return 0;
    }

    /* Send *blank* MPPE keys to the sstpc client */
    if (!sstp_notify_sent) {
        nm_sstp_notify();
    }

    new_phase_hook = NULL;
    return 0;
}

/**
 * Let's steal the keys here after pppd has completed the authentication, but before
 * the CCP layer has completed and thus zero'd them out.
 *
 * BUG: if the MPPE keys are sent at ip-up; the WIN2K16 server expects the MPPE keys
 * to be all zero for computing the appropriate HLAK keys.
 */
static void
nm_snoop_recv(unsigned char *buf, int len)
{
    unsigned int psize;
    unsigned int proto;
    bool pcomp;

    /* Skip the HDLC header */
    if (buf[0] == 0xFF && buf[1] == 0x03) {
        buf += 2;
        len -= 2;
    }

    pcomp = (buf[0] & 0x10);
    psize = pcomp ? 1 : 2;

    /* Too short of a packet */
    if (len <= psize) {
        return;
    }

    /* Stop snooping if it is not a CHAP / EAP packet */
    proto = pcomp ? buf[0] : (buf[0] << 8 | buf[1]);
    if (proto != PPP_PROTO_CHAP && proto != PPP_PROTO_EAP) {
        return;
    }

    /* Skip the protocol header */
    buf += psize;
    len -= psize;

    /* Look for a SUCCESS packet indicating authentication complete */
    switch (proto)
    {
    case PPP_PROTO_CHAP:
        if (buf[0] != CHAP_SUCCESS) {
            return;
        }
        break;
    case PPP_PROTO_EAP:
        if (buf[0] != EAP_SUCCESS) {
            return;
        }
        break;
    }

    /* Don't bother if the keys aren't set yet */
    if (!mppe_keys_isset()) {
        return;
    }

    nm_sstp_notify();

    /* Disable the callback */
    snoop_recv_hook = NULL;
}

#else /* USE_PPPD_AUTH_HOOK */

/**
 * Called when Auth phase has completed and before Network phase is initiated (e.g. CCP).
 *
 * The introduction of pppd-2.4.9 now supports the callback via auth_up_notifier
 *    which previously was only done when peer had authenticated itself (server side).
 */
static void
nm_auth_notify (void *data, int arg)
{
    /* send the mppe keys to the sstpc client */
    nm_sstp_notify();
}

#endif /* USE_PPPD_AUTH_HOOK */

/**
 * Called when IPCP has finished
 */
static void 
nm_ip_up (void *data, int arg) 
{
    if (gl.is_ip6_up || !ipv6cp_protent.enabled_flag) {
        nm_send_config();
    }
    gl.is_ip_up = 1;
}

/**
 * Called when IPv6CP has finished. 
 */
static void
nm_ip6_up (void *data, int arg) 
{
    if (gl.is_ip_up || !ipcp_protent.enabled_flag) {
        nm_send_config();
    }
    gl.is_ip6_up = 1;
}

/**
 * If peer rejected the IPv6CP protocol, then we won't get an ip6_up callback.
 */
static void
nm_ipv6_protrej(int unit)
{
    gl.is_ip6_rej = 1;
    nm_ip6_up(NULL, 0);
    (*gl.old_protrej)(unit);
    ipv6cp_protent.protrej = gl.old_protrej;
}

/**
 * PPPD exited, clean up resources
 */
static void
nm_exit_notify (void *data, int arg)
{
    g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));
    _LOGI ("exit: cleaning up");
    g_clear_object (&gl.proxy);
}

int
plugin_init (void)
{
    GError *error = NULL;
    const char *bus_name;

    nm_g_type_init ();

    g_return_val_if_fail (!gl.proxy, -1);

    bus_name = getenv ("NM_DBUS_SERVICE_SSTP");
    if (!bus_name)
        bus_name = NM_DBUS_SERVICE_SSTP;

    gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
                                                 10, 0, LOG_DEBUG,
                                                 LOG_NOTICE);

    gl.log_prefix_token = getenv ("NM_VPN_LOG_PREFIX_TOKEN") ?: "???";

    _LOGI ("initializing");

    gl.proxy = g_dbus_proxy_new_for_bus_sync (
                       G_BUS_TYPE_SYSTEM,
                       G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
                       NULL,
                       bus_name,
                       NM_DBUS_PATH_SSTP_PPP,
                       NM_DBUS_INTERFACE_SSTP_PPP,
                       NULL, &error);
    if (!gl.proxy) {
        _LOGE ("couldn't create D-Bus proxy: %s",
               error->message);
        g_error_free (error);
        return -1;
    }

    chap_passwd_hook = nm_get_credentials;
    chap_check_hook = nm_get_chap_check;
    pap_passwd_hook = nm_get_credentials;
    pap_check_hook = nm_get_pap_check;
    eaptls_passwd_hook = nm_get_credentials;

#ifndef USE_PPPD_AUTH_HOOK
    snoop_recv_hook = nm_snoop_recv;
    new_phase_hook = nm_new_phase;
#endif

    ppp_add_notify (NF_PHASE_CHANGE, nm_phasechange, NULL);
    ppp_add_notify (NF_EXIT, nm_exit_notify, NULL);
    ppp_add_notify (NF_IP_UP, nm_ip_up, NULL);
    ppp_add_notify (NF_IPV6_UP, nm_ip6_up, NULL);
#ifdef USE_PPPD_AUTH_HOOK
    ppp_add_notify (NF_AUTH_UP, nm_auth_notify, NULL);
#endif

    gl.old_protrej = ipv6cp_protent.protrej;
    ipv6cp_protent.protrej = nm_ipv6_protrej;

    return 0;
}
