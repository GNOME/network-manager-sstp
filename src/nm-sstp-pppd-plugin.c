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

#include <config.h>
#define __CONFIG_H__
#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ccp.h>
#include <pppd/eui64.h>
#include <pppd/ipcp.h>
#include <pppd/ipv6cp.h>
#include <pppd/chap-new.h>
#include <pppd/chap_ms.h>
#include <pppd/mppe.h>
#include <pppd/eap.h>

#include "nm-default.h"

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

#include "nm-ppp-status.h"
#include "nm-sstp-service.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

static int sstp_notify_sent = 0;

#define PPP_PROTO_EAP   0xc227
#define PPP_PROTO_CHAP  0xc223

int plugin_init (void);

char pppd_version[] = VERSION;

/*****************************************************************************/

struct {
    int log_level;
    const char *log_prefix_token;
    GDBusProxy *proxy;
    bool is_ip_up;
    bool is_ip6_up;
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
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/var/run/sstpc/sstpc-%s", ipparam);

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
nm_sstp_getaddr(struct sockaddr_in *addr)
{
    char *buff = NULL;
    int retval = (-1);
    int sock   = (-1);
    int ret    = (-1);
    int cnt    = (SSTP_API_ATTR_MAX+1);
    char name[255] = {};
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
    memcpy(addr, attr->attr_data, sizeof(struct sockaddr_in));

    /* Get the gateway name */
    attr = list[SSTP_API_ATTR_GATEWAY];
    if (!attr) {
        _LOGE ("sstp-plugin: Could not get resolved name");
        goto done;
    }

    /* Copy the name */
    memcpy(name, attr->attr_data, attr->attr_len);

    _LOGI ("sstp-plugin: sstpc is connected to %s using %s",
           name, inet_ntoa(addr->sin_addr));

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
nm_sstp_notify(unsigned char *skey, int slen, unsigned char *rkey, int rlen)
{
    int ret    = (-1);
    int sock   = (-1);
    int retval = (-1);
    uint8_t buf[NM_SSTP_MAX_BUFLEN+1] = {};
    sstp_api_msg_st  *msg  = NULL;

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
    sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_SEND, slen, skey);
    sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_RECV, rlen, rkey);

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
    _LOGI ("sstp-plugin: MPPE keys exchanged with sstpc");

    /* Success */
    retval = 0;

done:

    /* Close socket */
    if (sock > 0) {
        close(sock);
    }

    return retval;
}

extern int no_ifaceid_neg;

static GVariant* nm_ip6_get_params(void)
{
    GVariantBuilder builder;
    ipv6cp_options *opts = &ipv6cp_gotoptions[0];
    ipv6cp_options *peer_opts = &ipv6cp_hisoptions[0];
    struct in6_addr addr;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    if (no_ifaceid_neg || eui64_iszero(opts->ourid) || eui64_iszero(peer_opts->hisid)) {
        _LOGI ("No IPv6 addresses negotiated");
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

static GVariant*
nm_ip4_get_params(void)
{
    guint32 pppd_made_up_address = htonl (0x0a404040 + ifunit);
    ipcp_options *opts = &ipcp_gotoptions[0];
    ipcp_options *peer_opts = &ipcp_hisoptions[0];
    GVariantBuilder builder;

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
        } else if (opts->hisaddr) {
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_PTP,
                                   g_variant_new_uint32 (opts->hisaddr));
        } else if (peer_opts->hisaddr == pppd_made_up_address) {
            /* As a last resort, use the made-up address */
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_PTP,
                                   g_variant_new_uint32 (peer_opts->ouraddr));
        }

        /* DNS Servers */
        if (opts->dnsaddr[0] || opts->dnsaddr[1]) {
            guint32 dns[2];
            int len = 0;

            if (opts->dnsaddr[0])
                dns[len++] = opts->dnsaddr[0];
            if (opts->dnsaddr[1])
                dns[len++] = opts->dnsaddr[1];

            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_DNS,
                                   g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
                                                              dns, len, sizeof (guint32)));
        }

        /* NetBIOS or WINS server if configured */
        if (opts->winsaddr[0] || opts->winsaddr[1]) {
            guint32 wins[2];
            int len = 0;

            if (opts->winsaddr[0])
                wins[len++] = opts->winsaddr[0];
            if (opts->winsaddr[1])
                wins[len++] = opts->winsaddr[1];

            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_IP4_CONFIG_NBNS,
                                   g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
                                                              wins, len, sizeof (guint32)));
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
    struct sockaddr_in addr;
    int mtu;

    g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add (&builder, "{sv}",
                           NM_VPN_PLUGIN_CONFIG_TUNDEV,
                           g_variant_new_string (ifname));

    mtu = netif_get_mtu (ifunit);
    g_variant_builder_add (&builder, "{sv}",
                           NM_VPN_PLUGIN_CONFIG_MTU,
                            g_variant_new_uint32 (mtu));

    /* Request the address of the server sstpc connected to */
    if (0 == nm_sstp_getaddr(&addr)) {

        if (addr.sin_family == AF_INET) {
            g_variant_builder_add (&builder, "{sv}",
                                   NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY,
                                   g_variant_new_uint32 (addr.sin_addr.s_addr));
        }
        if (addr.sin_family == AF_INET6) {
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

/**
 * Called on transitions between phases, but only act when
 *   pppd has reached state running.
 */
static int
nm_new_phase(int phase)
{
    if (PHASE_RUNNING != phase) {
        return 0;
    }

    /* Send *blank* MPPE keys to the sstpc client */
    if (!sstp_notify_sent) {
        BZERO(mppe_send_key, sizeof(mppe_send_key));
        BZERO(mppe_recv_key, sizeof(mppe_recv_key));
        nm_sstp_notify(mppe_send_key, sizeof(mppe_send_key),
                       mppe_recv_key, sizeof(mppe_recv_key));
        sstp_notify_sent = 1;
    }

    new_phase_hook = NULL;
    return 0;
}

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
 *
 * NOTE: if enabled, but protocol is rejected; we may never get here.
 *       Disable IPv6 support in Network Manager to bypass this.
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
 * Called when Auth phase has completed and before Network phase is initiated (e.g. CCP).
 */
static void
nm_auth_notify (void *data, int arg)
{
    eap_state *eap = NULL;

    /* Print the MPPE keys for debugging */
    if (debug) {
        char key[255];

        /* Add the MPPE Send Key */
        slprintf(key, sizeof(key)-1, "S:%0.*B", sizeof(mppe_send_key),
                 mppe_send_key);
        _LOGI ("The mppe send key: %s", key);

        /* Add the MPPE Recv Key */
        slprintf(key, sizeof(key)-1, "S:%0.*B", sizeof(mppe_recv_key),
                 mppe_recv_key);
        _LOGI ("The mppe recv key: %s", key);
    }

    eap = &eap_states[0];
    if (eap->es_client.ea_using_eaptls ||
        eap->es_client.ea_using_eaptls) {

        _LOGI ("EAP-TLS was used for authentication");

        /* Use the MSK(0..32) as the key */
        nm_sstp_notify(mppe_send_key, 16,
                       mppe_send_key+16, 16);
    }
    else {

        /* send the mppe keys to the sstpc client */
        nm_sstp_notify(mppe_send_key, 16,
                       mppe_recv_key, 16);
    }
    sstp_notify_sent = 1;
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
    new_phase_hook = nm_new_phase;
    eaptls_passwd_hook = nm_get_credentials;

    add_notifier (&phasechange, nm_phasechange, NULL);
    add_notifier (&exitnotify, nm_exit_notify, NULL);
    add_notifier (&ip_up_notifier, nm_ip_up, NULL);
    add_notifier (&ipv6_up_notifier, nm_ip6_up, NULL);
    add_notifier (&auth_up_notifier, nm_auth_notify, NULL);

    return 0;
}
