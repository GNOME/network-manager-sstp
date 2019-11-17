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
#define ___CONFIG_H__

/* pppd headers *sigh* */
#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ccp.h>
#include <pppd/ipcp.h>
#include <pppd/chap-new.h>
#include <pppd/chap_ms.h>

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

#include "nm-sstp-service.h"
#include "nm-ppp-status.h"

#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#ifndef MPPE
#define MPPE_MAX_KEY_LEN 16
extern u_char mppe_send_key[MPPE_MAX_KEY_LEN];
extern u_char mppe_recv_key[MPPE_MAX_KEY_LEN];
extern int mppe_keys_set;
#endif
static int sstp_notify_sent = 1;

int plugin_init (void);

char pppd_version[] = VERSION;

/*****************************************************************************/

struct {
	int log_level;
	const char *log_prefix_token;
	GDBusProxy *proxy;
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
    if (sock < 0)
    {
        _LOGE ("sstp-plugin: could not create a socket to sstpc");
        goto done;
    }

    /* Setup the address */
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/var/run/sstpc/sstpc-%s", ipparam);

    /* Connect the socket */
    ret = connect(sock, (struct sockaddr*) &addr, alen);
    if (ret < 0)
    {
        _LOGE ("sstp-plugin: Could not connect to sstpc (%s), %m", addr.sun_path);
        goto done;
    }

    /* Sucess */
    retval = sock;
 
done:

    if (retval <= 0)
    {
        close(sock);
    }

    return retval; 
}

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
    if (sock <= 0)
    {
        goto done;
    }
    
    /* Create an address request */
    sstp_api_msg_new((unsigned char*)&msg, SSTP_API_MSG_ADDR);

    /* Send the request */
    ret = send(sock, &msg, sizeof(msg), 0);
    if (ret < 0)
    {
        _LOGE ("sstp-plugin: Could not send data to sstpc");
        goto done;
    }
    
    /* Wait for the ACK to be received */
    ret = recv(sock, &msg, (sizeof(msg)), 0);
    if (ret < 0 || ret != (sizeof(msg)))
    {
        _LOGE ("sstp-plugin: Failed to receive ack from sstpc");
        goto done;
    }

    /* Validate message header */
    if (sstp_api_msg_type(&msg, &type) && 
        SSTP_API_MSG_ACK != type)
    {
        _LOGE ("sstp-plugin: Received invalid response from sstpc");
        goto done;
    }

    /* Allocate memory for response */
    buff = alloca(msg.msg_len);
    if (!buff)
    {
        _LOGE ("sstp-plugin: Could not allocate space for response");
        goto done;
    }

    /* Read the remainder of the payload */
    ret = read(sock, buff, msg.msg_len);
    if (ret < 0 || ret != msg.msg_len)
    {
        _LOGE ("sstp-plugin: Could not read the response");
        goto done;
    }

    /* Parse the Attributes */
    ret = sstp_api_attr_parse(buff, msg.msg_len, list, cnt);
    if (ret != 0)
    {
        _LOGE ("sstp-plugin: Could not parse attributes");
        goto done;
    }

    /* Get the address */
    attr = list[SSTP_API_ATTR_ADDR];
    if (!attr)
    {
        _LOGE ("sstp-plugin: Could not get resolved address");
        goto done;
    }

    /* Copy the result to the output argument */
    memcpy(addr, attr->attr_data, sizeof(struct sockaddr_in));

    /* Get the gateway name */
    attr = list[SSTP_API_ATTR_GATEWAY];
    if (!attr)
    {
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
    if (sock > 0)
    {
        close(sock);
    }

    return retval;
}


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
    if (sock <= 0)
    {
        goto done;
    }

    /* Create a new message */
    msg = sstp_api_msg_new((unsigned char*) buf, SSTP_API_MSG_AUTH);
    if (!msg)
    {
        _LOGE ("sstp-plugin: Could not create message to sstpc");
        goto done;
    }

    /* Add the attributes for the MPPE keys */
    sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_SEND, slen, skey);
    sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_RECV, rlen, rkey);

    /* Send the structure */
    ret = send(sock, msg, sstp_api_msg_len(msg), 0);
    if (ret < 0)
    {
        _LOGE ("sstp-plugin: Could not send data to sstpc");
        goto done;
    }
    
    /* Wait for the ACK to be received */
    ret = recv(sock, msg, (sizeof(*msg)), 0);
    if (ret <= 0 || ret != (sizeof(*msg)))
    {
        _LOGE ("sstp-plugin: Could not wait for ack from sstpc (%d)", ret);
        goto done;
    }

    /* Sent credentials to sstpc */
    _LOGI ("sstp-plugin: MPPE keys exchanged with sstpc");

    /* Success */
    retval = 0;
    
    /* We have communicated the keys */
    sstp_notify_sent = 1;

done:

    /* Close socket */
    if (sock > 0)
    {
        close(sock);
    }

    return retval;
}


static void
nm_ip_up (void *data, int arg)
{
	guint32 pppd_made_up_address = htonl (0x0a404040 + ifunit);
	ipcp_options opts = ipcp_gotoptions[0];
	ipcp_options peer_opts = ipcp_hisoptions[0];
	GVariantBuilder builder;
	struct sockaddr_in addr;

	g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));

	_LOGI ("ip-up: event");

	/* Auth-Type is not MSCHAPv2, reset the keys and send blank keys */
	if (!sstp_notify_sent) {
		if (!mppe_keys_set)
		{
			memset(&mppe_send_key, 0, sizeof(mppe_send_key));
			memset(&mppe_recv_key, 0, sizeof(mppe_recv_key));
		}

		/* Send the MPPE keys to the sstpc client */
		nm_sstp_notify(mppe_send_key, sizeof(mppe_send_key),
			       mppe_recv_key, sizeof(mppe_recv_key));
	}



	if (!opts.ouraddr) {
		_LOGW ("ip-up: didn't receive an internal IP from pppd!");
        nm_phasechange (NULL, PHASE_DEAD);
		return;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV,
	                       g_variant_new_string (ifname));

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
	                       g_variant_new_uint32 (opts.ouraddr));

	/* Request the address of the server sstpc connected to */
	if (0 == nm_sstp_getaddr(&addr))
	{
		/* This will eliminate the need to have nm-sstp-service
		 * insert a new entry for "gateway" as we have already set it.
		 */
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY,
		                       g_variant_new_uint32 (addr.sin_addr.s_addr));
	}

	/* Prefer the peer options remote address first, _unless_ pppd made the
	 * address up, at which point prefer the local options remote address,
	 * and if that's not right, use the made-up address as a last resort.
	 */
	if (peer_opts.hisaddr && (peer_opts.hisaddr != pppd_made_up_address)) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (peer_opts.hisaddr));
	} else if (opts.hisaddr) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (opts.hisaddr));
	} else if (peer_opts.hisaddr == pppd_made_up_address) {
		/* As a last resort, use the made-up address */
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (peer_opts.ouraddr));
	}

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
	                       g_variant_new_uint32 (32));

	if (opts.dnsaddr[0] || opts.dnsaddr[1]) {
		guint32 dns[2];
		int len = 0;

		if (opts.dnsaddr[0])
			dns[len++] = opts.dnsaddr[0];
		if (opts.dnsaddr[1])
			dns[len++] = opts.dnsaddr[1];

		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_DNS,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  dns, len, sizeof (guint32)));
	}

	/* Default MTU to 1400, which is also what Windows XP/Vista use */
	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_MTU,
	                        g_variant_new_uint32 (1400));

	_LOGI ("ip-up: sending Ip4Config to NetworkManager-sstp...");

	g_dbus_proxy_call (gl.proxy,
	                   "SetIp4Config",
	                   g_variant_new ("(a{sv})", &builder),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   NULL, NULL);
}

static int
get_chap_check (void)
{
	return 1;
}

static int
get_pap_check (void)
{
	return 1;
}

static int
get_credentials (char *username, char *password)
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

static void 
nm_snoop_send(unsigned char *buf, int len)
{
    uint16_t protocol;

    /* Skip the HDLC header */
    buf += 2;
    len -= 2;
   
    /* Too short of a packet */
    if (len <= 0)
        return;
    
    /* Stop snooping if it is not a LCP Auth Chap packet */
    protocol = (buf[0] & 0x10) ? buf[0] : (buf[0] << 8 | buf[1]);
    if (protocol != 0xC223)
        return;

    /* Skip the LCP header */
    buf += 2;
    len -= 2;

    /* Too short of a packet */
    if (len <= 0)
        return;
    
    /* Check if packet is a CHAP response */
    if (buf[0] != 0x02)
        return;
 
    /* Don't bother if the keys aren't set yet */   
    if (!mppe_keys_set)
        return;

    /* ChapMS2/ChapMS sets the MPPE keys as a part of the make_response
     * call, these might not be enabled dependent on negotiated options
     * such as MPPE and compression. If they are enabled, the keys are 
     * zeroed out in ccp.c before ip-up is called.
     * 
     * Let's steal the keys here over implementing all the code to
     * calculate the MPPE keys here.
     */
    if (debug)
    {
        char key[255];
        _LOGI ("sstp-plugin: mppe keys are set");

        /* Add the MPPE Send Key */
        slprintf(key, sizeof(key)-1, "S:%0.*B", sizeof(mppe_send_key),
                 mppe_send_key);
        _LOGI ("sstp-plugin: The mppe send key: %s", key);

        /* Add the MPPE Recv Key */
        slprintf(key, sizeof(key)-1, "S:%0.*B", sizeof(mppe_recv_key),
                 mppe_recv_key);
        _LOGI ("sstp-plugin: The mppe recv key: %s", key);
    }

    /* Send the MPPE keys to the sstpc client */
    _LOGI ("sstp-plugin: sending mppe keys");

    nm_sstp_notify(mppe_send_key, sizeof(mppe_send_key), 
                   mppe_recv_key, sizeof(mppe_recv_key));
    snoop_send_hook = NULL;
}

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
	GDBusConnection *bus;
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

	bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!bus) {
        _LOGE ("couldn't connect to system bus: %s",
               error->message);
		g_error_free (error);
		return -1;
	}

	gl.proxy = g_dbus_proxy_new_sync (bus,
				       G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
				       NULL,
	                               bus_name,
	                               NM_DBUS_PATH_SSTP_PPP,
				       NM_DBUS_INTERFACE_SSTP_PPP,
	                               NULL, &error);
	g_object_unref (bus);
	if (!gl.proxy) {
		_LOGE ("couldn't create D-Bus proxy: %s",
		       error->message);
		g_error_free (error);
		return -1;
	}

	chap_passwd_hook = get_credentials;
	chap_check_hook = get_chap_check;
	pap_passwd_hook = get_credentials;
	pap_check_hook = get_pap_check;
	snoop_send_hook = nm_snoop_send;

	add_notifier (&phasechange, nm_phasechange, NULL);
	add_notifier (&ip_up_notifier, nm_ip_up, NULL);
	add_notifier (&exitnotify, nm_exit_notify, NULL);

	return 0;
}
