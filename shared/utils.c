/* -*- Mode: C; tab-width: 4; indent-tabs-mode: s; c-basic-offset: 4 -*- */
/*
 * Eivind Naess <eivnaes@yahoo.com>
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include "nm-default.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <math.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>

#include "nm-utils/nm-shared-utils.h"


// This will evaluate the active directory username@domain.com
#define MICROSOFT_OID_USERNAME "1.2.840.113549.1.9.1"
#define MAX_SUBJECT_SZ 255

/**
 * Initialize the libgnutls crypto library
 */
static gboolean 
nm_sstp_crypto_init(GError **error) 
{
    static gboolean initialized = FALSE;

    if (!initialized) { 
    
        if (gnutls_global_init() != 0) {
            gnutls_global_deinit();
            g_set_error_literal (error, 
                                 NM_CRYPTO_ERROR,
                                 NM_CRYPTO_ERROR_FAILED,
                                 _("Failed to initialize the crypto engine"));
            return FALSE;
        }
        initialized = TRUE;
    }
    return initialized;
}

static char *
nm_sstp_x509_get_subject_name(gnutls_x509_crt_t cert, GError **error) 
{
    char subject[MAX_SUBJECT_SZ+1] = {};
    size_t size = MAX_SUBJECT_SZ;
    int ret;

    ret = gnutls_x509_crt_get_dn_by_oid(cert, MICROSOFT_OID_USERNAME,
            0, 0, subject, &size);
    if (ret != GNUTLS_E_SUCCESS) {
        ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 
                0, 0, subject, &size);
    }
    if (ret == GNUTLS_E_SUCCESS) {
        return g_strdup(subject);
    } else {
        g_set_error (error,
                     NM_CRYPTO_ERROR,
                     NM_CRYPTO_ERROR_FAILED,
                     _("Failed to get subject name"));
    }
    return NULL;
}

char *
nm_sstp_get_subject_name(const char *filename, GError **error) {
    
    gnutls_x509_crt_t cert;
    gnutls_datum_t dt;
    char *retval = NULL;
    int ret = 0;

    if (!nm_sstp_crypto_init(error)) {
        return FALSE;
    }

    ret = gnutls_load_file (filename, &dt);
    if (ret == GNUTLS_E_SUCCESS) {
    
        ret = gnutls_x509_crt_init(&cert);
        if (ret == GNUTLS_E_SUCCESS) {

            ret = gnutls_x509_crt_import(cert, &dt, GNUTLS_X509_FMT_PEM);
            if (ret != GNUTLS_E_SUCCESS) {
                    
                ret = gnutls_x509_crt_import(cert, &dt, GNUTLS_X509_FMT_DER);
            }
            if (ret == GNUTLS_E_SUCCESS) {
            
                retval = nm_sstp_x509_get_subject_name(cert, error);

            } else {
                g_set_error (error, 
                             NM_CRYPTO_ERROR,
                             NM_CRYPTO_ERROR_INVALID_DATA,
                             _("Failed to load certificate"));
            }
            gnutls_x509_crt_deinit(cert);
        } else {
            g_set_error (error, 
                        NM_CRYPTO_ERROR,
                        NM_CRYPTO_ERROR_FAILED,
                        _("Failed to initialize certificate"));
        }
        gnutls_free(dt.data);
    } else {
        g_set_error (error, 
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_FAILED,
                    _("Failed to load certificate"));
    }
    return retval;
}

char *
nm_sstp_get_suject_name_pkcs12(const char *filename, const char *password, GError **error)
{
    gnutls_pkcs12_t pkcs12;
    gnutls_datum_t data = {};
    gnutls_x509_privkey_t pkey;
    gnutls_x509_crt_t *chain, *extras;
    unsigned int chain_size = 0, extras_size = 0, i;
    char *retval = NULL;
    int ret = GNUTLS_E_SUCCESS;

    if (!nm_sstp_crypto_init(error)) {
        return NULL;
    }

    ret = gnutls_load_file (filename, &data);
    if (ret == GNUTLS_E_SUCCESS) {
        
        ret = gnutls_pkcs12_init (&pkcs12);
        if (ret == GNUTLS_E_SUCCESS) {

            ret = gnutls_pkcs12_import(pkcs12, &data, GNUTLS_X509_FMT_DER, 0);
            if (ret == GNUTLS_E_SUCCESS) {

                ret = gnutls_pkcs12_simple_parse(pkcs12, password, &pkey, &chain,
                        &chain_size, &extras, &extras_size, NULL, 0);
                if (ret == GNUTLS_E_SUCCESS) {
                    
                    if (chain_size > 0) {
                        retval = nm_sstp_x509_get_subject_name(chain[0], error);
                    }
                    for (i = 0; i < chain_size; i++) {
                        gnutls_x509_crt_deinit(chain[i]);
                    }
                    gnutls_free(chain);

                    for (i = 0; i < extras_size; i++) {
                        gnutls_x509_crt_deinit(extras[i]);
                    }
                    gnutls_free(extras);

                } else {
                    g_set_error (error, 
                                NM_CRYPTO_ERROR,
                                NM_CRYPTO_ERROR_FAILED,
                                _("Failed to parse pkcs12 file"));
                }
            } else {
                g_set_error (error, 
                            NM_CRYPTO_ERROR,
                            NM_CRYPTO_ERROR_FAILED,
                            _("Failed to import pkcs12 file"));
            }
            gnutls_pkcs12_deinit(pkcs12);
        } else {
            g_set_error (error, 
                        NM_CRYPTO_ERROR,
                        NM_CRYPTO_ERROR_FAILED,
                        _("Failed to initialize pkcs12 structure"));
        }
        gnutls_free(data.data);
    } else {
        g_set_error (error, 
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_FAILED,
                    _("Failed to read file"));
    }
    return retval;
}

/**
 * Verify that the password is indeed the password needed to decrypt the key.
 *    this works with .pfx, and .pem files?
 */
gboolean
nm_sstp_verify_private_key(const char *keyfile, const char *password, GError **error)
{
    gnutls_x509_privkey_t key;
    gnutls_datum_t data;
    int ret;

    if (!nm_sstp_crypto_init(error)) {
        return FALSE;
    }

    ret = gnutls_load_file (keyfile, &data);
    if (ret == GNUTLS_E_SUCCESS) {

        ret = gnutls_x509_privkey_init(&key);
        if (ret == GNUTLS_E_SUCCESS) {

            ret = gnutls_x509_privkey_import2(key, &data, GNUTLS_X509_FMT_PEM, password, 0);
            if (ret != GNUTLS_E_SUCCESS) {

                ret = gnutls_x509_privkey_import2(key, &data, GNUTLS_X509_FMT_DER, password, 0);
                if (ret != GNUTLS_E_SUCCESS) {
                    g_set_error(error, 
                                NM_CRYPTO_ERROR,
                                NM_CRYPTO_ERROR_FAILED,
                                _("Failed to decrypt private key"));
                }
            }
            if (ret == GNUTLS_E_SUCCESS) {
                gnutls_x509_privkey_deinit(key);
            }
        } else {
            g_set_error(error, 
                        NM_CRYPTO_ERROR,
                        NM_CRYPTO_ERROR_FAILED,
                        _("Failed to initialize private key"));
            return FALSE;
        }
        gnutls_free(data.data);
    } else {
        g_set_error(error, 
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_FAILED,
                    _("Failed read file"));
    }
    return (ret == GNUTLS_E_SUCCESS);
}


static gboolean
_is_inet6_addr (const char *str, gboolean with_square_brackets)
{
	struct in6_addr a;
	gsize l;

	if (   with_square_brackets
	    && str[0] == '[') {
		l = strlen (str);
		if (str[l - 1] == ']') {
			gs_free char *s = g_strndup (&str[1], l - 2);

			return inet_pton (AF_INET6, s, &a) == 1;
		}
	}
	return inet_pton (AF_INET6, str, &a) == 1;
}

gssize 
nm_sstp_parse_gateway (const char *str, char **out_buf, const char **out_host,
        const char **out_port, GError **error)
{
	gs_free char *str_copy = NULL;
	char *t;
	char *host = NULL;
	char *port = NULL;
	gssize idx_fail;

	g_return_val_if_fail (str, 0);
	if (!out_buf) {
		/* one can omit @out_buf only if also no other out-arguments
		 * are requested. */
		if (out_host || out_port)
			g_return_val_if_reached (0);
	}
	g_return_val_if_fail (!error || !*error, 0);

	t = strchr (str, ' ');
	if (!t)
		t = strchr (str, ',');
	if (t) {
		g_set_error (error, 
                     NM_UTILS_ERROR, 
                     NM_UTILS_ERROR_UNKNOWN,
		             _("invalid delimiter character '%c'"), t[0]);
		idx_fail = t - str;
		goto out_fail;
	}

	if (!g_utf8_validate (str, -1, (const char **) &t)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("invalid non-utf-8 character"));
		idx_fail = t - str;
		goto out_fail;
	}

	str_copy = g_strdup (str);

	/* we already checked that there is no space above.
	 * Strip tabs nonetheless. */
	host = nm_str_skip_leading_spaces (str_copy);
	g_strchomp (host);

	t = strrchr (host, ':');
	if (   t
	    && !_is_inet6_addr (host, TRUE)) {
		t[0] = '\0';
		port = &t[1];
		t = strrchr (host, ':');
		if (   t
		    && !_is_inet6_addr (host, TRUE)) {
			t[0] = '\0';
			port = &t[1];
		}
	}

	if (!host[0]) {
		g_set_error (error, 
                     NM_UTILS_ERROR, 
                     NM_UTILS_ERROR_UNKNOWN,
		             _("empty host"));
		idx_fail = host - str_copy;
		goto out_fail;
	}
	if (port) {
		if (!port[0]) {
			/* allow empty port like "host::udp". */
			port = NULL;
		} else if (_nm_utils_ascii_str_to_int64 (port, 10, 1, 0xFFFF, 0) == 0) {
			g_set_error (error, 
                         NM_UTILS_ERROR, 
                         NM_UTILS_ERROR_UNKNOWN,
			             _("invalid port"));
			idx_fail = port - str_copy;
			goto out_fail;
		}
	}
	if (out_buf) {
		*out_buf = g_steal_pointer (&str_copy);
		if (   host[0] == '['
		    && _is_inet6_addr (host, TRUE)
		    && !_is_inet6_addr (host, FALSE)) {
			gsize l;

			host++;
			l = strlen (host);
			nm_assert (l > 0 && host[l - 1] == ']');
			host[l - 1] = '\0';
			nm_assert (_is_inet6_addr (host, FALSE));
		}
		NM_SET_OUT (out_host, host);
		NM_SET_OUT (out_port, port);
	}
	return -1;

out_fail:
	if (out_buf) {
		*out_buf = NULL;
		NM_SET_OUT (out_host, NULL);
		NM_SET_OUT (out_port, NULL);
	}
	return idx_fail;
}



