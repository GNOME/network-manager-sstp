/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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

#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-io-utils.h"


// This will evaluate the active directory username@domain.com
#define MICROSOFT_OID_USERNAME "1.2.840.113549.1.9.1"

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

/**
 * Lookup the common name, or the active directory username
 */
char *
nm_sstp_get_subject_name(const char *filename, GError **error) {
    
    nm_auto_clear_secret_ptr NMSecretPtr out_contents = { 0 };
    gnutls_x509_crt_t cert;
    gnutls_datum_t dt;
    char subject[255];
    size_t size = sizeof(subject) - 1;
    int ret = 0;

    if (!nm_sstp_crypto_init(error)) {
        return FALSE;
    }

    if (nm_utils_file_get_contents (-1, 
                                    filename,
                                    1024*1024,
                                    NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET,
                                    &out_contents.str,
                                    &out_contents.len,
                                    error)) {
        return NULL;
    }

    ret = gnutls_x509_crt_init(&cert);
    if (ret != GNUTLS_E_SUCCESS) {
        g_set_error (error, 
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_FAILED,
                    _("Failed to initialze certificate"));
        return NULL;
    }

    dt.data = out_contents.bin;
    dt.size = out_contents.len;

    ret = gnutls_x509_crt_import(cert, &dt, GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS) {
            
        ret = gnutls_x509_crt_import(cert, &dt, GNUTLS_X509_FMT_DER);
        if (ret != GNUTLS_E_SUCCESS) {
            gnutls_x509_crt_deinit(cert);
            g_set_error (error, 
                         NM_CRYPTO_ERROR,
                         NM_CRYPTO_ERROR_INVALID_DATA,
                         _("Failed to load certificate"));
            return NULL;
        }
    }


    ret = gnutls_x509_crt_get_dn_by_oid(cert, MICROSOFT_OID_USERNAME,
            0, 0, subject, &size);
    if (ret != GNUTLS_E_SUCCESS) {
        ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 
                0, 0, subject, &size);
    }
    gnutls_x509_crt_deinit(cert);

    if (ret != GNUTLS_E_SUCCESS) {
        g_set_error (error, 
                     NM_CRYPTO_ERROR,
                     NM_CRYPTO_ERROR_FAILED,
                     _("Failed to lookup certificate name"));
    } else {
        size = MIN(size, sizeof(subject));
        subject[size] = 0;
    }
    
    return (ret == GNUTLS_E_SUCCESS)
        ? strdup(subject)
        : NULL;
}

/* If we need to look at other fields ...
    gnutls_x509_dn_t dn;
    ret = gnutls_x509_crt_get_subject(cert, &dn);
    if (ret == GNUTLS_E_SUCCESS) {
        gnutls_x509_ava_st ava;
        int i = 0;

        ret = gnutls_x509_dn_get_rdn_ava(dn, i++, 0, &ava);
        while (ret == GNUTLS_E_SUCCESS) {
            
            ret = gnutls_x509_dn_get_rdn_ava(dn, i++, 0, &ava);
        }
    }
    else {
        g_message("Failed to get dn");
    }
*/


gboolean
nm_sstp_verify_private_key(const char *keyfile, const char *password, GError **error)
{
    nm_auto_clear_secret_ptr NMSecretPtr content;
    gnutls_x509_privkey_t key;
    gnutls_datum_t dt;
    int ret;

    if (!nm_sstp_crypto_init(error)) {
        return FALSE;
    }

    if (nm_utils_file_get_contents(-1, keyfile, 1024*1024, 
        NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET, &content.str, 
        &content.len, error)) {
        return FALSE;
    }

    dt.data = content.bin;
    dt.size = content.len;

    ret = gnutls_x509_privkey_init(&key);
    if (ret != GNUTLS_E_SUCCESS) {
        g_set_error(error, 
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_FAILED,
                    _("Failed to initialize private key"));
        return FALSE;
    }

    ret = gnutls_x509_privkey_import2(key, &dt, GNUTLS_X509_FMT_PEM, password, 0);
    if (ret != GNUTLS_E_SUCCESS) {

        ret = gnutls_x509_privkey_import2(key, &dt, GNUTLS_X509_FMT_DER, password, 0);
        if (ret != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(key);
            g_set_error(error, 
                        NM_CRYPTO_ERROR,
                        NM_CRYPTO_ERROR_FAILED,
                        _("Failed to decrypt private key"));
            return FALSE;
        }
    }

    gnutls_x509_privkey_deinit(key);
    return TRUE;
}

