/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#ifndef UTILS_H
#define UTILS_H

static inline void
nm_sstp_cache_value(char **value, const char *str)
{
    g_free(*value);
    *value = (str != NULL) ? strdup(str) : NULL;
        
}

static inline gboolean
nm_sstp_cache_check(const char *val1, const char *val2) 
{
    return (!val1 || strcmp(val1, val2));
}

/**
 * Extract the subjectname from a certificate file
 */
char* nm_sstp_get_subject_name(const char *file, GError **error);

/**
 * Extract the subject name from a pcks12 envelope
 */
char* nm_sstp_get_suject_name_pkcs12(const char *file, const char *password, 
        GError **error);

/**
 * Verify that the private key can be decrypt the key
 */
gboolean nm_sstp_verify_private_key(const char *keyfile, const char *password, 
        GError **error);

/**
 * nm_sstp_parse_gateway:
 * @str: the input string to be split. It is modified inplace.
 * @out_buf: an allocated string, to which the other arguments
 *   point to. Must be freed by caller.
 * @out_host: pointer to the host out argument.
 * @out_port: pointer to the port out argument.
 * @error:
 *
 * Splits @str in two parts: host and port.
 *
 * Returns: -1 on success or index in @str of first invalid character.
 *  Note that the error index can be at strlen(str), if some data is missing.
 */
gssize nm_sstp_parse_gateway (const char *str, char **out_buf, const char **out_host, 
        const char **out_port, GError **error);

#endif  /* UTILS_H */
