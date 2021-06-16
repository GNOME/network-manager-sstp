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

#ifndef __SSTP_MPPE_H__
#define __SSTP_MPPE_H__


#ifdef HAVE_MPPE_KEYS_FUNCTIONS
#define MPPE 1
#include <pppd/chap_ms.h>
#include <pppd/mppe.h>
#else

/*
 * Get the MPPE recv key
 */
int mppe_get_recv_key(unsigned char *recv_key, int length);

/*
 * Get the MPPE send key
 */
int mppe_get_send_key(unsigned char *send_key, int length);

/*
 * Check if the MPPE keys are set
 */
bool mppe_keys_isset(void);

#endif  // #ifdef HAVE_MPPE_KEYS_FUNCTIONS
#endif  // #ifdef __SSTP_MPPE_H__
