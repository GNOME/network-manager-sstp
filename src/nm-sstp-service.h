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

#define NM_TYPE_SSTP_PLUGIN            (nm_sstp_plugin_get_type ())
#define NM_SSTP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SSTP_PLUGIN, NMSstpPlugin))
#define NM_SSTP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SSTP_PLUGIN, NMSstpPluginClass))
#define NM_IS_SSTP_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SSTP_PLUGIN))
#define NM_IS_SSTP_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SSTP_PLUGIN))
#define NM_SSTP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SSTP_PLUGIN, NMSstpPluginClass))

typedef struct {
    NMVpnServicePlugin parent;
} NMSstpPlugin;

typedef struct {
    NMVpnServicePluginClass parent;
} NMSstpPluginClass;

GType nm_sstp_plugin_get_type (void);

NMSstpPlugin *nm_sstp_plugin_new (const gchar *);

#endif /* NM_SSTP_PLUGIN_H */
