/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#ifndef __NM_SSTP_EDITOR_PLUGIN_H__
#define __NM_SSTP_EDITOR_PLUGIN_H__

#define SSTP_TYPE_PLUGIN_UI            (sstp_plugin_ui_get_type ())
#define SSTP_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSTP_TYPE_PLUGIN_UI, SstpPluginUi))
#define SSTP_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSTP_TYPE_PLUGIN_UI, SstpPluginUiClass))
#define SSTP_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSTP_TYPE_PLUGIN_UI))
#define SSTP_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SSTP_TYPE_PLUGIN_UI))
#define SSTP_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSTP_TYPE_PLUGIN_UI, SstpPluginUiClass))

typedef struct _SstpPluginUi SstpPluginUi;
typedef struct _SstpPluginUiClass SstpPluginUiClass;

struct _SstpPluginUi {
	GObject parent;
};

struct _SstpPluginUiClass {
	GObjectClass parent;
};

GType sstp_plugin_ui_get_type (void);

typedef NMVpnEditor *(*NMVpnEditorFactory) (NMVpnEditorPlugin *editor_plugin,
                                            NMConnection *connection,
                                            GError **error);

NMVpnEditor *
nm_vpn_editor_factory_sstp (NMVpnEditorPlugin *editor_plugin,
                            NMConnection *connection,
                            GError **error);

#endif /* __NM_SSTP_EDITOR_PLUGIN_H__ */

