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

#ifndef _NM_SSTP_H_
#define _NM_SSTP_H_

#define SSTP_TYPE_PLUGIN_UI_WIDGET            (sstp_plugin_ui_widget_get_type ())
#define SSTP_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSTP_TYPE_PLUGIN_UI_WIDGET, SstpPluginUiWidget))
#define SSTP_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSTP_TYPE_PLUGIN_UI_WIDGET, SstpPluginUiWidgetClass))
#define SSTP_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSTP_TYPE_PLUGIN_UI_WIDGET))
#define SSTP_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SSTP_TYPE_PLUGIN_UI_WIDGET))
#define SSTP_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSTP_TYPE_PLUGIN_UI_WIDGET, SstpPluginUiWidgetClass))

typedef struct _SstpPluginUiWidget SstpPluginUiWidget;
typedef struct _SstpPluginUiWidgetClass SstpPluginUiWidgetClass;

struct _SstpPluginUiWidget {
	GObject parent;
};

struct _SstpPluginUiWidgetClass {
	GObjectClass parent;
};

GType sstp_plugin_ui_widget_get_type (void);

NMVpnEditor *nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error);

#endif	/* _NM_SSTP_H_ */

