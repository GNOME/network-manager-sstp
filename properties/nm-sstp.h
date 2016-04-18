/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-sstp.h : GNOME UI dialogs for configuring sstp VPN connections
 *
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

#include <glib-object.h>

#define SSTP_TYPE_EDITOR_PLUGIN            (sstp_editor_plugin_get_type ())
#define SSTP_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSTP_TYPE_EDITOR_PLUGIN, SstpEditorPlugin))
#define SSTP_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSTP_TYPE_EDITOR_PLUGIN, SstpEditorPluginClass))
#define SSTP_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSTP_TYPE_EDITOR_PLUGIN))
#define SSTP_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SSTP_TYPE_EDITOR_PLUGIN))
#define SSTP_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSTP_TYPE_EDITOR_PLUGIN, SstpEditorPluginClass))

typedef struct _SstpEditorPlugin SstpEditorPlugin;
typedef struct _SstpEditorPluginClass SstpEditorPluginClass;

struct _SstpEditorPlugin {
	GObject parent;
};

struct _SstpEditorPluginClass {
	GObjectClass parent;
};

GType sstp_editor_plugin_get_type (void);


#define SSTP_TYPE_EDITOR            (sstp_editor_get_type ())
#define SSTP_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSTP_TYPE_EDITOR, SstpEditor))
#define SSTP_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSTP_TYPE_EDITOR, SstpEditorClass))
#define SSTP_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSTP_TYPE_EDITOR))
#define SSTP_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SSTP_TYPE_EDITOR))
#define SSTP_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSTP_TYPE_EDITOR, SstpEditorClass))

typedef struct _SstpEditor SstpEditor;
typedef struct _SstpEditorClass SstpEditorClass;

struct _SstpEditor {
	GObject parent;
};

struct _SstpEditorClass {
	GObjectClass parent;
};

GType sstp_editor_get_type (void);

#endif	/* _NM_SSTP_H_ */

