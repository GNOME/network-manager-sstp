/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 * Based on work by David Zeuthen, <davidz@redhat.com>
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

#include "nm-default.h"

#include "nm-sstp-editor.h"

#include <gtk/gtk.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "advanced-dialog.h"
#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

/*****************************************************************************/

static void sstp_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (SstpPluginUiWidget, sstp_plugin_ui_widget, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               sstp_plugin_ui_widget_interface_init))

#define SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SSTP_TYPE_PLUGIN_UI_WIDGET, SstpPluginUiWidgetPrivate))

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

typedef struct {
    GtkBuilder *builder;
    GtkWidget *widget;
    GtkWindowGroup *window_group;
    gboolean window_added;
    GHashTable *advanced;
    gboolean new_connection;
} SstpPluginUiWidgetPrivate;

/*****************************************************************************/

#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

static gboolean
auth_widget_check_validity (GtkBuilder *builder, const char *type, GError **error)
{
    gboolean encrypted, secrets_required;
    NMACertChooser *chooser;
    NMSetting8021xCKScheme scheme;
    NMSettingSecretFlags pw_flags;
    GError *local = NULL;
    char *tmp;

    if (!strcmp (type, NM_SSTP_CONTYPE_TLS)) {
        
        chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_ca_cert"));
        if (!nma_cert_chooser_validate (chooser, &local)) {
            g_set_error (error, 
                         NMV_EDITOR_PLUGIN_ERROR,
                         NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
                         "%s: %s", NM_SSTP_KEY_TLS_CA_CERT, local->message);
            g_error_free(local);
            return FALSE;
        }

        chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_user_cert"));
        if (!nma_cert_chooser_validate (chooser, &local)) {
            g_set_error (error, 
                         NMV_EDITOR_PLUGIN_ERROR,
                         NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
                         "%s: %s", NM_SSTP_KEY_TLS_USER_CERT, local->message);
            g_error_free(local);
            return FALSE;
        }

        /* Encrypted certificates require a password */
        tmp = nma_cert_chooser_get_cert (chooser, &scheme);
        encrypted = is_encrypted (tmp);
        g_free (tmp);

        pw_flags = nma_cert_chooser_get_key_password_flags (chooser);
        if (pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED ||
            pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
            secrets_required = FALSE;
        }

        if (encrypted && secrets_required) {
            if (!nma_cert_chooser_get_key_password (chooser)) {
                g_set_error (error,
                             NMV_EDITOR_PLUGIN_ERROR,
                             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
                             NM_SSTP_KEY_TLS_USER_KEY_SECRET);
                return FALSE;
            }
        }
    }
    /* Nothing to validate for NM_SSTP_CONTYPE_PASSWORD */
    return TRUE;
}

static gboolean
check_validity (SstpPluginUiWidget *self, GError **error)
{
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    GtkWidget *widget;
    GtkTreeModel *model;
    GtkTreeIter iter;
    gs_free char *auth_type = NULL;
    const char *str;
    gboolean status;

    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
    g_return_val_if_fail (widget, FALSE);
    str = gtk_entry_get_text (GTK_ENTRY (widget));
    if (str != NULL && strlen (str) > 0) {
        gtk_style_context_remove_class (gtk_widget_get_style_context (widget), "error");
    } else {
        gtk_style_context_add_class (gtk_widget_get_style_context (widget), "error");
        g_set_error (error,
                     NMV_EDITOR_PLUGIN_ERROR,
                     NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
                     NM_SSTP_KEY_GATEWAY);
        return FALSE;
    }

    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
    g_return_val_if_fail (widget, FALSE);

    model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
    g_return_val_if_fail (model, FALSE);

    status = gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
    g_return_val_if_fail (status, FALSE);

    gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);
    status = auth_widget_check_validity (priv->builder, auth_type, error);
    g_return_val_if_fail (status, FALSE);

    return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
    g_signal_emit_by_name (SSTP_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
    SstpPluginUiWidget *self = SSTP_PLUGIN_UI_WIDGET(user_data);
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    GtkWidget *auth_notebook;
    GtkTreeModel *model;
    GtkTreeIter iter;
    int new_page;
    gboolean status;

    model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
    status = gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
    g_assert (status);
    gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);

    auth_notebook = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_notebook"));
    gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

    stuff_changed_cb (combo, self);
}

static void
advanced_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
    gtk_widget_hide (dialog);
    /* gtk_widget_destroy() will remove the window from the window group */
    gtk_widget_destroy (dialog);
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
    SstpPluginUiWidget *self = SSTP_PLUGIN_UI_WIDGET (user_data);
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    GError *error = NULL;

    if (response != GTK_RESPONSE_OK) {
        advanced_dialog_close_cb (dialog, self);
        return;
    }

    if (priv->advanced) {
        g_hash_table_destroy (priv->advanced);
    }
    priv->advanced = advanced_dialog_new_hash_from_dialog (dialog, &error);
    if (!priv->advanced) {
        g_message ("%s: error reading advanced settings: %s", __func__, error->message);
        g_error_free (error);
    }
    advanced_dialog_close_cb (dialog, self);

    stuff_changed_cb (NULL, self);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
    SstpPluginUiWidget *self = SSTP_PLUGIN_UI_WIDGET (user_data);
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    GtkWidget *dialog, *toplevel;

    toplevel = gtk_widget_get_toplevel (priv->widget);
    g_return_if_fail (gtk_widget_is_toplevel (toplevel));

    dialog = advanced_dialog_new (priv->advanced);
    if (!dialog) {
        g_warning ("%s: failed to create the Advanced dialog!", __func__);
        return;
    }

    gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
    if (!priv->window_added) {
        gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
        priv->window_added = TRUE;
    }

    gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
    g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (advanced_dialog_response_cb), self);
    g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (advanced_dialog_close_cb), self);

    gtk_widget_show_all (dialog);
}

static void
show_toggled_cb (GtkCheckButton *button, SstpPluginUiWidget *self)
{
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    GtkWidget *widget;
    gboolean visible;

    visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
    g_assert (widget);
    gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
password_storage_changed_cb (GObject *entry, GParamSpec *pspec, gpointer user_data)
{
    SstpPluginUiWidget *self = SSTP_PLUGIN_UI_WIDGET (user_data);
    stuff_changed_cb (NULL, self);
}

static void
tls_cert_changed_cb (NMACertChooser *this, gpointer user_data)
{
    NMACertChooser *other = user_data;
    NMSetting8021xCKScheme scheme;
    gs_free char *this_cert = NULL;
    gs_free char *other_cert = NULL;
    gs_free char *this_key = NULL;
    gs_free char *other_key = NULL;

    other_key = nma_cert_chooser_get_key (other, &scheme);
    this_key = nma_cert_chooser_get_key (this, &scheme);
    other_cert = nma_cert_chooser_get_cert (other, &scheme);
    this_cert = nma_cert_chooser_get_cert (this, &scheme);
    if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
        && is_pkcs12 (this_cert)) {
        if (!this_key) {
            nma_cert_chooser_set_key (this, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
        }
        if (!other_cert) {
            nma_cert_chooser_set_cert (other, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
            if (!other_key) {
                nma_cert_chooser_set_key (other, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
            }
        }
    }
}

static gboolean
pw_setup(SstpPluginUiWidget *self, NMSettingVpn *s_vpn, ChangedCallback changed_cb) 
{
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
    GtkWidget *widget;
    const char *value;
    
    /* Username */
    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
    g_return_val_if_fail (widget != NULL, FALSE);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_USER);
        if (value && strlen (value))
            gtk_entry_set_text (GTK_ENTRY (widget), value);
    }
    g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), self);
    
    /* Domain */
    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
    g_return_val_if_fail (widget != NULL, FALSE);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_DOMAIN);
        if (value && strlen (value))
            gtk_entry_set_text (GTK_ENTRY (widget), value);
    }
    g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), self);
 
    /* Password */
    widget = GTK_WIDGET (gtk_builder_get_object(priv->builder, "user_password_entry"));
    g_return_val_if_fail (widget != NULL, FALSE);
    if (s_vpn) {
        value = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PASSWORD);
        if (value) {
            gtk_entry_set_text (GTK_ENTRY (widget), value);
        }
    }
    g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), self);

    nma_utils_setup_password_storage (widget, 0, (NMSetting *) s_vpn, NM_SSTP_KEY_PASSWORD,
                                      TRUE, FALSE);
    
    /* If there's no password and no flags in the setting initialize flags as "always-ask". */
    if (s_vpn) {
        nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_SSTP_KEY_PASSWORD, &pw_flags, NULL);
    }

    value = gtk_entry_get_text (GTK_ENTRY (widget));
    if ((!value || !*value) && (pw_flags == NM_SETTING_SECRET_FLAG_NONE)) {
        nma_utils_update_password_storage (widget, NM_SETTING_SECRET_FLAG_NOT_SAVED,
                           (NMSetting *) s_vpn, NM_SSTP_KEY_PASSWORD);
    }
    g_signal_connect (widget, "notify::secondary-icon-name",
                      G_CALLBACK (password_storage_changed_cb), self);

    /* Show Password */
    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
    g_return_val_if_fail (widget != NULL, FALSE);
    g_signal_connect (G_OBJECT (widget), "toggled", (GCallback) show_toggled_cb, self);

    return TRUE;
}

static gboolean
tls_setup(SstpPluginUiWidget *self, NMSettingVpn *s_vpn, ChangedCallback changed_cb) 
{
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    NMACertChooser *cert;
    NMACertChooser *ca;
    const char *value;
 
    cert = NMA_CERT_CHOOSER (gtk_builder_get_object (priv->builder, "tls_user_cert"));
    g_return_val_if_fail (cert != NULL, FALSE);
    nma_cert_chooser_add_to_size_group (cert, GTK_SIZE_GROUP (gtk_builder_get_object (priv->builder, "labels")));
    g_signal_connect (G_OBJECT (cert), "changed", G_CALLBACK (changed_cb), self);
    
    ca = NMA_CERT_CHOOSER (gtk_builder_get_object (priv->builder, "tls_ca_cert"));
    g_return_val_if_fail (ca != NULL, FALSE);
    nma_cert_chooser_add_to_size_group (ca, GTK_SIZE_GROUP (gtk_builder_get_object (priv->builder, "labels")));
    g_signal_connect (G_OBJECT (ca), "changed", G_CALLBACK (changed_cb), self);

    if (s_vpn) {
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_CA_CERT);
        if (value && *value) {
            nma_cert_chooser_set_cert (ca, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
        }
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_CERT);
        if (value && *value) {
            nma_cert_chooser_set_cert (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
        }
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_KEY);
        if (value && *value) {
            nma_cert_chooser_set_key (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
        }
        value = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_TLS_USER_KEY_SECRET);
        if (value) {
            nma_cert_chooser_set_key_password (cert, value);
        }
    }

    nma_cert_chooser_setup_key_password_storage (cert, 0, (NMSetting *) s_vpn,
            NM_SSTP_KEY_TLS_USER_KEY_SECRET, TRUE, FALSE);

    /* Link choosers to the PKCS#12 changer callback */
    g_signal_connect_object (ca, "changed", G_CALLBACK (tls_cert_changed_cb), cert, 0);
    g_signal_connect_object (cert, "changed", G_CALLBACK (tls_cert_changed_cb), ca, 0);

    return TRUE;
}

static gboolean
init_plugin_ui (SstpPluginUiWidget *self, NMConnection *connection, GError **error)
{
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    NMSettingVpn *s_vpn;
    GtkWidget *widget;
    GtkListStore *store;
    GtkTreeIter iter;
    int active = -1;
    const char *value;
    const char *contype = NM_SSTP_CONTYPE_PASSWORD;

    s_vpn = nm_connection_get_setting_vpn (connection);

    /* Gateway */
    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
    g_return_val_if_fail (widget != NULL, FALSE);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_GATEWAY);
        if (value && strlen (value)) {
            gtk_entry_set_text (GTK_ENTRY (widget), value);
        }
    }
    g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

    /* Authentication Combo */
    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
    g_return_val_if_fail (widget != NULL, FALSE);
    if (s_vpn) {
        contype = nm_setting_vpn_get_data_item (s_vpn, NM_SSTP_KEY_CONNECTION_TYPE);
        if (!NM_IN_STRSET (contype, NM_SSTP_CONTYPE_TLS,
                                    NM_SSTP_CONTYPE_PASSWORD))
            contype = NM_SSTP_CONTYPE_PASSWORD;
    }

    /* Certificate (TLS) Tab */
    store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter,
                        COL_AUTH_NAME, _("Certificates (TLS)"),
                        COL_AUTH_PAGE, 0,
                        COL_AUTH_TYPE, NM_SSTP_CONTYPE_TLS,
                        -1);
    tls_setup(self, s_vpn, stuff_changed_cb);

    /* Password Tab */
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter,
                        COL_AUTH_NAME, _("Password"),
                        COL_AUTH_PAGE, 1,
                        COL_AUTH_TYPE, NM_SSTP_CONTYPE_PASSWORD,
                        -1);
    pw_setup(self, s_vpn, stuff_changed_cb);

    if (active < 0
        && nm_streq (contype, NM_SSTP_CONTYPE_PASSWORD)) {
        active = 1;
    }

    /* Apply Auth-Combo changes */
    gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
    g_object_unref (store);
    g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
    gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
    
    /* Advanced button */
    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
    g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);
    return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
    SstpPluginUiWidget *self = SSTP_PLUGIN_UI_WIDGET (iface);
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

    return G_OBJECT (priv->widget);
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
    NMSettingVpn *s_vpn = NM_SETTING_VPN (user_data);
    
    /* HTTP Proxy password is a secret, not a data item */
    if (NM_IN_SET (key, NM_SSTP_KEY_PROXY_PASSWORD)) {
        nm_setting_vpn_add_secret (s_vpn, (const char *) key, 
                          (const char *) data);
    } else {
        nm_setting_vpn_add_data_item (s_vpn, (const char *) key, (const char *) data);
    }
}

static char *
get_auth_type (GtkBuilder *builder)
{
    GtkComboBox *combo;
    GtkTreeModel *model;
    GtkTreeIter iter;
    char *auth_type;
    gboolean success;

    combo = GTK_COMBO_BOX (GTK_WIDGET (gtk_builder_get_object (builder, "auth_combo")));
    model = gtk_combo_box_get_model (combo);

    success = gtk_combo_box_get_active_iter (combo, &iter);
    g_return_val_if_fail (success == TRUE, NULL);
    gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);
    return auth_type;
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
    SstpPluginUiWidget *self = SSTP_PLUGIN_UI_WIDGET (iface);
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
    NMSettingVpn *s_vpn;
    NMSetting8021xCKScheme scheme;
    NMSettingSecretFlags flags;
    NMACertChooser *chooser;
    GtkWidget *widget;
    gs_free char *auth_type = NULL;
    const char *str;
    char *value;

    if (!check_validity (self, error)) {
        return FALSE;
    }

    s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
    g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_SSTP, NULL);

    /* Gateway */
    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
    str = gtk_entry_get_text (GTK_ENTRY (widget));
    if (str && strlen (str)) {
        nm_setting_vpn_add_data_item (s_vpn, NM_SSTP_KEY_GATEWAY, str);
    }

    auth_type = get_auth_type (priv->builder);
    if (auth_type) {

        nm_setting_vpn_add_data_item (s_vpn, NM_SSTP_KEY_CONNECTION_TYPE, auth_type);

        if (!strcmp(auth_type, NM_SSTP_CONTYPE_PASSWORD)) {

            /* Username */
            widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
            str = gtk_entry_get_text (GTK_ENTRY (widget));
            if (str && strlen (str)) {
                nm_setting_vpn_add_data_item (s_vpn, NM_SSTP_KEY_USER, str);
            }

            /* User password */
            widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
            str = gtk_entry_get_text (GTK_ENTRY (widget));
            if (str && *str) {
                nm_setting_vpn_add_secret (s_vpn, NM_SSTP_KEY_PASSWORD, str);
            }

            /* User password flags */
            flags = nma_utils_menu_to_secret_flags (widget);
            nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_SSTP_KEY_PASSWORD, flags, NULL);

            /* Domain */
            widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
            str = gtk_entry_get_text (GTK_ENTRY (widget));
            if (str && strlen (str)) {
                nm_setting_vpn_add_data_item (s_vpn, NM_SSTP_KEY_DOMAIN, str);
            }
        }
        else if (!strcmp(auth_type, NM_SSTP_CONTYPE_TLS)) {
             
            chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (priv->builder, "tls_user_cert"));

            /* User certificate */
            value = nma_cert_chooser_get_cert (chooser, &scheme);
            if (value && *value) {
                nm_setting_vpn_add_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_CERT, value);
                g_free (value);
            }

            /* User Certificate Key File */
            value = nma_cert_chooser_get_key (chooser, &scheme);
            if (value && *value) {
                nm_setting_vpn_add_data_item (s_vpn, NM_SSTP_KEY_TLS_USER_KEY, value);
                g_free (value);
            }

            /* User Certificate Key Password */
            str = nma_cert_chooser_get_key_password (chooser);
            if (str && *str) {
                nm_setting_vpn_add_secret (s_vpn, NM_SSTP_KEY_TLS_USER_KEY_SECRET, str);
            }

            /* User Certificate Key Password Flags */
            flags = nma_cert_chooser_get_key_password_flags (chooser);
            nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_SSTP_KEY_TLS_USER_KEY_SECRET, 
                    flags, NULL);

            /* CA certificate for the EAP-TLS tunnel */
            chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (priv->builder, "tls_ca_cert"));
            value = nma_cert_chooser_get_cert (chooser, &scheme);
            if (value && *value) {
                nm_setting_vpn_add_data_item (s_vpn, NM_SSTP_KEY_TLS_CA_CERT, value);
                g_free (value);
            }
        }
        else {
            return FALSE;
        }
    }

    /* Account for the advanced options */
    if (priv->advanced) {
         g_hash_table_foreach (priv->advanced, hash_copy_advanced, s_vpn);
    }

    /* Default to agent owned secret for new connections */
    if (priv->new_connection) {
        if (nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PASSWORD)) {
            nm_setting_set_secret_flags (NM_SETTING(s_vpn),
                                         NM_SSTP_KEY_PASSWORD,
                                         NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                         NULL);
        }

        if (nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_TLS_USER_KEY_SECRET)) {
            nm_setting_set_secret_flags (NM_SETTING(s_vpn),
                                         NM_SSTP_KEY_TLS_USER_KEY_SECRET,
                                         NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                         NULL);
        }

        if (nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PROXY_PASSWORD)) {
            nm_setting_set_secret_flags (NM_SETTING(s_vpn),
                                         NM_SSTP_KEY_PROXY_PASSWORD,
                                         NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                         NULL);
        }
    }

    /* Save the setting */
    nm_connection_add_setting (connection, NM_SETTING (s_vpn));
    return TRUE;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
    gboolean *is_new = user_data;

    /* If there are any VPN data items the connection isn't new */
    *is_new = FALSE;
}

/*****************************************************************************/

static void
sstp_plugin_ui_widget_init (SstpPluginUiWidget *plugin)
{
}

NMVpnEditor *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
    NMVpnEditor *object;
    SstpPluginUiWidgetPrivate *priv;
    gboolean new = TRUE;
    NMSettingVpn *s_vpn;

    if (error)
        g_return_val_if_fail (*error == NULL, NULL);

    object = NM_VPN_EDITOR (g_object_new (SSTP_TYPE_PLUGIN_UI_WIDGET, NULL));
    if (!object) {
        g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not create sstp object");
        return NULL;

    }

    priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (object);
    priv->builder = gtk_builder_new ();
    gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);
    if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-sstp/nm-sstp-dialog.ui", error)) {
        g_object_unref (object);
        return NULL;
    }

    priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "sstp-vbox"));
    if (!priv->widget) {
        g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
        g_object_unref (object);
        return NULL;
    }
    g_object_ref_sink (priv->widget);

    priv->window_group = gtk_window_group_new ();

    s_vpn = nm_connection_get_setting_vpn (connection);
    if (s_vpn)
        nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
    priv->new_connection = new;

    if (!init_plugin_ui (SSTP_PLUGIN_UI_WIDGET (object), connection, error)) {
        g_object_unref (object);
        return NULL;
    }

    priv->advanced = advanced_dialog_new_hash_from_connection (connection, error);
    if (!priv->advanced) {
        g_object_unref (object);
        return NULL;
    }

    return object;
}

static void
dispose (GObject *object)
{
    SstpPluginUiWidget *plugin = SSTP_PLUGIN_UI_WIDGET (object);
    SstpPluginUiWidgetPrivate *priv = SSTP_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);
    GtkWidget *widget;

    widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
    g_signal_handlers_disconnect_by_func (G_OBJECT (widget),
                                          (GCallback) password_storage_changed_cb,
                                          plugin);

    if (priv->window_group)
        g_object_unref (priv->window_group);

    if (priv->widget)
        g_object_unref (priv->widget);

    if (priv->builder)
        g_object_unref (priv->builder);

    if (priv->advanced)
        g_hash_table_destroy (priv->advanced);

    G_OBJECT_CLASS (sstp_plugin_ui_widget_parent_class)->dispose (object);
}

static void
sstp_plugin_ui_widget_class_init (SstpPluginUiWidgetClass *req_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (req_class);

    g_type_class_add_private (req_class, sizeof (SstpPluginUiWidgetPrivate));

    object_class->dispose = dispose;
}

static void
sstp_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class)
{
    iface_class->get_widget = get_widget;
    iface_class->update_connection = update_connection;
}

/*****************************************************************************/

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL)

#include "nm-sstp-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_sstp (NMVpnEditorPlugin *editor_plugin,
                            NMConnection *connection,
                            GError **error)
{
    g_return_val_if_fail (!error || !*error, NULL);

    return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}
#endif

