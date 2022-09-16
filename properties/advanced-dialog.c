/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
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
#include "advanced-dialog.h"

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

#define COL_NAME      0
#define COL_VALUE     1
#define COL_TAG       2
#define COL_SENSITIVE 3

#define TAG_PAP       0
#define TAG_CHAP      1
#define TAG_MSCHAP    2
#define TAG_MSCHAPV2  3
#define TAG_EAP       4

#define PAGE_CONNECTION  0
#define PAGE_POINT2POINT 1
#define PAGE_TLS         2
#define PAGE_PROXY       3

static const char *advanced_keys[] = {
    NM_SSTP_KEY_REFUSE_EAP,
    NM_SSTP_KEY_REFUSE_PAP,
    NM_SSTP_KEY_REFUSE_CHAP,
    NM_SSTP_KEY_REFUSE_MSCHAP,
    NM_SSTP_KEY_REFUSE_MSCHAPV2,
    NM_SSTP_KEY_REQUIRE_MPPE,
    NM_SSTP_KEY_REQUIRE_MPPE_40,
    NM_SSTP_KEY_REQUIRE_MPPE_128,
    NM_SSTP_KEY_MPPE_STATEFUL,
    NM_SSTP_KEY_NOBSDCOMP,
    NM_SSTP_KEY_NODEFLATE,
    NM_SSTP_KEY_NO_VJ_COMP,
    NM_SSTP_KEY_LCP_ECHO_FAILURE,
    NM_SSTP_KEY_LCP_ECHO_INTERVAL,
    NM_SSTP_KEY_UNIT_NUM,
    NM_SSTP_KEY_MTU,
    NM_SSTP_KEY_PROXY_SERVER,
    NM_SSTP_KEY_PROXY_PORT,
    NM_SSTP_KEY_PROXY_USER,
    NM_SSTP_KEY_PROXY_PASSWORD,
    NM_SSTP_KEY_IGN_CERT_WARN,
    NM_SSTP_KEY_CA_CERT,
    NM_SSTP_KEY_CRL_REVOCATION_FILE,
    NM_SSTP_KEY_TLS_EXT_ENABLE,
    NM_SSTP_KEY_TLS_IDENTITY,
    NM_SSTP_KEY_TLS_VERIFY_METHOD,
    NM_SSTP_KEY_TLS_VERIFY_KEY_USAGE,
    NM_SSTP_KEY_TLS_REMOTENAME,
    NM_SSTP_KEY_TLS_MAX_VERSION,
    NULL
};


static void
show_proxy_password_toggled_cb (GtkCheckButton *button, gpointer user_data)
{
    GtkBuilder *builder = (GtkBuilder *) user_data;
    GtkWidget *widget;
    gboolean visible;
    
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
    g_assert (widget);
    
    visible = gtk_check_button_get_active (GTK_CHECK_BUTTON (button));
    gtk_entry_set_visibility (GTK_ENTRY(widget), visible);
}

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
    GHashTable *hash = (GHashTable *) user_data;
    const char **i;

    for (i = &advanced_keys[0]; *i; i++) {
        if (strcmp (key, *i))
            continue;
        g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
    }
}

GHashTable *
advanced_dialog_new_hash_from_connection (NMConnection *connection,
                                         GError **error)
{
    GHashTable *hash;
    NMSettingVpn *s_vpn;
    const char *secret;
    NMSettingSecretFlags flags;

    hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

    s_vpn = nm_connection_get_setting_vpn (connection);
    nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

    /* HTTP Proxy Password is special */
    secret = nm_setting_vpn_get_secret (s_vpn, NM_SSTP_KEY_PROXY_PASSWORD);
    if (secret) {
        g_hash_table_insert (hash,
                             g_strdup(NM_SSTP_KEY_PROXY_PASSWORD),
                             g_strdup(secret));
    }
    
    if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_SSTP_KEY_PROXY_PASSWORD, &flags, NULL)) {
        g_hash_table_insert (hash,
                             g_strdup(NM_SSTP_KEY_PROXY_PASSWORD_FLAGS),
                             g_strdup_printf("%d", flags));
    }
    
    /* Default to disable PAP */
    if (!g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_PAP)) {
        g_hash_table_insert (hash,
                             g_strdup(NM_SSTP_KEY_REFUSE_PAP),
                             g_strdup("yes"));
    }

    /* Default to disable CHAP */
    if (!g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_CHAP)) {
        g_hash_table_insert (hash,
                             g_strdup(NM_SSTP_KEY_REFUSE_CHAP),
                             g_strdup("yes"));
    }

    /* Default to use tls hostname extensions */
    if (!g_hash_table_lookup (hash, NM_SSTP_KEY_TLS_EXT_ENABLE)) {
        g_hash_table_insert (hash,
                             g_strdup(NM_SSTP_KEY_TLS_EXT_ENABLE),
                             g_strdup("yes"));
    }

    return hash;
}

static void handle_mppe_changed (GtkWidget *check, gboolean is_init, GtkBuilder *builder)
{
    GtkWidget *widget;
    gboolean use_mppe;
    gboolean mppe_sensitive;
    GtkTreeModel *model;
    GtkTreeIter iter;
    gboolean valid;

    mppe_sensitive = gtk_widget_get_sensitive (check);
    use_mppe = gtk_check_button_get_active (GTK_CHECK_BUTTON (check));

    /* (De)-sensitize MPPE related stuff */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mppe_security_label"));
    gtk_widget_set_sensitive (widget, use_mppe && mppe_sensitive);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mppe_security_combo"));
    gtk_widget_set_sensitive (widget, use_mppe && mppe_sensitive);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_stateful_mppe"));
    gtk_widget_set_sensitive (widget, use_mppe && mppe_sensitive);

    /* At dialog-setup time, don't touch the auth methods if MPPE is disabled
     * since that could overwrite the user's previously chosen auth methods.
     * But ensure that at init time if MPPE is on that incompatible auth methods
     * aren't selected.
     */
    if (is_init && !use_mppe)
        return;

    /* If MPPE is active, PAP, CHAP aren't allowed by the MPPE specs;
     * likewise, if MPPE is inactive, sensitize the PAP, CHAP, and EAP checkboxes.
     */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_auth_methods"));
    model = gtk_tree_view_get_model (GTK_TREE_VIEW (widget));
    valid = gtk_tree_model_get_iter_first (model, &iter);
    while (valid) {
        guint32 tag;

        gtk_tree_model_get (model, &iter, COL_TAG, &tag, -1);
        switch (tag) {
        case TAG_PAP:
        case TAG_CHAP:
            gtk_list_store_set (GTK_LIST_STORE (model), &iter, COL_SENSITIVE, !(use_mppe && mppe_sensitive), -1);
            break;
        default:
            break;
        }

        valid = gtk_tree_model_iter_next (model, &iter);
    }
}

static void
mppe_toggled_cb (GtkWidget *check, gpointer user_data)
{
    handle_mppe_changed (check, FALSE, (GtkBuilder *) user_data);
}

#define SEC_INDEX_DEFAULT   0
#define SEC_INDEX_MPPE_128  1
#define SEC_INDEX_MPPE_40   2

static void
setup_security_combo (GtkBuilder *builder, GHashTable *hash)
{
    GtkWidget *widget;
    GtkListStore *store;
    GtkTreeIter iter;
    int active = -1;
    const char *value;

    g_return_if_fail (builder != NULL);
    g_return_if_fail (hash != NULL);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mppe_security_combo"));

    store = gtk_list_store_new (1, G_TYPE_STRING);

    /* Default (allow use of all encryption types that both server and client support) */
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter, 0, _("All Available (Default)"), -1);

    /* MPPE-128 */
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter, 0, _("128-bit (most secure)"), -1);
    if (active < 0) {
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE_128);
        if (value && !strcmp (value, "yes"))
            active = SEC_INDEX_MPPE_128;
    }

    /* MPPE-40 */
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter, 0, _("40-bit (less secure)"), -1);
    if (active < 0) {
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE_40);
        if (value && !strcmp (value, "yes"))
            active = SEC_INDEX_MPPE_40;
    }

    gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
    g_object_unref (store);
    gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? SEC_INDEX_DEFAULT : active);
}

static void
check_toggled_cb (GtkCellRendererToggle *cell, gchar *path_str, gpointer user_data)
{
    GtkBuilder *builder = (GtkBuilder *) user_data;
    GtkWidget *widget;
    GtkTreePath *path = gtk_tree_path_new_from_string (path_str);
    GtkTreeModel *model;
    GtkTreeIter iter;
    gboolean toggle_item;
    gboolean valid;
    gboolean mppe = FALSE;

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_auth_methods"));
    model = gtk_tree_view_get_model (GTK_TREE_VIEW (widget));

    gtk_tree_model_get_iter (model, &iter, path);
    gtk_tree_model_get (model, &iter, COL_VALUE, &toggle_item, -1);

    toggle_item ^= 1;

    /* set new value */
    gtk_list_store_set (GTK_LIST_STORE (model), &iter, COL_VALUE, toggle_item, -1);

    gtk_tree_path_free (path);

    /* If MSCHAP and MSCHAPv2 are both disabled, also disable MPPE */
    valid = gtk_tree_model_get_iter_first (model, &iter);
    while (valid) {
        gboolean allowed;
        guint32 tag;

        gtk_tree_model_get (model, &iter, COL_VALUE, &allowed, COL_TAG, &tag, -1);
        switch (tag) {
        case TAG_MSCHAP:
            if (allowed) {
                mppe = TRUE;
            }
            break;
        case TAG_MSCHAPV2:
            if (allowed) {
                mppe = TRUE;
            }
            break;
        case TAG_EAP:
            if (allowed) {
                mppe = TRUE;
            }
            break;
        default:
            break;
        }

        valid = gtk_tree_model_iter_next (model, &iter);
    }
    /* Make sure MPPE is non-sensitive if MSCHAP, MSCHAPv2 and EAP are disabled */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
    if (!mppe) {
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);
        gtk_widget_set_sensitive (widget, FALSE);
    } else {
        gtk_widget_set_sensitive (widget, TRUE);
    }
    /* Make sure also MPPE security combo and stateful checkbox are non-sensitive */
    mppe_toggled_cb (widget, builder);
}

static void
auth_methods_setup (GtkBuilder *builder, GHashTable *hash)
{
    GtkWidget *widget;
    GtkListStore *store;
    GtkTreeIter iter;
    const char *value;
    gboolean allowed;
    gboolean use_mppe = FALSE;
    GtkCellRendererToggle *check_renderer;
    GtkCellRenderer *text_renderer;
    GtkTreeViewColumn *column;
    gint offset;
    gboolean mschap_state = TRUE;
    gboolean mschap2_state = TRUE;
    gboolean eap_state = TRUE;

    store = gtk_list_store_new (4, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_UINT, G_TYPE_BOOLEAN);

    /* Check for MPPE */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE);
    if (value && !strcmp (value, "yes"))
        use_mppe = TRUE;

    /* Or MPPE-128 */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE_128);
    if (value && !strcmp (value, "yes"))
        use_mppe = TRUE;

    /* Or MPPE-40 */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE_40);
    if (value && !strcmp (value, "yes"))
        use_mppe = TRUE;

    /* PAP */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_PAP);
    allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
    if (use_mppe)
        allowed = FALSE;
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter,
                        COL_NAME, _("PAP"),
                        COL_VALUE, allowed,
                        COL_TAG, TAG_PAP,
                        COL_SENSITIVE, !use_mppe,
                        -1);

    /* CHAP */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_CHAP);
    allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
    if (use_mppe)
        allowed = FALSE;
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter,
                        COL_NAME, _("CHAP"),
                        COL_VALUE, allowed,
                        COL_TAG, TAG_CHAP,
                        COL_SENSITIVE, !use_mppe,
                        -1);

    /* MSCHAP */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_MSCHAP);
    allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
    mschap_state = allowed;
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter,
                        COL_NAME, _("MSCHAP"),
                        COL_VALUE, allowed,
                        COL_TAG, TAG_MSCHAP,
                        COL_SENSITIVE, TRUE,
                        -1);

    /* MSCHAPv2 */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_MSCHAPV2);
    allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
    mschap2_state = allowed;
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter,
                        COL_NAME, _("MSCHAPv2"),
                        COL_VALUE, allowed,
                        COL_TAG, TAG_MSCHAPV2,
                        COL_SENSITIVE, TRUE,
                        -1);

    /* EAP */
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_EAP);
    allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
    eap_state = allowed;
    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter,
                        COL_NAME, _("EAP"),
                        COL_VALUE, allowed,
                        COL_TAG, TAG_EAP,
                        COL_SENSITIVE, TRUE,
                        -1);

    /* Set up the tree view */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_auth_methods"));
    gtk_tree_view_set_model (GTK_TREE_VIEW (widget), GTK_TREE_MODEL (store));

    check_renderer = GTK_CELL_RENDERER_TOGGLE (gtk_cell_renderer_toggle_new ());
    g_signal_connect (check_renderer, "toggled", G_CALLBACK (check_toggled_cb), builder);

    offset = gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (widget),
                                                          -1, "", GTK_CELL_RENDERER (check_renderer),
                                                          "active", COL_VALUE,
                                                          "sensitive", COL_SENSITIVE,
                                                          "activatable", COL_SENSITIVE,
                                                          NULL);
    column = gtk_tree_view_get_column (GTK_TREE_VIEW (widget), offset - 1);
    gtk_tree_view_column_set_sizing (GTK_TREE_VIEW_COLUMN (column), GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_fixed_width (GTK_TREE_VIEW_COLUMN (column), 30);
    gtk_tree_view_column_set_clickable (GTK_TREE_VIEW_COLUMN (column), TRUE);

    text_renderer = gtk_cell_renderer_text_new ();
    offset = gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (widget),
                                                          -1, "", text_renderer,
                                                          "text", COL_NAME,
                                                          "sensitive", COL_SENSITIVE,
                                                          NULL);
    column = gtk_tree_view_get_column (GTK_TREE_VIEW (widget), offset - 1);
    gtk_tree_view_column_set_expand (GTK_TREE_VIEW_COLUMN (column), TRUE);

    /* Make sure MPPE is non-sensitive if MSCHAP and MSCHAPv2 are disabled */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
    if (!mschap_state && !mschap2_state && !eap_state) {
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);
        gtk_widget_set_sensitive (widget, FALSE);
    } else
        gtk_widget_set_sensitive (widget, TRUE);
}

static void
tls_page_setup(GtkBuilder *builder, GHashTable *hash, gboolean is_tls, gchar *subject)
{
    GtkWidget *widget, *page;
    GtkListStore *store;
    GtkTreeIter iter;
    const char  *value;
    int active = -1;

    if (is_tls) {
        // Use the user-specified value for identity, or extracted subject name if not specified
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_identity"));
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_TLS_IDENTITY);
        if (value && strlen (value)) {
            gtk_editable_set_text (GTK_EDITABLE (widget), value);
        }
        else if (subject && strlen (subject)) {
            gtk_editable_set_text (GTK_EDITABLE (widget), subject);
        }

        value = g_hash_table_lookup (hash, NM_SSTP_KEY_TLS_VERIFY_METHOD);
        store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, _("Don't verify certificate identification"),
                            COL_VALUE, NM_SSTP_VERIFY_MODE_NONE,
                            -1);
        if (nm_streq0 (value, NM_SSTP_VERIFY_MODE_NONE))
            active = 0;

        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, _("Verify subject exactly"),
                            COL_VALUE, NM_SSTP_VERIFY_MODE_SUBJECT,
                            -1);
        if (nm_streq0 (value, NM_SSTP_VERIFY_MODE_SUBJECT))
            active = 1;

        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, _("Verify name exactly"),
                            COL_VALUE, NM_SSTP_VERIFY_MODE_NAME,
                            -1);
        if (nm_streq0 (value, NM_SSTP_VERIFY_MODE_NAME))
            active = 2;

        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, _("Verify name by suffix"),
                            COL_VALUE, NM_SSTP_VERIFY_MODE_NAME_SUFFIX,
                            -1);
        if (nm_streq0 (value, NM_SSTP_VERIFY_MODE_NAME_SUFFIX))
            active = 3;

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
        gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
        if (active >= 0)
            gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active);
        g_object_unref (store);

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_TLS_REMOTENAME);
        if (value && strlen (value)) {
          gtk_editable_set_text (GTK_EDITABLE (widget), value);
        }

        active = -1;
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_keyusage_check"));
        gtk_check_button_set_active (GTK_CHECK_BUTTON(widget), FALSE);
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_TLS_VERIFY_KEY_USAGE);
        if (value && !strcmp (value, "yes"))
            gtk_check_button_set_active (GTK_CHECK_BUTTON(widget), TRUE);

#ifndef USE_PPP_EXT_TLS_SETTINGS
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "vbox_tls_validation"));
        gtk_widget_set_sensitive(widget, FALSE);
#endif

        value = g_hash_table_lookup (hash, NM_SSTP_KEY_TLS_MAX_VERSION);
        store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, "TLS 1.0",
                            COL_VALUE, NM_SSTP_TLS_1_0_SUPPORT,
                            -1);
        if (nm_streq0 (value, NM_SSTP_TLS_1_0_SUPPORT))
            active = 0;

        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, "TLS 1.1",
                            COL_VALUE, NM_SSTP_TLS_1_1_SUPPORT,
                            -1);
        if (nm_streq0 (value, NM_SSTP_TLS_1_1_SUPPORT))
            active = 1;

        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, _("TLS 1.2 (Default)"),
                            COL_VALUE, NM_SSTP_TLS_1_2_SUPPORT,
                            -1);
        if (nm_streq0 (value, NM_SSTP_TLS_1_2_SUPPORT))
            active = 2;

        gtk_list_store_append (store, &iter);
        gtk_list_store_set (store, &iter,
                            COL_NAME, _("TLS 1.3"),
                            COL_VALUE, NM_SSTP_TLS_1_3_SUPPORT,
                            -1);
        if (nm_streq0 (value, NM_SSTP_TLS_1_3_SUPPORT))
            active = 3;

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_max_combo"));
        gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
        if (active > 0)
            gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active);
        g_object_unref (store);

#ifndef USE_PPP_EXT_TLS_SETTINGS
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "vbox_tls_version"));
        gtk_widget_set_sensitive(widget, FALSE);
#endif

    } else {
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "adv_notebook"));
        page = GTK_WIDGET (gtk_notebook_get_nth_page(GTK_NOTEBOOK(widget), PAGE_TLS));
        gtk_widget_hide(page);
    }
}

static void
checkbox_toggled_update_widget_cb (GtkWidget *check, gpointer user_data)
{
    GtkWidget *widget = (GtkWidget*) user_data;

    gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

GtkWidget *
advanced_dialog_new (GHashTable *hash, gboolean is_tls, gchar *subject)
{
    GtkBuilder *builder;
    GtkWidget *dialog = NULL;
    GtkWidget *widget, *spin;
    NMACertChooser *cert;
    const char *value;
    const char *value2;
    gboolean mppe = FALSE;
    GError *error = NULL;
    NMSettingSecretFlags pw_flags;

    g_return_val_if_fail (hash != NULL, NULL);

    builder = gtk_builder_new ();

    gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);
    if (!gtk_builder_add_from_resource (builder, "/org/freedesktop/network-manager-sstp/nm-sstp-dialog.ui", &error)) {
        g_warning ("Couldn't load builder file: %s",
                   error ? error->message : "(unknown)");
        g_clear_error (&error);
        g_object_unref (G_OBJECT (builder));
        return NULL;
    }

    dialog = GTK_WIDGET (gtk_builder_get_object (builder, "sstp-advanced-dialog"));
    if (!dialog) {
        g_object_unref (G_OBJECT (builder));
        return NULL;
    }
    gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

    g_object_set_data_full (G_OBJECT (dialog), "gtkbuilder-xml",
                            builder, (GDestroyNotify) g_object_unref);

    cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_ca_cert_chooser"));
    if (cert) {
        nma_cert_chooser_add_to_size_group (cert, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels_group_3")));
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_CA_CERT);
        if (value && strlen (value) && access(value, R_OK) == 0) {
            nma_cert_chooser_set_cert (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
        }
    }

    cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_crl_cert_chooser"));
    if (cert) {
        nma_cert_chooser_add_to_size_group (cert, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels_group_3")));
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_CRL_REVOCATION_FILE);
        if (value && strlen (value) && access(value, R_OK) == 0) {
            nma_cert_chooser_set_cert (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
        }
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_cert_warn_checkbutton"));
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_IGN_CERT_WARN);
    if (!value || !strcmp (value, "no")) {
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_hostext_checkbutton"));
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_TLS_EXT_ENABLE);
    if (value && !strcmp (value, "yes")) {
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
    }

    setup_security_combo (builder, hash);

    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE);
    if (value && !strcmp (value, "yes"))
        mppe = TRUE;

    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE_40);
    if (value && !strcmp (value, "yes"))
        mppe = TRUE;

    value = g_hash_table_lookup (hash, NM_SSTP_KEY_REQUIRE_MPPE_128);
    if (value && !strcmp (value, "yes"))
        mppe = TRUE;

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
    if (mppe)
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_stateful_mppe"));
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_MPPE_STATEFUL);
    if (value && !strcmp (value, "yes"))
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_bsdcomp"));
    gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_NOBSDCOMP);
    if (value && !strcmp (value, "yes"))
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_deflate"));
    gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_NODEFLATE);
    if (value && !strcmp (value, "yes"))
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_usevj"));
    gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_NO_VJ_COMP);
    if (value && !strcmp (value, "yes"))
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_send_echo_packets"));
    value = g_hash_table_lookup (hash, NM_SSTP_KEY_LCP_ECHO_INTERVAL);
    if (value && strlen (value)) {
        long int tmp_int;

        errno = 0;
        tmp_int = strtol (value, NULL, 10);
        if (errno == 0 && tmp_int > 0)
            gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
    }

    auth_methods_setup (builder, hash);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
    handle_mppe_changed (widget, TRUE, builder);
    g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (mppe_toggled_cb), builder);

    tls_page_setup (builder, hash, is_tls, subject);

    value = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_SERVER);
    value2 = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_PORT);
    if (value && strlen(value) && value2 && strlen(value2))
    {
        long int tmp;

        errno = 0;
        tmp = strtol (value2, NULL, 10);
        if (errno != 0 || tmp < 0 || tmp > 65535)
            tmp = 0;
        
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
        gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
        
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
        gtk_editable_set_text (GTK_EDITABLE (widget), value);
        
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_USER);
        if (value && strlen (value)) {
            widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
            gtk_editable_set_text (GTK_EDITABLE (widget), value);
        }
        
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_PASSWORD);
        if (value && strlen (value)) {
            widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
            gtk_editable_set_text (GTK_EDITABLE (widget), value);
        }
        
        value = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_PASSWORD_FLAGS);
        G_STATIC_ASSERT_EXPR (((guint) (NMSettingSecretFlags) 0xFFFFu) == 0xFFFFu);
        pw_flags = _nm_utils_ascii_str_to_int64 (value, 10, 0, 0xFFFF, NM_SETTING_SECRET_FLAG_NONE);
    } else {
        pw_flags = NM_SETTING_SECRET_FLAG_NONE;
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
    nma_utils_setup_password_storage (widget, pw_flags, NULL, NULL,
                                      TRUE, FALSE);

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "show_proxy_password"));
    g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (show_proxy_password_toggled_cb), builder);
    
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_checkbutton"));
    spin = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_spinbutton"));
    g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

    value = g_hash_table_lookup (hash, NM_SSTP_KEY_UNIT_NUM);
    if (value && *value) {
        long int tmp;

        errno = 0;
        tmp = strtol (value, NULL, 10);
        if (errno == 0 && tmp >= 0 && tmp < 65536) {
            gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

            widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_spinbutton"));
            gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
            gtk_widget_set_sensitive (widget, TRUE);
        }
    } else {
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_spinbutton"));
        gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 0.0);
        gtk_widget_set_sensitive (widget, FALSE);
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mtu_checkbutton"));
    spin = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mtu_spinbutton"));
    g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

    value = g_hash_table_lookup (hash, NM_SSTP_KEY_MTU);
    if (value && *value) {
        long int tmp;

        errno = 0;
        tmp = strtol (value, NULL, 10);
        if (errno == 0 && tmp >= 0 && tmp <= 1500) {
            gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

            widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mtu_spinbutton"));
            gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
            gtk_widget_set_sensitive (widget, TRUE);
        }
    } else {
        gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mtu_spinbutton"));
        gtk_widget_set_sensitive (widget, FALSE);
    }

    return dialog;
}

GHashTable *
advanced_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
    GHashTable *hash;
    GtkWidget *widget;
    GtkBuilder *builder;
    GtkTreeModel *model;
    GtkTreeIter iter;
    NMACertChooser *cert;
    NMSetting8021xCKScheme scheme;
    gboolean valid;
    const char *value;

    g_return_val_if_fail (dialog != NULL, NULL);
    if (error)
        g_return_val_if_fail (*error == NULL, NULL);

    builder = g_object_get_data (G_OBJECT (dialog), "gtkbuilder-xml");
    g_return_val_if_fail (builder != NULL, NULL);

    hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    
    cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_ca_cert_chooser"));
    if (cert) {
        value = nma_cert_chooser_get_cert(cert, &scheme);
        if (value && strlen (value)) {
            g_hash_table_insert (hash,
                                 g_strdup (NM_SSTP_KEY_CA_CERT),
                                 (char*) value);
        }
    }

    cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, "tls_crl_cert_chooser"));
    if (cert) {
        value = nma_cert_chooser_get_cert(cert, &scheme);
        if (value && strlen (value)) {
            g_hash_table_insert (hash,
                                 g_strdup (NM_SSTP_KEY_CRL_REVOCATION_FILE),
                                 (char*) value);
        }
    }


    /* Verify certificate type and extended key usage, if checked the sstp-connection will
       fail if certificate cannot be validated, otherwise it will ignore the error and connect
    */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_cert_warn_checkbutton"));
    g_hash_table_insert (hash, g_strdup(NM_SSTP_KEY_IGN_CERT_WARN),
            !gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))
                    ? g_strdup("yes") : g_strdup("no"));

    /* Enable TLS hostname extensions */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_hostext_checkbutton"));
    g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_TLS_EXT_ENABLE),
            gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))
                    ? g_strdup ("yes") : g_strdup("no"));

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_auth_methods"));
    model = gtk_tree_view_get_model (GTK_TREE_VIEW (widget));
    valid = gtk_tree_model_get_iter_first (model, &iter);
    while (valid) {
        gboolean allowed;
        guint32 tag;

        gtk_tree_model_get (model, &iter, COL_VALUE, &allowed, COL_TAG, &tag, -1);
        switch (tag) {
        case TAG_PAP:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_PAP), !allowed 
                    ? g_strdup ("yes") : g_strdup("no"));
            break;
        case TAG_CHAP:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_CHAP), !allowed
                    ? g_strdup ("yes") : g_strdup("no"));
            break;
        case TAG_MSCHAP:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_MSCHAP), !allowed
                    ? g_strdup ("yes") : g_strdup("no"));
            break;
        case TAG_MSCHAPV2:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_MSCHAPV2), !allowed
                    ? g_strdup ("yes") : g_strdup("no"));
            break;
        case TAG_EAP:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_EAP), !allowed
                    ? g_strdup ("yes") : g_strdup("no"));
            break;
        default:
            break;
        }

        valid = gtk_tree_model_iter_next (model, &iter);
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
    if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mppe_security_combo"));
        switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
        case SEC_INDEX_MPPE_128:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REQUIRE_MPPE_128), g_strdup ("yes"));
            break;
        case SEC_INDEX_MPPE_40:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REQUIRE_MPPE_40), g_strdup ("yes"));
            break;
        default:
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REQUIRE_MPPE), g_strdup ("yes"));
            break;
        }

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_stateful_mppe"));
        if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_MPPE_STATEFUL), g_strdup ("yes"));
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_bsdcomp"));
    if (!gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_NOBSDCOMP), g_strdup ("yes"));

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_deflate"));
    if (!gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_NODEFLATE), g_strdup ("yes"));

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_usevj"));
    if (!gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_NO_VJ_COMP), g_strdup ("yes"));

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_send_echo_packets"));
    if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_LCP_ECHO_FAILURE), g_strdup_printf ("%d", 5));
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_LCP_ECHO_INTERVAL), g_strdup_printf ("%d", 30));
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_checkbutton"));
    if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
        int unit_num;

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_spinbutton"));
        unit_num = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_UNIT_NUM),
                             g_strdup_printf ("%d", unit_num));
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mtu_checkbutton"));
    if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
        int mtu;

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_mtu_spinbutton"));
        mtu = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_MTU),
                             g_strdup_printf ("%d", mtu));
    }

    /* TLS Authentication */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_identity"));
    value = gtk_editable_get_text (GTK_EDITABLE (widget));
    if (value && strlen (value)) {
        g_hash_table_insert (hash,
                             g_strdup (NM_SSTP_KEY_TLS_IDENTITY),
                             g_strdup (value));
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
    model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
    if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
        char *method = NULL;

        gtk_tree_model_get (model, &iter,
                            COL_VALUE, &method, -1);

        if (method && strlen (method)) {
            g_hash_table_insert (hash,
                                 g_strdup (NM_SSTP_KEY_TLS_VERIFY_METHOD),
                                 method);
        }
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
    value = gtk_editable_get_text (GTK_EDITABLE (widget));
    if (value && strlen (value)) {
        g_hash_table_insert (hash,
                             g_strdup (NM_SSTP_KEY_TLS_REMOTENAME),
                             g_strdup (value));
    }

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_keyusage_check"));
    g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_TLS_VERIFY_KEY_USAGE),
                               g_strdup (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)) ? "yes" : "no"));

    widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_max_combo"));
    model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
    if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
        char *version = NULL;

        gtk_tree_model_get (model, &iter,
                            COL_VALUE, &version, -1);

        if (version && strlen (version)) {
            g_hash_table_insert (hash,
                                 g_strdup (NM_SSTP_KEY_TLS_MAX_VERSION),
                                 version);
        }
    }

    /* Proxy support */
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
    value = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
    if (value && strlen(value))
    {
        NMSettingSecretFlags pw_flags;
        int proxy_port;
        
        g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_PROXY_SERVER), g_strdup (value));
        
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
        proxy_port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
        if (proxy_port > 0) {
            g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_PROXY_PORT),
                                 g_strdup_printf ("%d", proxy_port));
        }
        
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
        value = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
        if (value && strlen (value)) {
            g_hash_table_insert (hash,
                                 g_strdup (NM_SSTP_KEY_PROXY_USER),
                                 g_strdup (value));
        }
        
        widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
        value = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
        if (value && strlen (value)) {
            g_hash_table_insert (hash,
                                 g_strdup (NM_SSTP_KEY_PROXY_PASSWORD),
                                 g_strdup (value));
        }

        pw_flags = nma_utils_menu_to_secret_flags (widget);
        if (pw_flags != NM_SETTING_SECRET_FLAG_NONE) {
            g_hash_table_insert (hash,
                                 g_strdup (NM_SSTP_KEY_PROXY_PASSWORD_FLAGS),
                                 g_strdup_printf ("%d", pw_flags));
        }
    }
    
    return hash;
}

