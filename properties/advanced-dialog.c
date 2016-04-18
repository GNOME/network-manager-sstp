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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include <glib/gi18n-lib.h>

#ifdef NM_SSTP_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-connection.h>
#include <nm-setting-vpn.h>

#else /* !NM_SSTP_OLD */
#include <NetworkManager.h>
#endif

#include "advanced-dialog.h"
#include "nm-sstp.h"
#include "../src/nm-sstp-service-defines.h"

#define COL_NAME  0
#define COL_VALUE 1
#define COL_TAG 2
#define COL_SENSITIVE 3

#define TAG_PAP      0
#define TAG_CHAP     1
#define TAG_MSCHAP   2
#define TAG_MSCHAPV2 3
#define TAG_EAP      4

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
	NM_SSTP_KEY_PROXY_SERVER,
	NM_SSTP_KEY_PROXY_PORT,
	NM_SSTP_KEY_PROXY_USER,
	NM_SSTP_KEY_PROXY_PASSWORD,
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
	
	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
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
	const char *secret = NULL;
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
	
	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_SSTP_KEY_PROXY_PASSWORD, &flags, NULL))
	{
		g_hash_table_insert (hash,
							 g_strdup(NM_SSTP_KEY_PROXY_PASSWORD_FLAGS),
							 g_strdup_printf("%d", flags));
	}
	
	/* Default to disable PAP */
	if (!g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_PAP))
	{
		g_hash_table_insert (hash,
							 g_strdup(NM_SSTP_KEY_REFUSE_PAP),
							 g_strdup("yes"));
	}

	/* Default to disable CHAP */
	if (!g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_CHAP))
	{
		g_hash_table_insert (hash,
							 g_strdup(NM_SSTP_KEY_REFUSE_CHAP),
							 g_strdup("yes"));
	}

 	g_message("Refusing EAP");

	/* Default to disable EAP */
	if (!g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_EAP))
	{
 		g_message("Refusing EAP setting value to 'yes'");
		g_hash_table_insert (hash,
							 g_strdup(NM_SSTP_KEY_REFUSE_EAP),
							 g_strdup("yes"));
	}
	return hash;
}

static void
handle_mppe_changed (GtkWidget *check, gboolean is_init, GtkBuilder *builder)
{
	GtkWidget *widget;
	gboolean use_mppe;
	gboolean mppe_sensitive;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean valid;

	mppe_sensitive = gtk_widget_get_sensitive (check);
	use_mppe = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check));

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

	/* If MPPE is active, PAP, CHAP, and EAP aren't allowed by the MPPE specs;
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
		case TAG_EAP:
			// EAP not supported
			gtk_list_store_set (GTK_LIST_STORE (model), &iter, COL_VALUE, FALSE, -1);
			gtk_list_store_set (GTK_LIST_STORE (model), &iter, COL_SENSITIVE, FALSE, -1);
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
	gboolean mschap_state = TRUE;
	gboolean mschap2_state = TRUE;

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
			mschap_state = allowed;
			break;
		case TAG_MSCHAPV2:
			mschap2_state = allowed;
			break;
		default:
			break;
		}

		valid = gtk_tree_model_iter_next (model, &iter);
	}
	/* Make sure MPPE is non-sensitive if MSCHAP and MSCHAPv2 are disabled */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
	if (!mschap_state && !mschap2_state) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
		gtk_widget_set_sensitive (widget, FALSE);
	} else {
	    gtk_widget_set_sensitive (widget, mschap_state || mschap2_state);
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

	/* EAP: Disabled by default, and de-sensiticed.
	value = g_hash_table_lookup (hash, NM_SSTP_KEY_REFUSE_EAP);
	allowed = (value && !strcmp (value, "yes")) ? FALSE : TRUE;
	if (use_mppe)
		allowed = FALSE;
	*/
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_NAME, _("EAP"),
	                    COL_VALUE, FALSE,
	                    COL_TAG, TAG_EAP,
	                    COL_SENSITIVE, FALSE,
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
	if (!mschap_state && !mschap2_state) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
		gtk_widget_set_sensitive (widget, FALSE);
	} else
		gtk_widget_set_sensitive (widget, TRUE);
}

static void
checkbox_toggled_update_widget_cb (GtkWidget *check, gpointer user_data)
{
	GtkWidget *widget = (GtkWidget*) user_data;

	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

GtkWidget *
advanced_dialog_new (GHashTable *hash)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	char *ui_file = NULL;
	GtkWidget *widget, *spin;
	const char *value;
	const char *value2;
	gboolean mppe = FALSE;
	GError *error = NULL;

	g_return_val_if_fail (hash != NULL, NULL);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-sstp-dialog.ui");
	builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);
	if (!gtk_builder_add_from_file (builder, ui_file, &error)) {
		g_warning ("Couldn't load builder file: %s",
		           error ? error->message : "(unknown)");
		g_clear_error (&error);
		g_object_unref (G_OBJECT (builder));
		goto out;
	}

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "sstp-advanced-dialog"));
	if (!dialog) {
		g_object_unref (G_OBJECT (builder));
		goto out;
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "gtkbuilder-xml",
	                        builder, (GDestroyNotify) g_object_unref);

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
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_stateful_mppe"));
	value = g_hash_table_lookup (hash, NM_SSTP_KEY_MPPE_STATEFUL);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_bsdcomp"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	value = g_hash_table_lookup (hash, NM_SSTP_KEY_NOBSDCOMP);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_deflate"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	value = g_hash_table_lookup (hash, NM_SSTP_KEY_NODEFLATE);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_usevj"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	value = g_hash_table_lookup (hash, NM_SSTP_KEY_NO_VJ_COMP);
	if (value && !strcmp (value, "yes"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_send_echo_packets"));
	value = g_hash_table_lookup (hash, NM_SSTP_KEY_LCP_ECHO_INTERVAL);
	if (value && strlen (value)) {
		long int tmp_int;

		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0 && tmp_int > 0)
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	auth_methods_setup (builder, hash);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
	handle_mppe_changed (widget, TRUE, builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (mppe_toggled_cb), builder);

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
		gtk_entry_set_text (GTK_ENTRY (widget), value);
		
		value = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_USER);
		if (value && strlen (value)) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
			gtk_entry_set_text (GTK_ENTRY (widget), value);
		}
		
		value = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_PASSWORD);
		if (value && strlen (value)) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
			gtk_entry_set_text (GTK_ENTRY (widget), value);
		}
		
		value = g_hash_table_lookup (hash, NM_SSTP_KEY_PROXY_PASSWORD_FLAGS);
		if (value && strlen (value)) {
			errno = 0; 
			tmp = strtol (value, NULL, 10); 
			if (errno != 0 || tmp < 0 || tmp > 65535)
				tmp = 0; 
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
			g_object_set_data (G_OBJECT (widget), "flags", GUINT_TO_POINTER ((guint32) tmp));
		}
	}
	
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
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 0.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

out:
	g_free (ui_file);
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
	gboolean valid;
	const char *value;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "gtkbuilder-xml");
	g_return_val_if_fail (builder != NULL, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_use_mppe"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {

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
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
			g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_MPPE_STATEFUL), g_strdup ("yes"));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_bsdcomp"));
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_NOBSDCOMP), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_allow_deflate"));
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_NODEFLATE), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_usevj"));
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_NO_VJ_COMP), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_send_echo_packets"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_LCP_ECHO_FAILURE), g_strdup_printf ("%d", 5));
		g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_LCP_ECHO_INTERVAL), g_strdup_printf ("%d", 30));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_auth_methods"));
	model = gtk_tree_view_get_model (GTK_TREE_VIEW (widget));
	valid = gtk_tree_model_get_iter_first (model, &iter);
	while (valid) {
		gboolean allowed;
		guint32 tag;

		gtk_tree_model_get (model, &iter, COL_VALUE, &allowed, COL_TAG, &tag, -1);
		switch (tag) {
		case TAG_PAP:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_PAP), g_strdup ("yes"));
			break;
		case TAG_CHAP:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_CHAP), g_strdup ("yes"));
			break;
		case TAG_MSCHAP:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_MSCHAP), g_strdup ("yes"));
			break;
		case TAG_MSCHAPV2:
			if (!allowed)
				g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_MSCHAPV2), g_strdup ("yes"));
			break;
		case TAG_EAP:
			// always refuse-eap
			g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_REFUSE_EAP), g_strdup ("yes"));
			break;
		default:
			break;
		}

		valid = gtk_tree_model_iter_next (model, &iter);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
	value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (value && strlen(value))
	{
		guint32 pw_flags;
		int proxy_port;
		
		g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_PROXY_SERVER), g_strdup (value));
		
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
		proxy_port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		if (proxy_port > 0) {
			g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_PROXY_PORT),
								 g_strdup_printf ("%d", proxy_port));
		}
		
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
		value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (value && strlen (value)) {
			g_hash_table_insert (hash,
								 g_strdup (NM_SSTP_KEY_PROXY_USER),
								 g_strdup (value));
		}
		
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
		value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (value && strlen (value)) {
			g_hash_table_insert (hash,
								 g_strdup (NM_SSTP_KEY_PROXY_PASSWORD),
								 g_strdup (value));
		}
		
		pw_flags = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (widget), "flags"));
		if (pw_flags != NM_SETTING_SECRET_FLAG_NONE) {
			g_hash_table_insert (hash,
								 g_strdup (NM_SSTP_KEY_PROXY_PASSWORD_FLAGS),
								 g_strdup_printf ("%d", pw_flags));
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int unit_num;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ppp_unit_spinbutton"));
		unit_num = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSTP_KEY_UNIT_NUM),
		                     g_strdup_printf ("%d", unit_num));
	}

	return hash;
}

