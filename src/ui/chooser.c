/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "chooser.h"

#include <adwaita.h>
#include <gtk/gtk.h>

#include "external-window.h"

typedef struct
{
	XccUiId id;
	guint64 revision;
	GtkWindow* window;
	GtkWidget* list;
	GtkWidget* empty;
	GtkWidget* empty_detail;
	GtkWidget* use_button;
	GtkWidget* cancel_button;
	GtkEventController* keys;
	char* announcement;
	gboolean finished;
} Chooser;

static GHashTable* choosers;

static guint64 selected_candidate(Chooser* chooser)
{
	GtkListBoxRow* row = gtk_list_box_get_selected_row(GTK_LIST_BOX(chooser->list));
	guint64* id = row != NULL ? g_object_get_data(G_OBJECT(row), "candidate-id") : NULL;

	return id != NULL ? *id : 0;
}

static void on_use(GtkWidget* widget, gpointer user_data)
{
	Chooser* chooser = user_data;
	guint64 candidate = selected_candidate(chooser);

	if (candidate != 0)
		certificate_chooser_choose(chooser->id, chooser->revision, candidate);
}

static void on_cancel(GtkWidget* widget, gpointer user_data)
{
	Chooser* chooser = user_data;

	certificate_chooser_cancel(chooser->id);
}

static gboolean on_close_request(GtkWindow* window, gpointer user_data)
{
	on_cancel(NULL, user_data);
	return TRUE;
}

static gboolean on_key_pressed(GtkEventControllerKey* controller, guint keyval, guint keycode,
                               GdkModifierType state, gpointer user_data)
{
	if (keyval == GDK_KEY_Escape)
	{
		on_cancel(NULL, user_data);
		return GDK_EVENT_STOP;
	}

	return GDK_EVENT_PROPAGATE;
}

static void on_row_selected(GtkListBox* list, GtkListBoxRow* row, gpointer user_data)
{
	Chooser* chooser = user_data;

	/* List teardown emits row-selected after dependent widgets may have been disposed. */
	if (chooser->finished)
		return;

	gtk_widget_set_sensitive(chooser->use_button, row != NULL);
}

static void on_row_activated(GtkListBox* list, GtkListBoxRow* row, gpointer user_data)
{
	Chooser* chooser = user_data;

	if (chooser->finished)
		return;

	on_use(NULL, chooser);
}

/* Display frontend-established identity assurance beside the caller name. */
static GtkWidget* build_identity(const XccChooserView* view)
{
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget* name = NULL;
	GtkWidget* level = NULL;
	const char* display = view->caller_name;
	const char* app_id = view->app_id;

	name = gtk_label_new(display);
	gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
	gtk_label_set_wrap(GTK_LABEL(name), TRUE);
	gtk_widget_add_css_class(name, "title-2");
	gtk_box_append(GTK_BOX(box), name);

	/* Always show the established app ID alongside the desktop-file display name. */
	if (app_id != NULL && g_strcmp0(app_id, display) != 0)
	{
		GtkWidget* id_label = gtk_label_new(app_id);

		gtk_label_set_xalign(GTK_LABEL(id_label), 0.0f);
		gtk_label_set_selectable(GTK_LABEL(id_label), TRUE);
		gtk_widget_add_css_class(id_label, "dim-label");
		gtk_widget_add_css_class(id_label, "monospace");
		gtk_box_append(GTK_BOX(box), id_label);
	}

	level = gtk_label_new(view->identity_detail);
	gtk_label_set_xalign(GTK_LABEL(level), 0.0f);
	gtk_label_set_wrap(GTK_LABEL(level), TRUE);
	if (view->identity_level != CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED)
		gtk_widget_add_css_class(level, "warning");
	else
		gtk_widget_add_css_class(level, "dim-label");
	gtk_box_append(GTK_BOX(box), level);

	return box;
}

static GtkWidget* build_row(const XccChooserCandidateView* candidate)
{
	GtkWidget* row = gtk_list_box_row_new();
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget* subject = NULL;
	const char* detail = candidate->detail;
	g_autoptr(GString) accessible = g_string_new(NULL);
	const char* subject_text = candidate->subject;
	const char* issuer_text = candidate->issuer;
	guint64* id = g_new(guint64, 1);

	gtk_widget_set_margin_top(box, 8);
	gtk_widget_set_margin_bottom(box, 8);
	gtk_widget_set_margin_start(box, 10);
	gtk_widget_set_margin_end(box, 10);

	subject = gtk_label_new(subject_text);
	gtk_label_set_xalign(GTK_LABEL(subject), 0.0f);
	gtk_label_set_ellipsize(GTK_LABEL(subject), PANGO_ELLIPSIZE_END);
	gtk_widget_add_css_class(subject, "heading");
	gtk_box_append(GTK_BOX(box), subject);
	g_string_append(accessible, subject_text);

	{
		g_autofree char* issuer = g_strdup_printf("Issued by %s", issuer_text);
		GtkWidget* label = gtk_label_new(issuer);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
		gtk_widget_add_css_class(label, "dim-label");
		gtk_box_append(GTK_BOX(box), label);
		g_string_append_printf(accessible, ", %s", issuer);
	}

	{
		GtkWidget* label = gtk_label_new(detail);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_wrap(GTK_LABEL(label), TRUE);
		gtk_widget_add_css_class(label, "caption");
		if (candidate->invalid)
			gtk_widget_add_css_class(label, "warning");
		gtk_box_append(GTK_BOX(box), label);
		g_string_append_printf(accessible, ", %s", detail);
	}

	gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
	gtk_accessible_update_property(GTK_ACCESSIBLE(row), GTK_ACCESSIBLE_PROPERTY_LABEL,
	                               accessible->str, -1);
	*id = candidate->id;
	g_object_set_data_full(G_OBJECT(row), "candidate-id", id, g_free);

	return row;
}

static CertificateChooserAnnounceHook announce_hook = NULL;
static gpointer announce_hook_data = NULL;

void certificate_chooser_set_announce_hook(CertificateChooserAnnounceHook hook, gpointer user_data)
{
	announce_hook = hook;
	announce_hook_data = user_data;
}

static void announce_accessible(GtkAccessible* accessible, const char* text)
{
#if GTK_CHECK_VERSION(4, 14, 0)
	GtkATContext* context = gtk_accessible_get_at_context(accessible);

	/* GTK's test/stub contexts lack the announce vfunc. */
	if (context != NULL)
	{
		if (g_strcmp0(G_OBJECT_TYPE_NAME(context), "GtkAtSpiContext") == 0)
			gtk_accessible_announce(accessible, text, GTK_ACCESSIBLE_ANNOUNCEMENT_PRIORITY_MEDIUM);
		g_object_unref(context);
	}
#endif
}

static void announce_empty_state(GtkWidget* window, gpointer user_data)
{
	Chooser* chooser = user_data;

	if (chooser->announcement == NULL || !gtk_widget_get_mapped(window))
		return;
	if (announce_hook != NULL)
		announce_hook(chooser->announcement, announce_hook_data);
	announce_accessible(GTK_ACCESSIBLE(window), chooser->announcement);
}

static void gtk_chooser_update(gpointer user_data, XccUiId id, const XccChooserView* view)
{
	Chooser* chooser = g_hash_table_lookup(choosers, &id);
	guint64 selected = selected_candidate(chooser);
	GtkListBoxRow* selected_row = NULL;
	GtkWidget* child = NULL;
	GtkWidget* focus = NULL;
	gboolean list_focused = FALSE;
	const char* empty_text = "Insert your security token";
	const char* detail = "No certificate on the inserted token can be used for this request";

	if (chooser->finished)
		return;

	focus = gtk_root_get_focus(GTK_ROOT(chooser->window));
	list_focused = focus != NULL && (focus == chooser->list ||
	                                 gtk_widget_is_ancestor(focus, chooser->list));
	while ((child = gtk_widget_get_first_child(chooser->list)) != NULL)
		gtk_list_box_remove(GTK_LIST_BOX(chooser->list), child);
	chooser->revision = view->revision;

	for (guint i = 0; i < view->n_candidates; i++)
	{
		const XccChooserCandidateView* candidate = xcc_chooser_view_candidate(view, i);
		GtkWidget* row = build_row(candidate);

		gtk_list_box_append(GTK_LIST_BOX(chooser->list), row);
		if (selected != 0 && selected == candidate->id)
			selected_row = GTK_LIST_BOX_ROW(row);
	}
	gtk_list_box_select_row(GTK_LIST_BOX(chooser->list), selected_row);
	gtk_widget_set_sensitive(chooser->use_button, selected_row != NULL);
	/* Removing rows drops keyboard focus; return it to the list or to Cancel. */
	if (list_focused)
	{
		if (selected_row != NULL)
			gtk_widget_grab_focus(GTK_WIDGET(selected_row));
		else if (view->n_candidates > 0)
			gtk_widget_grab_focus(chooser->list);
		else
			gtk_widget_grab_focus(chooser->cancel_button);
	}
	gtk_widget_set_visible(chooser->empty, view->n_candidates == 0);
	gtk_widget_set_visible(chooser->empty_detail, view->n_candidates == 0 && view->tokens_present);
	g_clear_pointer(&chooser->announcement, g_free);
	if (view->n_candidates == 0)
	{
		chooser->announcement = view->tokens_present
		    ? g_strdup_printf("%s. %s", empty_text, detail) : g_strdup(empty_text);

		gtk_accessible_update_property(GTK_ACCESSIBLE(chooser->list),
		                               GTK_ACCESSIBLE_PROPERTY_LABEL, chooser->announcement, -1);
		announce_empty_state(GTK_WIDGET(chooser->window), chooser);
	}
	else
		gtk_accessible_update_property(GTK_ACCESSIBLE(chooser->list),
		                               GTK_ACCESSIBLE_PROPERTY_LABEL,
		                               "Certificates available on your security tokens", -1);
}

static void gtk_chooser_show(gpointer user_data, XccUiId id, const XccChooserView* view)
{
	Chooser* chooser = g_new0(Chooser, 1);
	GtkWidget* window = NULL;
	GtkWidget* header = NULL;
	GtkWidget* toolbar = NULL;
	GtkWidget* content = NULL;
	GtkWidget* scroller = NULL;
	GtkWidget* buttons = NULL;
	GtkWidget* cancel = NULL;
	GtkEventController* keys = NULL;

	chooser->id = id;
	if (choosers == NULL)
		choosers = g_hash_table_new(g_int64_hash, g_int64_equal);
	g_hash_table_insert(choosers, &chooser->id, chooser);

	window = adw_window_new();
	chooser->window = GTK_WINDOW(window);
	gtk_window_set_title(GTK_WINDOW(window), "Use a Certificate");
	gtk_window_set_modal(GTK_WINDOW(window), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(window), 520, 560);

	header = adw_header_bar_new();
	adw_header_bar_set_show_end_title_buttons(ADW_HEADER_BAR(header), FALSE);

	content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
	gtk_widget_set_margin_top(content, 18);
	gtk_widget_set_margin_bottom(content, 18);
	gtk_widget_set_margin_start(content, 18);
	gtk_widget_set_margin_end(content, 18);

	gtk_box_append(GTK_BOX(content), build_identity(view));

	{
		GtkWidget* label = gtk_label_new(view->purpose_text);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_wrap(GTK_LABEL(label), TRUE);
		gtk_box_append(GTK_BOX(content), label);
	}

	/* Caller text stays labelled and subordinate to trusted identity text. */
	if (view->untrusted_reason != NULL)
	{
		GtkWidget* frame = gtk_frame_new(view->reason_label);
		GtkWidget* label = NULL;
		g_autofree char* quoted = g_strdup_printf("\xe2\x80\x9c%s\xe2\x80\x9d", view->untrusted_reason);

		label = gtk_label_new(quoted);
		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_wrap(GTK_LABEL(label), TRUE);
		gtk_widget_add_css_class(label, "dim-label");
		gtk_widget_set_margin_top(label, 8);
		gtk_widget_set_margin_bottom(label, 8);
		gtk_widget_set_margin_start(label, 8);
		gtk_widget_set_margin_end(label, 8);
		gtk_frame_set_child(GTK_FRAME(frame), label);
		gtk_box_append(GTK_BOX(content), frame);
	}

	{
		GtkWidget* label = gtk_label_new("Choose a certificate");

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_widget_add_css_class(label, "heading");
		gtk_box_append(GTK_BOX(content), label);
	}

	chooser->list = gtk_list_box_new();
	gtk_list_box_set_selection_mode(GTK_LIST_BOX(chooser->list), GTK_SELECTION_SINGLE);
	gtk_widget_add_css_class(chooser->list, "boxed-list");
	gtk_accessible_update_property(GTK_ACCESSIBLE(chooser->list), GTK_ACCESSIBLE_PROPERTY_LABEL,
	                               "Certificates available on your security tokens", -1);

	chooser->empty = gtk_label_new("Insert your security token");
	gtk_label_set_wrap(GTK_LABEL(chooser->empty), TRUE);
	gtk_widget_add_css_class(chooser->empty, "heading");
	gtk_box_append(GTK_BOX(content), chooser->empty);
	chooser->empty_detail = gtk_label_new(
	    "No certificate on the inserted token can be used for this request");
	gtk_label_set_wrap(GTK_LABEL(chooser->empty_detail), TRUE);
	gtk_widget_add_css_class(chooser->empty_detail, "dim-label");
	gtk_box_append(GTK_BOX(content), chooser->empty_detail);

	scroller = gtk_scrolled_window_new();
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller), GTK_POLICY_NEVER,
	                               GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), chooser->list);
	gtk_widget_set_vexpand(scroller, TRUE);
	gtk_box_append(GTK_BOX(content), scroller);

	{
		g_autofree char* text = g_strdup_printf(
		    "%s\n\nThis grant lasts %s. %s %s",
		    view->purpose_detail, view->duration, view->operation_scope, view->later_prompt);
		GtkWidget* label = gtk_label_new(text);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_wrap(GTK_LABEL(label), TRUE);
		gtk_widget_add_css_class(label, "caption");
		gtk_box_append(GTK_BOX(content), label);
	}

	buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign(buttons, GTK_ALIGN_END);

	cancel = gtk_button_new_with_mnemonic("_Cancel");
	chooser->cancel_button = cancel;
	g_signal_connect(cancel, "clicked", G_CALLBACK(on_cancel), chooser);
	gtk_box_append(GTK_BOX(buttons), cancel);

	chooser->use_button = gtk_button_new_with_mnemonic("_Use Certificate");
	gtk_widget_add_css_class(chooser->use_button, "suggested-action");
	gtk_widget_set_sensitive(chooser->use_button, FALSE);
	g_signal_connect(chooser->use_button, "clicked", G_CALLBACK(on_use), chooser);
	gtk_box_append(GTK_BOX(buttons), chooser->use_button);

	gtk_box_append(GTK_BOX(content), buttons);

	g_signal_connect(chooser->list, "row-selected", G_CALLBACK(on_row_selected), chooser);
	g_signal_connect(chooser->list, "row-activated", G_CALLBACK(on_row_activated), chooser);

	toolbar = adw_toolbar_view_new();
	adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
	adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), content);
	adw_window_set_content(ADW_WINDOW(window), toolbar);

	keys = gtk_event_controller_key_new();
	chooser->keys = keys;
	g_signal_connect(keys, "key-pressed", G_CALLBACK(on_key_pressed), chooser);
	gtk_widget_add_controller(window, keys);

	g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), chooser);
	g_signal_connect_after(window, "map", G_CALLBACK(announce_empty_state), chooser);

	gtk_chooser_update(NULL, id, view);
	certificate_external_window_present(GTK_WINDOW(window), view->parent_window,
	                                    view->activation_token);

	gtk_widget_grab_focus(view->n_candidates == 0 ? cancel : chooser->list);
}

static void gtk_chooser_close(gpointer user_data, XccUiId id)
{
	Chooser* chooser = g_hash_table_lookup(choosers, &id);

	chooser->finished = TRUE;
	g_hash_table_remove(choosers, &id);
	g_signal_handlers_disconnect_by_data(chooser->list, chooser);
	g_signal_handlers_disconnect_by_data(chooser->window, chooser);
	g_signal_handlers_disconnect_by_data(chooser->use_button, chooser);
	g_signal_handlers_disconnect_by_data(chooser->cancel_button, chooser);
	g_signal_handlers_disconnect_by_data(chooser->keys, chooser);
	gtk_window_destroy(chooser->window);
	g_free(chooser->announcement);
	g_free(chooser);
	if (g_hash_table_size(choosers) == 0)
		g_clear_pointer(&choosers, g_hash_table_unref);
}

const CertificateChooserProvider* certificate_chooser_provider_gtk(void)
{
	static const CertificateChooserProvider provider = {
		.name = "gtk",
		.needs_display = TRUE,
		.chooser_show = gtk_chooser_show,
		.chooser_update = gtk_chooser_update,
		.close = gtk_chooser_close,
	};

	return &provider;
}
