/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "chooser.h"

#include <adwaita.h>
#include <gtk/gtk.h>

#include "../redact.h"
#include "external-window.h"
#include "pin.h"

#define CERTIFICATE_REASON_MAX_CHARS 160

typedef struct
{
	/* Cancellation and idle references may be released on different threads. */
	gint refs;

	GPtrArray* candidates;
	char* app_id;
	CertificateIdentityLevel identity_level;
	CertificatePurpose purpose;
	CertificateChooserDone done;
	gpointer user_data;

	GCancellable* cancellable;
	gulong cancel_id;
	guint cancel_idle;

	GtkWindow* window;
	GtkWidget* list;
	GtkWidget* use_button;
	GtkWidget* cancel_button;
	GtkEventController* keys;

	gboolean finished;
} Chooser;

static void chooser_free(Chooser* chooser)
{
	g_clear_pointer(&chooser->candidates, g_ptr_array_unref);
	g_free(chooser->app_id);
	g_clear_object(&chooser->cancellable);
	g_free(chooser);
}

static Chooser* chooser_ref(Chooser* chooser)
{
	g_atomic_int_inc(&chooser->refs);
	return chooser;
}

static void chooser_unref(gpointer data)
{
	Chooser* chooser = data;

	if (chooser == NULL)
		return;

	if (!g_atomic_int_dec_and_test(&chooser->refs))
		return;

	chooser_free(chooser);
}

static void chooser_finish(Chooser* chooser, CertificateCandidate* chosen)
{
	CertificateChooserResult result = { chosen };
	CertificateChooserDone done = chooser->done;
	gpointer user_data = chooser->user_data;

	if (chooser->finished)
		return;

	chooser->finished = TRUE;

	/* Disconnect before removing the idle so concurrent cancellation cannot queue another source. */
	if (chooser->cancel_id != 0)
	{
		g_cancellable_disconnect(chooser->cancellable, chooser->cancel_id);
		chooser->cancel_id = 0;
	}

	if (chooser->cancel_idle != 0)
	{
		g_source_remove(chooser->cancel_idle);
		chooser->cancel_idle = 0;
	}

	if (chosen != NULL)
		certificate_candidate_ref(chosen);

	/* Disconnect before destroy because widget disposal can emit signals after dependent widgets are gone. */
	if (chooser->list != NULL)
		g_signal_handlers_disconnect_by_data(chooser->list, chooser);
	if (chooser->window != NULL)
		g_signal_handlers_disconnect_by_data(chooser->window, chooser);
	if (chooser->use_button != NULL)
		g_signal_handlers_disconnect_by_data(chooser->use_button, chooser);
	if (chooser->cancel_button != NULL)
		g_signal_handlers_disconnect_by_data(chooser->cancel_button, chooser);
	if (chooser->keys != NULL)
		g_signal_handlers_disconnect_by_data(chooser->keys, chooser);

	if (chooser->window != NULL)
	{
		gtk_window_destroy(chooser->window);
		chooser->window = NULL;
	}

	certificate_log_decision(chosen != NULL ? CERTIFICATE_REASON_CONSENT_GRANTED
	                                        : CERTIFICATE_REASON_CHOOSER_CANCELLED,
	                         chooser->app_id,
	                         certificate_identity_level_to_string(chooser->identity_level),
	                         certificate_purpose_to_string(chooser->purpose), chosen != NULL);

	done(&result, user_data);

	if (chosen != NULL)
		certificate_candidate_unref(chosen);

	chooser_unref(chooser);
}

static CertificateCandidate* selected_candidate(Chooser* chooser)
{
	GtkListBoxRow* row = gtk_list_box_get_selected_row(GTK_LIST_BOX(chooser->list));

	if (row == NULL)
		return NULL;

	return g_object_get_data(G_OBJECT(row), "candidate");
}

static void on_use(GtkWidget* widget, gpointer user_data)
{
	Chooser* chooser = user_data;
	CertificateCandidate* candidate = selected_candidate(chooser);

	if (candidate == NULL)
		return;

	chooser_finish(chooser, candidate);
}

static void on_cancel(GtkWidget* widget, gpointer user_data)
{
	chooser_finish(user_data, NULL);
}

static gboolean on_close_request(GtkWindow* window, gpointer user_data)
{
	chooser_finish(user_data, NULL);
	return TRUE;
}

static gboolean on_key_pressed(GtkEventControllerKey* controller, guint keyval, guint keycode,
                               GdkModifierType state, gpointer user_data)
{
	if (keyval == GDK_KEY_Escape)
	{
		chooser_finish(user_data, NULL);
		return GDK_EVENT_STOP;
	}

	return GDK_EVENT_PROPAGATE;
}

static gboolean on_cancelled_idle(gpointer user_data)
{
	Chooser* chooser = user_data;

	chooser->cancel_idle = 0;
	chooser_finish(chooser, NULL);
	return G_SOURCE_REMOVE;
}

/* Cancellation may arrive off-thread; the queued idle holds a reference and finish removes its source. */
static void on_cancelled(GCancellable* cancellable, gpointer user_data)
{
	Chooser* chooser = user_data;

	if (chooser->cancel_idle != 0)
		return;

	chooser->cancel_idle = g_idle_add_full(G_PRIORITY_DEFAULT, on_cancelled_idle,
	                                       chooser_ref(chooser), chooser_unref);
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
static GtkWidget* build_identity(const CertificateCallerIdentity* caller)
{
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget* name = NULL;
	GtkWidget* level = NULL;
	const char* level_text = NULL;
	g_autofree char* display = certificate_chooser_display_name(caller);
	g_autofree char* app_id =
	    certificate_display_text(caller->app_id, CERTIFICATE_DISPLAY_MAX_APP_ID, NULL);

	switch (caller->level)
	{
		case CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED:
			level_text = "Sandboxed application, identity verified by the system";
			break;
		case CERTIFICATE_IDENTITY_DERIVED_HOST:
			level_text = "Unsandboxed application. The name below was derived from the "
			             "running process and is a useful label, not proof.";
			break;
		default:
			level_text = "This application could not be identified. Only continue if you "
			             "know what asked.";
			break;
	}

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

	level = gtk_label_new(level_text);
	gtk_label_set_xalign(GTK_LABEL(level), 0.0f);
	gtk_label_set_wrap(GTK_LABEL(level), TRUE);
	if (caller->level != CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED)
		gtk_widget_add_css_class(level, "warning");
	else
		gtk_widget_add_css_class(level, "dim-label");
	gtk_box_append(GTK_BOX(box), level);

	return box;
}

char* certificate_chooser_format_lifetime(guint32 seconds)
{
	if (seconds < 120)
		return g_strdup_printf("%u seconds", seconds);

	if (seconds < 7200)
		return g_strdup_printf("%u minutes", (seconds + 59) / 60);

	return g_strdup_printf("%u hours", (seconds + 3599) / 3600);
}

char* certificate_chooser_display_name(const CertificateCallerIdentity* caller)
{
	/* Desktop-file Name values are writable external input and may contain escaped newlines. */
	g_autofree char* app_name =
	    certificate_display_text(caller->app_display_name, CERTIFICATE_DISPLAY_MAX_APP_NAME, NULL);
	g_autofree char* app_id =
	    certificate_display_text(caller->app_id, CERTIFICATE_DISPLAY_MAX_APP_ID, NULL);

	if (app_name != NULL)
		return g_steal_pointer(&app_name);

	if (app_id != NULL)
		return g_steal_pointer(&app_id);

	return g_strdup("An unidentified application");
}

char* certificate_chooser_format_expiry(const CertificateCandidate* candidate, gint64 now)
{
	g_autoptr(GDateTime) expiry = g_date_time_new_from_unix_local(candidate->not_after);
	g_autofree char* date =
	    expiry != NULL ? g_date_time_format(expiry, "%x") : g_strdup("an unknown date");

	if (date == NULL)
		date = g_strdup("an unknown date");

	/* Expiry must be stated in words for screen readers and monochrome displays. */
	if (certificate_candidate_is_expired(candidate, now))
		return g_strdup_printf("EXPIRED on %s", date);

	if (certificate_candidate_is_not_yet_valid(candidate, now))
		return g_strdup("NOT YET VALID");

	return g_strdup_printf("Valid until %s", date);
}

char* certificate_chooser_format_detail(const CertificateCandidate* candidate, gint64 now)
{
	g_autofree char* expiry_text = certificate_chooser_format_expiry(candidate, now);
	/* Token labels and reader names are external input and require display sanitization. */
	g_autofree char* token_text = certificate_display_text(
	    candidate->token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "unnamed token");
	g_autofree char* reader_text = certificate_display_text(
	    candidate->token->reader_name, CERTIFICATE_DISPLAY_MAX_READER, NULL);

	return g_strdup_printf("%s  ·  %s %u-bit  ·  %s%s%s", expiry_text,
	                       candidate->key_type != NULL ? candidate->key_type : "unknown",
	                       candidate->key_size, token_text, reader_text != NULL ? " in " : "",
	                       reader_text != NULL ? reader_text : "");
}

static GtkWidget* build_row(CertificateCandidate* candidate, gint64 now)
{
	GtkWidget* row = gtk_list_box_row_new();
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget* subject = NULL;
	g_autofree char* detail = certificate_chooser_format_detail(candidate, now);
	g_autoptr(GString) accessible = g_string_new(NULL);
	/* Certificate subjects and issuers require display sanitization. */
	g_autofree char* subject_text = certificate_display_text(
	    candidate->subject_display, CERTIFICATE_DISPLAY_MAX_SUBJECT, "Unnamed certificate");
	g_autofree char* issuer_text = certificate_display_text(
	    candidate->issuer_display, CERTIFICATE_DISPLAY_MAX_ISSUER, "an unnamed issuer");

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
		if (certificate_candidate_is_expired(candidate, now) ||
		    certificate_candidate_is_not_yet_valid(candidate, now))
			gtk_widget_add_css_class(label, "warning");
		gtk_box_append(GTK_BOX(box), label);
		g_string_append_printf(accessible, ", %s", detail);
	}

	gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
	gtk_accessible_update_property(GTK_ACCESSIBLE(row), GTK_ACCESSIBLE_PROPERTY_LABEL,
	                               accessible->str, -1);
	g_object_set_data_full(G_OBJECT(row), "candidate", certificate_candidate_ref(candidate),
	                       (GDestroyNotify) certificate_candidate_unref);

	return row;
}

void certificate_chooser_show(const char* parent_window, const char* activation_token,
                              GPtrArray* candidates, const CertificateChooserRequest* request,
                              GCancellable* cancellable, CertificateChooserDone done,
                              gpointer user_data)
{
	Chooser* chooser = NULL;
	GtkWidget* window = NULL;
	GtkWidget* header = NULL;
	GtkWidget* toolbar = NULL;
	GtkWidget* content = NULL;
	GtkWidget* scroller = NULL;
	GtkWidget* buttons = NULL;
	GtkWidget* cancel = NULL;
	GtkEventController* keys = NULL;
	g_autofree char* reason = NULL;
	g_autofree char* lifetime = NULL;
	gint64 now = g_get_real_time() / G_USEC_PER_SEC;

	if (!certificate_ui_has_display())
	{
		CertificateChooserResult result = { NULL };

		done(&result, user_data);
		return;
	}

	chooser = g_new0(Chooser, 1);
	chooser->refs = 1;
	chooser->candidates = g_ptr_array_ref(candidates);
	chooser->app_id = g_strdup(request->caller->app_id);
	chooser->identity_level = request->caller->level;
	chooser->purpose = request->purpose;
	chooser->done = done;
	chooser->user_data = user_data;
	chooser->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;

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

	gtk_box_append(GTK_BOX(content), build_identity(request->caller));

	{
		g_autofree char* text =
		    g_strdup_printf("wants to use a certificate on your security token to %s.",
		                    certificate_purpose_display(request->purpose));
		GtkWidget* label = gtk_label_new(text);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_wrap(GTK_LABEL(label), TRUE);
		gtk_box_append(GTK_BOX(content), label);
	}

	/* Caller text stays labelled and subordinate to trusted identity text. */
	reason = certificate_sanitize_untrusted_text(request->reason, CERTIFICATE_REASON_MAX_CHARS);
	if (reason != NULL)
	{
		GtkWidget* frame = gtk_frame_new("The application says");
		GtkWidget* label = NULL;
		g_autofree char* quoted = g_strdup_printf("\xe2\x80\x9c%s\xe2\x80\x9d", reason);

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

	for (guint i = 0; i < candidates->len; i++)
	{
		CertificateCandidate* candidate = g_ptr_array_index(candidates, i);
		GtkWidget* row = build_row(candidate, now);

		gtk_list_box_append(GTK_LIST_BOX(chooser->list), row);
	}

	scroller = gtk_scrolled_window_new();
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller), GTK_POLICY_NEVER,
	                               GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), chooser->list);
	gtk_widget_set_vexpand(scroller, TRUE);
	gtk_box_append(GTK_BOX(content), scroller);

	lifetime = certificate_chooser_format_lifetime(request->lifetime_seconds);
	{
		g_autofree char* text = g_strdup_printf(
		    "%s\n\nThis grant lasts %s. %s You will be asked for your PIN the first time the "
		    "key is used.",
		    certificate_purpose_detail(request->purpose), lifetime,
		    request->may_sign && request->may_decrypt ? "It allows signing and decryption."
		    : request->may_decrypt                    ? "It allows decryption only."
		    : request->may_sign                       ? "It allows signing only."
		                                              : "It allows no operations.");
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

	if (chooser->cancellable != NULL)
		chooser->cancel_id =
		    g_cancellable_connect(chooser->cancellable, G_CALLBACK(on_cancelled), chooser, NULL);

	certificate_log_decision(CERTIFICATE_REASON_CHOOSER_SHOWN, request->caller->app_id,
	                         certificate_identity_level_to_string(request->caller->level),
	                         certificate_purpose_to_string(request->purpose), FALSE);

	certificate_external_window_present(GTK_WINDOW(window), parent_window, activation_token);

	gtk_widget_grab_focus(chooser->list);
}
