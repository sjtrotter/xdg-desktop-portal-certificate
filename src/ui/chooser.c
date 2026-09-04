/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
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
	GPtrArray* candidates;
	CertificateChooserDone done;
	gpointer user_data;

	GCancellable* cancellable;
	gulong cancel_id;

	GtkWindow* window;
	GtkWidget* list;
	GtkWidget* use_button;
	GtkWidget* remember;

	gboolean finished;
} Chooser;

static void chooser_free(Chooser* chooser)
{
	g_clear_pointer(&chooser->candidates, g_ptr_array_unref);
	g_clear_object(&chooser->cancellable);
	g_free(chooser);
}

static void chooser_finish(Chooser* chooser, CertificateCandidate* chosen, gboolean remember)
{
	CertificateChooserResult result = { chosen, remember };
	CertificateChooserDone done = chooser->done;
	gpointer user_data = chooser->user_data;

	if (chooser->finished)
		return;

	chooser->finished = TRUE;

	if (chooser->cancel_id != 0)
	{
		g_cancellable_disconnect(chooser->cancellable, chooser->cancel_id);
		chooser->cancel_id = 0;
	}

	if (chosen != NULL)
		certificate_candidate_ref(chosen);

	if (chooser->window != NULL)
	{
		gtk_window_destroy(chooser->window);
		chooser->window = NULL;
	}

	certificate_log_decision(chosen != NULL ? CERTIFICATE_REASON_CONSENT_GRANTED
	                                        : CERTIFICATE_REASON_CHOOSER_CANCELLED,
	                         NULL, NULL, NULL, chosen != NULL);

	chooser_free(chooser);

	done(&result, user_data);

	if (chosen != NULL)
		certificate_candidate_unref(chosen);
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
	gboolean remember = FALSE;

	if (candidate == NULL)
		return;

	if (chooser->remember != NULL)
		remember = gtk_check_button_get_active(GTK_CHECK_BUTTON(chooser->remember));

	chooser_finish(chooser, candidate, remember);
}

static void on_cancel(GtkWidget* widget, gpointer user_data)
{
	chooser_finish(user_data, NULL, FALSE);
}

static gboolean on_close_request(GtkWindow* window, gpointer user_data)
{
	chooser_finish(user_data, NULL, FALSE);
	return TRUE;
}

static gboolean on_key_pressed(GtkEventControllerKey* controller, guint keyval, guint keycode,
                               GdkModifierType state, gpointer user_data)
{
	if (keyval == GDK_KEY_Escape)
	{
		chooser_finish(user_data, NULL, FALSE);
		return GDK_EVENT_STOP;
	}

	return GDK_EVENT_PROPAGATE;
}

static gboolean on_cancelled_idle(gpointer user_data)
{
	chooser_finish(user_data, NULL, FALSE);
	return G_SOURCE_REMOVE;
}

static void on_cancelled(GCancellable* cancellable, gpointer user_data)
{
	g_idle_add(on_cancelled_idle, user_data);
}

static void on_row_selected(GtkListBox* list, GtkListBoxRow* row, gpointer user_data)
{
	Chooser* chooser = user_data;

	gtk_widget_set_sensitive(chooser->use_button, row != NULL);
}

static void on_row_activated(GtkListBox* list, GtkListBoxRow* row, gpointer user_data)
{
	on_use(NULL, user_data);
}

/* ------------------------------------------------------------- the chrome */

/* THE TRUSTED IDENTITY POSITION. Everything in here came from the frontend as
 * an argument; none of it can be influenced by the application. The identity
 * LEVEL is stated in words next to the name, because an application name shown
 * without saying how it was established is a lie by omission. */
static GtkWidget* build_identity(const CertificateCallerIdentity* caller)
{
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget* name = NULL;
	GtkWidget* level = NULL;
	const char* level_text = NULL;
	const char* display = NULL;

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

	if (caller->app_display_name != NULL && *caller->app_display_name != '\0')
		display = caller->app_display_name;
	else if (caller->app_id != NULL && *caller->app_id != '\0')
		display = caller->app_id;
	else
		display = "An unidentified application";

	name = gtk_label_new(display);
	gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
	gtk_label_set_wrap(GTK_LABEL(name), TRUE);
	gtk_widget_add_css_class(name, "title-2");
	gtk_box_append(GTK_BOX(box), name);

	/* The raw app id is always shown as well, even when a display name was
	 * resolved: the name comes from a desktop file and the id is the thing the
	 * frontend actually established. */
	if (caller->app_id != NULL && *caller->app_id != '\0' &&
	    g_strcmp0(caller->app_id, display) != 0)
	{
		GtkWidget* id_label = gtk_label_new(caller->app_id);

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

static char* format_lifetime(guint32 seconds)
{
	if (seconds == 0)
		return g_strdup("this operation only");

	if (seconds < 120)
		return g_strdup_printf("%u seconds", seconds);

	if (seconds < 7200)
		return g_strdup_printf("%u minutes", (seconds + 59) / 60);

	return g_strdup_printf("%u hours", (seconds + 3599) / 3600);
}

static GtkWidget* build_row(CertificateCandidate* candidate, gint64 now)
{
	GtkWidget* row = gtk_list_box_row_new();
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget* subject = NULL;
	g_autoptr(GDateTime) expiry = NULL;
	g_autofree char* expiry_text = NULL;
	g_autofree char* detail = NULL;
	g_autoptr(GString) accessible = g_string_new(NULL);

	gtk_widget_set_margin_top(box, 8);
	gtk_widget_set_margin_bottom(box, 8);
	gtk_widget_set_margin_start(box, 10);
	gtk_widget_set_margin_end(box, 10);

	subject = gtk_label_new(candidate->subject_display);
	gtk_label_set_xalign(GTK_LABEL(subject), 0.0f);
	gtk_label_set_ellipsize(GTK_LABEL(subject), PANGO_ELLIPSIZE_END);
	gtk_widget_add_css_class(subject, "heading");
	gtk_box_append(GTK_BOX(box), subject);
	g_string_append(accessible, candidate->subject_display);

	{
		g_autofree char* issuer = g_strdup_printf("Issued by %s", candidate->issuer_display);
		GtkWidget* label = gtk_label_new(issuer);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
		gtk_widget_add_css_class(label, "dim-label");
		gtk_box_append(GTK_BOX(box), label);
		g_string_append_printf(accessible, ", %s", issuer);
	}

	expiry = g_date_time_new_from_unix_local(candidate->not_after);

	/* EXPIRY IS A WORD, NOT A COLOUR. "Expired" has to survive a monochrome
	 * screen and a screen reader; the CSS class is an addition, never the
	 * carrier of the fact. */
	if (certificate_candidate_is_expired(candidate, now))
		expiry_text = g_strdup_printf("EXPIRED on %s",
		                              expiry != NULL ? g_date_time_format(expiry, "%x") : "an "
		                                                                                  "unknown "
		                                                                                  "date");
	else if (certificate_candidate_is_not_yet_valid(candidate, now))
		expiry_text = g_strdup("NOT YET VALID");
	else
		expiry_text = g_strdup_printf(
		    "Valid until %s", expiry != NULL ? g_date_time_format(expiry, "%x") : "an unknown date");

	detail = g_strdup_printf("%s  ·  %s %u-bit  ·  %s%s%s", expiry_text,
	                         candidate->key_type != NULL ? candidate->key_type : "unknown",
	                         candidate->key_size,
	                         candidate->token->label != NULL && *candidate->token->label != '\0'
	                             ? candidate->token->label
	                             : "unnamed token",
	                         candidate->token->reader_name != NULL &&
	                                 *candidate->token->reader_name != '\0'
	                             ? " in "
	                             : "",
	                         candidate->token->reader_name != NULL ? candidate->token->reader_name
	                                                               : "");

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
	GtkListBoxRow* preselected = NULL;

	if (!certificate_ui_has_display())
	{
		CertificateChooserResult result = { NULL, FALSE };

		done(&result, user_data);
		return;
	}

	chooser = g_new0(Chooser, 1);
	chooser->candidates = g_ptr_array_ref(candidates);
	chooser->done = done;
	chooser->user_data = user_data;
	chooser->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;

	window = adw_window_new();
	chooser->window = GTK_WINDOW(window);
	/* The window's own title is this backend's, never the caller's. */
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
		/* The purpose in THIS BACKEND'S OWN WORDS. Never the caller's. */
		g_autofree char* text =
		    g_strdup_printf("wants to use a certificate on your security token to %s.",
		                    certificate_purpose_display(request->purpose));
		GtkWidget* label = gtk_label_new(text);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_wrap(GTK_LABEL(label), TRUE);
		gtk_box_append(GTK_BOX(content), label);
	}

	/* THE CALLER'S OWN TEXT, VISIBLY SEPARATED AND LABELLED AS THE
	 * APPLICATION'S. Sanitised to one line so that it cannot draw chrome of its
	 * own, and never in the identity position above. */
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

		/* PRESELECTION ONLY. The window still opens and the user still
		 * confirms; a remembered choice is a shortcut, never a bypass. */
		if (request->preselect_certificate != NULL &&
		    g_strcmp0(request->preselect_certificate, candidate->certificate_id) == 0)
			preselected = GTK_LIST_BOX_ROW(row);
	}

	scroller = gtk_scrolled_window_new();
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller), GTK_POLICY_NEVER,
	                               GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), chooser->list);
	gtk_widget_set_vexpand(scroller, TRUE);
	gtk_box_append(GTK_BOX(content), scroller);

	lifetime = format_lifetime(request->lifetime_seconds);
	{
		/* WHETHER FURTHER OPERATIONS MAY HAPPEN WITHOUT ANOTHER PROMPT, stated
		 * plainly, because this is the part users get wrong. */
		g_autofree char* text = g_strdup_printf(
		    "%s\n\nThis grant lasts %s. %s You will be asked for your PIN the first time the "
		    "key is used.",
		    certificate_purpose_detail(request->purpose), lifetime,
		    request->may_decrypt
		        ? "It allows signing and decryption."
		        : (request->may_sign ? "It allows signing only." : "It allows no operations."));
		GtkWidget* label = gtk_label_new(text);

		gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
		gtk_label_set_wrap(GTK_LABEL(label), TRUE);
		gtk_widget_add_css_class(label, "caption");
		gtk_box_append(GTK_BOX(content), label);
	}

	if (request->offer_selection_memory)
	{
		chooser->remember =
		    gtk_check_button_new_with_mnemonic("_Use this certificate for this application next "
		                                       "time without asking which one");
		gtk_box_append(GTK_BOX(content), chooser->remember);
	}

	buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign(buttons, GTK_ALIGN_END);

	cancel = gtk_button_new_with_mnemonic("_Cancel");
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
	g_signal_connect(keys, "key-pressed", G_CALLBACK(on_key_pressed), chooser);
	gtk_widget_add_controller(window, keys);

	g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), chooser);

	if (chooser->cancellable != NULL)
		chooser->cancel_id =
		    g_cancellable_connect(chooser->cancellable, G_CALLBACK(on_cancelled), chooser, NULL);

	if (preselected != NULL)
		gtk_list_box_select_row(GTK_LIST_BOX(chooser->list), preselected);

	certificate_log_decision(CERTIFICATE_REASON_CHOOSER_SHOWN, request->caller->app_id,
	                         certificate_identity_level_to_string(request->caller->level),
	                         certificate_purpose_to_string(request->purpose), FALSE);

	certificate_external_window_present(GTK_WINDOW(window), parent_window, activation_token);

	gtk_widget_grab_focus(chooser->list);
}
