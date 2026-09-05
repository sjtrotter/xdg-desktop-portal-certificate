/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * THE IN-PROCESS PIN WINDOW. This file draws widgets and reports what the user
 * did; every decision -- whether an attempt may be spent, whether a retry is
 * offered, what the token's flags mean -- is ui/pin.c's. See ui/pin-internal.h
 * for the contract.
 */

#include <adwaita.h>
#include <gtk/gtk.h>

#include "../certificate.h"
#include "external-window.h"
#include "pin-internal.h"

typedef struct
{
	PinPrompt* prompt; /* borrowed: the prompt owns this struct */

	GtkWindow* window;
	GtkWidget* entry;
	GtkWidget* unlock_button;
	GtkWidget* confirm_button;
	GtkWidget* cancel_button;
	GtkEventController* keys;
	GtkWidget* status;
	GtkWidget* hint;
	GtkWidget* spinner;
} GtkPinPrompt;

static void gtk_pin_free(gpointer data)
{
	g_free(data);
}

static GtkPinPrompt* gtk_pin(PinPrompt* prompt)
{
	return prompt->impl_data;
}

static void set_status(PinPrompt* prompt, const char* text, gboolean is_error)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	if (ui->status == NULL)
		return;

	gtk_label_set_text(GTK_LABEL(ui->status), text != NULL ? text : "");
	gtk_widget_set_visible(ui->status, text != NULL && *text != '\0');

	if (is_error)
	{
		gtk_widget_add_css_class(ui->status, "error");
		/* The failure state IS announced: a screen-reader user must learn that
		 * an attempt was spent. The PIN itself never enters this tree. */
		if (ui->window != NULL)
			gtk_accessible_announce(GTK_ACCESSIBLE(ui->window), text,
			                        GTK_ACCESSIBLE_ANNOUNCEMENT_PRIORITY_HIGH);
	}
	else
	{
		gtk_widget_remove_css_class(ui->status, "error");
	}
}

static void update_retry_hint(PinPrompt* prompt)
{
	GtkPinPrompt* ui = gtk_pin(prompt);
	const char* hint = certificate_pin_prompt_retry_hint(prompt);

	if (ui->hint == NULL)
		return;

	gtk_label_set_text(GTK_LABEL(ui->hint), hint != NULL ? hint : "");
	gtk_widget_set_visible(ui->hint, hint != NULL);
}

static void on_unlock(GtkWidget* widget, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	GtkPinPrompt* ui = gtk_pin(prompt);
	const char* text = NULL;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	/* AN EMPTY FIELD IS NOT AN ATTEMPT, and that rule is no longer written
	 * here: it is certificate_pin_prompt_hold()'s, so that the shell's prompter
	 * obeys the same one. What comes back is FALSE and a retry with a warning.
	 *
	 * GTK's own storage is a GtkPasswordEntryBuffer, which GTK allocates from
	 * its secure-memory pool and zeroes when it frees it -- but GTK guarantees
	 * nothing about the intermediate copies a text widget, an input method or a
	 * Pango layout may have made, so this backend does not claim the PIN
	 * existed in exactly one place. It claims what is true: ui/pin.c holds it
	 * in one wiped, locked, non-dumpable page. */
	text = gtk_editable_get_text(GTK_EDITABLE(ui->entry));
	set_status(prompt, NULL, FALSE);

	if (!certificate_pin_prompt_hold(prompt, text))
		return;

	/* THE LAST ATTEMPT IS NOT SPENT ON A SINGLE CLICK. When the token says
	 * CKF_USER_PIN_FINAL_TRY, the next refusal locks the card, so the window
	 * says so and requires the user to press Unlock a second time -- with what
	 * they already typed still in the field, so the confirmation is a decision
	 * rather than a retype. The value is already in the locked page by then;
	 * the second press spends the attempt, exactly as the confirmation round
	 * does on the shell's prompt. */
	if (certificate_pin_prompt_needs_final_confirm(prompt))
	{
		set_status(prompt, certificate_pin_prompt_final_try_warning(), TRUE);
		return;
	}

	/* Cleared the moment the value is in the locked buffer, and before the
	 * worker starts, so the field is empty for the whole time the card is
	 * busy. */
	gtk_editable_set_text(GTK_EDITABLE(ui->entry), "");
	certificate_pin_prompt_submit(prompt);
}

/* THE LAST ATTEMPT ON A PIN PAD IS STILL THE LAST ATTEMPT. A protected
 * authentication path has no field in this window, so the second press that
 * confirms CKF_USER_PIN_FINAL_TRY is a button of its own -- without it the
 * NULL-PIN login went out the moment the window appeared, which made the
 * "unconditional" in docs/SECURITY.md untrue for exactly the tokens whose
 * counter cannot be seen. */
static void on_protected_confirm(GtkWidget* widget, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	certificate_pin_prompt_submit(prompt);
}

static void on_cancel(GtkWidget* widget, gpointer user_data)
{
	certificate_pin_prompt_answer(user_data, CERTIFICATE_PIN_CANCELLED);
}

static gboolean on_close_request(GtkWindow* window, gpointer user_data)
{
	certificate_pin_prompt_answer(user_data, CERTIFICATE_PIN_CANCELLED);
	return TRUE;
}

static gboolean on_key_pressed(GtkEventControllerKey* controller, guint keyval, guint keycode,
                               GdkModifierType state, gpointer user_data)
{
	if (keyval == GDK_KEY_Escape)
	{
		certificate_pin_prompt_answer(user_data, CERTIFICATE_PIN_CANCELLED);
		return GDK_EVENT_STOP;
	}

	return GDK_EVENT_PROPAGATE;
}

static GtkWidget* label_row(const char* title, const char* value)
{
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget* name = gtk_label_new(title);
	GtkWidget* text = gtk_label_new(value);

	gtk_widget_add_css_class(name, "dim-label");
	gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
	gtk_label_set_xalign(GTK_LABEL(text), 0.0f);
	gtk_label_set_wrap(GTK_LABEL(text), TRUE);
	gtk_label_set_selectable(GTK_LABEL(text), FALSE);
	gtk_widget_set_hexpand(text, TRUE);
	gtk_widget_set_size_request(name, 110, -1);

	gtk_box_append(GTK_BOX(box), name);
	gtk_box_append(GTK_BOX(box), text);

	return box;
}

static void gtk_pin_start(PinPrompt* prompt)
{
	GtkPinPrompt* ui = g_new0(GtkPinPrompt, 1);
	GtkWidget* window = NULL;
	GtkWidget* toolbar = NULL;
	GtkWidget* header = NULL;
	GtkWidget* content = NULL;
	GtkWidget* buttons = NULL;
	GtkWidget* cancel = NULL;
	GtkEventController* keys = NULL;
	gboolean protected_path = prompt->protected_path;

	ui->prompt = prompt;
	prompt->impl_data = ui;
	prompt->impl_data_free = gtk_pin_free;

	window = adw_window_new();
	ui->window = GTK_WINDOW(window);
	gtk_window_set_title(GTK_WINDOW(window), "Unlock Security Token");
	gtk_window_set_modal(GTK_WINDOW(window), TRUE);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_window_set_default_size(GTK_WINDOW(window), 440, -1);

	header = adw_header_bar_new();
	adw_header_bar_set_show_end_title_buttons(ADW_HEADER_BAR(header), FALSE);

	content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
	gtk_widget_set_margin_top(content, 18);
	gtk_widget_set_margin_bottom(content, 18);
	gtk_widget_set_margin_start(content, 18);
	gtk_widget_set_margin_end(content, 18);

	{
		GtkWidget* heading = gtk_label_new(certificate_pin_prompt_heading(prompt));

		gtk_label_set_wrap(GTK_LABEL(heading), TRUE);
		gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
		gtk_widget_add_css_class(heading, "title-2");
		gtk_box_append(GTK_BOX(content), heading);
	}

	/* The window restates the verified caller and the purpose from the chooser,
	 * so that a PIN prompt arriving on its own is still attributable. EVERY
	 * VALUE BELOW IS SANITISED AND CAPPED: the caller display comes from a
	 * desktop file and the token label and reader name come off the card, and
	 * none of the three may draw chrome of its own inside this window. */
	{
		g_autofree char* caller = certificate_display_text(prompt->caller_display,
		                                                   CERTIFICATE_DISPLAY_MAX_APP_NAME, NULL);
		g_autofree char* purpose = certificate_display_text(prompt->purpose_display,
		                                                    CERTIFICATE_DISPLAY_MAX_PURPOSE, NULL);
		g_autofree char* label = certificate_display_text(
		    prompt->token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "Unnamed token");
		g_autofree char* reader = certificate_display_text(prompt->token->reader_name,
		                                                   CERTIFICATE_DISPLAY_MAX_READER, NULL);

		if (caller != NULL)
			gtk_box_append(GTK_BOX(content), label_row("Application", caller));
		if (purpose != NULL)
			gtk_box_append(GTK_BOX(content), label_row("In order to", purpose));
		gtk_box_append(GTK_BOX(content), label_row("Token", label));
		if (reader != NULL)
			gtk_box_append(GTK_BOX(content), label_row("Reader", reader));
	}

	if (!protected_path)
	{
		ui->entry = gtk_password_entry_new();
		gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(ui->entry), FALSE);
		gtk_widget_set_hexpand(ui->entry, TRUE);
		gtk_accessible_update_property(GTK_ACCESSIBLE(ui->entry),
		                               GTK_ACCESSIBLE_PROPERTY_LABEL, "Token PIN", -1);
		g_signal_connect(ui->entry, "activate", G_CALLBACK(on_unlock), prompt);
		gtk_box_append(GTK_BOX(content), ui->entry);
	}
	else
	{
		GtkWidget* note = gtk_label_new(certificate_pin_prompt_protected_note());

		gtk_label_set_wrap(GTK_LABEL(note), TRUE);
		gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
		gtk_widget_add_css_class(note, "dim-label");
		gtk_box_append(GTK_BOX(content), note);
	}

	ui->status = gtk_label_new(NULL);
	gtk_label_set_wrap(GTK_LABEL(ui->status), TRUE);
	gtk_label_set_xalign(GTK_LABEL(ui->status), 0.0f);
	gtk_widget_set_visible(ui->status, FALSE);
	gtk_box_append(GTK_BOX(content), ui->status);

	/* Created whether or not there is a hint to show right now: the flags are
	 * re-read after every refusal, and a warning that only exists if it was
	 * needed at window-open time is a warning that arrives too late. */
	ui->hint = gtk_label_new(NULL);
	gtk_label_set_wrap(GTK_LABEL(ui->hint), TRUE);
	gtk_label_set_xalign(GTK_LABEL(ui->hint), 0.0f);
	gtk_widget_add_css_class(ui->hint, "warning");
	gtk_box_append(GTK_BOX(content), ui->hint);
	update_retry_hint(prompt);

	ui->spinner = gtk_spinner_new();
	gtk_spinner_set_spinning(GTK_SPINNER(ui->spinner), TRUE);
	gtk_widget_set_visible(ui->spinner, FALSE);
	gtk_widget_set_halign(ui->spinner, GTK_ALIGN_CENTER);
	gtk_box_append(GTK_BOX(content), ui->spinner);

	buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign(buttons, GTK_ALIGN_END);

	cancel = gtk_button_new_with_mnemonic("_Cancel");
	ui->cancel_button = cancel;
	g_signal_connect(cancel, "clicked", G_CALLBACK(on_cancel), prompt);
	gtk_box_append(GTK_BOX(buttons), cancel);

	if (!protected_path)
	{
		ui->unlock_button = gtk_button_new_with_mnemonic("_Unlock");
		gtk_widget_add_css_class(ui->unlock_button, "suggested-action");
		g_signal_connect(ui->unlock_button, "clicked", G_CALLBACK(on_unlock), prompt);
		gtk_box_append(GTK_BOX(buttons), ui->unlock_button);
	}
	else if (certificate_pin_prompt_needs_final_confirm(prompt))
	{
		/* The reader will collect the PIN, but the attempt this window is about
		 * to spend is the last one the token has -- so it is asked for, here,
		 * before the NULL-PIN login goes out. Calling
		 * certificate_pin_prompt_needs_final_confirm() has already RECORDED the
		 * confirmation, so the button below is the second press. */
		ui->confirm_button = gtk_button_new_with_mnemonic("Use the _last attempt");
		gtk_widget_add_css_class(ui->confirm_button, "destructive-action");
		g_signal_connect(ui->confirm_button, "clicked", G_CALLBACK(on_protected_confirm),
		                 prompt);
		gtk_box_append(GTK_BOX(buttons), ui->confirm_button);
	}

	gtk_box_append(GTK_BOX(content), buttons);

	toolbar = adw_toolbar_view_new();
	adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
	adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), content);
	adw_window_set_content(ADW_WINDOW(window), toolbar);

	keys = gtk_event_controller_key_new();
	ui->keys = keys;
	g_signal_connect(keys, "key-pressed", G_CALLBACK(on_key_pressed), prompt);
	gtk_widget_add_controller(window, keys);

	g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), prompt);

	certificate_external_window_present(GTK_WINDOW(window), prompt->parent_window, NULL);

	if (ui->entry != NULL)
	{
		gtk_widget_grab_focus(ui->entry);
	}
	else if (ui->confirm_button != NULL)
	{
		/* NOTHING IS SUBMITTED YET. The reader is not asked for anything until
		 * the last attempt has been confirmed; Cancel keeps the focus so that a
		 * stray Return does not spend it. */
		set_status(prompt, certificate_pin_prompt_final_try_warning(), TRUE);
		gtk_widget_grab_focus(ui->cancel_button);
	}
	else
	{
		certificate_pin_prompt_submit(prompt);
	}
}

static void gtk_pin_busy(PinPrompt* prompt, gboolean busy)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	if (ui->entry != NULL)
		gtk_widget_set_sensitive(ui->entry, !busy);
	if (ui->unlock_button != NULL)
		gtk_widget_set_sensitive(ui->unlock_button, !busy);
	if (ui->spinner != NULL)
		gtk_widget_set_visible(ui->spinner, busy);
}

static void gtk_pin_retry(PinPrompt* prompt, const char* status)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	/* The flags were re-read on the worker thread after the refusal, so this is
	 * about the state the token is in NOW. */
	update_retry_hint(prompt);

	if (ui->entry != NULL)
	{
		gtk_editable_set_text(GTK_EDITABLE(ui->entry), "");
		gtk_widget_grab_focus(ui->entry);
	}

	set_status(prompt, status, TRUE);
}

static void gtk_pin_hide(PinPrompt* prompt)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	if (ui->window != NULL)
		gtk_widget_set_visible(GTK_WIDGET(ui->window), FALSE);
}

static void gtk_pin_close(PinPrompt* prompt)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	if (ui == NULL)
		return;

	/* Disconnected before the destroy, for the same reason the chooser does it:
	 * tearing a window down emits signals at a point where the widgets those
	 * handlers touch have already been disposed. EVERY handler, not only the
	 * two that used to be listed. The `finished` guard makes a late callback
	 * harmless, but "harmless because the first line returns" is a weaker
	 * property than "cannot be called". */
	if (ui->entry != NULL)
		g_signal_handlers_disconnect_by_data(ui->entry, prompt);
	if (ui->window != NULL)
		g_signal_handlers_disconnect_by_data(ui->window, prompt);
	if (ui->unlock_button != NULL)
		g_signal_handlers_disconnect_by_data(ui->unlock_button, prompt);
	if (ui->confirm_button != NULL)
		g_signal_handlers_disconnect_by_data(ui->confirm_button, prompt);
	if (ui->cancel_button != NULL)
		g_signal_handlers_disconnect_by_data(ui->cancel_button, prompt);
	if (ui->keys != NULL)
		g_signal_handlers_disconnect_by_data(ui->keys, prompt);

	if (ui->window != NULL)
	{
		gtk_window_destroy(ui->window);
		ui->window = NULL;
	}

	ui->entry = NULL;
	ui->unlock_button = NULL;
	ui->confirm_button = NULL;
	ui->cancel_button = NULL;
	ui->keys = NULL;
	ui->status = NULL;
	ui->hint = NULL;
	ui->spinner = NULL;
}

const PinPromptImpl* certificate_pin_impl_gtk(void)
{
	static const PinPromptImpl impl = {
		.name = "gtk",
		.needs_display = TRUE,
		.start = gtk_pin_start,
		.busy = gtk_pin_busy,
		.retry = gtk_pin_retry,
		.hide = gtk_pin_hide,
		.close = gtk_pin_close,
	};

	return &impl;
}
