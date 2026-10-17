/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <adwaita.h>
#include <gtk/gtk.h>
#include <string.h>

#include "../certificate.h"
#include "external-window.h"
#include "../core/pin-internal.h"
#include "pin-backends.h"

typedef struct
{
	PinPrompt* prompt; /* Borrowed; owned by the prompt. */

	GtkWindow* window;
	GtkWidget* entry;
	GtkWidget* unlock_button;
	GtkWidget* confirm_button;
	GtkWidget* cancel_button;
	GtkEventController* keys;
	GtkWidget* status;
	GtkWidget* hint;
	GtkWidget* spinner;
	gboolean warning_pending;
} GtkPinPrompt;

static void gtk_pin_free(gpointer data)
{
	g_free(data);
}

static GtkPinPrompt* gtk_pin(PinPrompt* prompt)
{
	return prompt->impl_data;
}

/* GTK's stub accessibility context has no announce vfunc; only the AT-SPI context supports announcements. */
static gboolean announcement_reaches_anyone(GtkAccessible* accessible)
{
	GtkATContext* context = gtk_accessible_get_at_context(accessible);
	gboolean live = FALSE;

	if (context == NULL)
		return FALSE;

	live = g_strcmp0(G_OBJECT_TYPE_NAME(context), "GtkAtSpiContext") == 0;
	g_object_unref(context);
	return live;
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
		/* Announce attempt failures without exposing the PIN to accessibility. */
		if (ui->window != NULL && announcement_reaches_anyone(GTK_ACCESSIBLE(ui->window)))
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
	XccSecret* secret;
	size_t capacity;
	size_t length;
	uint8_t* data;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	/* GTK may make intermediate PIN copies; locked core storage guarantees are documented in docs/SECURITY.md. */
	text = gtk_editable_get_text(GTK_EDITABLE(ui->entry));
	set_status(prompt, NULL, FALSE);
	length = strlen(text);
	secret = xcc_secret_new();
	if (secret != NULL)
	{
		data = xcc_secret_data(secret, &capacity);
		if (length < capacity && length <= 511)
			memcpy(data, text, length);
	}
	if (!certificate_pin_prompt_hold(prompt, secret, length))
		return;

	if (ui->warning_pending)
	{
		ui->warning_pending = FALSE;
		certificate_pin_prompt_warning_reply(prompt, TRUE);
	}
	else
		certificate_pin_prompt_submit(prompt);
}

/* Protected-path login also requires explicit confirmation before its final attempt. */
static void on_protected_confirm(GtkWidget* widget, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	certificate_pin_prompt_warning_reply(prompt, TRUE);
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

static void gtk_pin_show(gpointer user_data, PinPrompt* prompt)
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

	/* Restate the caller and purpose; sanitize desktop and token metadata before display. */
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

	/* Create the warning widget before login because retries may newly set PIN warning flags. */
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
	else if (prompt->token->pin_final_try)
	{
		/* The core requests confirmation after the protected-path notice is shown. */
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
	else
		certificate_pin_prompt_submit(prompt);
}

static void gtk_pin_busy(PinPrompt* prompt, gboolean busy)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	if (ui->entry != NULL)
	{
		if (busy)
			gtk_editable_set_text(GTK_EDITABLE(ui->entry), "");
		gtk_widget_set_sensitive(ui->entry, !busy);
	}
	if (ui->unlock_button != NULL)
		gtk_widget_set_sensitive(ui->unlock_button, !busy);
	if (ui->spinner != NULL)
		gtk_widget_set_visible(ui->spinner, busy);
}

static void gtk_pin_retry(PinPrompt* prompt, const char* status)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	update_retry_hint(prompt);

	if (ui->entry != NULL)
	{
		gtk_editable_set_text(GTK_EDITABLE(ui->entry), "");
		gtk_widget_grab_focus(ui->entry);
	}

	set_status(prompt, status, TRUE);
}

static void gtk_pin_update(gpointer user_data, PinPrompt* prompt, const char* status)
{
	if (status != NULL)
		gtk_pin_retry(prompt, status);
	else
		gtk_pin_busy(prompt, prompt->busy);
}

static void gtk_pin_warning(gpointer user_data, PinPrompt* prompt, const char* message)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	ui->warning_pending = TRUE;
	set_status(prompt, message, TRUE);
	if (prompt->protected_path)
		gtk_widget_grab_focus(ui->cancel_button);
}

static void gtk_pin_hide(gpointer user_data, PinPrompt* prompt)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	if (ui->window != NULL)
		gtk_widget_set_visible(GTK_WIDGET(ui->window), FALSE);
}

static void gtk_pin_close(gpointer user_data, PinPrompt* prompt)
{
	GtkPinPrompt* ui = gtk_pin(prompt);

	if (ui == NULL)
		return;

	/* Disconnect before destroying widgets because disposal emits signals. */
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

const CertificatePinProvider* certificate_pin_provider_gtk(void)
{
	static const CertificatePinProvider provider = {
		.name = "gtk",
		.needs_display = TRUE,
		.pin_show = gtk_pin_show,
		.pin_update = gtk_pin_update,
		.warning = gtk_pin_warning,
		.hide = gtk_pin_hide,
		.close = gtk_pin_close,
	};

	return &provider;
}
