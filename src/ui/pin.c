/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

/* explicit_bzero(), posix_memalign(), mlock(): the PIN buffer needs all three. */
#define _GNU_SOURCE 1

#include "pin.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <adwaita.h>
#include <gtk/gtk.h>

#include "../redact.h"
#include "external-window.h"

static gboolean ui_has_display = FALSE;

void certificate_ui_set_has_display(gboolean has_display)
{
	ui_has_display = has_display;
}

gboolean certificate_ui_has_display(void)
{
	return ui_has_display;
}

/* ------------------------------------------------------------- PIN buffer */

/* Page-aligned, mlock()ed where the kernel and the rlimit allow, and wiped with
 * explicit_bzero() on every exit path. mlock() failing is not fatal -- the
 * default RLIMIT_MEMLOCK is small and a desktop session may have spent it --
 * but it is the difference between "not written to swap" and "probably not
 * written to swap", so it is attempted every time. */
typedef struct
{
	char* data;
	gsize capacity;
	gboolean locked;
} PinBuffer;

#define PIN_BUFFER_CAPACITY 512

static PinBuffer* pin_buffer_new(void)
{
	PinBuffer* buffer = g_new0(PinBuffer, 1);
	long page = sysconf(_SC_PAGESIZE);
	gsize size = page > 0 ? (gsize) page : 4096;

	if (posix_memalign((void**) &buffer->data, size, size) != 0)
	{
		g_free(buffer);
		return NULL;
	}

	buffer->capacity = size;
	memset(buffer->data, 0, buffer->capacity);
	buffer->locked = mlock(buffer->data, buffer->capacity) == 0;

	return buffer;
}

static void pin_buffer_wipe(PinBuffer* buffer)
{
	if (buffer == NULL || buffer->data == NULL)
		return;

	explicit_bzero(buffer->data, buffer->capacity);
}

static void pin_buffer_free(PinBuffer* buffer)
{
	if (buffer == NULL)
		return;

	pin_buffer_wipe(buffer);

	if (buffer->locked)
		munlock(buffer->data, buffer->capacity);

	free(buffer->data);
	g_free(buffer);
}

static gboolean pin_buffer_set(PinBuffer* buffer, const char* text)
{
	gsize length = text != NULL ? strlen(text) : 0;

	pin_buffer_wipe(buffer);

	if (length + 1 > buffer->capacity)
		return FALSE;

	memcpy(buffer->data, text, length);
	buffer->data[length] = '\0';
	return TRUE;
}

/* -------------------------------------------------------------- the prompt */

typedef struct
{
	CertificateToken* token;
	char* parent_window;
	char* caller_display;
	char* purpose_display;

	CertificatePinLoginFunc login;
	gpointer login_data;
	GCancellable* cancellable;
	gulong cancel_id;
	CertificatePinDone done;
	gpointer user_data;

	GtkWindow* window;
	GtkWidget* entry;
	GtkWidget* unlock_button;
	GtkWidget* status;
	GtkWidget* spinner;

	PinBuffer* buffer;
	gboolean finished;
	gboolean busy;
} PinPrompt;

/* PROMPTS ARE SERIALISED PROCESS-WIDE. Two grants must not race two PIN windows
 * at the user: whichever arrives second waits, and a user who is asked for one
 * PIN is never looking at two windows wondering which is real. */
static GQueue pin_queue = G_QUEUE_INIT;
static PinPrompt* pin_active = NULL;

static void pin_prompt_start(PinPrompt* prompt);

static void pin_prompt_free(PinPrompt* prompt)
{
	g_clear_pointer(&prompt->buffer, pin_buffer_free);
	g_clear_pointer(&prompt->token, certificate_token_unref);
	g_free(prompt->parent_window);
	g_free(prompt->caller_display);
	g_free(prompt->purpose_display);
	g_clear_object(&prompt->cancellable);
	g_free(prompt);
}

static void pin_prompt_finish(PinPrompt* prompt, CertificatePinOutcome outcome)
{
	CertificatePinDone done = prompt->done;
	gpointer user_data = prompt->user_data;

	if (prompt->finished)
		return;

	prompt->finished = TRUE;

	if (prompt->cancel_id != 0)
	{
		g_cancellable_disconnect(prompt->cancellable, prompt->cancel_id);
		prompt->cancel_id = 0;
	}

	/* The buffer is wiped before anything else can run, including the caller's
	 * callback. */
	if (prompt->buffer != NULL)
		pin_buffer_wipe(prompt->buffer);

	/* Disconnected before the destroy, for the same reason the chooser does it:
	 * tearing a window down emits signals at a point where the widgets those
	 * handlers touch have already been disposed. */
	if (prompt->entry != NULL)
		g_signal_handlers_disconnect_by_data(prompt->entry, prompt);
	if (prompt->window != NULL)
		g_signal_handlers_disconnect_by_data(prompt->window, prompt);

	if (prompt->window != NULL)
	{
		gtk_window_destroy(prompt->window);
		prompt->window = NULL;
	}

	if (pin_active == prompt)
	{
		pin_active = NULL;

		if (!g_queue_is_empty(&pin_queue))
			pin_prompt_start(g_queue_pop_head(&pin_queue));
	}
	else
	{
		g_queue_remove(&pin_queue, prompt);
	}

	pin_prompt_free(prompt);

	done(outcome, user_data);
}

typedef struct
{
	PinPrompt* prompt;
	PinBuffer* buffer; /* borrowed */
	gboolean protected_path;
} LoginTask;

static void login_thread(GTask* task, gpointer source, gpointer task_data,
                         GCancellable* cancellable)
{
	LoginTask* data = task_data;
	g_autoptr(GError) error = NULL;
	const char* pin = data->protected_path ? NULL : data->buffer->data;

	/* C_Login on a card takes hundreds of milliseconds and can block for as
	 * long as the middleware wants. It never runs on the main thread. */
	if (data->prompt->login(pin, data->prompt->login_data, &error))
		g_task_return_boolean(task, TRUE);
	else
		g_task_return_error(task, g_steal_pointer(&error));
}

static void set_status(PinPrompt* prompt, const char* text, gboolean is_error)
{
	if (prompt->status == NULL)
		return;

	gtk_label_set_text(GTK_LABEL(prompt->status), text != NULL ? text : "");
	gtk_widget_set_visible(prompt->status, text != NULL && *text != '\0');

	if (is_error)
	{
		gtk_widget_add_css_class(prompt->status, "error");
		/* The failure state IS announced: a screen-reader user must learn that
		 * an attempt was spent. The PIN itself never enters this tree. */
		gtk_accessible_announce(GTK_ACCESSIBLE(prompt->window), text,
		                        GTK_ACCESSIBLE_ANNOUNCEMENT_PRIORITY_HIGH);
	}
	else
	{
		gtk_widget_remove_css_class(prompt->status, "error");
	}
}

static void set_busy(PinPrompt* prompt, gboolean busy)
{
	prompt->busy = busy;

	if (prompt->entry != NULL)
		gtk_widget_set_sensitive(prompt->entry, !busy);
	if (prompt->unlock_button != NULL)
		gtk_widget_set_sensitive(prompt->unlock_button, !busy);
	if (prompt->spinner != NULL)
		gtk_widget_set_visible(prompt->spinner, busy);
}

static void on_login_done(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	g_autoptr(GError) error = NULL;

	if (prompt->finished)
		return;

	if (g_task_propagate_boolean(G_TASK(result), &error))
	{
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL, "pin-accepted");
		pin_prompt_finish(prompt, CERTIFICATE_PIN_OK);
		return;
	}

	set_busy(prompt, FALSE);

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, NULL, "retry-offered");

		if (prompt->entry == NULL)
		{
			/* A protected authentication path cannot be retried from here: the
			 * reader owns the interaction. */
			pin_prompt_finish(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		/* RETRIES ARE USER-INITIATED. The window stays up with the field
		 * cleared; nothing here spends another attempt on its own. */
		pin_buffer_wipe(prompt->buffer);
		gtk_editable_set_text(GTK_EDITABLE(prompt->entry), "");
		set_status(prompt, "That PIN was not accepted. Try again.", TRUE);
		gtk_widget_grab_focus(prompt->entry);
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_LOCKED))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, NULL, "terminal");
		pin_prompt_finish(prompt, CERTIFICATE_PIN_LOCKED);
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
	{
		pin_prompt_finish(prompt, CERTIFICATE_PIN_TOKEN_REMOVED);
		return;
	}

	pin_prompt_finish(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
}

static void run_login(PinPrompt* prompt, gboolean protected_path)
{
	g_autoptr(GTask) task = NULL;
	LoginTask* data = g_new0(LoginTask, 1);

	data->prompt = prompt;
	data->buffer = prompt->buffer;
	data->protected_path = protected_path;

	set_busy(prompt, TRUE);

	task = g_task_new(NULL, NULL, on_login_done, prompt);
	g_task_set_task_data(task, data, g_free);
	g_task_run_in_thread(task, login_thread);
}

static void on_unlock(GtkWidget* widget, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	const char* text = NULL;

	if (prompt->busy || prompt->finished)
		return;

	text = gtk_editable_get_text(GTK_EDITABLE(prompt->entry));
	if (text == NULL || *text == '\0')
	{
		set_status(prompt, "Enter the PIN for this token.", FALSE);
		return;
	}

	if (!pin_buffer_set(prompt->buffer, text))
	{
		set_status(prompt, "That is longer than any PIN this backend will send.", TRUE);
		return;
	}

	/* The entry is cleared the moment the value is in the locked buffer, so the
	 * PIN exists in exactly one place from here on. GTK's own text buffer is
	 * not locked memory and is not something this process can wipe. */
	gtk_editable_set_text(GTK_EDITABLE(prompt->entry), "");
	set_status(prompt, NULL, FALSE);

	run_login(prompt, FALSE);
}

static void on_cancel(GtkWidget* widget, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
}

static gboolean on_close_request(GtkWindow* window, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
	return TRUE;
}

static gboolean on_key_pressed(GtkEventControllerKey* controller, guint keyval, guint keycode,
                               GdkModifierType state, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	if (keyval == GDK_KEY_Escape)
	{
		pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
		return GDK_EVENT_STOP;
	}

	return GDK_EVENT_PROPAGATE;
}

static gboolean on_cancelled_idle(gpointer user_data)
{
	PinPrompt* prompt = user_data;

	pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
	return G_SOURCE_REMOVE;
}

static void on_cancelled(GCancellable* cancellable, gpointer user_data)
{
	/* Close() can arrive on any thread GDBus feels like; the window is only
	 * ever touched from the main context. */
	g_idle_add(on_cancelled_idle, user_data);
}

/* The remaining-attempts hint, and NOTHING ELSE. PKCS#11 has no portable way to
 * ask a token how many tries are left, so this reports only the three flags the
 * standard defines, and never a number. A wrong count is worse than none. */
static const char* retry_hint(const CertificateToken* token)
{
	if (token->pin_locked)
		return "This token is locked. It cannot be unlocked here.";
	if (token->pin_final_try)
		return "This is the last attempt before the token locks.";
	if (token->pin_count_low)
		return "There have been recent failed attempts on this token.";

	return NULL;
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

static void pin_prompt_start(PinPrompt* prompt)
{
	GtkWidget* window = NULL;
	GtkWidget* toolbar = NULL;
	GtkWidget* header = NULL;
	GtkWidget* content = NULL;
	GtkWidget* buttons = NULL;
	GtkWidget* cancel = NULL;
	GtkEventController* keys = NULL;
	gboolean protected_path = prompt->token->protected_authentication_path;
	const char* hint = retry_hint(prompt->token);

	pin_active = prompt;

	window = adw_window_new();
	prompt->window = GTK_WINDOW(window);
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
		GtkWidget* heading = gtk_label_new(protected_path
		                                       ? "Enter your PIN on the reader"
		                                       : "Enter your PIN to unlock this token");

		gtk_label_set_wrap(GTK_LABEL(heading), TRUE);
		gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
		gtk_widget_add_css_class(heading, "title-2");
		gtk_box_append(GTK_BOX(content), heading);
	}

	/* The window restates the verified caller and the purpose from the chooser,
	 * so that a PIN prompt arriving on its own is still attributable. */
	if (prompt->caller_display != NULL)
		gtk_box_append(GTK_BOX(content), label_row("Application", prompt->caller_display));
	if (prompt->purpose_display != NULL)
		gtk_box_append(GTK_BOX(content), label_row("In order to", prompt->purpose_display));
	gtk_box_append(GTK_BOX(content),
	               label_row("Token", prompt->token->label != NULL && *prompt->token->label != '\0'
	                                      ? prompt->token->label
	                                      : "Unnamed token"));
	if (prompt->token->reader_name != NULL && *prompt->token->reader_name != '\0')
		gtk_box_append(GTK_BOX(content), label_row("Reader", prompt->token->reader_name));

	if (!protected_path)
	{
		prompt->entry = gtk_password_entry_new();
		gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(prompt->entry), FALSE);
		gtk_widget_set_hexpand(prompt->entry, TRUE);
		gtk_accessible_update_property(GTK_ACCESSIBLE(prompt->entry),
		                               GTK_ACCESSIBLE_PROPERTY_LABEL, "Token PIN", -1);
		g_signal_connect(prompt->entry, "activate", G_CALLBACK(on_unlock), prompt);
		gtk_box_append(GTK_BOX(content), prompt->entry);
	}
	else
	{
		GtkWidget* note = gtk_label_new(
		    "This reader collects the PIN itself. Follow the instructions on the reader; "
		    "nothing you type here is sent to the token.");

		gtk_label_set_wrap(GTK_LABEL(note), TRUE);
		gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
		gtk_widget_add_css_class(note, "dim-label");
		gtk_box_append(GTK_BOX(content), note);
	}

	prompt->status = gtk_label_new(NULL);
	gtk_label_set_wrap(GTK_LABEL(prompt->status), TRUE);
	gtk_label_set_xalign(GTK_LABEL(prompt->status), 0.0f);
	gtk_widget_set_visible(prompt->status, FALSE);
	gtk_box_append(GTK_BOX(content), prompt->status);

	if (hint != NULL)
	{
		GtkWidget* warning = gtk_label_new(hint);

		gtk_label_set_wrap(GTK_LABEL(warning), TRUE);
		gtk_label_set_xalign(GTK_LABEL(warning), 0.0f);
		gtk_widget_add_css_class(warning, "warning");
		gtk_box_append(GTK_BOX(content), warning);
	}

	prompt->spinner = gtk_spinner_new();
	gtk_spinner_set_spinning(GTK_SPINNER(prompt->spinner), TRUE);
	gtk_widget_set_visible(prompt->spinner, FALSE);
	gtk_widget_set_halign(prompt->spinner, GTK_ALIGN_CENTER);
	gtk_box_append(GTK_BOX(content), prompt->spinner);

	buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign(buttons, GTK_ALIGN_END);

	cancel = gtk_button_new_with_mnemonic("_Cancel");
	g_signal_connect(cancel, "clicked", G_CALLBACK(on_cancel), prompt);
	gtk_box_append(GTK_BOX(buttons), cancel);

	if (!protected_path)
	{
		prompt->unlock_button = gtk_button_new_with_mnemonic("_Unlock");
		gtk_widget_add_css_class(prompt->unlock_button, "suggested-action");
		g_signal_connect(prompt->unlock_button, "clicked", G_CALLBACK(on_unlock), prompt);
		gtk_box_append(GTK_BOX(buttons), prompt->unlock_button);
	}

	gtk_box_append(GTK_BOX(content), buttons);

	toolbar = adw_toolbar_view_new();
	adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
	adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), content);
	adw_window_set_content(ADW_WINDOW(window), toolbar);

	keys = gtk_event_controller_key_new();
	g_signal_connect(keys, "key-pressed", G_CALLBACK(on_key_pressed), prompt);
	gtk_widget_add_controller(window, keys);

	g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), prompt);

	certificate_log_grant(CERTIFICATE_REASON_PIN_PROMPTED, NULL,
	                      protected_path ? "protected-path" : "on-screen");

	certificate_external_window_present(GTK_WINDOW(window), prompt->parent_window, NULL);

	if (prompt->entry != NULL)
		gtk_widget_grab_focus(prompt->entry);
	else
		run_login(prompt, TRUE);
}

void certificate_pin_login(CertificateToken* token, const char* parent_window,
                           const char* caller_display, const char* purpose_display,
                           CertificatePinLoginFunc login, gpointer login_data,
                           GCancellable* cancellable, CertificatePinDone done, gpointer user_data)
{
	PinPrompt* prompt = NULL;

	if (!certificate_ui_has_display())
	{
		/* NEVER READ A PIN FROM STDIN. With no display there is no way to ask,
		 * and inventing one would be a trusted prompt nobody can see. */
		done(CERTIFICATE_PIN_NO_DISPLAY, user_data);
		return;
	}

	if (token->pin_locked)
	{
		done(CERTIFICATE_PIN_LOCKED, user_data);
		return;
	}

	prompt = g_new0(PinPrompt, 1);
	prompt->token = certificate_token_ref(token);
	prompt->parent_window = g_strdup(parent_window);
	prompt->caller_display = g_strdup(caller_display);
	prompt->purpose_display = g_strdup(purpose_display);
	prompt->login = login;
	prompt->login_data = login_data;
	prompt->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;
	prompt->done = done;
	prompt->user_data = user_data;
	prompt->buffer = pin_buffer_new();

	if (prompt->buffer == NULL)
	{
		pin_prompt_free(prompt);
		done(CERTIFICATE_PIN_DEVICE_ERROR, user_data);
		return;
	}

	if (prompt->cancellable != NULL)
		prompt->cancel_id =
		    g_cancellable_connect(prompt->cancellable, G_CALLBACK(on_cancelled), prompt, NULL);

	if (pin_active != NULL)
	{
		g_queue_push_tail(&pin_queue, prompt);
		return;
	}

	pin_prompt_start(prompt);
}
