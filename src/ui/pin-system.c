/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "config.h"

/* gcr-4 requires explicit opt-in to its unstable API. */
#define GCR_API_SUBJECT_TO_CHANGE 1

#include <gcr/gcr.h>
#include <string.h>

#include "../certificate.h"
#include "../redact.h"
#include "../core/pin-internal.h"
#include "pin-backends.h"

/* The prompter name is fixed because changing it redirects PIN input. */
#define SYSTEM_PROMPTER_NAME "org.gnome.keyring.SystemPrompter"

/* Bound the wait for a busy prompter; login timeout starts only after submission. */
#define SYSTEM_PROMPT_OPEN_TIMEOUT_SECONDS 60

typedef struct
{
	PinPrompt* prompt; /* Borrowed; owned by the prompt. */

	GcrPrompt* gcr;

	gulong close_id;

	/** Suppress user-dismissal handling during programmatic close. */
	gboolean closing;

	gboolean closed;

	guint dismiss_idle;

	gboolean passive_confirm;

	XccPinView view; /* Snapshot retained while system prompt open is pending. */
} SystemPinPrompt;

/* Close the prompt to cancel; gcr 4.4 can complete cancellable rounds twice. */

/* gcr may complete a round twice; store the claim on the result, which outlives prompt state. */
#define ROUND_SETTLED_KEY "certificate-pin-round-settled"

static gboolean round_claim(GAsyncResult* result)
{
	if (g_object_get_data(G_OBJECT(result), ROUND_SETTLED_KEY) != NULL)
	{
		g_message("pin-prompt-round-completed-twice detail=system-prompter");
		return FALSE;
	}

	g_object_set_data(G_OBJECT(result), ROUND_SETTLED_KEY, GINT_TO_POINTER(1));
	return TRUE;
}

static SystemPinPrompt* system_pin(PinPrompt* prompt)
{
	return prompt->impl_data;
}

static void system_pin_free(gpointer data)
{
	SystemPinPrompt* ui = data;

	if (ui->dismiss_idle != 0)
		g_source_remove(ui->dismiss_idle);

	if (ui->gcr != NULL && ui->close_id != 0)
		g_signal_handler_disconnect(ui->gcr, ui->close_id);

	g_clear_object(&ui->gcr);
	g_free(ui);
}

gboolean certificate_pin_provider_system_available(void)
{
	g_autoptr(GDBusConnection) bus = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	gboolean has_owner = FALSE;

	bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (bus == NULL)
		return FALSE;

	/* A prompter is available if owned or activatable, including on a private bus. */
	reply = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                                    "org.freedesktop.DBus", "NameHasOwner",
	                                    g_variant_new("(s)", SYSTEM_PROMPTER_NAME),
	                                    G_VARIANT_TYPE("(b)"), G_DBUS_CALL_FLAGS_NONE, 2000, NULL,
	                                    &error);
	if (reply != NULL)
		g_variant_get(reply, "(b)", &has_owner);

	if (has_owner)
		return TRUE;

	g_clear_pointer(&reply, g_variant_unref);
	g_clear_error(&error);

	reply = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                                    "org.freedesktop.DBus", "ListActivatableNames", NULL,
	                                    G_VARIANT_TYPE("(as)"), G_DBUS_CALL_FLAGS_NONE, 2000,
	                                    NULL, &error);
	if (reply == NULL)
		return FALSE;

	{
		g_autoptr(GVariant) child = g_variant_get_child_value(reply, 0);
		g_autofree const char** names = g_variant_get_strv(child, NULL);

		for (gsize i = 0; names != NULL && names[i] != NULL; i++)
		{
			if (g_strcmp0(names[i], SYSTEM_PROMPTER_NAME) == 0)
				return TRUE;
		}
	}

	return FALSE;
}

/* GcrPrompt expects bare handles; GNOME's session-modal prompter may ignore caller-window. */
static char* caller_window_handle(const char* parent_window)
{
	if (parent_window == NULL || *parent_window == '\0')
		return NULL;

	if (g_str_has_prefix(parent_window, "x11:"))
		return g_strdup(parent_window + 4);
	if (g_str_has_prefix(parent_window, "wayland:"))
		return g_strdup(parent_window + 8);

	return NULL;
}

/* Sanitize desktop and token metadata before sending it to the trusted system prompt. */
static void set_prompt_text(PinPrompt* prompt)
{
	SystemPinPrompt* ui = system_pin(prompt);
	g_autofree char* caller = certificate_display_text(prompt->caller_display,
	                                                   CERTIFICATE_DISPLAY_MAX_APP_NAME, NULL);
	g_autofree char* purpose = certificate_display_text(prompt->purpose_display,
	                                                    CERTIFICATE_DISPLAY_MAX_PURPOSE, NULL);
	g_autofree char* label = certificate_display_text(
	    prompt->token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "Unnamed token");
	g_autofree char* reader = certificate_display_text(prompt->token->reader_name,
	                                                   CERTIFICATE_DISPLAY_MAX_READER, NULL);
	g_autofree char* window = caller_window_handle(prompt->parent_window);
	g_autoptr(GString) description = g_string_new(NULL);

	gcr_prompt_set_title(ui->gcr, "Unlock Security Token");
	gcr_prompt_set_message(ui->gcr, certificate_pin_prompt_heading(prompt));

	if (caller != NULL)
		g_string_append_printf(description, "Application: %s\n", caller);
	if (purpose != NULL)
		g_string_append_printf(description, "In order to: %s\n", purpose);
	g_string_append_printf(description, "Token: %s\n", label);
	if (reader != NULL)
		g_string_append_printf(description, "Reader: %s\n", reader);
	if (prompt->protected_path)
		g_string_append_printf(description, "\n%s", certificate_pin_prompt_protected_note());

	gcr_prompt_set_description(ui->gcr, description->str);
	gcr_prompt_set_warning(ui->gcr, certificate_pin_prompt_retry_hint(&ui->view));

	/* An empty choice-label suppresses PIN persistence options. */
	gcr_prompt_set_choice_label(ui->gcr, NULL);
	gcr_prompt_set_password_new(ui->gcr, FALSE);
	gcr_prompt_set_continue_label(ui->gcr, "Unlock");
	gcr_prompt_set_cancel_label(ui->gcr, "Cancel");
	gcr_prompt_set_caller_window(ui->gcr, window);
}

static void ask_for_password(PinPrompt* prompt);

/* Each callback owns a reference released only by the round_claim() winner. */
static void handle_confirmed(PinPrompt* prompt, GObject* source, GAsyncResult* result)
{
	SystemPinPrompt* ui = system_pin(prompt);
	g_autoptr(GError) error = NULL;
	gboolean passive = ui->passive_confirm;
	GcrPromptReply reply;

	ui->passive_confirm = FALSE;
	reply = gcr_prompt_confirm_finish(GCR_PROMPT(source), result, &error);

	if (prompt->finished)
		return;

	if (error != NULL)
	{
		/* Prompter loss may report G_IO_ERROR_CANCELLED; every error must settle the interaction. */
		g_autofree char* text = certificate_redact_error_text(error->message);

		g_message("pin-prompt-failed detail=system-prompter: %s", text);
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
		return;
	}

	if (reply != GCR_PROMPT_REPLY_CONTINUE)
	{
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
		return;
	}

	/* The protected-path notice dismisses a message while login runs; it must not submit again. */
	if (passive)
		return;

	certificate_pin_prompt_warning_reply(prompt, TRUE);
}

static void on_confirmed(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	/* Claim before touching prompt state, which a duplicate completion may outlive. */
	if (!round_claim(result))
		return;

	handle_confirmed(prompt, source, result);
	certificate_pin_prompt_unref(prompt);
}

static void handle_password(PinPrompt* prompt, GObject* source, GAsyncResult* result)
{
	g_autoptr(GError) error = NULL;
	const char* password = NULL;
	XccSecret* secret;
	size_t capacity;
	size_t length;
	uint8_t* data;

	/* GcrPrompt owns secure password storage until its next call; copy only into the core's locked page. */
	password = gcr_prompt_password_finish(GCR_PROMPT(source), result, &error);

	if (prompt->finished)
		return;

	if (password == NULL)
	{
		if (error == NULL)
		{
			/* NULL without an error means user cancellation. */
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
			return;
		}

		{
			g_autofree char* text = certificate_redact_error_text(error->message);

			g_message("pin-prompt-failed detail=system-prompter: %s", text);
		}

		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
		return;
	}

	/* A rejected held PIN rearms retry without spending an attempt. */
	length = strlen(password);
	secret = xcc_secret_new();
	if (secret != NULL)
	{
		data = xcc_secret_data(secret, &capacity);
		if (length < capacity && length <= 511)
			memcpy(data, password, length);
	}
	if (!certificate_pin_prompt_hold(prompt, secret, length))
		return;

	certificate_pin_prompt_submit(prompt);
}

static void on_password(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	/* Claim before touching prompt state, which a duplicate completion may outlive. */
	if (!round_claim(result))
		return;

	handle_password(prompt, source, result);
	certificate_pin_prompt_unref(prompt);
}

static void ask_for_password(PinPrompt* prompt)
{
	SystemPinPrompt* ui = system_pin(prompt);

	if (ui->gcr == NULL || ui->closed || prompt->finished)
		return;

	gcr_prompt_password_async(ui->gcr, NULL, on_password, certificate_pin_prompt_ref(prompt));
}

/* Run dismissal fallback below gcr's completion priority so a pending round's outcome arrives first. */
static gboolean settle_dismissal(gpointer user_data)
{
	PinPrompt* prompt = user_data;
	SystemPinPrompt* ui = system_pin(prompt);

	ui->dismiss_idle = 0;

	if (prompt->finished)
		return G_SOURCE_REMOVE;

	g_message("pin-prompt-dismissed detail=system-prompter");
	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
	return G_SOURCE_REMOVE;
}

/* Unsolicited prompt-close cancels even during login; programmatic close is suppressed by closing. */
static void on_gcr_prompt_close(GcrPrompt* gcr, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	SystemPinPrompt* ui = system_pin(prompt);

	if (ui->closing || ui->closed)
		return;

	ui->closed = TRUE;

	if (prompt->finished || ui->dismiss_idle != 0)
		return;

	ui->dismiss_idle = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, settle_dismissal,
	                                   certificate_pin_prompt_ref(prompt),
	                                   (GDestroyNotify) certificate_pin_prompt_unref);
}

static void system_pin_release(PinPrompt* prompt);

static void handle_prompt_opened(PinPrompt* prompt, GAsyncResult* result)
{
	SystemPinPrompt* ui = system_pin(prompt);
	g_autoptr(GError) error = NULL;

	ui->gcr = gcr_system_prompt_open_finish(result, &error);

	/* If settlement precedes open completion, close the newly opened dialog. */
	if (prompt->finished)
	{
		system_pin_release(prompt);
		return;
	}

	if (ui->gcr == NULL)
	{
		g_autofree char* text = certificate_redact_error_text(
		    error != NULL ? error->message : "the prompter withdrew the prompt");

		/* Every open error settles; a failed system prompt must not silently switch to GTK. */
		g_message("pin-prompt-failed detail=system-prompter-unreachable: %s", text);
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_NO_DISPLAY);
		return;
	}

	ui->close_id =
	    g_signal_connect(ui->gcr, "prompt-close", G_CALLBACK(on_gcr_prompt_close), prompt);

	set_prompt_text(prompt);

	/* Protected authentication shows no password field and still requires confirmation on FINAL_TRY. */
	if (prompt->protected_path)
	{
		if (!ui->view.final_try)
		{
			ui->passive_confirm = TRUE;
			gcr_prompt_confirm_async(ui->gcr, NULL, on_confirmed,
			                         certificate_pin_prompt_ref(prompt));
		}

		certificate_pin_prompt_submit(prompt);

		return;
	}

	ask_for_password(prompt);
}

static void on_prompt_opened(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	/* Claim before touching prompt state because gcr's open timeout may complete twice. */
	if (!round_claim(result))
		return;

	handle_prompt_opened(prompt, result);
	certificate_pin_prompt_unref(prompt);
}

static void system_pin_show(gpointer user_data, PinPrompt* prompt, const XccPinView* view)
{
	SystemPinPrompt* ui = g_new0(SystemPinPrompt, 1);

	ui->prompt = prompt;
	ui->view = *view;
	prompt->impl_data = ui;
	prompt->impl_data_free = system_pin_free;

	gcr_system_prompt_open_for_prompter_async(SYSTEM_PROMPTER_NAME,
	                                          SYSTEM_PROMPT_OPEN_TIMEOUT_SECONDS, NULL,
	                                          on_prompt_opened,
	                                          certificate_pin_prompt_ref(prompt));
}

static void system_pin_update(gpointer user_data, PinPrompt* prompt, const XccPinView* view)
{
	SystemPinPrompt* ui = system_pin(prompt);
	const char* hint = certificate_pin_prompt_retry_hint(view);
	const char* status = view->status;
	g_autofree char* warning = NULL;

	if (status == NULL || ui->gcr == NULL || ui->closed)
		return;

	/* Reuse the open prompt for retries and display only token-reported state flags. */
	warning = hint != NULL ? g_strdup_printf("%s %s", status, hint) : g_strdup(status);
	gcr_prompt_set_warning(ui->gcr, warning);
	gcr_prompt_set_continue_label(ui->gcr, "Unlock");

	ask_for_password(prompt);
}

static void system_pin_warning(gpointer user_data, PinPrompt* prompt, const char* message)
{
	SystemPinPrompt* ui = system_pin(prompt);

	if (ui->gcr == NULL || ui->closed)
	{
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
		return;
	}

	gcr_prompt_set_warning(ui->gcr, message);
	gcr_prompt_set_continue_label(ui->gcr, "Continue");
	gcr_prompt_confirm_async(ui->gcr, NULL, on_confirmed,
	                         certificate_pin_prompt_ref(prompt));
}

/* Release the reference held across asynchronous close. */
static void on_system_prompt_closed(GObject* source, GAsyncResult* result, gpointer user_data)
{
	g_autoptr(GcrSystemPrompt) prompt = user_data;
	g_autoptr(GError) error = NULL;

	if (!gcr_system_prompt_close_finish(prompt, result, &error) && error != NULL)
	{
		g_autofree char* text = certificate_redact_error_text(error->message);

		g_message("pin-prompt-close-failed detail=system-prompter: %s", text);
	}
}

/* Close asynchronously and release gcr's password storage immediately; callbacks retain their own references. */
static void system_pin_release(PinPrompt* prompt)
{
	SystemPinPrompt* ui = system_pin(prompt);

	if (ui == NULL)
		return;

	if (ui->dismiss_idle != 0)
	{
		g_source_remove(ui->dismiss_idle);
		ui->dismiss_idle = 0;
	}

	if (ui->gcr == NULL)
		return;

	/* Disconnect before programmatic close emits prompt-close. */
	if (ui->close_id != 0)
	{
		g_signal_handler_disconnect(ui->gcr, ui->close_id);
		ui->close_id = 0;
	}

	if (!ui->closed)
	{
		ui->closed = TRUE;
		ui->closing = TRUE;
		gcr_prompt_close(ui->gcr);
		ui->closing = FALSE;
	}

	/* Close asynchronously because synchronous gcr_system_prompt_close() leaks a nested GMainContext per prompt on gcr 4.4. */
	if (GCR_IS_SYSTEM_PROMPT(ui->gcr))
		gcr_system_prompt_close_async(GCR_SYSTEM_PROMPT(ui->gcr), NULL, on_system_prompt_closed,
		                              g_object_ref(ui->gcr));

	g_clear_object(&ui->gcr);
}

static void system_pin_hide(gpointer user_data, PinPrompt* prompt)
{
	system_pin_release(prompt);
}

static void system_pin_close(gpointer user_data, PinPrompt* prompt)
{
	system_pin_release(prompt);
}

const CertificatePinProvider* certificate_pin_provider_system(void)
{
	static const CertificatePinProvider provider = {
		.name = "system",
		/* The shell draws this prompt, so the backend needs no display connection for it. */
		.needs_display = FALSE,
		.pin_show = system_pin_show,
		.pin_update = system_pin_update,
		.warning = system_pin_warning,
		.hide = system_pin_hide,
		.close = system_pin_close,
	};

	return &provider;
}
