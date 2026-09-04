/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * THE PIN PROMPT DRAWN BY THE DESKTOP SHELL. The same contract as
 * ui/pin-gtk.c -- see ui/pin-internal.h -- with the window on the other side of
 * org.gnome.keyring.SystemPrompter.
 *
 * WHY THIS EXISTS AND WHAT IT CHANGES. On GNOME the system prompter is the
 * component the session already trusts to ask for secrets: it is owned by
 * gnome-shell, it is drawn inside the shell rather than as a client window, and
 * it is what the user has been taught a password request looks like. A window
 * this backend draws itself can be covered, spoofed by another client window,
 * or simply not look like the thing the user recognises. Handing the FIELD to
 * the shell is a real improvement in the one place where "is this dialog real"
 * is the whole question.
 *
 * WHAT MOVES OUT OF THIS PROCESS: the entry widget and its buffer, the input
 * method, and every intermediate copy a text widget might make -- all of that
 * is now the shell's, and this project no longer has to reason about GTK's
 * secure-memory pool at all.
 *
 * WHAT DOES NOT MOVE: we still hold a copy. C_Login takes a PIN, so the PIN has
 * to arrive here. It comes over gcr's secret exchange (an ephemeral
 * Diffie-Hellman over the bus, so the plaintext is not in a D-Bus message),
 * lands in gcr's own secure memory, is copied into the same locked, wiped,
 * non-dumpable page ui/pin.c uses for the GTK path, and gcr's copy is released
 * when the prompt is closed. docs/SECURITY.md says this in the same words.
 *
 * WHAT WE DO NOT ASK THE PROMPTER FOR: "remember", ever. GcrPrompt's
 * choice-label is never given text, which is what makes the shell draw no
 * checkbox. password-new is FALSE, so it asks for one secret rather than a new
 * one with a confirmation field.
 */

#include "config.h"

/* gcr-4 refuses to be included without this, and says why: the API "has not yet
 * reached stability". That is a real risk and it is stated here rather than
 * buried in a build file -- gcr may change under this file, which is one more
 * reason the whole dependency is optional and the in-process window is what a
 * build without it gets. */
#define GCR_API_SUBJECT_TO_CHANGE 1

#include <gcr/gcr.h>

#include "../certificate.h"
#include "../redact.h"
#include "pin-internal.h"

/* gcr's own name for the session prompter. Not configurable: a "use this
 * prompter instead" switch is a switch for pointing a PIN at something else. */
#define SYSTEM_PROMPTER_NAME "org.gnome.keyring.SystemPrompter"

/* How long gcr waits for the prompter to become free when another prompt is
 * already up. -1 is "wait indefinitely"; a bounded wait means a stuck prompter
 * fails the interaction rather than hanging it, and the login timeout in
 * ui/pin.c does not cover this half. */
#define SYSTEM_PROMPT_OPEN_TIMEOUT_SECONDS 60

typedef struct
{
	PinPrompt* prompt; /* borrowed: the prompt owns this struct */

	GcrPrompt* gcr;
	gboolean closed;
	gboolean asking;
} SystemPinPrompt;

/* NOT ONE gcr CALL IS MADE WITH A GCANCELLABLE, and that is the opposite of
 * what it looks like it should be.
 *
 * gcr 4.4 completes a prompt round TWICE when the round is cancelled AND the
 * prompter answers it: once from the cancellation and once from
 * on_perform_prompt_complete(). The callback ran a second time on a prompt
 * whose last reference the first run had dropped -- a use-after-free reached by
 * doing nothing worse than pressing Escape at the right moment, and found by
 * tests/test-pin-system.c crashing.
 *
 * So the interaction is ended the one way gcr has that is not racy: close the
 * prompt. A round in flight then comes back once, as a dismissal, which is what
 * every path here already knows how to read. The cost is that a prompt whose
 * open() is still waiting for a busy prompter keeps this object alive until
 * that open returns -- the caller has already been answered, so what is held is
 * memory and not the user's attention -- and that the open, when it lands, is
 * closed immediately by handle_prompt_opened(). */

static void system_pin_free(gpointer data)
{
	SystemPinPrompt* ui = data;

	g_clear_object(&ui->gcr);
	g_free(ui);
}

static SystemPinPrompt* system_pin(PinPrompt* prompt)
{
	return prompt->impl_data;
}

/* --------------------------------------------------------- is one reachable */

gboolean certificate_pin_impl_system_available(void)
{
	g_autoptr(GDBusConnection) bus = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	gboolean has_owner = FALSE;

	bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (bus == NULL)
		return FALSE;

	/* ACTIVATABLE COUNTS. The prompter is a session service and may not be
	 * running when the first AcquireCredential arrives; refusing to use it
	 * because nothing has needed a password yet would pick the wrong prompt for
	 * the whole life of the process. ListActivatableNames is asked only if
	 * nobody owns the name. */
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

/* ------------------------------------------------------------- the interaction */

/* THE PARENT WINDOW HANDLE, AND ITS LIMITS. GcrPrompt:caller-window is
 * documented as "a stringified XWindow handle" under X11 and "the result of an
 * export using the XDG foreign protocol" under Wayland -- in both cases the
 * bare handle, with no scheme. The portal hands this backend the same two
 * things with "x11:" and "wayland:" in front, so the prefix is stripped and the
 * rest passed through.
 *
 * WHAT ACTUALLY HAPPENS TO IT: nothing, on a current GNOME session. The shell's
 * prompter draws the prompt as a session-modal dialog of its own and ignores
 * caller-window; there is no Wayland protocol by which an out-of-process
 * prompter could parent a shell-drawn dialog to a client's surface anyway. So
 * the GTK path parents to the application window and this one does not, and
 * that is the one behavioural difference between them a user can see. It is
 * sent regardless, because a prompter that does use it should get it. */
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

/* Everything the prompt says about the request, in this backend's own words and
 * through the same sanitiser the chooser and the GTK window use: the caller
 * display comes from a desktop file and the token label and reader name come
 * off the card, and none of them may draw chrome of its own inside a dialog the
 * SHELL is presenting as trusted. */
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
	gcr_prompt_set_warning(ui->gcr, certificate_pin_prompt_retry_hint(prompt));

	/* NEVER "REMEMBER". An empty choice-label is what makes a prompter draw no
	 * additional checkbox, and there is no code path in this repository that
	 * gives it text. It is set explicitly rather than left alone so that the
	 * absence is a statement; gcr transports properties as a vardict and a
	 * GVariant "s" cannot carry NULL, so what the prompter actually receives is
	 * "" either way. tests/test-pin-system.c asserts it. */
	gcr_prompt_set_choice_label(ui->gcr, NULL);
	gcr_prompt_set_password_new(ui->gcr, FALSE);
	gcr_prompt_set_continue_label(ui->gcr, "Unlock");
	gcr_prompt_set_cancel_label(ui->gcr, "Cancel");
	gcr_prompt_set_caller_window(ui->gcr, window);
}

static void ask_for_password(PinPrompt* prompt);

/* EVERY CALLBACK BELOW OWNS A REFERENCE, taken by the call that armed it.
 * gcr answers a password or confirmation round from an idle, and the core drops
 * its own reference the moment the answer is settled -- so a prompt that was
 * cancelled, or answered by another round, is freed before the prompter's reply
 * arrives. It arrives anyway. */
static void handle_confirmed(PinPrompt* prompt, GObject* source, GAsyncResult* result)
{
	SystemPinPrompt* ui = system_pin(prompt);
	g_autoptr(GError) error = NULL;
	GcrPromptReply reply;

	ui->asking = FALSE;
	reply = gcr_prompt_confirm_finish(GCR_PROMPT(source), result, &error);

	if (prompt->finished)
		return;

	if (error != NULL)
	{
		/* Nothing here passes a GCancellable to gcr any more (see the note on
		 * SystemPinPrompt), so this is defensive rather than expected. */
		if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			return;

		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
		return;
	}

	if (reply != GCR_PROMPT_REPLY_CONTINUE)
	{
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
		return;
	}

	/* The second, explicit confirmation the GTK window gets from a second press
	 * of Unlock. certificate_pin_prompt_needs_final_confirm() has already
	 * recorded it, so this submission is the one that spends the attempt. */
	certificate_pin_prompt_submit(prompt);
}

static void on_confirmed(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	handle_confirmed(prompt, source, result);
	certificate_pin_prompt_unref(prompt);
}

static void handle_password(PinPrompt* prompt, GObject* source, GAsyncResult* result)
{
	SystemPinPrompt* ui = system_pin(prompt);
	g_autoptr(GError) error = NULL;
	const char* password = NULL;

	ui->asking = FALSE;

	/* OWNED BY THE PROMPT, IN GCR'S SECURE MEMORY. It is valid until the next
	 * call on this GcrPrompt or until the prompt is closed, and it is never
	 * copied anywhere but into ui/pin.c's locked page by the submit() below. */
	password = gcr_prompt_password_finish(GCR_PROMPT(source), result, &error);

	if (prompt->finished)
		return;

	if (password == NULL)
	{
		if (error == NULL)
		{
			/* gcr reports "the user cancelled" as NULL with no error. */
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
			return;
		}

		if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			return;

		{
			g_autofree char* text = certificate_redact_error_text(error->message);

			g_message("pin-prompt-failed detail=system-prompter: %s", text);
		}

		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
		return;
	}

	/* THE LAST ATTEMPT IS NOT SPENT ON A SINGLE ANSWER, exactly as in the GTK
	 * window. The PIN goes into the locked page first so that gcr's copy can be
	 * released on the next call, and the confirmation round runs on the same
	 * open prompt. */
	if (!certificate_pin_prompt_hold(prompt, password))
		return;

	if (certificate_pin_prompt_needs_final_confirm(prompt))
	{
		gcr_prompt_set_warning(ui->gcr, certificate_pin_prompt_final_try_warning());
		gcr_prompt_set_continue_label(ui->gcr, "Use the last attempt");
		ui->asking = TRUE;
		gcr_prompt_confirm_async(ui->gcr, NULL, on_confirmed,
		                         certificate_pin_prompt_ref(prompt));
		return;
	}

	certificate_pin_prompt_submit(prompt);
}

static void on_password(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	handle_password(prompt, source, result);
	certificate_pin_prompt_unref(prompt);
}

static void ask_for_password(PinPrompt* prompt)
{
	SystemPinPrompt* ui = system_pin(prompt);

	if (ui->gcr == NULL || ui->closed || prompt->finished)
		return;

	ui->asking = TRUE;
	gcr_prompt_password_async(ui->gcr, NULL, on_password, certificate_pin_prompt_ref(prompt));
}

static void handle_prompt_opened(PinPrompt* prompt, GAsyncResult* result)
{
	SystemPinPrompt* ui = system_pin(prompt);
	g_autoptr(GError) error = NULL;

	ui->gcr = gcr_system_prompt_open_finish(result, &error);

	/* The interaction was settled while the prompter was still busy with
	 * somebody else's prompt. What just opened has to be closed again, or the
	 * shell is left holding a dialog for a request that has been answered. */
	if (prompt->finished)
	{
		if (ui->gcr != NULL && !ui->closed)
		{
			ui->closed = TRUE;
			gcr_prompt_close(ui->gcr);
			gcr_system_prompt_close(GCR_SYSTEM_PROMPT(ui->gcr), NULL, NULL);
			g_clear_object(&ui->gcr);
		}

		return;
	}

	if (ui->gcr == NULL)
	{
		if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			return;

		{
			g_autofree char* text = certificate_redact_error_text(error->message);

			/* NO SILENT FALLBACK TO THE IN-PROCESS WINDOW. Which process asked
			 * for the PIN is a fact about the interaction, and swapping it
			 * under the user because a bus call failed would make that fact
			 * depend on timing. The caller is told the prompt failed and can
			 * ask again. */
			g_message("pin-prompt-failed detail=system-prompter-unreachable: %s", text);
		}

		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_NO_DISPLAY);
		return;
	}

	set_prompt_text(prompt);

	/* A PROTECTED AUTHENTICATION PATH HAS NO FIELD ANYWHERE. The reader
	 * collects the secret, so the prompter is shown a message and a Cancel and
	 * is never asked for a password; the login goes out with a NULL PIN at
	 * once. gcr has no "notification only" round, so what the user gets is the
	 * confirm form: the instruction, Cancel, and a continue button that does
	 * nothing but dismiss it. */
	if (prompt->protected_path)
	{
		ui->asking = TRUE;
		gcr_prompt_confirm_async(ui->gcr, NULL, on_confirmed,
		                         certificate_pin_prompt_ref(prompt));
		certificate_pin_prompt_submit(prompt);
		return;
	}

	ask_for_password(prompt);
}

static void on_prompt_opened(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	handle_prompt_opened(prompt, result);
	certificate_pin_prompt_unref(prompt);
}

static void system_pin_start(PinPrompt* prompt)
{
	SystemPinPrompt* ui = g_new0(SystemPinPrompt, 1);

	ui->prompt = prompt;
	prompt->impl_data = ui;
	prompt->impl_data_free = system_pin_free;

	gcr_system_prompt_open_for_prompter_async(SYSTEM_PROMPTER_NAME,
	                                          SYSTEM_PROMPT_OPEN_TIMEOUT_SECONDS, NULL,
	                                          on_prompt_opened,
	                                          certificate_pin_prompt_ref(prompt));
}

static void system_pin_retry(PinPrompt* prompt, const char* status)
{
	SystemPinPrompt* ui = system_pin(prompt);
	const char* hint = certificate_pin_prompt_retry_hint(prompt);
	g_autofree char* warning = NULL;

	if (ui->gcr == NULL)
		return;

	/* THE SAME PROMPT, ASKED AGAIN. gcr keeps the dialog up between rounds on
	 * one GcrPrompt, which is what makes a retry look like a retry rather than
	 * a second unexplained request. The warning is this backend's refusal
	 * wording plus whatever the token's three flags say -- and never a count. */
	warning = hint != NULL ? g_strdup_printf("%s %s", status, hint) : g_strdup(status);
	gcr_prompt_set_warning(ui->gcr, warning);
	gcr_prompt_set_continue_label(ui->gcr, "Unlock");

	ask_for_password(prompt);
}

static void system_pin_hide(PinPrompt* prompt)
{
	SystemPinPrompt* ui = system_pin(prompt);

	/* The prompter's dialog goes away at once; the answer still waits for the
	 * worker. gcr_prompt_close() is the "take it off the screen" call and does
	 * not release the object. */
	if (ui->gcr != NULL && !ui->closed)
	{
		ui->closed = TRUE;
		gcr_prompt_close(ui->gcr);
	}
}

/* The reference the close held; dropped when the prompter has acknowledged. */
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

static void system_pin_close(PinPrompt* prompt)
{
	SystemPinPrompt* ui = system_pin(prompt);

	if (ui == NULL || ui->gcr == NULL)
		return;

	if (!ui->closed)
	{
		ui->closed = TRUE;
		gcr_prompt_close(ui->gcr);
	}

	/* CLOSING THE SYSTEM PROMPT IS WHAT WIPES GCR'S COPY of the last password
	 * it handed us: the string belongs to the prompt and gcr frees it, from its
	 * own secure memory, when the prompt goes. Releasing it here is therefore
	 * part of the PIN's exit path, not bookkeeping.
	 *
	 * ASYNCHRONOUSLY, for two reasons. It is a D-Bus round trip and this runs on
	 * the main thread inside the answer path, where a stall is a window that
	 * stops redrawing. And gcr_system_prompt_close() -- the synchronous one --
	 * spins a nested GMainContext that it never frees: LeakSanitizer reports it
	 * against this call site, once per prompt, on gcr 4.4. */
	if (GCR_IS_SYSTEM_PROMPT(ui->gcr))
		gcr_system_prompt_close_async(GCR_SYSTEM_PROMPT(ui->gcr), NULL, on_system_prompt_closed,
		                              g_object_ref(ui->gcr));

	g_clear_object(&ui->gcr);
}

const PinPromptImpl* certificate_pin_impl_system(void)
{
	static const PinPromptImpl impl = {
		.name = "system",
		/* THE WINDOW IS THE SHELL'S, so this process needs no display of its
		 * own. It still needs a graphical session -- there has to be a shell to
		 * draw it -- but that is the prompter's business and not GTK's. */
		.needs_display = FALSE,
		.start = system_pin_start,
		.retry = system_pin_retry,
		.hide = system_pin_hide,
		.close = system_pin_close,
	};

	return &impl;
}
