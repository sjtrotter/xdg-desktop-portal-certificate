/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#define _GNU_SOURCE 1

#include "pin.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../certificate.h"
#include "../redact.h"
#include "config.h"
#include "pin-internal.h"

static gboolean ui_has_display = FALSE;

void certificate_ui_set_has_display(gboolean has_display)
{
	ui_has_display = has_display;
}

gboolean certificate_ui_has_display(void)
{
	return ui_has_display;
}

/* Linking the PIN module defaults to GTK; only main() opts into automatic system-prompt selection. */
static CertificatePinPromptKind pin_prompt_kind = CERTIFICATE_PIN_PROMPT_GTK;
static const PinPromptImpl* pin_prompt_resolved = NULL;

gboolean certificate_pin_set_prompt_kind(const char* name, GError** error)
{
	if (name == NULL || g_ascii_strcasecmp(name, "auto") == 0)
		pin_prompt_kind = CERTIFICATE_PIN_PROMPT_AUTO;
	else if (g_ascii_strcasecmp(name, "gtk") == 0)
		pin_prompt_kind = CERTIFICATE_PIN_PROMPT_GTK;
	else if (g_ascii_strcasecmp(name, "system") == 0)
		pin_prompt_kind = CERTIFICATE_PIN_PROMPT_SYSTEM;
	else
	{
		g_set_error(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
		            "Unknown PIN prompt '%s'; expected auto, gtk or system", name);
		return FALSE;
	}

	pin_prompt_resolved = NULL;
	return TRUE;
}

/* Resolve once and log which process will draw the PIN prompt. */
static const PinPromptImpl* pin_impl(void)
{
	if (pin_prompt_resolved != NULL)
		return pin_prompt_resolved;

	switch (pin_prompt_kind)
	{
		case CERTIFICATE_PIN_PROMPT_SYSTEM:
#if HAVE_GCR
			pin_prompt_resolved = certificate_pin_impl_system();
			break;
#else
			pin_prompt_resolved = certificate_pin_impl_gtk();
			break;
#endif

		case CERTIFICATE_PIN_PROMPT_AUTO:
#if HAVE_GCR
			if (certificate_pin_impl_system_available())
			{
				pin_prompt_resolved = certificate_pin_impl_system();
				break;
			}
#endif
			pin_prompt_resolved = certificate_pin_impl_gtk();
			break;

		case CERTIFICATE_PIN_PROMPT_GTK:
		default:
			pin_prompt_resolved = certificate_pin_impl_gtk();
			break;
	}

	g_message("pin-prompt-selected detail=%s", pin_prompt_resolved->name);
	return pin_prompt_resolved;
}

const char* certificate_pin_prompt_name(void)
{
	return pin_impl()->name;
}

/* PIN buffer locking, dump exclusion and wipe guarantees are documented in docs/SECURITY.md. */
typedef struct
{
	char* data;
	gsize capacity;
	gboolean locked;
} PinBuffer;

#define PIN_BUFFER_CAPACITY 512

/* Limit attempts per prompt to avoid unbounded token retries. */
#define PIN_MAX_ATTEMPTS 3

static gboolean pin_mlock_warned = FALSE;

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

	if (!buffer->locked && !pin_mlock_warned)
	{
		pin_mlock_warned = TRUE;
		g_message("pin-buffer-unlocked detail=mlock-failed");
	}

	/* MADV_DONTDUMP is best effort; main.c also disables process dumps. */
#ifdef MADV_DONTDUMP
	(void) madvise(buffer->data, buffer->capacity, MADV_DONTDUMP);
#endif

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

static gsize pin_buffer_limit(const PinBuffer* buffer)
{
	return MIN(buffer->capacity, (gsize) PIN_BUFFER_CAPACITY);
}

static gboolean pin_buffer_set(PinBuffer* buffer, const char* text)
{
	gsize length = text != NULL ? strlen(text) : 0;

	pin_buffer_wipe(buffer);

	if (length + 1 > pin_buffer_limit(buffer))
		return FALSE;

	memcpy(buffer->data, text, length);
	buffer->data[length] = '\0';
	return TRUE;
}

/* The worker owns and wipes a private PIN copy that survives prompt cancellation. */
static PinBuffer* pin_buffer_dup(const PinBuffer* source)
{
	PinBuffer* copy = pin_buffer_new();

	if (copy == NULL)
		return NULL;

	if (!pin_buffer_set(copy, source->data))
	{
		pin_buffer_free(copy);
		return NULL;
	}

	return copy;
}

/* Timeout hides the prompt but waits for C_Login to return; discard and undo any late success. */
#define PIN_LOGIN_TIMEOUT_DEFAULT_SECONDS 60

static guint pin_login_timeout_seconds = PIN_LOGIN_TIMEOUT_DEFAULT_SECONDS;

void certificate_pin_set_login_timeout(guint seconds)
{
	pin_login_timeout_seconds = seconds;
}

guint certificate_pin_login_timeout(void)
{
	return pin_login_timeout_seconds;
}

/* Serialize PIN prompts process-wide across grants. */
static GQueue pin_queue = G_QUEUE_INIT;
static PinPrompt* pin_active = NULL;

static void pin_prompt_start(PinPrompt* prompt);

static void pin_prompt_free(PinPrompt* prompt)
{
	if (prompt->impl_data != NULL && prompt->impl_data_free != NULL)
		prompt->impl_data_free(prompt->impl_data);
	prompt->impl_data = NULL;

	pin_buffer_free(prompt->buffer_opaque);
	prompt->buffer_opaque = NULL;
	g_clear_pointer(&prompt->token, certificate_token_unref);
	g_free(prompt->parent_window);
	g_free(prompt->caller_display);
	g_free(prompt->purpose_display);
	g_clear_object(&prompt->cancellable);

	/* Free login_data after both done and any abandon callback. */
	if (prompt->login_data_free != NULL)
		prompt->login_data_free(prompt->login_data);

	g_free(prompt);
}

static PinPrompt* pin_prompt_ref(PinPrompt* prompt)
{
	g_atomic_int_inc(&prompt->refs);
	return prompt;
}

static void pin_prompt_unref(gpointer data)
{
	PinPrompt* prompt = data;

	if (prompt == NULL)
		return;

	if (!g_atomic_int_dec_and_test(&prompt->refs))
		return;

	pin_prompt_free(prompt);
}

PinPrompt* certificate_pin_prompt_ref(PinPrompt* prompt)
{
	return pin_prompt_ref(prompt);
}

void certificate_pin_prompt_unref(PinPrompt* prompt)
{
	pin_prompt_unref(prompt);
}

void certificate_pin_prompt_answer(PinPrompt* prompt, CertificatePinOutcome outcome)
{
	CertificatePinDone done = NULL;
	gpointer user_data = NULL;
	CertificatePinAbandonFunc abandon = NULL;
	gpointer login_data = NULL;

	if (prompt->finished)
		return;

	/* Cancellation cannot withdraw C_Login; retain buffers and defer completion until the worker returns. */
	if (prompt->login_in_flight)
	{
		if (!prompt->cancel_deferred)
		{
			prompt->cancel_deferred = TRUE;
			prompt->deferred_outcome = outcome;

			if (prompt->impl->hide != NULL)
				prompt->impl->hide(prompt);

			certificate_log_grant(outcome == CERTIFICATE_PIN_TIMED_OUT
			                          ? CERTIFICATE_REASON_PIN_TIMEOUT
			                          : CERTIFICATE_REASON_CHOOSER_CANCELLED,
			                      NULL, "deferred-login-in-flight");
		}

		return;
	}

	prompt->finished = TRUE;
	done = prompt->done;
	user_data = prompt->user_data;
	abandon = prompt->login_succeeded && outcome != CERTIFICATE_PIN_OK ? prompt->abandon : NULL;
	login_data = prompt->login_data;

	/* Disconnect before idle removal so concurrent cancellation cannot queue another source. */
	if (prompt->cancel_id != 0)
	{
		g_cancellable_disconnect(prompt->cancellable, prompt->cancel_id);
		prompt->cancel_id = 0;
	}

	if (prompt->cancel_idle != 0)
	{
		g_source_remove(prompt->cancel_idle);
		prompt->cancel_idle = 0;
	}

	if (prompt->login_timeout_id != 0)
	{
		g_source_remove(prompt->login_timeout_id);
		prompt->login_timeout_id = 0;
	}

	/* Wipe the buffer before invoking the caller's callback. */
	pin_buffer_wipe(prompt->buffer_opaque);

	prompt->impl->close(prompt);

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

	done(outcome, user_data);

	/* After done(), abandon a successful cancelled login so it cannot authorize later operations. */
	if (abandon != NULL)
	{
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL, "abandoning-cancelled-login");
		abandon(login_data);
	}

	pin_prompt_unref(prompt);
}

typedef struct
{
	PinPrompt* prompt; /* Owned task reference. */
	PinBuffer* buffer; /* Private PIN copy owned and wiped by the task. */
	gboolean protected_path;
} LoginTask;

static void login_task_free(gpointer data)
{
	LoginTask* task = data;

	g_clear_pointer(&task->buffer, pin_buffer_free);
	g_clear_pointer(&task->prompt, pin_prompt_unref);
	g_free(task);
}

static void login_thread(GTask* task, gpointer source, gpointer task_data,
                         GCancellable* cancellable)
{
	LoginTask* data = task_data;
	g_autoptr(GError) error = NULL;
	const char* pin = data->protected_path || data->buffer == NULL ? NULL : data->buffer->data;

	/* C_Login may block indefinitely and must run on a worker. */
	if (data->prompt->login(pin, data->prompt->login_data, &error))
	{
		g_task_return_boolean(task, TRUE);
		return;
	}

	/* Refresh flags after refusal because the failed attempt may newly set FINAL_TRY. */
	if (data->prompt->refresh != NULL &&
	    g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
		data->prompt->refresh(data->prompt->token, data->prompt->login_data);

	g_task_return_error(task, g_steal_pointer(&error));
}

static void set_busy(PinPrompt* prompt, gboolean busy)
{
	prompt->busy = busy;

	if (prompt->impl->busy != NULL)
		prompt->impl->busy(prompt, busy);
}

/* PKCS#11 exposes retry-state flags without a portable remaining-attempt count. */
const char* certificate_pin_prompt_retry_hint(const PinPrompt* prompt)
{
	if (prompt->token->pin_locked)
		return "This token is locked. It cannot be unlocked here.";
	if (prompt->token->pin_final_try)
		return "This is the last attempt before the token locks.";
	if (prompt->token->pin_count_low)
		return "There have been recent failed attempts on this token.";

	return NULL;
}

const char* certificate_pin_prompt_final_try_warning(void)
{
	return "Token will lock if this last attempt fails. Confirm to continue, or Cancel.";
}

const char* certificate_pin_prompt_heading(const PinPrompt* prompt)
{
	return prompt->protected_path ? "Enter your PIN on the reader"
	                              : "Enter your PIN to unlock this token";
}

const char* certificate_pin_prompt_protected_note(void)
{
	return "This reader collects the PIN itself. Follow the instructions on the reader; "
	       "nothing typed on screen is sent to the token.";
}

gboolean certificate_pin_prompt_needs_final_confirm(PinPrompt* prompt)
{
	/* FINAL_TRY requires explicit second confirmation before submission. */
	if (!prompt->token->pin_final_try || prompt->final_try_confirmed)
		return FALSE;

	prompt->final_try_confirmed = TRUE;
	return TRUE;
}

static void on_login_done(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	g_autoptr(GError) error = NULL;
	gboolean ok = g_task_propagate_boolean(G_TASK(result), &error);

	prompt->login_in_flight = FALSE;

	if (prompt->login_timeout_id != 0)
	{
		g_source_remove(prompt->login_timeout_id);
		prompt->login_timeout_id = 0;
	}

	if (ok)
		prompt->login_succeeded = TRUE;

	if (prompt->cancel_deferred)
	{
		prompt->cancel_deferred = FALSE;

		if (ok)
			certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL,
			                      prompt->deferred_outcome == CERTIFICATE_PIN_TIMED_OUT
			                          ? "login-landed-after-timeout"
			                          : "cancelled-after-login");

		certificate_pin_prompt_answer(prompt, prompt->deferred_outcome);
		return;
	}

	if (prompt->finished)
		return;

	if (ok)
	{
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL, "pin-accepted");
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_OK);
		return;
	}

	set_busy(prompt, FALSE);

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, NULL, "retry-offered");

		prompt->final_try_confirmed = FALSE;

		if (prompt->token->pin_locked)
		{
			certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, NULL, "terminal");
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_LOCKED);
			return;
		}

		if (prompt->protected_path)
		{
			/* The reader owns protected-path interaction, so this UI cannot retry it. */
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		if (prompt->attempts >= PIN_MAX_ATTEMPTS)
		{
			certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, NULL, "attempt-cap");
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		/* Retries require user input after the entry has been cleared. */
		pin_buffer_wipe(prompt->buffer_opaque);
		prompt->impl->retry(prompt, "That PIN was not accepted. Try again.");
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_LOCKED))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, NULL, "terminal");
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_LOCKED);
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
	{
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_TOKEN_REMOVED);
		return;
	}

	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
}

static gboolean on_login_timeout(gpointer user_data)
{
	PinPrompt* prompt = user_data;

	prompt->login_timeout_id = 0;

	if (!prompt->login_in_flight)
		return G_SOURCE_REMOVE;

	certificate_log_grant(CERTIFICATE_REASON_PIN_TIMEOUT, NULL, "login-did-not-return");
	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_TIMED_OUT);
	return G_SOURCE_REMOVE;
}

gboolean certificate_pin_prompt_hold(PinPrompt* prompt, const char* pin)
{
	if (prompt->finished || prompt->login_in_flight)
		return FALSE;

	/* Empty PINs rearm the prompt without submission because a token may count them as failed attempts. */
	if (pin == NULL || *pin == '\0')
	{
		prompt->impl->retry(prompt, "Enter the PIN for this token.");
		return FALSE;
	}

	if (!pin_buffer_set(prompt->buffer_opaque, pin))
	{
		prompt->impl->retry(prompt, "PIN exceeds the supported length.");
		return FALSE;
	}

	return TRUE;
}

void certificate_pin_prompt_submit(PinPrompt* prompt)
{
	g_autoptr(GTask) task = NULL;
	LoginTask* data = NULL;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	data = g_new0(LoginTask, 1);
	data->prompt = pin_prompt_ref(prompt);
	data->protected_path = prompt->protected_path;

	if (!prompt->protected_path)
	{
		data->buffer = pin_buffer_dup(prompt->buffer_opaque);

		if (data->buffer == NULL)
		{
			login_task_free(data);
			prompt->impl->retry(prompt, "The PIN could not be held in locked memory.");
			return;
		}
	}

	/* Only the task's private page retains this module's PIN copy after submission. */
	pin_buffer_wipe(prompt->buffer_opaque);

	prompt->attempts++;
	prompt->login_in_flight = TRUE;
	set_busy(prompt, TRUE);

	if (pin_login_timeout_seconds > 0)
		prompt->login_timeout_id =
		    g_timeout_add_seconds(pin_login_timeout_seconds, on_login_timeout, prompt);

	task = g_task_new(NULL, NULL, on_login_done, prompt);
	g_task_set_task_data(task, data, login_task_free);
	g_task_run_in_thread(task, login_thread);
}

static gboolean on_cancelled_idle(gpointer user_data)
{
	PinPrompt* prompt = user_data;

	prompt->cancel_idle = 0;
	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
	return G_SOURCE_REMOVE;
}

static void on_cancelled(GCancellable* cancellable, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	/* Cancellation may run off-thread; queue an idle with its own reference and touch no widgets here. */
	if (prompt->cancel_idle != 0)
		return;

	prompt->cancel_idle = g_idle_add_full(G_PRIORITY_DEFAULT, on_cancelled_idle,
	                                      pin_prompt_ref(prompt), pin_prompt_unref);
}

static void pin_prompt_start(PinPrompt* prompt)
{
	pin_active = prompt;

	certificate_log_grant(CERTIFICATE_REASON_PIN_PROMPTED, NULL,
	                      prompt->protected_path ? "protected-path" : "on-screen");

	prompt->impl->start(prompt);
}

void certificate_pin_login_full(CertificateToken* token, const char* parent_window,
                                const char* caller_display, const char* purpose_display,
                                CertificatePinLoginFunc login, CertificatePinRefreshFunc refresh,
                                CertificatePinAbandonFunc abandon, gpointer login_data,
                                GDestroyNotify login_data_free, GCancellable* cancellable,
                                CertificatePinDone done, gpointer user_data)
{
	PinPrompt* prompt = NULL;
	const PinPromptImpl* impl = pin_impl();

	/* Never read PINs from stdin; GTK requires a display and system prompts require a graphical prompter. */
	if (impl->needs_display && !certificate_ui_has_display())
	{
		done(CERTIFICATE_PIN_NO_DISPLAY, user_data);

		if (login_data_free != NULL)
			login_data_free(login_data);

		return;
	}

	if (token->pin_locked)
	{
		done(CERTIFICATE_PIN_LOCKED, user_data);

		if (login_data_free != NULL)
			login_data_free(login_data);

		return;
	}

	prompt = g_new0(PinPrompt, 1);
	prompt->refs = 1;
	prompt->impl = impl;
	prompt->token = certificate_token_ref(token);
	prompt->protected_path = token->protected_authentication_path;
	prompt->parent_window = g_strdup(parent_window);
	prompt->caller_display = g_strdup(caller_display);
	prompt->purpose_display = g_strdup(purpose_display);
	prompt->login = login;
	prompt->refresh = refresh;
	prompt->abandon = abandon;
	prompt->login_data = login_data;
	prompt->login_data_free = login_data_free;
	prompt->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;
	prompt->done = done;
	prompt->user_data = user_data;
	prompt->buffer_opaque = pin_buffer_new();

	if (prompt->buffer_opaque == NULL)
	{
		/* Deliver the answer before the last reference can free login_data. */
		done(CERTIFICATE_PIN_DEVICE_ERROR, user_data);
		pin_prompt_unref(prompt);
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

void certificate_pin_login(CertificateToken* token, const char* parent_window,
                           const char* caller_display, const char* purpose_display,
                           CertificatePinLoginFunc login, CertificatePinRefreshFunc refresh,
                           CertificatePinAbandonFunc abandon, gpointer login_data,
                           GCancellable* cancellable, CertificatePinDone done,
                           gpointer user_data)
{
	certificate_pin_login_full(token, parent_window, caller_display, purpose_display, login,
	                           refresh, abandon, login_data, NULL, cancellable, done, user_data);
}
