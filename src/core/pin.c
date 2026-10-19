/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "pin.h"
#include "sources.h"
#include "context-private.h"

#include "../certificate.h"
#include "../redact.h"
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

static CertificatePinProvider pin_provider;

const CertificatePinProvider* certificate_pin_get_provider(void)
{
	return &pin_provider;
}

void certificate_pin_set_provider(const CertificatePinProvider* provider)
{
	if (provider == NULL)
	{
		pin_provider = (CertificatePinProvider){0};
		return;
	}
	g_return_if_fail(provider->pin_show != NULL && provider->pin_update != NULL);
	g_return_if_fail(provider->warning != NULL && provider->hide != NULL && provider->close != NULL);

	pin_provider = *provider;
}

/* Limit attempts per prompt to avoid unbounded token retries. */
#define PIN_MAX_ATTEMPTS 3

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

	g_clear_pointer(&prompt->secret, xcc_secret_free);
	g_clear_pointer(&prompt->token, certificate_token_unref);
	g_free(prompt->session_id);
	g_free(prompt->parent_window);
	g_free(prompt->caller_display);
	g_free(prompt->purpose_display);
	g_clear_object(&prompt->cancellable);

	/* Free login_data after both done and any abandon callback. */
	if (prompt->login_data_free != NULL)
		prompt->login_data_free(prompt->login_data);

	if (prompt->ui_context != NULL)
	{
		g_atomic_int_add(&prompt->ui_context->ui_handles, -1);
		xcc_context_unref(prompt->ui_context);
	}
	g_main_context_unref(prompt->coordinator);
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
	if (prompt->ui_context != NULL)
	{
		if (!prompt->finished)
		{
			if (outcome == CERTIFICATE_PIN_CANCELLED)
				xcc_ui_cancel(prompt->ui_context, prompt->ui_id);
			else
				xcc_ui_failed(prompt->ui_context, prompt->ui_id, XCC_ERROR_DEVICE);
		}
		return;
	}
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

			if (prompt->provider.hide != NULL)
				prompt->provider.hide(prompt->provider.user_data, prompt);

			certificate_log_grant(outcome == CERTIFICATE_PIN_TIMED_OUT
			                          ? CERTIFICATE_REASON_PIN_TIMEOUT
			                          : CERTIFICATE_REASON_CHOOSER_CANCELLED,
			                      prompt->session_id, "deferred-login-in-flight");
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
		xcc_source_remove(prompt->cancel_idle);
		prompt->cancel_idle = 0;
	}

	if (prompt->login_timeout_id != 0)
	{
		xcc_source_remove(prompt->login_timeout_id);
		prompt->login_timeout_id = 0;
	}

	/* Wipe the buffer before invoking the caller's callback. */
	g_clear_pointer(&prompt->secret, xcc_secret_free);

	prompt->provider.close(prompt->provider.user_data, prompt);

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
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, prompt->session_id,
		                      "abandoning-cancelled-login");
		abandon(login_data);
	}

	pin_prompt_unref(prompt);
}

typedef struct
{
	PinPrompt* prompt; /* Owned task reference. */
	XccSecret* secret; /* Transferred PIN page owned and wiped by the task. */
	gboolean protected_path;
} LoginTask;

static void login_task_free(gpointer data)
{
	LoginTask* task = data;

	g_clear_pointer(&task->secret, xcc_secret_free);
	g_clear_pointer(&task->prompt, pin_prompt_unref);
	g_free(task);
}

static void login_thread(GTask* task, gpointer source, gpointer task_data,
                         GCancellable* cancellable)
{
	LoginTask* data = task_data;
	g_autoptr(GError) error = NULL;
	const char* pin = data->protected_path ? NULL : xcc_secret_view(data->secret);
	gboolean ok;

	/* C_Login may block indefinitely and must run on a worker. */
	ok = data->prompt->login(pin, data->prompt->login_data, &error);
	g_clear_pointer(&data->secret, xcc_secret_free);
	if (ok)
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

static const char* pin_status_text(XccPinStatus status)
{
	switch (status)
	{
	case XCC_PIN_STATUS_INCORRECT:
		return "That PIN was not accepted. Try again.";
	case XCC_PIN_STATUS_REQUIRED:
		return "Enter the PIN for this token.";
	case XCC_PIN_STATUS_TOO_LONG:
		return "PIN exceeds the supported length.";
	case XCC_PIN_STATUS_MEMORY_UNAVAILABLE:
		return "The PIN could not be held in locked memory.";
	default:
		return NULL;
	}
}

static XccPinView pin_view(const PinPrompt* prompt, XccPinStatus status)
{
	/* The private legacy PIN entry point takes core-owned purpose wording.
	 * Resolve it here so desktop consumers never have to inspect English. */
	uint32_t purpose = XCC_PURPOSE_CLIENT_AUTH;
	gboolean generic = TRUE;
	for (uint32_t p = XCC_PURPOSE_CLIENT_AUTH; p <= XCC_PURPOSE_SSH; p++)
	{
		if (g_strcmp0(prompt->purpose_display, certificate_purpose_display(p)) == 0)
		{
			purpose = p;
			generic = FALSE;
			break;
		}
	}
	g_autofree char* label = certificate_display_text(prompt->token->label,
	    CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, NULL);
	return (XccPinView){
		.struct_size = sizeof(XccPinView),
		.abi_version = XCC_ABI_VERSION,
		.token_label = prompt->token->label,
		.reader = prompt->token->reader_name,
		.caller_display = prompt->caller_display,
		.purpose_display = prompt->purpose_display,
		.parent_window = prompt->parent_window,
		.context_specific = prompt->context_specific,
		.protected_path = prompt->protected_path,
		.busy = prompt->busy,
		.count_low = prompt->token->pin_count_low,
		.final_try = prompt->token->pin_final_try,
		.locked = prompt->token->pin_locked,
		.status = pin_status_text(status),
		.purpose = purpose,
		.generic_purpose = generic,
		.status_code = status,
		.display_flags = label == NULL ? XCC_DISPLAY_TOKEN_FALLBACK : 0,
	};
}

static void pin_update(PinPrompt* prompt, XccPinStatus status)
{
	XccPinView view = pin_view(prompt, status);

	prompt->provider.pin_update(prompt->provider.user_data, prompt, &view);
}

static void set_busy(PinPrompt* prompt, gboolean busy)
{
	prompt->busy = busy;

	pin_update(prompt, XCC_PIN_STATUS_NONE);
}

void certificate_pin_prompt_warning_reply(PinPrompt* prompt, gboolean accepted)
{
	if (prompt->ui_context != NULL)
	{
		xcc_warning_reply(prompt->ui_context, prompt->ui_id, prompt->warning_id, accepted);
		return;
	}
	if (!prompt->protected_path || prompt->finished || prompt->login_in_flight ||
	    !prompt->warning_pending)
		return;

	prompt->warning_pending = FALSE;
	if (!accepted)
	{
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
		return;
	}

	prompt->protected_path_confirmed = TRUE;
	certificate_pin_prompt_submit(prompt);
}

static void on_login_done(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	g_autoptr(GError) error = NULL;
	gboolean ok = g_task_propagate_boolean(G_TASK(result), &error);

	prompt->login_in_flight = FALSE;

	if (prompt->login_timeout_id != 0)
	{
		xcc_source_remove(prompt->login_timeout_id);
		prompt->login_timeout_id = 0;
	}

	if (ok)
		prompt->login_succeeded = TRUE;

	if (prompt->cancel_deferred)
	{
		prompt->cancel_deferred = FALSE;

		if (ok)
			certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, prompt->session_id,
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
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, prompt->session_id, "pin-accepted");
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_OK);
		return;
	}

	set_busy(prompt, FALSE);

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, prompt->session_id, "retry-offered");

		if (prompt->token->pin_locked)
		{
			certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, prompt->session_id, "terminal");
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
			certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, prompt->session_id, "attempt-cap");
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		/* Retries require user input after the entry has been cleared. */
		g_clear_pointer(&prompt->secret, xcc_secret_free);
		pin_update(prompt, XCC_PIN_STATUS_INCORRECT);
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_LOCKED))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, prompt->session_id, "terminal");
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

	certificate_log_grant(CERTIFICATE_REASON_PIN_TIMEOUT, prompt->session_id, "login-did-not-return");
	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_TIMED_OUT);
	return G_SOURCE_REMOVE;
}

gboolean certificate_pin_prompt_hold(PinPrompt* prompt, XccSecret* secret, size_t length)
{
	if (prompt->finished || prompt->login_in_flight)
	{
		xcc_secret_free(secret);
		return FALSE;
	}

	g_clear_pointer(&prompt->secret, xcc_secret_free);
	if (secret == NULL || !xcc_secret_set_length(secret, length))
	{
		XccPinStatus status = secret == NULL ? XCC_PIN_STATUS_MEMORY_UNAVAILABLE
		                    : length == 0 ? XCC_PIN_STATUS_REQUIRED
		                                  : XCC_PIN_STATUS_TOO_LONG;

		xcc_secret_free(secret);
		pin_update(prompt, status);
		return FALSE;
	}

	prompt->secret = secret;
	return TRUE;
}

void certificate_pin_prompt_ready(PinPrompt* prompt)
{
	if (prompt->finished)
		return;
	if (prompt->ui_context != NULL)
		xcc_pin_ready(prompt->ui_context, prompt->ui_id);
	else if (prompt->protected_path)
		certificate_pin_prompt_submit(prompt);
}

void certificate_pin_prompt_submit(PinPrompt* prompt)
{
	if (prompt->ui_context != NULL)
	{
		if (prompt->finished || prompt->busy)
			return;
		xcc_pin_submit(prompt->ui_context, prompt->ui_id, g_steal_pointer(&prompt->secret));
		return;
	}
	g_autoptr(GTask) task = NULL;
	LoginTask* data = NULL;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	if (prompt->protected_path && prompt->token->pin_final_try &&
	    !prompt->protected_path_confirmed)
	{
		if (!prompt->warning_pending)
		{
			prompt->warning_pending = TRUE;
			prompt->provider.warning(prompt->provider.user_data, prompt,
			                         certificate_pin_prompt_final_try_warning());
		}
		return;
	}

	data = g_new0(LoginTask, 1);
	data->prompt = pin_prompt_ref(prompt);
	data->protected_path = prompt->protected_path;

	if (!prompt->protected_path && xcc_secret_length(prompt->secret) == 0)
	{
		login_task_free(data);
		pin_update(prompt, XCC_PIN_STATUS_REQUIRED);
		return;
	}

	data->secret = g_steal_pointer(&prompt->secret);

	prompt->attempts++;
	prompt->login_in_flight = TRUE;
	set_busy(prompt, TRUE);

	if (pin_login_timeout_seconds > 0)
		prompt->login_timeout_id =
			xcc_timeout_add(pin_login_timeout_seconds, on_login_timeout, prompt);

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

	prompt->cancel_idle = xcc_idle_add(prompt->coordinator, on_cancelled_idle,
									   pin_prompt_ref(prompt), pin_prompt_unref);
}

static void pin_prompt_start(PinPrompt* prompt)
{
	XccPinView view = pin_view(prompt, XCC_PIN_STATUS_NONE);

	pin_active = prompt;

	certificate_log_grant(CERTIFICATE_REASON_PIN_PROMPTED, prompt->session_id,
	                      prompt->protected_path ? "protected-path" : "on-screen");

	prompt->provider.pin_show(prompt->provider.user_data, prompt, &view);
}

void certificate_pin_login_full_kind(CertificateToken* token, const char* session_id,
									 const char* parent_window, const char* caller_display,
									 const char* purpose_display, CertificatePinLoginFunc login,
									 CertificatePinRefreshFunc refresh,
									 CertificatePinAbandonFunc abandon, gpointer login_data,
									 GDestroyNotify login_data_free, GCancellable* cancellable,
									 CertificatePinDone done, gpointer user_data,
									 gboolean context_specific)
{
	PinPrompt* prompt = NULL;
	CertificatePinProvider provider = pin_provider;

	/* Never read PINs from stdin; providers declare whether they require a local display. */
	if (provider.pin_show == NULL || (provider.needs_display && !certificate_ui_has_display()))
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
	prompt->context_specific = context_specific;
	prompt->coordinator = g_main_context_ref_thread_default();
	prompt->provider = provider;
	prompt->token = certificate_token_ref(token);
	prompt->session_id = g_strdup(session_id);
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
	certificate_pin_login_full(token, NULL, parent_window, caller_display, purpose_display, login,
	                           refresh, abandon, login_data, NULL, cancellable, done, user_data);
}

void certificate_pin_login_full(CertificateToken* token, const char* session_id,
								const char* parent_window, const char* caller_display,
								const char* purpose_display, CertificatePinLoginFunc login,
								CertificatePinRefreshFunc refresh,
								CertificatePinAbandonFunc abandon, gpointer login_data,
								GDestroyNotify login_data_free, GCancellable* cancellable,
								CertificatePinDone done, gpointer user_data)
{
	certificate_pin_login_full_kind(token, session_id, parent_window, caller_display,
									purpose_display, login, refresh, abandon, login_data,
									login_data_free, cancellable, done, user_data, FALSE);
}
