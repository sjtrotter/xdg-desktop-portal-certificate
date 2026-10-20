/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "operations.h"
#include "../core/sources.h"

#include <string.h>

#include "../core/session-private.h"
#include "../redact.h"
#include "../core/pin.h"

/* The task, prompt and waiter list each hold an operation reference. */
typedef struct
{
	/* References are released from both workers and the main thread. */
	GMainContext* coordinator;
	gint refs;
	gboolean answered;

	CertificateTokens* tokens;
	XccSession* session;
	gboolean decrypt;
	char* operation_id;
	CertificateMechanism mechanism;
	GBytes* payload;
	char* parent_window;
	char* caller_display;
	char* purpose_display;
	GCancellable* cancellable;
	CertificateBrokerDone done;
	gpointer user_data;

	/* Each login waiter watches its own cancellation independently. */
	gulong login_cancel_id;
	guint login_cancel_idle;
	CertificatePinOutcome context_outcome;
	gboolean retry_open;
	gboolean retried_open;
	gboolean retry_login; /* Queued for a fresh interaction after cancellation settles. */
	guint64 open_login_generation;
} Operation;

static void operation_free(Operation* operation)
{
	certificate_mechanism_clear(&operation->mechanism);
	g_clear_pointer(&operation->payload, g_bytes_unref);
	g_clear_object(&operation->session);
	g_clear_object(&operation->cancellable);
	g_free(operation->operation_id);
	g_free(operation->parent_window);
	g_free(operation->caller_display);
	g_free(operation->purpose_display);
	g_main_context_unref(operation->coordinator);
	g_free(operation);
}

static Operation* operation_ref(Operation* operation)
{
	g_atomic_int_inc(&operation->refs);
	return operation;
}

static void operation_unref(gpointer data)
{
	Operation* operation = data;

	if (operation == NULL)
		return;

	if (!g_atomic_int_dec_and_test(&operation->refs))
		return;

	operation_free(operation);
}

/* Completion guards ensure one response; callers retain responsibility for references. */
static void operation_fail(Operation* operation, GError* error)
{
	g_autoptr(GError) owned = error;

	if (operation->answered)
		return;

	operation->answered = TRUE;
	operation->done(NULL, owned, operation->user_data);
}

static void operation_succeed(Operation* operation, GBytes* result)
{
	g_autoptr(GBytes) owned = result;

	if (operation->answered)
		return;

	operation->answered = TRUE;
	operation->done(owned, NULL, operation->user_data);
}

/* Grant budgets belong to the coordinator. */
static gboolean certificate_broker_decrypts_spent(XccSession* session)
{
	return session->decrypt_count >= CERTIFICATE_MAX_DECRYPTS_PER_GRANT;
}

/* PKCS#11 cannot revoke submitted work; recheck expiry under the device lock before submission. */
static gboolean operation_still_authorised(Operation* operation, GError** error)
{
	XccSession* session = operation->session;

	if (operation->cancellable != NULL && g_cancellable_is_cancelled(operation->cancellable))
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_CANCELLED,
		                    "Request cancelled");
		return FALSE;
	}

	if (xcc_session_is_closed(session))
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Session closed");
		return FALSE;
	}

	if (xcc_session_is_expired(session))
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Grant expired");
		return FALSE;
	}

	return TRUE;
}

/* Runs on a worker thread under device_lock. */
static gboolean ensure_session_locked(Operation* operation, GError** error)
{
	XccSession* session = operation->session;

	return certificate_device_open(&session->device, operation->tokens, session->candidate,
	                               error);
}

/* The session owns the shared login interaction across individual request cancellations. */
typedef struct
{
	/* The prompt and completion callback hold independent atomic references. */
	gint refs;

	CertificateTokens* tokens;
	XccSession* session;
	GCancellable* cancellable;
	CertificatePinOutcome outcome;

	/* Close the session only if this interaction submitted ordinary login. */
	gboolean performed_login;
} LoginInteraction;

static LoginInteraction* login_interaction_ref(LoginInteraction* interaction)
{
	g_atomic_int_inc(&interaction->refs);
	return interaction;
}

static void login_interaction_unref(gpointer data)
{
	LoginInteraction* interaction = data;

	if (interaction == NULL)
		return;

	if (!g_atomic_int_dec_and_test(&interaction->refs))
		return;

	g_clear_object(&interaction->session);
	g_clear_object(&interaction->cancellable);
	g_free(interaction);
}

/* The PIN worker borrows locked memory and must neither copy nor log the PIN. */
static gboolean do_login(const char* pin, gpointer user_data, GError** error)
{
	LoginInteraction* interaction = user_data;
	XccSession* session = interaction->session;
	Operation authorisation = { .session = session, .tokens = interaction->tokens,
	                            .cancellable = interaction->cancellable };
	gboolean ok;

	g_mutex_lock(&session->device_lock);

	/* A cancelled login may have closed the device since the open snapshot. */
	if (!operation_still_authorised(&authorisation, error) ||
	    !ensure_session_locked(&authorisation, error) ||
	    !operation_still_authorised(&authorisation, error))
	{
		g_mutex_unlock(&session->device_lock);
		return FALSE;
	}

	/* Another request may have completed login while the prompt was open. */
	if (session->device.logged_in)
	{
		g_mutex_unlock(&session->device_lock);
		return TRUE;
	}

	ok = certificate_device_login(&session->device, session->candidate, pin, error);
	interaction->performed_login = ok;
	g_mutex_unlock(&session->device_lock);

	return ok;
}

static void do_refresh_flags(CertificateToken* token, gpointer user_data)
{
	LoginInteraction* interaction = user_data;

	certificate_tokens_refresh_flags(interaction->tokens, token);
}

typedef struct
{
	Operation* operation;
	GMutex lock;
	GCond cond;
	gboolean done;
	CertificatePinOutcome outcome;
	CK_SESSION_HANDLE handle;
} ContextAuthentication;

static gboolean do_context_login(const char* pin, gpointer user_data, GError** error)
{
	ContextAuthentication* authentication = user_data;
	Operation* operation = authentication->operation;
	XccSession* session = operation->session;
	gboolean ok;

	g_mutex_lock(&session->device_lock);
	ok = operation_still_authorised(operation, error);
	if (ok && session->device.session != authentication->handle)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		ok = FALSE;
	}
	if (ok)
		ok = certificate_device_login_context(&session->device, pin, error);
	g_mutex_unlock(&session->device_lock);

	return ok;
}

static void refresh_context_flags(CertificateToken* token, gpointer user_data)
{
	ContextAuthentication* authentication = user_data;
	Operation* operation = authentication->operation;

	certificate_tokens_refresh_flags(operation->tokens, token);
}

static void on_context_pin_done(CertificatePinOutcome outcome, gpointer user_data)
{
	ContextAuthentication* authentication = user_data;

	g_mutex_lock(&authentication->lock);
	authentication->outcome = outcome;
	authentication->done = TRUE;
	g_cond_signal(&authentication->cond);
	g_mutex_unlock(&authentication->lock);
}

static gboolean prompt_context_pin(gpointer user_data)
{
	ContextAuthentication* authentication = user_data;
	Operation* operation = authentication->operation;
	XccSession* session = operation->session;

	certificate_pin_login_full_kind(
		session->candidate->token, session->id, operation->parent_window, operation->caller_display,
		operation->purpose_display, do_context_login, refresh_context_flags, NULL, authentication,
		NULL, operation->cancellable, on_context_pin_done, authentication, TRUE);
	return G_SOURCE_REMOVE;
}

/* The operation lock preserves SignInit while the main thread runs the PIN interaction. */
static gboolean authenticate_context(gpointer user_data, GError** error)
{
	Operation* operation = user_data;
	XccSession* session = operation->session;
	ContextAuthentication authentication = {
		.operation = operation, .handle = session->device.session
	};

	g_mutex_init(&authentication.lock);
	g_cond_init(&authentication.cond);
	g_mutex_unlock(&session->device_lock);

	g_mutex_lock(&authentication.lock);
	xcc_idle_add(operation->coordinator, prompt_context_pin, &authentication, NULL);
	while (!authentication.done)
		g_cond_wait(&authentication.cond, &authentication.lock);
	g_mutex_unlock(&authentication.lock);

	g_mutex_lock(&session->device_lock);
	operation->context_outcome = authentication.outcome;
	g_cond_clear(&authentication.cond);
	g_mutex_clear(&authentication.lock);

	if (operation->context_outcome != CERTIFICATE_PIN_OK)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Token refused authentication");
		return FALSE;
	}

	if (!operation_still_authorised(operation, error))
		return FALSE;

	if (session->device.module == NULL || session->device.session != authentication.handle)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		return FALSE;
	}

	return TRUE;
}

static CertificateBrokerGate certificate_broker_gate = NULL;
static gpointer certificate_broker_gate_data = NULL;

void certificate_broker_set_gate(CertificateBrokerGate gate, gpointer user_data)
{
	certificate_broker_gate = gate;
	certificate_broker_gate_data = user_data;
}

static CertificateBrokerGate certificate_broker_open_gate = NULL;
static gpointer certificate_broker_open_gate_data = NULL;

void certificate_broker_set_open_gate(CertificateBrokerGate gate, gpointer user_data)
{
	certificate_broker_open_gate = gate;
	certificate_broker_open_gate_data = user_data;
}

static void sign_thread(GTask* task, gpointer source, gpointer task_data,
                        GCancellable* cancellable)
{
	Operation* operation = task_data;
	XccSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	GBytes* result = NULL;

	if (!operation_still_authorised(operation, &error))
	{
		g_task_return_error(task, g_steal_pointer(&error));
		return;
	}

	g_mutex_lock(&session->operation_lock);
	g_mutex_lock(&session->device_lock);

	/* Recheck under the lock immediately before submitting work to the token. */
	if (!operation_still_authorised(operation, &error))
	{
		g_mutex_unlock(&session->device_lock);
		g_mutex_unlock(&session->operation_lock);
		g_task_return_error(task, g_steal_pointer(&error));
		return;
	}

	/* A preceding operation may have reset the device while this request waited. */
	if ((session->device.module != NULL &&
	     !certificate_device_refresh_login(&session->device, &error)) ||
	    !operation_still_authorised(operation, &error))
	{
		g_mutex_unlock(&session->device_lock);
		g_mutex_unlock(&session->operation_lock);
		g_task_return_error(task, g_steal_pointer(&error));
		return;
	}

	if (session->device.module == NULL ||
	    (!session->device.logged_in &&
	     (session->candidate->token->login_required ||
	      session->device.private_key == CK_INVALID_HANDLE)))
	{
		operation->retry_open = TRUE;
		g_mutex_unlock(&session->device_lock);
		g_mutex_unlock(&session->operation_lock);
		g_task_return_pointer(task, NULL, NULL);
		return;
	}

	if (certificate_broker_gate != NULL)
		certificate_broker_gate(certificate_broker_gate_data);

	result = certificate_device_perform(&session->device, operation->decrypt,
	                                    &operation->mechanism, operation->payload,
	                                    authenticate_context, operation, &error);
	g_mutex_unlock(&session->device_lock);
	g_mutex_unlock(&session->operation_lock);

	if (result == NULL)
	{
		/* Decryption failures share one response; timing remains token-dependent and query counts are bounded per grant. */
		if (operation->decrypt)
		{
			certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, session->id,
			                          operation->operation_id,
			                          operation->mechanism.name);
			g_debug("Decryption failed: %s", error->message);
			g_clear_error(&error);
			g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
			                    "Decryption failed");
		}

		g_task_return_error(task, g_steal_pointer(&error));
	}
	else
	{
		g_task_return_pointer(task, result, (GDestroyNotify) g_bytes_unref);
	}
}

static void apply_login_outcome(Operation* operation, CertificatePinOutcome outcome);
static void open_operation(Operation* operation);

static void on_signed(GObject* source, GAsyncResult* result, gpointer user_data)
{
	Operation* operation = user_data;
	g_autoptr(GError) error = NULL;
	g_autoptr(GBytes) signature = g_task_propagate_pointer(G_TASK(result), &error);

	if (operation->retry_open && error == NULL)
	{
		operation->retry_open = FALSE;
		/* Bound reauthentication when login and session state disagree. */
		if (operation->retried_open)
		{
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_FAILED,
			                                   "Token login state did not settle"));
			return;
		}
		operation->retried_open = TRUE;
		open_operation(operation);
		return;
	}

	if (signature == NULL && operation->context_outcome != CERTIFICATE_PIN_OK)
	{
		apply_login_outcome(operation, operation->context_outcome);
		return;
	}

	if (signature == NULL)
	{
		if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
			xcc_session_invalidate(operation->session, "token_removed");

		operation_fail(operation, g_steal_pointer(&error));
		return;
	}

	if (operation->mechanism.type == CKM_ECDSA &&
	    operation->mechanism.encoding == CERTIFICATE_SIGNATURE_DER)
	{
		gsize size = 0;
		const guint8* raw = g_bytes_get_data(signature, &size);
		GBytes* der = certificate_ecdsa_raw_to_der(raw, size, &error);

		if (der == NULL)
		{
			operation_fail(operation, g_steal_pointer(&error));
			return;
		}

		certificate_log_operation(CERTIFICATE_REASON_OPERATION_COMPLETED, operation->session->id,
		                          operation->operation_id,
		                          operation->mechanism.name);
		operation_succeed(operation, der);
		return;
	}

	certificate_log_operation(CERTIFICATE_REASON_OPERATION_COMPLETED, operation->session->id,
	                          operation->operation_id,
	                          operation->mechanism.name);
	operation_succeed(operation, g_steal_pointer(&signature));
}

static void run_operation(Operation* operation)
{
	g_autoptr(GTask) task = g_task_new(NULL, operation->cancellable, on_signed, operation);

	g_task_set_task_data(task, operation_ref(operation), operation_unref);
	g_task_run_in_thread(task, sign_thread);
}

static void apply_login_outcome(Operation* operation, CertificatePinOutcome outcome)
{
	/* A cancelled waiter must not receive an operation result from the shared login. */
	if (operation->cancellable != NULL && g_cancellable_is_cancelled(operation->cancellable))
	{
		operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
		                                   CERTIFICATE_PKCS11_ERROR_CANCELLED,
		                                   "Request cancelled"));
		return;
	}

	switch (outcome)
	{
		case CERTIFICATE_PIN_OK:
			run_operation(operation);
			return;

		case CERTIFICATE_PIN_CANCELLED:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_CANCELLED,
			                                   "User cancelled the PIN prompt"));
			return;

		case CERTIFICATE_PIN_LOCKED:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_PIN_LOCKED,
			                                   "Token is locked"));
			return;

		case CERTIFICATE_PIN_TOKEN_REMOVED:
			xcc_session_invalidate(operation->session, "token_removed");
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
			                                   "Token removed"));
			return;

		case CERTIFICATE_PIN_INCORRECT:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
														  CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT,
														  "Token refused login"));
			return;

		case CERTIFICATE_PIN_TIMED_OUT:
			/* A timed-out login may still complete; the abandon callback then closes the session. */
			operation_fail(operation,
			               g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT,
			                                   "Token login timed out"));
			return;

		case CERTIFICATE_PIN_NO_DISPLAY:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_NO_DISPLAY,
			                                   "PIN entry requires a display"));
			return;

		default:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_FAILED,
			                                   "Token refused login"));
			return;
	}
}

/* Disconnect only on the main thread outside the handler, since disconnect waits for running handlers. */
static void detach_waiter_cancel(Operation* operation)
{
	if (operation->login_cancel_id != 0)
	{
		g_cancellable_disconnect(operation->cancellable, operation->login_cancel_id);
		operation->login_cancel_id = 0;
	}

	if (operation->login_cancel_idle != 0)
	{
		xcc_source_remove(operation->login_cancel_idle);
		operation->login_cancel_idle = 0;
	}
}

static void finish_login(gpointer user_data)
{
	LoginInteraction* interaction = user_data;
	XccSession* session = interaction->session;
	/* The array owns one reference per waiter. */
	g_autoptr(GPtrArray) waiters = NULL;
	g_autoptr(GCancellable) cancellable = NULL;

	session->login_in_progress = FALSE;
	session->login_generation++;
	waiters = g_steal_pointer(&session->login_waiters);
	cancellable = g_steal_pointer(&session->login_cancellable);

	if (waiters != NULL)
	{
		for (guint i = 0; i < waiters->len; i++)
		{
			Operation* waiter = g_ptr_array_index(waiters, i);

			detach_waiter_cancel(waiter);
			if (waiter->retry_login)
			{
				waiter->retry_login = FALSE;
				open_operation(waiter);
			}
			else
				apply_login_outcome(waiter, interaction->outcome);
		}
	}

	login_interaction_unref(interaction);
}

static void on_pin_done(CertificatePinOutcome outcome, gpointer user_data)
{
	LoginInteraction* interaction = user_data;
	XccSession* session = interaction->session;

	/* The cancellation idle may still be queued when the login worker completes. */
	if (outcome == CERTIFICATE_PIN_OK && g_cancellable_is_cancelled(interaction->cancellable))
		outcome = CERTIFICATE_PIN_CANCELLED;

	interaction->outcome = outcome;
	if (outcome != CERTIFICATE_PIN_OK && interaction->performed_login)
	{
		/* New requests wait until the cancelled login's session has closed. */
		g_cancellable_cancel(interaction->cancellable);
		certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id,
		                      "closing-session-after-cancelled-login");
		xcc_session_release_device_async_full(session, finish_login, interaction);
		return;
	}

	finish_login(interaction);
}

static gboolean waiter_cancelled_idle(gpointer user_data)
{
	Operation* operation = user_data;
	XccSession* session = operation->session;
	g_autoptr(GCancellable) close_the_window = NULL;
	gboolean was_waiting = FALSE;

	operation->login_cancel_idle = 0;

	if (session->login_waiters != NULL)
	{
		/* The idle reference keeps the operation alive after removal from the waiter list. */
		was_waiting = g_ptr_array_remove(session->login_waiters, operation);

		if (was_waiting && session->login_waiters->len == 0 &&
		    session->login_cancellable != NULL)
			close_the_window = g_object_ref(session->login_cancellable);
	}

	if (was_waiting)
	{
		detach_waiter_cancel(operation);
		operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
		                                   CERTIFICATE_PKCS11_ERROR_CANCELLED,
		                                   "Request cancelled"));
	}

	if (close_the_window != NULL)
		g_cancellable_cancel(close_the_window);

	return G_SOURCE_REMOVE;
}

static void on_waiter_cancelled(GCancellable* cancellable, gpointer user_data)
{
	Operation* operation = user_data;

	/* Cancellation may arrive on a worker; the idle holds a reference until main-thread cleanup. */
	if (operation->login_cancel_idle != 0)
		return;

	operation->login_cancel_idle = xcc_idle_add(operation->coordinator, waiter_cancelled_idle,
												operation_ref(operation), operation_unref);
}

typedef struct
{
	gboolean needs_login;
} OpenResult;

static void open_thread(GTask* task, gpointer source, gpointer task_data,
                        GCancellable* cancellable)
{
	Operation* operation = task_data;
	XccSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	g_autofree OpenResult* opened = g_new0(OpenResult, 1);
	gboolean ok;

	if (!operation_still_authorised(operation, &error))
	{
		g_task_return_error(task, g_steal_pointer(&error));
		return;
	}

	g_mutex_lock(&session->device_lock);
	ok = operation_still_authorised(operation, &error) &&
	     ensure_session_locked(operation, &error);
	if (ok)
		opened->needs_login = !session->device.logged_in &&
		                      (session->candidate->token->login_required ||
		                       session->device.private_key == CK_INVALID_HANDLE);
	g_mutex_unlock(&session->device_lock);

	if (ok && certificate_broker_open_gate != NULL)
	{
		CertificateBrokerGate gate = certificate_broker_open_gate;

		certificate_broker_open_gate = NULL;
		gate(certificate_broker_open_gate_data);
	}

	if (!ok)
		g_task_return_error(task, g_steal_pointer(&error));
	else
		g_task_return_pointer(task, g_steal_pointer(&opened), g_free);
}

static void on_opened(GObject* source, GAsyncResult* result, gpointer user_data)
{
	Operation* operation = user_data;
	XccSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	g_autofree OpenResult* opened = g_task_propagate_pointer(G_TASK(result), &error);
	LoginInteraction* interaction = NULL;
	g_autoptr(GCancellable) prompt_cancellable = NULL;

	if (opened == NULL)
	{
		if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
			xcc_session_invalidate(session, "token_removed");

		operation_fail(operation, g_steal_pointer(&error));
		return;
	}

	if (!operation_still_authorised(operation, &error))
	{
		operation_fail(operation, g_steal_pointer(&error));
		return;
	}

	/* Waiter bookkeeping belongs to the coordinator; C_Login may hold device_lock. */
	if (session->login_in_progress)
	{
		/* A cancelled interaction cannot authenticate new requests. */
		operation->retry_login = certificate_pin_login_is_cancelling(session->login_cancellable);
		g_ptr_array_add(session->login_waiters, operation_ref(operation));
		goto attach_waiter;
	}
	/* A completed login invalidates earlier snapshots; refresh them on a worker. */
	if (opened->needs_login && operation->open_login_generation != session->login_generation)
	{
		open_operation(operation);
		return;
	}

	if (opened->needs_login)
	{
		if (session->login_waiters == NULL)
			session->login_waiters = g_ptr_array_new_with_free_func(operation_unref);

		g_ptr_array_add(session->login_waiters, operation_ref(operation));

		session->login_in_progress = TRUE;
		/* The session's cancellable keeps one request from cancelling other login waiters. */
		session->login_cancellable = g_cancellable_new();
		interaction = g_new0(LoginInteraction, 1);
		interaction->refs = 1;
		interaction->tokens = operation->tokens;
		interaction->session = g_object_ref(session);
		interaction->cancellable = g_object_ref(session->login_cancellable);
		prompt_cancellable = g_object_ref(session->login_cancellable);
	}

	if (!opened->needs_login)
	{
		run_operation(operation);
		return;
	}

attach_waiter:
	if (operation->cancellable != NULL)
		operation->login_cancel_id = g_cancellable_connect(
		    operation->cancellable, G_CALLBACK(on_waiter_cancelled), operation, NULL);

	if (interaction == NULL)
		return;

	/* The prompt and on_pin_done() each own a reference until their callbacks finish. */
	certificate_pin_login_full(session->candidate->token, session->id, operation->parent_window,
	                           operation->caller_display, operation->purpose_display, do_login,
	                           do_refresh_flags, NULL, interaction,
	                           login_interaction_unref, prompt_cancellable, on_pin_done,
	                           login_interaction_ref(interaction));
}

static void open_operation(Operation* operation)
{
	g_autoptr(GTask) task = g_task_new(NULL, operation->cancellable, on_opened, operation);

	operation->open_login_generation = operation->session->login_generation;
	g_task_set_task_data(task, operation_ref(operation), operation_unref);
	g_task_run_in_thread(task, open_thread);
}

void certificate_broker_perform(CertificateTokens* tokens, XccSession* session,
                                gboolean decrypt, const char* operation_id,
                                const char* mechanism_name,
                                GVariant* parameters, GBytes* data, const char* parent_window,
                                const char* caller_display, GCancellable* cancellable,
                                CertificateBrokerDone done, gpointer user_data)
{
	Operation* operation = NULL;
	g_autoptr(GError) error = NULL;
	CertificateMechanism mechanism;
	g_autoptr(GBytes) payload = NULL;

	if (g_atomic_int_get(&session->grant_pending))
	{
		g_set_error_literal(&error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		                    "Acquisition is pending");
		done(NULL, error, user_data);
		return;
	}

	if (!session->granted || session->candidate == NULL)
	{
		g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Session has no credential");
		done(NULL, error, user_data);
		return;
	}

	if (xcc_session_is_closed(session))
	{
		g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Session closed");
		done(NULL, error, user_data);
		return;
	}

	if (xcc_session_is_expired(session))
	{
		g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Grant expired");
		done(NULL, error, user_data);
		return;
	}

	/* Decryption queries are bounded per grant; see docs/SECURITY.md. */
	if (decrypt && certificate_broker_decrypts_spent(session))
	{
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, session->id, operation_id,
		                          mechanism_name);
		g_set_error(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED,
		            "Grant decryption limit reached (%d); acquire a new grant",
		            CERTIFICATE_MAX_DECRYPTS_PER_GRANT);
		done(NULL, error, user_data);
		return;
	}

	if (decrypt ? !session->may_decrypt : !session->may_sign)
	{
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, session->id, operation_id,
		                          mechanism_name);
		g_set_error(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED,
		            "Grant does not permit %s", decrypt ? "decryption" : "signing");
		done(NULL, error, user_data);
		return;
	}

	if (!certificate_mechanism_parse(mechanism_name, parameters, session->candidate->key_type,
	                                 session->candidate->key_size, decrypt, &mechanism, &error))
	{
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, session->id, operation_id,
		                          mechanism_name);
		done(NULL, error, user_data);
		return;
	}

	payload = certificate_mechanism_prepare(&mechanism, data, &error);
	if (payload == NULL)
	{
		certificate_mechanism_clear(&mechanism);
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, session->id, operation_id,
		                          mechanism_name);
		done(NULL, error, user_data);
		return;
	}

	operation = g_new0(Operation, 1);
	operation->refs = 1;
	operation->coordinator = g_main_context_ref_thread_default();
	operation->tokens = tokens;
	operation->session = g_object_ref(session);
	operation->decrypt = decrypt;
	operation->operation_id = g_strdup(operation_id);
	operation->mechanism = mechanism;
	operation->payload = g_steal_pointer(&payload);
	operation->parent_window = g_strdup(parent_window);
	operation->caller_display = g_strdup(caller_display);
	operation->purpose_display = g_strdup(certificate_purpose_display(session->purpose));
	operation->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;
	operation->done = done;
	operation->user_data = user_data;

	/* Charge failed attempts too; the coordinator owns the budget. */
	if (decrypt)
		session->decrypt_count++;

	certificate_log_operation(CERTIFICATE_REASON_REQUEST_RECEIVED, session->id, operation_id,
	                          mechanism.name);

	open_operation(operation);

	/* Release the creation reference while the task chain holds its own. */
	operation_unref(operation);
}
