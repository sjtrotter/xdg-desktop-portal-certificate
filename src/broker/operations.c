/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "operations.h"

#include <string.h>

#include "../redact.h"
#include "../ui/pin.h"

/* REFERENCE COUNTED, because more than one thing outlives the call that made
 * it: the worker task, the PIN prompt that is waiting on a card, and the
 * waiter list of a second Sign that arrived while the first was logging in. An
 * Operation freed while a C_Login is reading through it was the worst bug in
 * this file's history. */
typedef struct
{
	/* ATOMIC. The worker task drops its reference from the thread pool, the
	 * waiter list drops its from the main thread, and a cancellation handler
	 * takes one on whichever thread cancelled; g_atomic_int_* costs nothing
	 * measurable and removes an argument about which of those coincide today. */
	gint refs;
	gboolean answered;

	CertificateTokens* tokens;
	CertificateImplSession* session;
	gboolean decrypt;
	CertificateMechanism mechanism;
	GBytes* payload;
	char* parent_window;
	char* caller_display;
	char* purpose_display;
	GCancellable* cancellable;
	CertificateBrokerDone done;
	gpointer user_data;

	/* Set while this operation is one of the session's login waiters. Its own
	 * cancellation has to answer IT and nothing else, so it gets its own
	 * handler for as long as it is waiting. */
	gulong login_cancel_id;
	guint login_cancel_idle;
} Operation;

static void operation_free(Operation* operation)
{
	certificate_mechanism_clear(&operation->mechanism);
	g_clear_pointer(&operation->payload, g_bytes_unref);
	g_clear_object(&operation->session);
	g_clear_object(&operation->cancellable);
	g_free(operation->parent_window);
	g_free(operation->caller_display);
	g_free(operation->purpose_display);
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

/* THE CALLER IS ANSWERED EXACTLY ONCE. Every path that can produce an answer
 * goes through these two, and the guard is here rather than at each call site
 * because there are six of them. Neither touches the reference count: the
 * operation lives as long as the task, prompt or waiter list holding it does.
 */
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

/* The fast refusal on the main thread, before a mechanism is parsed or an
 * Operation exists. It is a HINT: the check that decides is the one under the
 * device lock in certificate_broker_perform(), which charges in the same
 * critical section it reads in. */
static gboolean certificate_broker_decrypts_spent(CertificateImplSession* session)
{
	gboolean spent;

	g_mutex_lock(&session->device_lock);
	spent = session->decrypt_count >= CERTIFICATE_MAX_DECRYPTS_PER_GRANT;
	g_mutex_unlock(&session->device_lock);

	return spent;
}

/* Closed, expired, cancelled: checked before the device lock is taken and
 * again with it held, immediately before the operation is submitted. Expiry
 * cannot revoke a call the card has already accepted -- PKCS#11 has no way to
 * take one back -- so the value of the second check is that the window in
 * which one can be STARTED after the authorisation ended is as small as the
 * lock discipline allows. */
static gboolean operation_still_authorised(Operation* operation, GError** error)
{
	CertificateImplSession* session = operation->session;

	if (operation->cancellable != NULL && g_cancellable_is_cancelled(operation->cancellable))
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_CANCELLED,
		                    "The request was cancelled");
		return FALSE;
	}

	if (session->closed)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "The session was closed");
		return FALSE;
	}

	if (certificate_impl_session_is_expired(session))
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "The grant has expired");
		return FALSE;
	}

	return TRUE;
}

/* ------------------------------------------------- opening the card session */

/* Runs on a worker thread, under the session's device lock. */
static gboolean ensure_session_locked(Operation* operation, GError** error)
{
	CertificateImplSession* session = operation->session;

	return certificate_device_open(&session->device, operation->tokens, session->candidate,
	                               error);
}

/* ------------------------------------------------------------------- login */

/* ONE LOGIN INTERACTION PER SESSION, OWNED BY THE SESSION. It outlives the
 * operation that opened the window -- that one can be cancelled while others go
 * on waiting -- so it holds what the login needs and nothing that belongs to
 * any single caller. */
typedef struct
{
	CertificateTokens* tokens;
	CertificateImplSession* session; /* a reference */

	/* Whether THIS interaction is the one that authenticated the token. It is
	 * false when the login function found the session already logged in, and
	 * abandoning a login this interaction did not perform would log out a
	 * session somebody else is using. */
	gboolean performed_login;
} LoginInteraction;

static void login_interaction_free(LoginInteraction* interaction)
{
	g_clear_object(&interaction->session);
	g_free(interaction);
}

/* Runs on the PIN module's worker thread, with the PIN in locked memory that
 * this function does not own, does not copy, and does not log. */
static gboolean do_login(const char* pin, gpointer user_data, GError** error)
{
	LoginInteraction* interaction = user_data;
	CertificateImplSession* session = interaction->session;
	gboolean ok;

	g_mutex_lock(&session->device_lock);

	/* A second Sign may have logged the session in while this prompt was on
	 * screen. Spending an attempt to prove what is already true would be one
	 * more countdown on the user's card for nothing. */
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

/* Runs on the same worker thread, right after a refused PIN. */
static void do_refresh_flags(CertificateToken* token, gpointer user_data)
{
	LoginInteraction* interaction = user_data;

	certificate_tokens_refresh_flags(interaction->tokens, token);
}

/* THE CARD IS LOGGED IN AND NOBODY ASKED FOR IT. Called on the main thread
 * after the outcome has been delivered, in the one case where a C_Login
 * succeeded and the answer given was not "unlocked": the user cancelled while
 * the card was still thinking, and PKCS#11 cannot withdraw the attempt.
 *
 * THE POLICY, stated because it is one: the login is undone. The design is
 * "one PIN per grant, then sign freely", so leaving it would turn a cancelled
 * request into an unprompted signing capability for the rest of the grant --
 * the next Sign would go through with no window at all. Undoing it costs the
 * user one more PIN entry if they ask again, which is the answer their cancel
 * asked for. The token session is closed rather than only C_Logout-ed, because
 * a logged-out session is a handle with nothing behind it and reopening is what
 * the next operation does anyway.
 *
 * The device is closed ON A WORKER: this is the main thread. */
static void do_abandon(gpointer user_data)
{
	LoginInteraction* interaction = user_data;
	CertificateImplSession* session = interaction->session;
	gboolean still_wanted = FALSE;

	if (!interaction->performed_login)
		return;

	/* Belt to the braces: by the time this runs the waiter list has been
	 * emptied and answered, so there is nobody left who wanted the login. If
	 * that ever stops being true, the ones still waiting keep it. */
	g_mutex_lock(&session->device_lock);
	still_wanted = session->login_waiters != NULL && session->login_waiters->len > 0;
	g_mutex_unlock(&session->device_lock);

	if (still_wanted)
		return;

	certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id,
	                      "logged-out-after-cancelled-login");
	certificate_impl_session_release_device_async(session);
}

/* ------------------------------------------------------- the operation itself */

static CertificateBrokerGate certificate_broker_gate = NULL;
static gpointer certificate_broker_gate_data = NULL;

void certificate_broker_set_gate(CertificateBrokerGate gate, gpointer user_data)
{
	certificate_broker_gate = gate;
	certificate_broker_gate_data = user_data;
}

static void sign_thread(GTask* task, gpointer source, gpointer task_data,
                        GCancellable* cancellable)
{
	Operation* operation = task_data;
	CertificateImplSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	GBytes* result = NULL;

	if (!operation_still_authorised(operation, &error))
	{
		g_task_return_error(task, g_steal_pointer(&error));
		return;
	}

	g_mutex_lock(&session->device_lock);

	/* Again, with the lock held: the check above and C_SignInit below are the
	 * two ends of the only window that matters. */
	if (!operation_still_authorised(operation, &error))
	{
		g_mutex_unlock(&session->device_lock);
		g_task_return_error(task, g_steal_pointer(&error));
		return;
	}

	/* Where a card would be busy. See certificate_broker_set_gate(). */
	if (certificate_broker_gate != NULL)
		certificate_broker_gate(certificate_broker_gate_data);

	result = certificate_device_perform(&session->device, operation->decrypt,
	                                    &operation->mechanism, operation->payload, &error);
	g_mutex_unlock(&session->device_lock);

	if (result == NULL)
	{
		/* ONE ANSWER FOR EVERY DECRYPTION FAILURE. The module distinguishes a
		 * malformed OAEP encoding from a device fault from a key that will not
		 * do this, and the caller must not: "which failure" is precisely the
		 * signal that makes PKCS#1 v1.5 a Bleichenbacher oracle, and OAEP is
		 * only safe from it as long as nobody rebuilds the distinction by
		 * hand. The real reason is in the journal, where the user can see it
		 * and the caller cannot.
		 *
		 * This equalises the ANSWER, not the time it took to produce it.
		 * Nothing here can equalise a card's timing, which is why the
		 * per-grant budget in certificate_broker_perform() is the other half:
		 * an attack that needs thousands of queries does not get thousands of
		 * queries. */
		if (operation->decrypt)
		{
			certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL,
			                          operation->mechanism.name);
			g_debug("decryption failed: %s", error->message);
			g_clear_error(&error);
			g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
			                    "The decryption failed");
		}

		g_task_return_error(task, g_steal_pointer(&error));
	}
	else
	{
		g_task_return_pointer(task, result, (GDestroyNotify) g_bytes_unref);
	}
}

static void on_signed(GObject* source, GAsyncResult* result, gpointer user_data)
{
	Operation* operation = user_data;
	g_autoptr(GError) error = NULL;
	g_autoptr(GBytes) signature = g_task_propagate_pointer(G_TASK(result), &error);

	if (signature == NULL)
	{
		operation_fail(operation, g_steal_pointer(&error));
		return;
	}

	/* ECDSA comes off PKCS#11 as the raw r||s pair. A caller that asked for the
	 * DER ECDSA-Sig-Value gets it re-encoded here rather than having to know
	 * how PKCS#11 spells a signature. */
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

		certificate_log_operation(CERTIFICATE_REASON_OPERATION_COMPLETED, NULL, NULL,
		                          operation->mechanism.name);
		operation_succeed(operation, der);
		return;
	}

	certificate_log_operation(CERTIFICATE_REASON_OPERATION_COMPLETED, NULL, NULL,
	                          operation->mechanism.name);
	operation_succeed(operation, g_steal_pointer(&signature));
}

static void run_operation(Operation* operation)
{
	g_autoptr(GTask) task = g_task_new(NULL, operation->cancellable, on_signed, operation);

	g_task_set_task_data(task, operation_ref(operation), operation_unref);
	g_task_run_in_thread(task, sign_thread);
}

/* One login outcome, applied to one operation. Called for the operation that
 * put the window up and for every operation that arrived while it was up. */
static void apply_login_outcome(Operation* operation, CertificatePinOutcome outcome)
{
	/* CHECKED FIRST, WHATEVER THE OUTCOME WAS. A waiter whose own Close()
	 * arrived while the shared prompt was still on screen is answered
	 * "cancelled" -- not handed a signature it no longer wants, and not shown a
	 * second window either. The login itself stands: it was asked for by
	 * somebody, and the ones who still want it get it. */
	if (operation->cancellable != NULL && g_cancellable_is_cancelled(operation->cancellable))
	{
		operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
		                                   CERTIFICATE_PKCS11_ERROR_CANCELLED,
		                                   "The request was cancelled"));
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
			                                   "The user cancelled the PIN prompt"));
			return;

		case CERTIFICATE_PIN_LOCKED:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_PIN_LOCKED,
			                                   "The token is locked"));
			return;

		case CERTIFICATE_PIN_TOKEN_REMOVED:
			certificate_impl_session_invalidate(operation->session, "token_removed");
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
			                                   "The token was removed"));
			return;

		case CERTIFICATE_PIN_TIMED_OUT:
			/* A DISTINCT REASON, because it is a distinct situation: the token
			 * was sent a login and never answered. The attempt may still be
			 * spent and the login may still land -- ui/pin.h says why nothing
			 * can withdraw it -- in which case the abandon path logs the
			 * session out again on a worker. */
			operation_fail(operation,
			               g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT,
			                                   "The token did not answer the login in time"));
			return;

		case CERTIFICATE_PIN_NO_DISPLAY:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_FAILED,
			                                   "A PIN is needed and there is no display to ask on"));
			return;

		default:
			operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
			                                   CERTIFICATE_PKCS11_ERROR_FAILED,
			                                   "The token refused the login"));
			return;
	}
}

/* Stop watching this operation's own cancellable on behalf of the login. Only
 * ever called from the main thread and never from inside the handler itself,
 * which is what makes g_cancellable_disconnect() safe here: it blocks until a
 * handler already running has returned, and deadlocks if called from one. */
static void detach_waiter_cancel(Operation* operation)
{
	if (operation->login_cancel_id != 0)
	{
		g_cancellable_disconnect(operation->cancellable, operation->login_cancel_id);
		operation->login_cancel_id = 0;
	}

	if (operation->login_cancel_idle != 0)
	{
		g_source_remove(operation->login_cancel_idle);
		operation->login_cancel_idle = 0;
	}
}

static void on_pin_done(CertificatePinOutcome outcome, gpointer user_data)
{
	LoginInteraction* interaction = user_data;
	CertificateImplSession* session = interaction->session;
	g_autoptr(GPtrArray) waiters = NULL;
	g_autoptr(GCancellable) cancellable = NULL;

	g_mutex_lock(&session->device_lock);
	session->login_in_progress = FALSE;
	waiters = g_steal_pointer(&session->login_waiters);
	cancellable = g_steal_pointer(&session->login_cancellable);
	g_mutex_unlock(&session->device_lock);

	/* ONE PROMPT, ONE ANSWER, EVERY WAITER. Two Sign calls on a logged-out
	 * grant used to produce two windows for the same token, which is exactly
	 * the "type your PIN whenever asked" habit this project exists to end. */
	if (waiters != NULL)
	{
		for (guint i = 0; i < waiters->len; i++)
		{
			Operation* waiter = g_ptr_array_index(waiters, i);

			detach_waiter_cancel(waiter);
			apply_login_outcome(waiter, outcome);
		}
	}

	/* The array's free function drops the reference each waiter was added with;
	 * an operation whose task chain is still running keeps its own. */
	login_interaction_free(interaction);
}

/* One waiter, cancelled on its own. It leaves the queue and is answered here
 * and now; the window stays up for whoever is left, and comes down only when
 * nobody is. */
static gboolean waiter_cancelled_idle(gpointer user_data)
{
	Operation* operation = user_data;
	CertificateImplSession* session = operation->session;
	g_autoptr(GCancellable) close_the_window = NULL;
	gboolean was_waiting = FALSE;

	operation->login_cancel_idle = 0;

	g_mutex_lock(&session->device_lock);
	if (session->login_waiters != NULL)
	{
		/* g_ptr_array_remove() runs the free function, so the reference the
		 * list held goes here; the idle's own reference keeps this alive. */
		was_waiting = g_ptr_array_remove(session->login_waiters, operation);

		if (was_waiting && session->login_waiters->len == 0 &&
		    session->login_cancellable != NULL)
			close_the_window = g_object_ref(session->login_cancellable);
	}
	g_mutex_unlock(&session->device_lock);

	if (was_waiting)
	{
		detach_waiter_cancel(operation);
		operation_fail(operation, g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
		                                   CERTIFICATE_PKCS11_ERROR_CANCELLED,
		                                   "The request was cancelled"));
	}

	/* THE LAST ONE OUT TURNS THE WINDOW OFF. Cancelling the prompt while
	 * somebody is still waiting for it would answer them for a request they did
	 * not cancel, which is the defect this whole arrangement replaces. */
	if (close_the_window != NULL)
		g_cancellable_cancel(close_the_window);

	return G_SOURCE_REMOVE;
}

static void on_waiter_cancelled(GCancellable* cancellable, gpointer user_data)
{
	Operation* operation = user_data;

	/* Queued rather than done here: a cancel can be delivered from a thread
	 * that must not touch the waiter list or a window, and the operation may be
	 * answered and freed before the idle is dispatched, so the idle holds a
	 * reference of its own. */
	if (operation->login_cancel_idle != 0)
		return;

	operation->login_cancel_idle = g_idle_add_full(G_PRIORITY_DEFAULT, waiter_cancelled_idle,
	                                               operation_ref(operation), operation_unref);
}

static void open_thread(GTask* task, gpointer source, gpointer task_data,
                        GCancellable* cancellable)
{
	Operation* operation = task_data;
	CertificateImplSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	gboolean ok;

	if (!operation_still_authorised(operation, &error))
	{
		g_task_return_error(task, g_steal_pointer(&error));
		return;
	}

	g_mutex_lock(&session->device_lock);
	ok = ensure_session_locked(operation, &error);
	g_mutex_unlock(&session->device_lock);

	if (!ok)
		g_task_return_error(task, g_steal_pointer(&error));
	else
		g_task_return_boolean(task, TRUE);
}

static void on_opened(GObject* source, GAsyncResult* result, gpointer user_data)
{
	Operation* operation = user_data;
	CertificateImplSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	gboolean needs_login;
	gboolean wait_for_login = FALSE;
	LoginInteraction* interaction = NULL;
	g_autoptr(GCancellable) prompt_cancellable = NULL;

	if (!g_task_propagate_boolean(G_TASK(result), &error))
	{
		if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
			certificate_impl_session_invalidate(session, "token_removed");

		operation_fail(operation, g_steal_pointer(&error));
		return;
	}

	/* THE LOGIN IS LAZY: it happens at first private-key use, not at grant
	 * time. Logging in early spends the user's presence before it is needed.
	 * The state it is decided from is written by worker threads, so it is read
	 * under the same lock they write it under. */
	g_mutex_lock(&session->device_lock);
	needs_login = !session->device.logged_in &&
	              (session->candidate->token->login_required ||
	               session->device.private_key == CK_INVALID_HANDLE);

	if (needs_login)
	{
		if (session->login_waiters == NULL)
			session->login_waiters = g_ptr_array_new_with_free_func(operation_unref);

		/* EVERY PARTICIPANT IS A WAITER, including the one that is about to
		 * open the window. The list is what "who still wants this login" means,
		 * and the operation that started it is not privileged: it can be
		 * cancelled on its own like any other, and the window stays up for the
		 * rest. */
		g_ptr_array_add(session->login_waiters, operation_ref(operation));

		if (session->login_in_progress)
		{
			wait_for_login = TRUE;
		}
		else
		{
			session->login_in_progress = TRUE;
			/* THE WINDOW'S CANCELLABLE IS THE SESSION'S, not this request's.
			 * Handing the prompt the first caller's cancellable meant that
			 * closing the first request closed the window every later one was
			 * waiting behind. */
			session->login_cancellable = g_cancellable_new();
			interaction = g_new0(LoginInteraction, 1);
			interaction->tokens = operation->tokens;
			interaction->session = g_object_ref(session);
			prompt_cancellable = g_object_ref(session->login_cancellable);
		}
	}
	g_mutex_unlock(&session->device_lock);

	if (!needs_login)
	{
		run_operation(operation);
		return;
	}

	/* Watched for as long as it is in the queue: this operation's own Close()
	 * answers this operation and takes it out, and nothing else. */
	if (operation->cancellable != NULL)
		operation->login_cancel_id = g_cancellable_connect(
		    operation->cancellable, G_CALLBACK(on_waiter_cancelled), operation, NULL);

	if (wait_for_login)
		return;

	certificate_pin_login(session->candidate->token, operation->parent_window,
	                      operation->caller_display, operation->purpose_display, do_login,
	                      do_refresh_flags, do_abandon, interaction, prompt_cancellable,
	                      on_pin_done, interaction);
}

void certificate_broker_perform(CertificateTokens* tokens, CertificateImplSession* session,
                                gboolean decrypt, const char* mechanism_name,
                                GVariant* parameters, GBytes* data, const char* parent_window,
                                const char* caller_display, GCancellable* cancellable,
                                CertificateBrokerDone done, gpointer user_data)
{
	Operation* operation = NULL;
	g_autoptr(GError) error = NULL;
	CertificateMechanism mechanism;
	g_autoptr(GBytes) payload = NULL;
	g_autoptr(GTask) task = NULL;

	/* CHECKED AGAIN, ALL OF IT, even though the frontend checked first. */
	if (!session->granted || session->candidate == NULL)
	{
		g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "This session does not hold a credential");
		done(NULL, error, user_data);
		return;
	}

	if (session->closed)
	{
		g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "The session was closed");
		done(NULL, error, user_data);
		return;
	}

	if (certificate_impl_session_is_expired(session))
	{
		g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "The grant has expired");
		done(NULL, error, user_data);
		return;
	}

	/* A PER-GRANT BUDGET ON DECRYPTIONS, and none on signatures. The
	 * difference is what one query is worth. A signature is over a digest the
	 * caller had to name the length of, and the interesting attacks on it need
	 * a chosen structure rather than a large number of tries. A decryption is a
	 * raw private-key operation on caller-chosen bytes: OAEP makes it safe to
	 * answer, but the whole family of attacks on RSA decryption -- padding
	 * oracles, fault injection, timing -- is built on making thousands to
	 * millions of queries against one key, and nothing else in either process
	 * counts them.
	 *
	 * 32 IS THE NUMBER, and the reasoning is that real decryption with a card
	 * key is unwrapping: an S/MIME message key, a TLS pre-master secret, a
	 * stored file key. That is one C_Decrypt, occasionally a handful when a
	 * client retries or a message has several recipients. Thirty-two is well
	 * over any of those and four orders of magnitude short of what an attack
	 * needs, so the honest client never sees it and the hostile one runs out.
	 * It is per grant rather than per unit time on purpose: re-consenting is
	 * what buys more, and a user who is asked again is a user who finds out. */
	if (decrypt && certificate_broker_decrypts_spent(session))
	{
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL,
		                          mechanism_name);
		g_set_error(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED,
		            "This grant has spent its %d decryptions; a further one needs a new grant",
		            CERTIFICATE_MAX_DECRYPTS_PER_GRANT);
		done(NULL, error, user_data);
		return;
	}

	if (decrypt ? !session->may_decrypt : !session->may_sign)
	{
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL,
		                          mechanism_name);
		g_set_error(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED,
		            "This grant does not permit %s", decrypt ? "decryption" : "signing");
		done(NULL, error, user_data);
		return;
	}

	if (!certificate_mechanism_parse(mechanism_name, parameters, session->candidate->key_type,
	                                 session->candidate->key_size, decrypt, &mechanism, &error))
	{
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL,
		                          mechanism_name);
		done(NULL, error, user_data);
		return;
	}

	payload = certificate_mechanism_prepare(&mechanism, data, &error);
	if (payload == NULL)
	{
		certificate_mechanism_clear(&mechanism);
		certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL,
		                          mechanism_name);
		done(NULL, error, user_data);
		return;
	}

	operation = g_new0(Operation, 1);
	operation->refs = 1;
	operation->tokens = tokens;
	operation->session = g_object_ref(session);
	operation->decrypt = decrypt;
	operation->mechanism = mechanism;
	operation->payload = g_steal_pointer(&payload);
	operation->parent_window = g_strdup(parent_window);
	operation->caller_display = g_strdup(caller_display);
	operation->purpose_display = g_strdup(certificate_purpose_display(session->purpose));
	operation->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;
	operation->done = done;
	operation->user_data = user_data;

	/* COUNTED WHEN IT IS ACCEPTED, not when it succeeds. A failed decryption is
	 * exactly the query an attacker wants; charging only for the successful
	 * ones would leave the budget unspent by the traffic it exists to bound.
	 *
	 * CHARGED UNDER THE DEVICE LOCK, which is the same lock the workers read
	 * and write every other piece of this session's device state under. The
	 * check above is a fast refusal on the main thread and cannot be relied on
	 * alone: read-then-increment without the lock is a budget that two callers
	 * can both spend the last unit of. The refusal is repeated here because
	 * this is the check that actually holds. */
	if (decrypt)
	{
		gboolean spent = FALSE;

		g_mutex_lock(&session->device_lock);
		spent = session->decrypt_count >= CERTIFICATE_MAX_DECRYPTS_PER_GRANT;
		if (!spent)
			session->decrypt_count++;
		g_mutex_unlock(&session->device_lock);

		if (spent)
		{
			certificate_log_operation(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL,
			                          mechanism.name);
			operation_fail(operation,
			               g_error_new(CERTIFICATE_PKCS11_ERROR,
			                           CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED,
			                           "This grant has spent its %d decryptions; a further one "
			                           "needs a new grant",
			                           CERTIFICATE_MAX_DECRYPTS_PER_GRANT));
			operation_unref(operation);
			return;
		}
	}

	certificate_log_operation(CERTIFICATE_REASON_REQUEST_RECEIVED, NULL, NULL, mechanism.name);

	task = g_task_new(NULL, operation->cancellable, on_opened, operation);
	g_task_set_task_data(task, operation_ref(operation), operation_unref);
	g_task_run_in_thread(task, open_thread);

	/* The creation reference is handed to the task chain; every later stage
	 * takes one of its own. */
	operation_unref(operation);
}
