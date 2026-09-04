/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "operations.h"

#include <string.h>

#include "../redact.h"
#include "../ui/pin.h"

typedef struct
{
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

static void operation_fail(Operation* operation, GError* error)
{
	g_autoptr(GError) owned = error;

	operation->done(NULL, owned, operation->user_data);
	operation_free(operation);
}

static void operation_succeed(Operation* operation, GBytes* result)
{
	g_autoptr(GBytes) owned = result;

	operation->done(owned, NULL, operation->user_data);
	operation_free(operation);
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

/* Runs on the PIN module's worker thread, with the PIN in locked memory that
 * this function does not own, does not copy, and does not log. */
static gboolean do_login(const char* pin, gpointer user_data, GError** error)
{
	Operation* operation = user_data;
	CertificateImplSession* session = operation->session;
	gboolean ok;

	g_mutex_lock(&session->device_lock);
	ok = certificate_device_login(&session->device, session->candidate, pin, error);
	g_mutex_unlock(&session->device_lock);

	return ok;
}

/* ------------------------------------------------------- the operation itself */

static void sign_thread(GTask* task, gpointer source, gpointer task_data,
                        GCancellable* cancellable)
{
	Operation* operation = task_data;
	CertificateImplSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	GBytes* result = NULL;

	g_mutex_lock(&session->device_lock);
	result = certificate_device_perform(&session->device, operation->decrypt,
	                                    &operation->mechanism, operation->payload, &error);
	g_mutex_unlock(&session->device_lock);

	if (result == NULL)
		g_task_return_error(task, g_steal_pointer(&error));
	else
		g_task_return_pointer(task, result, (GDestroyNotify) g_bytes_unref);
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

	g_task_set_task_data(task, operation, NULL);
	g_task_run_in_thread(task, sign_thread);
}

static void on_pin_done(CertificatePinOutcome outcome, gpointer user_data)
{
	Operation* operation = user_data;

	switch (outcome)
	{
		case CERTIFICATE_PIN_OK:
			run_operation(operation);
			return;

		case CERTIFICATE_PIN_CANCELLED:
			operation_fail(operation,
			               g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
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

		case CERTIFICATE_PIN_NO_DISPLAY:
			operation_fail(operation,
			               g_error_new_literal(CERTIFICATE_PKCS11_ERROR,
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

static void open_thread(GTask* task, gpointer source, gpointer task_data,
                        GCancellable* cancellable)
{
	Operation* operation = task_data;
	CertificateImplSession* session = operation->session;
	g_autoptr(GError) error = NULL;
	gboolean ok;

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

	if (!g_task_propagate_boolean(G_TASK(result), &error))
	{
		if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
			certificate_impl_session_invalidate(session, "token_removed");

		operation_fail(operation, g_steal_pointer(&error));
		return;
	}

	/* THE LOGIN IS LAZY: it happens at first private-key use, not at grant
	 * time. Logging in early spends the user's presence before it is needed. */
	needs_login = !session->device.logged_in &&
	              (session->candidate->token->login_required ||
	               session->device.private_key == CK_INVALID_HANDLE);

	if (!needs_login)
	{
		run_operation(operation);
		return;
	}

	certificate_pin_login(session->candidate->token, operation->parent_window,
	                      operation->caller_display, operation->purpose_display, do_login,
	                      operation, operation->cancellable, on_pin_done, operation);
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

	if (certificate_impl_session_is_expired(session))
	{
		g_set_error_literal(&error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "The grant has expired");
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

	certificate_log_operation(CERTIFICATE_REASON_REQUEST_RECEIVED, NULL, NULL, mechanism.name);

	task = g_task_new(NULL, operation->cancellable, on_opened, operation);
	g_task_set_task_data(task, operation, NULL);
	g_task_run_in_thread(task, open_thread);
}
