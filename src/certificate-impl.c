/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * The per-request handle struct, the "unexport the Request, then complete the
 * invocation, then destroy the window" order, and the handle-close split are
 * xdg-desktop-portal-gtk's src/access.c idioms, LGPL-2.1-or-later,
 * Copyright (C) 2016 Red Hat, Inc. See docs/decisions/0004-license.md.
 */

#include "certificate-impl.h"

#include <string.h>

#include "broker/operations.h"
#include "redact.h"
#include "request-impl.h"
#include "session-impl.h"
#include "tokens/filter.h"
#include "ui/chooser.h"
#include "ui/pin.h"
#include "xdp-impl-dbus.h"

static void on_session_invalidated(CertificateImplSession* session, const char* reason,
                                   gpointer user_data);

struct CertificateImpl
{
	GDBusConnection* connection;
	XdpImplExperimentalCertificate* skeleton;
	CertificateTokens* tokens;

	/* The unique name that currently owns org.freedesktop.portal.Desktop. NULL
	 * when nothing does, in which case every method is refused: with no
	 * frontend on the bus there is nobody who may legitimately call. */
	char* frontend_owner;
	guint frontend_watch;

	GHashTable* sessions; /* char *object_path -> CertificateImplSession* (owned) */
};

/* ------------------------------------------------------------ peer identity */

gboolean certificate_impl_sender_is_frontend(CertificateImpl* impl, const char* sender)
{
	if (sender == NULL || impl->frontend_owner == NULL)
		return FALSE;

	return g_strcmp0(sender, impl->frontend_owner) == 0;
}

static gboolean reject_stranger(CertificateImpl* impl, GDBusMethodInvocation* invocation)
{
	const char* sender = g_dbus_method_invocation_get_sender(invocation);

	if (certificate_impl_sender_is_frontend(impl, sender))
		return FALSE;

	/* Logged by reason code and never explained to the caller: a caller that is
	 * not the portal has no business learning why. */
	certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL, NULL, FALSE);

	g_dbus_method_invocation_return_error_literal(
	    invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
	    "Only xdg-desktop-portal may call this interface");

	return TRUE;
}

static void on_frontend_appeared(GDBusConnection* connection, const char* name, const char* owner,
                                 gpointer user_data)
{
	CertificateImpl* impl = user_data;

	g_free(impl->frontend_owner);
	impl->frontend_owner = g_strdup(owner);
	certificate_log_debug(CERTIFICATE_REASON_IDENTITY_RESOLVED, "frontend-present");
}

static void on_frontend_vanished(GDBusConnection* connection, const char* name, gpointer user_data)
{
	CertificateImpl* impl = user_data;

	g_clear_pointer(&impl->frontend_owner, g_free);
	certificate_log_debug(CERTIFICATE_REASON_IDENTITY_UNVERIFIED, "frontend-gone");

	/* The frontend going away takes every grant with it: nothing left on the
	 * bus can legitimately ask for an operation on one, and a logged-in card
	 * session held past that point is a capability nobody can account for. */
	{
		GHashTableIter iter;
		gpointer value = NULL;

		g_hash_table_iter_init(&iter, impl->sessions);
		while (g_hash_table_iter_next(&iter, NULL, &value))
			certificate_impl_session_close(CERTIFICATE_IMPL_SESSION(value));

		g_hash_table_remove_all(impl->sessions);
	}
}

/* ------------------------------------------------------------- per-request */

typedef struct
{
	CertificateImpl* impl;
	XdpImplExperimentalCertificate* object;
	GDBusMethodInvocation* invocation; /* borrowed until completed */
	CertificateImplRequest* request;
	CertificateImplSession* session; /* borrowed */
	gulong close_id;
	gboolean answered;

	/* AcquireCredential state */
	CertificateCallerIdentity caller;
	CertificatePurpose purpose;
	CertificateFilter filter;
	char* parent_window;
	char* activation_token;
	char* reason;
	char* preselect;
	guint32 lifetime;
	gboolean may_sign;
	gboolean may_decrypt;
	gboolean interaction_forbidden;
	gboolean offer_selection_memory;

	/* Sign/Decrypt state */
	gboolean decrypt;
} Transaction;

typedef enum
{
	TRANSACTION_CREATE_SESSION,
	TRANSACTION_ACQUIRE,
	TRANSACTION_OPERATION
} TransactionKind;

static void transaction_free(Transaction* transaction)
{
	if (transaction->close_id != 0 && transaction->request != NULL)
		g_signal_handler_disconnect(transaction->request, transaction->close_id);

	certificate_caller_identity_clear(&transaction->caller);
	certificate_filter_clear(&transaction->filter);
	g_clear_object(&transaction->request);
	g_free(transaction->parent_window);
	g_free(transaction->activation_token);
	g_free(transaction->reason);
	g_free(transaction->preselect);
	g_free(transaction);
}

/* THE ORDER IS LOAD-BEARING: unexport the Request first, then complete the
 * invocation, then free. The exported check is what makes the response path and
 * the Close() path mutually safe. */
static void transaction_respond(Transaction* transaction, TransactionKind kind, guint32 response,
                                GVariant* results)
{
	g_autoptr(GVariant) owned = g_variant_ref_sink(results);

	if (transaction->answered)
		return;

	transaction->answered = TRUE;

	if (transaction->request != NULL)
		certificate_impl_request_unexport(transaction->request);

	switch (kind)
	{
		case TRANSACTION_CREATE_SESSION:
			xdp_impl_experimental_certificate_complete_create_session(
			    transaction->object, transaction->invocation, response, owned);
			break;
		case TRANSACTION_ACQUIRE:
			xdp_impl_experimental_certificate_complete_acquire_credential(
			    transaction->object, transaction->invocation, response, owned);
			break;
		default:
			if (transaction->decrypt)
				xdp_impl_experimental_certificate_complete_decrypt(
				    transaction->object, transaction->invocation, response, owned);
			else
				xdp_impl_experimental_certificate_complete_sign(
				    transaction->object, transaction->invocation, response, owned);
			break;
	}

	transaction_free(transaction);
}

static GVariant* empty_results(void)
{
	GVariantBuilder builder;

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	return g_variant_builder_end(&builder);
}

static GVariant* error_results(const char* code)
{
	GVariantBuilder builder;

	/* The frontend drops every key it does not know, so this is a diagnostic
	 * for a direct impl call and for the journal, not a channel to the
	 * application. */
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "error", g_variant_new_string(code));
	return g_variant_builder_end(&builder);
}

/* Connected to the Request's "handle-close" signal, and it deliberately does
 * almost nothing: it RETURNS FALSE so that emission continues into the Request
 * class closure, which is the only place that answers Close() itself, unexports
 * and cancels. Everything this transaction owns -- the discovery worker, the
 * chooser, the PIN window, the in-flight operation -- is tied to that same
 * cancellable, so each of them answers the pending call on its own cancel path
 * with response 1. Answering here as well would be the second terminal
 * response, and there is only ever one. */
static gboolean on_request_close(XdpImplRequest* object, GDBusMethodInvocation* invocation,
                                 gpointer user_data)
{
	certificate_log_debug(CERTIFICATE_REASON_CHOOSER_CANCELLED, "close-from-frontend");
	return FALSE;
}

/* ------------------------------------------------------------ CreateSession */

static gboolean handle_create_session(XdpImplExperimentalCertificate* object,
                                      GDBusMethodInvocation* invocation, const char* arg_handle,
                                      const char* arg_session_handle, const char* arg_app_id,
                                      GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	CertificateImplSession* session = NULL;

	if (reject_stranger(impl, invocation))
		return TRUE;

	certificate_log_decision(CERTIFICATE_REASON_REQUEST_RECEIVED, arg_app_id, NULL,
	                         "create_session", TRUE);

	if (g_hash_table_contains(impl->sessions, arg_session_handle))
	{
		xdp_impl_experimental_certificate_complete_create_session(
		    object, invocation, CERTIFICATE_RESPONSE_OTHER, empty_results());
		return TRUE;
	}

	/* The Request is exported and immediately taken down again: CreateSession
	 * shows no window, so there is nothing for a Close() to interrupt, but the
	 * object has to exist at the handle path for the moment the frontend could
	 * look for it. */
	{
		g_autoptr(CertificateImplRequest) request = certificate_impl_request_new(
		    g_dbus_method_invocation_get_sender(invocation), arg_app_id, arg_handle);

		certificate_impl_request_export(request, impl->connection);
		certificate_impl_request_unexport(request);
	}

	session = certificate_impl_session_new(arg_session_handle, arg_app_id);
	certificate_impl_session_export(session, impl->connection);
	g_hash_table_insert(impl->sessions, g_strdup(arg_session_handle), session);

	/* The session's own signal, forwarded to the interface's. */
	g_signal_connect(session, "invalidated", G_CALLBACK(on_session_invalidated), impl);

	xdp_impl_experimental_certificate_complete_create_session(
	    object, invocation, CERTIFICATE_RESPONSE_SUCCESS, empty_results());

	return TRUE;
}

/* -------------------------------------------------------- AcquireCredential */

static GVariant* token_display_for(const CertificateToken* token)
{
	GVariantBuilder builder;

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "label",
	                      g_variant_new_string(token->label != NULL ? token->label : ""));
	g_variant_builder_add(
	    &builder, "{sv}", "manufacturer",
	    g_variant_new_string(token->manufacturer != NULL ? token->manufacturer : ""));
	g_variant_builder_add(&builder, "{sv}", "model",
	                      g_variant_new_string(token->model != NULL ? token->model : ""));
	g_variant_builder_add(
	    &builder, "{sv}", "reader",
	    g_variant_new_string(token->reader_name != NULL ? token->reader_name : ""));
	g_variant_builder_add(&builder, "{sv}", "protected_authentication_path",
	                      g_variant_new_boolean(token->protected_authentication_path));

	/* THE SERIAL IS DELIBERATELY NOT HERE. A card serial is a stable hardware
	 * identifier that would let every application that ever gets a grant
	 * correlate this user across all of them, and nothing in the interface
	 * needs it: it is display information, and the label and the reader are
	 * what a human reads. See docs/IMPL-INTERFACE.md. */

	return g_variant_builder_end(&builder);
}

static GVariant* bytes_to_variant(const GByteArray* bytes)
{
	return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes->data, bytes->len, 1);
}

static void finish_acquire(Transaction* transaction, CertificateCandidate* candidate,
                           gboolean remember)
{
	GVariantBuilder builder;
	GVariantBuilder chain;
	g_auto(GStrv) operations = NULL;
	g_autoptr(GStrvBuilder) operations_builder = g_strv_builder_new();

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add(&builder, "{sv}", "certificate_der",
	                      bytes_to_variant(candidate->der));

	/* CHAIN: leaf only. This backend reads the leaf certificate off the token
	 * and does not go looking for intermediates, so it says so rather than
	 * claiming a completeness it has not established. */
	g_variant_builder_init(&chain, G_VARIANT_TYPE("aay"));
	g_variant_builder_add(&builder, "{sv}", "chain_der", g_variant_builder_end(&chain));
	g_variant_builder_add(&builder, "{sv}", "chain_status", g_variant_new_string("leaf_only"));

	g_variant_builder_add(&builder, "{sv}", "token_display", token_display_for(candidate->token));
	g_variant_builder_add(&builder, "{sv}", "key_type",
	                      g_variant_new_string(candidate->key_type != NULL ? candidate->key_type
	                                                                       : "unknown"));
	g_variant_builder_add(&builder, "{sv}", "key_size", g_variant_new_uint32(candidate->key_size));
	if (candidate->key_curve != NULL)
		g_variant_builder_add(&builder, "{sv}", "key_curve",
		                      g_variant_new_string(candidate->key_curve));

	g_variant_builder_add(
	    &builder, "{sv}", "supported_mechanisms",
	    g_variant_new_strv((const char* const*) candidate->supported_mechanisms, -1));

	/* The operations the KEY permits, intersected with what the caller's
	 * operation_policy asked for. The frontend intersects again with its own
	 * list; a backend that returned more than it may does not get more. */
	if (transaction->may_sign && candidate->can_sign)
		g_strv_builder_add(operations_builder, "sign");
	if (transaction->may_decrypt && candidate->can_decrypt)
		g_strv_builder_add(operations_builder, "decrypt");
	operations = g_strv_builder_end(operations_builder);

	g_variant_builder_add(&builder, "{sv}", "permitted_operations",
	                      g_variant_new_strv((const char* const*) operations, -1));

	/* ALWAYS TRUE: the login is lazy, so the first Sign on this grant shows a
	 * PIN window. Saying otherwise would be a lie the caller builds a UI on. */
	g_variant_builder_add(&builder, "{sv}", "may_prompt_later", g_variant_new_boolean(TRUE));
	g_variant_builder_add(&builder, "{sv}", "certificate_id",
	                      g_variant_new_string(candidate->certificate_id));
	g_variant_builder_add(&builder, "{sv}", "remember_selection",
	                      g_variant_new_boolean(remember));

	certificate_impl_session_grant(transaction->session, candidate, transaction->purpose,
	                               transaction->may_sign && candidate->can_sign,
	                               transaction->may_decrypt && candidate->can_decrypt,
	                               transaction->lifetime);

	certificate_log_decision(CERTIFICATE_REASON_GRANT_CREATED, transaction->caller.app_id,
	                         certificate_identity_level_to_string(transaction->caller.level),
	                         certificate_purpose_to_string(transaction->purpose), TRUE);

	transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_SUCCESS,
	                    g_variant_builder_end(&builder));
}

static void on_chooser_done(const CertificateChooserResult* result, gpointer user_data)
{
	Transaction* transaction = user_data;

	if (result->chosen == NULL)
	{
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_CANCELLED,
		                    empty_results());
		return;
	}

	finish_acquire(transaction, result->chosen, result->remember_selection);
}

static void on_enumerated(GObject* source, GAsyncResult* result, gpointer user_data)
{
	Transaction* transaction = user_data;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) candidates = NULL;
	g_autoptr(GPtrArray) matching = NULL;
	CertificateChooserRequest request;

	candidates = certificate_tokens_enumerate_finish(NULL, result, &error);

	if (candidates == NULL)
	{
		if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		{
			transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_CANCELLED,
			                    empty_results());
			return;
		}

		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("device_error"));
		return;
	}

	matching = certificate_filter_apply(candidates, &transaction->filter);

	if (matching->len == 0)
	{
		/* TWO DIFFERENT DIAGNOSES, and the user needs to know which: insert a
		 * card, or talk to whoever issued the one that is in the reader. */
		const char* code = candidates->len == 0 ? "no_token" : "no_matching_certificate";

		certificate_log_counts(CERTIFICATE_REASON_NO_MATCHING_CERT, candidates->len, 0);
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results(code));
		return;
	}

	if (transaction->interaction_forbidden)
	{
		/* interaction_mode "forbidden" means never prompt, and consent for this
		 * backend IS a prompt: there is no path to a grant that does not open
		 * the chooser, not even with one candidate and a remembered selection.
		 * See docs/IMPL-INTERFACE.md. */
		certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED,
		                         transaction->caller.app_id, NULL, NULL, FALSE);
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("interaction_required"));
		return;
	}

	if (!certificate_ui_has_display())
	{
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("no_display"));
		return;
	}

	memset(&request, 0, sizeof(request));
	request.caller = &transaction->caller;
	request.purpose = transaction->purpose;
	request.may_sign = transaction->may_sign;
	request.may_decrypt = transaction->may_decrypt;
	request.lifetime_seconds = transaction->lifetime;
	request.reason = transaction->reason;
	request.offer_selection_memory = transaction->offer_selection_memory;
	request.preselect_certificate = transaction->preselect;

	certificate_chooser_show(transaction->parent_window, transaction->activation_token, matching,
	                         &request,
	                         certificate_impl_request_get_cancellable(transaction->request),
	                         on_chooser_done, transaction);
}

static gboolean handle_acquire_credential(XdpImplExperimentalCertificate* object,
                                          GDBusMethodInvocation* invocation,
                                          const char* arg_handle, const char* arg_session_handle,
                                          const char* arg_app_id, const char* arg_parent_window,
                                          GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	Transaction* transaction = NULL;
	CertificateImplSession* session = NULL;
	const char* text = NULL;
	g_autoptr(GVariant) policy = NULL;
	g_autoptr(GError) error = NULL;
	CertificatePurpose purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH;

	if (reject_stranger(impl, invocation))
		return TRUE;

	session = g_hash_table_lookup(impl->sessions, arg_session_handle);
	if (session == NULL || session->closed)
	{
		xdp_impl_experimental_certificate_complete_acquire_credential(
		    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("no_such_session"));
		return TRUE;
	}

	/* THE PURPOSE IS PARSED AGAIN. The frontend validated it and an unknown
	 * purpose never reaches a backend -- but a backend that trusted a string
	 * because "the frontend checked" is a backend that will one day be called
	 * by something else. */
	if (!g_variant_lookup(arg_options, "purpose", "&s", &text) ||
	    !certificate_purpose_parse(text, &purpose))
	{
		xdp_impl_experimental_certificate_complete_acquire_credential(
		    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("invalid_purpose"));
		return TRUE;
	}

	transaction = g_new0(Transaction, 1);
	transaction->impl = impl;
	transaction->object = object;
	transaction->invocation = invocation;
	transaction->session = session;
	transaction->purpose = purpose;
	transaction->parent_window = g_strdup(arg_parent_window);

	if (!certificate_filter_parse(arg_options, purpose, &transaction->filter, &error))
	{
		certificate_log_debug(CERTIFICATE_REASON_OPERATION_REFUSED, "malformed-filter");
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_filter"));
		return TRUE;
	}

	/* app_id and app_identity_level ARRIVED AS ARGUMENTS. Nothing here derives
	 * either of them, and the display name comes from the desktop file the app
	 * id names, never from anything the caller sent. */
	transaction->caller.app_id = g_strdup(arg_app_id);
	transaction->caller.level = certificate_identity_level_parse(
	    g_variant_lookup(arg_options, "app_identity_level", "&s", &text) ? text : NULL);
	transaction->caller.app_display_name = certificate_app_display_name(arg_app_id);

	if (g_variant_lookup(arg_options, "reason", "&s", &text))
		transaction->reason = g_strdup(text);
	if (g_variant_lookup(arg_options, "activation_token", "&s", &text))
		transaction->activation_token = g_strdup(text);
	if (g_variant_lookup(arg_options, "preselect_certificate", "&s", &text))
		transaction->preselect = g_strdup(text);
	if (g_variant_lookup(arg_options, "interaction_mode", "&s", &text))
		transaction->interaction_forbidden = g_strcmp0(text, "forbidden") == 0;

	/* `lifetime` is the frontend's DECISION, not the application's request. The
	 * backend clamps it again anyway: it is the side holding the card. */
	if (!g_variant_lookup(arg_options, "lifetime", "u", &transaction->lifetime) ||
	    transaction->lifetime == 0)
		transaction->lifetime = 300;
	transaction->lifetime = MIN(transaction->lifetime, 3600u);

	transaction->may_sign = TRUE;
	transaction->may_decrypt = FALSE;
	policy = g_variant_lookup_value(arg_options, "operation_policy", G_VARIANT_TYPE_VARDICT);
	if (policy != NULL)
	{
		gboolean value = FALSE;

		if (g_variant_lookup(policy, "sign", "b", &value))
			transaction->may_sign = value;
		if (g_variant_lookup(policy, "decrypt", "b", &value))
			transaction->may_decrypt = value;
	}

	transaction->offer_selection_memory =
	    transaction->caller.level != CERTIFICATE_IDENTITY_UNKNOWN;

	transaction->request = certificate_impl_request_new(
	    g_dbus_method_invocation_get_sender(invocation), arg_app_id, arg_handle);
	transaction->close_id = g_signal_connect(transaction->request, "handle-close",
	                                         G_CALLBACK(on_request_close), transaction);
	certificate_impl_request_export(transaction->request, impl->connection);

	certificate_log_decision(CERTIFICATE_REASON_DISCOVERY_STARTED, arg_app_id,
	                         certificate_identity_level_to_string(transaction->caller.level),
	                         certificate_purpose_to_string(purpose), FALSE);

	certificate_tokens_enumerate_async(impl->tokens,
	                                   certificate_impl_request_get_cancellable(
	                                       transaction->request),
	                                   on_enumerated, transaction);

	return TRUE;
}

/* --------------------------------------------------------- Sign and Decrypt */

static void on_operation_done(GBytes* result, const GError* error, gpointer user_data)
{
	Transaction* transaction = user_data;
	GVariantBuilder builder;
	gsize size = 0;
	const guint8* data = NULL;

	if (result == NULL)
	{
		guint32 response = CERTIFICATE_RESPONSE_OTHER;
		const char* code = "device_error";

		if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_CANCELLED))
		{
			response = CERTIFICATE_RESPONSE_CANCELLED;
			code = "cancelled";
		}
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
		                         CERTIFICATE_PKCS11_ERROR_PIN_LOCKED))
			code = "pin_locked";
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
		                         CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
			code = "token_removed";
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
		                         CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED) ||
		         g_error_matches(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT) ||
		         g_error_matches(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED))
			code = "invalid_request";

		transaction_respond(transaction, TRANSACTION_OPERATION, response, error_results(code));
		return;
	}

	data = g_bytes_get_data(result, &size);

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", transaction->decrypt ? "plaintext" : "signature",
	                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, size, 1));

	transaction_respond(transaction, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_SUCCESS,
	                    g_variant_builder_end(&builder));
}

static gboolean handle_key_operation(CertificateImpl* impl,
                                     XdpImplExperimentalCertificate* object,
                                     GDBusMethodInvocation* invocation, gboolean decrypt,
                                     const char* arg_handle, const char* arg_session_handle,
                                     const char* arg_app_id, const char* arg_parent_window,
                                     GVariant* arg_options)
{
	Transaction* transaction = NULL;
	CertificateImplSession* session = NULL;
	const char* mechanism = NULL;
	g_autoptr(GVariant) parameters = NULL;
	g_autoptr(GVariant) payload = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autofree char* caller_display = NULL;
	gsize size = 0;
	gconstpointer bytes = NULL;

	if (reject_stranger(impl, invocation))
		return TRUE;

	session = g_hash_table_lookup(impl->sessions, arg_session_handle);
	if (session == NULL || session->closed)
	{
		if (decrypt)
			xdp_impl_experimental_certificate_complete_decrypt(
			    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("no_such_session"));
		else
			xdp_impl_experimental_certificate_complete_sign(
			    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("no_such_session"));
		return TRUE;
	}

	transaction = g_new0(Transaction, 1);
	transaction->impl = impl;
	transaction->object = object;
	transaction->invocation = invocation;
	transaction->session = session;
	transaction->decrypt = decrypt;
	transaction->parent_window = g_strdup(arg_parent_window);

	g_variant_lookup(arg_options, "mechanism", "&s", &mechanism);
	parameters = g_variant_lookup_value(arg_options, "parameters", G_VARIANT_TYPE_VARDICT);
	payload = g_variant_lookup_value(arg_options, decrypt ? "ciphertext" : "data",
	                                 G_VARIANT_TYPE_BYTESTRING);

	if (payload == NULL)
	{
		transaction_respond(transaction, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_request"));
		return TRUE;
	}

	bytes = g_variant_get_fixed_array(payload, &size, 1);
	data = g_bytes_new(bytes, size);

	transaction->request = certificate_impl_request_new(
	    g_dbus_method_invocation_get_sender(invocation), arg_app_id, arg_handle);
	transaction->close_id = g_signal_connect(transaction->request, "handle-close",
	                                         G_CALLBACK(on_request_close), transaction);
	certificate_impl_request_export(transaction->request, impl->connection);

	caller_display = certificate_app_display_name(arg_app_id);

	certificate_broker_perform(
	    impl->tokens, session, decrypt, mechanism, parameters, data, arg_parent_window,
	    caller_display != NULL ? caller_display : arg_app_id,
	    certificate_impl_request_get_cancellable(transaction->request), on_operation_done,
	    transaction);

	return TRUE;
}

static gboolean handle_sign(XdpImplExperimentalCertificate* object,
                            GDBusMethodInvocation* invocation, const char* arg_handle,
                            const char* arg_session_handle, const char* arg_app_id,
                            const char* arg_parent_window, GVariant* arg_options,
                            gpointer user_data)
{
	return handle_key_operation(user_data, object, invocation, FALSE, arg_handle,
	                            arg_session_handle, arg_app_id, arg_parent_window, arg_options);
}

static gboolean handle_decrypt(XdpImplExperimentalCertificate* object,
                               GDBusMethodInvocation* invocation, const char* arg_handle,
                               const char* arg_session_handle, const char* arg_app_id,
                               const char* arg_parent_window, GVariant* arg_options,
                               gpointer user_data)
{
	return handle_key_operation(user_data, object, invocation, TRUE, arg_handle,
	                            arg_session_handle, arg_app_id, arg_parent_window, arg_options);
}

/* ----------------------------------------------------------- GetCapabilities */

static gboolean handle_get_capabilities(XdpImplExperimentalCertificate* object,
                                        GDBusMethodInvocation* invocation, const char* arg_app_id,
                                        GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	GVariantBuilder builder;
	g_auto(GStrv) mechanisms = NULL;
	gboolean protected_path = FALSE;
	static const char* const purposes[] = { "client_auth", "signing", "email", "ssh", NULL };
	static const char* const operations[] = { "sign", "decrypt", NULL };

	if (reject_stranger(impl, invocation))
		return TRUE;

	/* NO WINDOW IS SHOWN and nothing is authorised. This is a question about
	 * the backend, asked so that an application can adapt without provoking a
	 * dialog, and the answer discloses nothing about which cards are present:
	 * it is the mechanism vocabulary, not an inventory. */
	certificate_tokens_capabilities(impl->tokens, &mechanisms, &protected_path);

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "purposes", g_variant_new_strv(purposes, -1));
	g_variant_builder_add(&builder, "{sv}", "operations", g_variant_new_strv(operations, -1));
	g_variant_builder_add(&builder, "{sv}", "mechanisms",
	                      g_variant_new_strv((const char* const*) mechanisms, -1));
	g_variant_builder_add(&builder, "{sv}", "protected_authentication_path",
	                      g_variant_new_boolean(protected_path));
	g_variant_builder_add(&builder, "{sv}", "has_display",
	                      g_variant_new_boolean(certificate_ui_has_display()));

	xdp_impl_experimental_certificate_complete_get_capabilities(object, invocation,
	                                                            g_variant_builder_end(&builder));

	return TRUE;
}

/* ------------------------------------------------------------ token watching */

static void on_token_event(CertificateToken* token, gboolean added, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	GVariant* display = token_display_for(token);

	certificate_log_counts(added ? CERTIFICATE_REASON_DISCOVERY_RESULT
	                             : CERTIFICATE_REASON_TOKEN_REMOVED,
	                       1, 0);

	if (added)
	{
		xdp_impl_experimental_certificate_emit_token_added(impl->skeleton, display);
		return;
	}

	xdp_impl_experimental_certificate_emit_token_removed(impl->skeleton, display);

	/* A grant whose card has left the reader is over, and the frontend has to
	 * be told rather than letting the application discover it at the next
	 * Sign. */
	{
		GHashTableIter iter;
		gpointer value = NULL;
		g_autoptr(GPtrArray) doomed = g_ptr_array_new();

		g_hash_table_iter_init(&iter, impl->sessions);
		while (g_hash_table_iter_next(&iter, NULL, &value))
		{
			CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(value);

			if (session->candidate != NULL &&
			    certificate_token_same(session->candidate->token, token))
				g_ptr_array_add(doomed, session);
		}

		for (guint i = 0; i < doomed->len; i++)
		{
			CertificateImplSession* session = g_ptr_array_index(doomed, i);

			certificate_impl_session_invalidate(session, "token_removed");
			g_hash_table_remove(impl->sessions, session->id);
		}
	}
}

/* ------------------------------------------------------------------ set-up */

static void on_session_invalidated(CertificateImplSession* session, const char* reason,
                                   gpointer user_data)
{
	CertificateImpl* impl = user_data;

	xdp_impl_experimental_certificate_emit_session_invalidated(impl->skeleton, session->id,
	                                                           reason);
}

CertificateImpl* certificate_impl_new(GDBusConnection* connection, CertificateTokens* tokens,
                                      GError** error)
{
	CertificateImpl* impl = g_new0(CertificateImpl, 1);

	impl->connection = g_object_ref(connection);
	impl->tokens = tokens;
	impl->sessions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_object_unref);
	impl->skeleton = XDP_IMPL_EXPERIMENTAL_CERTIFICATE(
	    xdp_impl_experimental_certificate_skeleton_new());

	xdp_impl_experimental_certificate_set_version(impl->skeleton,
	                                              CERTIFICATE_IMPL_INTERFACE_VERSION);

	g_signal_connect(impl->skeleton, "handle-create-session", G_CALLBACK(handle_create_session),
	                 impl);
	g_signal_connect(impl->skeleton, "handle-acquire-credential",
	                 G_CALLBACK(handle_acquire_credential), impl);
	g_signal_connect(impl->skeleton, "handle-sign", G_CALLBACK(handle_sign), impl);
	g_signal_connect(impl->skeleton, "handle-decrypt", G_CALLBACK(handle_decrypt), impl);
	g_signal_connect(impl->skeleton, "handle-get-capabilities",
	                 G_CALLBACK(handle_get_capabilities), impl);

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(impl->skeleton), connection,
	                                      CERTIFICATE_IMPL_OBJECT_PATH, error))
	{
		certificate_impl_free(impl);
		return NULL;
	}

	/* WHO MAY CALL. Watched rather than asked per call, so that the comparison
	 * in every handler is a string compare and not a round trip. */
	impl->frontend_watch = g_bus_watch_name_on_connection(
	    connection, CERTIFICATE_FRONTEND_BUS_NAME, G_BUS_NAME_WATCHER_FLAGS_NONE,
	    on_frontend_appeared, on_frontend_vanished, impl, NULL);

	certificate_tokens_watch(tokens, on_token_event, impl);

	g_debug("providing %s", CERTIFICATE_IMPL_INTERFACE);

	return impl;
}

void certificate_impl_shutdown(CertificateImpl* impl)
{
	GHashTableIter iter;
	gpointer value = NULL;

	if (impl == NULL)
		return;

	/* Tell the frontend the truth on the way out rather than letting every
	 * caller discover it at its next Sign. */
	g_hash_table_iter_init(&iter, impl->sessions);
	while (g_hash_table_iter_next(&iter, NULL, &value))
		certificate_impl_session_invalidate(CERTIFICATE_IMPL_SESSION(value), "backend_shutdown");

	g_hash_table_remove_all(impl->sessions);

	certificate_tokens_stop_watch(impl->tokens);
}

void certificate_impl_free(CertificateImpl* impl)
{
	if (impl == NULL)
		return;

	if (impl->frontend_watch != 0)
		g_bus_unwatch_name(impl->frontend_watch);

	g_clear_pointer(&impl->sessions, g_hash_table_unref);
	g_clear_pointer(&impl->frontend_owner, g_free);
	g_clear_object(&impl->skeleton);
	g_clear_object(&impl->connection);
	g_free(impl);
}
