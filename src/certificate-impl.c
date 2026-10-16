/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
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
	XdpImplExperimentalCertificate1* skeleton;
	CertificateTokens* tokens;

	/* The cached frontend owner may only reject callers; acceptance requires a fresh bus lookup. */
	char* frontend_owner;
	gboolean owner_resolved;
	guint frontend_watch;

	/* Borrowed live transactions remove themselves on completion; frontend loss cancels their windows and workers. */
	GPtrArray* transactions;

	GHashTable* sessions; /* Owns each session, indexed by object path. */
};

/* One backend per process serves the Request and Session default handlers. */
static CertificateImpl* certificate_impl_singleton = NULL;

static void invalidate_foreign_sessions(CertificateImpl* impl, const char* owner);
static void cancel_transactions(CertificateImpl* impl, CertificateImplSession* session,
                                const char* code);

static void set_frontend_owner(CertificateImpl* impl, const char* owner)
{
	if (g_strcmp0(impl->frontend_owner, owner) == 0)
		return;

	/* Grants belong to the frontend connection that created them and cannot pass to a replacement. */
	invalidate_foreign_sessions(impl, owner);

	g_free(impl->frontend_owner);
	impl->frontend_owner = g_strdup(owner);

	certificate_log_debug(owner != NULL ? CERTIFICATE_REASON_IDENTITY_RESOLVED
	                                    : CERTIFICATE_REASON_IDENTITY_UNVERIFIED,
	                      owner != NULL ? "frontend-present" : "frontend-gone");
}

/* NameOwnerChanged is unordered against former-owner messages; bus lookups provide a snapshot. See docs/IMPL-INTERFACE.md. */
static const char* resolve_frontend_owner(CertificateImpl* impl)
{
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GError) error = NULL;
	const char* owner = NULL;

	impl->owner_resolved = TRUE;

	reply = g_dbus_connection_call_sync(
	    impl->connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
	    "GetNameOwner", g_variant_new("(s)", CERTIFICATE_FRONTEND_BUS_NAME),
	    G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 1000, NULL, &error);

	/* A failed owner lookup denies all callers. */
	if (reply != NULL)
		g_variant_get(reply, "(&s)", &owner);

	set_frontend_owner(impl, owner);

	return impl->frontend_owner;
}

/* Reject cached mismatches without a bus call to bound main-thread work; confirm every acceptance with GetNameOwner. */
gboolean certificate_impl_sender_is_frontend(CertificateImpl* impl, const char* sender)
{
	if (impl == NULL || sender == NULL)
		return FALSE;

	/* The name watch may not have delivered its initial owner yet. */
	if (!impl->owner_resolved)
		resolve_frontend_owner(impl);

	if (impl->frontend_owner == NULL || g_strcmp0(sender, impl->frontend_owner) != 0)
		return FALSE;

	resolve_frontend_owner(impl);

	return impl->frontend_owner != NULL && g_strcmp0(sender, impl->frontend_owner) == 0;
}

gboolean certificate_impl_sender_is_frontend_default(const char* sender)
{
	return certificate_impl_sender_is_frontend(certificate_impl_singleton, sender);
}

static gboolean reject_stranger(CertificateImpl* impl, GDBusMethodInvocation* invocation)
{
	const char* sender = g_dbus_method_invocation_get_sender(invocation);

	if (certificate_impl_sender_is_frontend(impl, sender))
		return FALSE;

	certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL, NULL, FALSE);

	g_dbus_method_invocation_return_error_literal(
	    invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
	    "Only xdg-desktop-portal may call this interface");

	return TRUE;
}

/* A NULL reason closes sessions silently when their frontend has left the bus. */
static void close_and_forget_all(CertificateImpl* impl, const char* reason)
{
	GHashTableIter iter;
	gpointer value = NULL;

	g_hash_table_iter_init(&iter, impl->sessions);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(value);

		if (reason != NULL)
			certificate_impl_session_invalidate(session, reason);
		else
			certificate_impl_session_close(session);

		certificate_impl_session_unexport(session);
	}

	g_hash_table_remove_all(impl->sessions);
}

static void invalidate_foreign_sessions(CertificateImpl* impl, const char* owner)
{
	GHashTableIter iter;
	gpointer value = NULL;
	g_autoptr(GPtrArray) doomed = g_ptr_array_new_with_free_func(g_object_unref);

	if (impl->sessions == NULL)
		return;

	g_hash_table_iter_init(&iter, impl->sessions);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(value);

		if (owner != NULL && g_strcmp0(session->owner, owner) == 0)
			continue;

		g_ptr_array_add(doomed, g_object_ref(session));
	}

	for (guint i = 0; i < doomed->len; i++)
	{
		CertificateImplSession* session = g_ptr_array_index(doomed, i);

		certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id, "frontend-gone");
		/* Cancel windows before closing the sessions their transactions reference. */
		cancel_transactions(impl, session, "owner_gone");
		/* The replacement frontend has no record of these sessions, so close them without emitting invalidation. */
		certificate_impl_session_close(session);
		certificate_impl_session_unexport(session);
		g_hash_table_remove(impl->sessions, session->id);
	}
}

static void on_frontend_appeared(GDBusConnection* connection, const char* name, const char* owner,
                                 gpointer user_data)
{
	CertificateImpl* impl = user_data;

	set_frontend_owner(impl, owner);
	impl->owner_resolved = TRUE;
}

static void on_frontend_vanished(GDBusConnection* connection, const char* name, gpointer user_data)
{
	CertificateImpl* impl = user_data;

	set_frontend_owner(impl, NULL);
	impl->owner_resolved = TRUE;

	close_and_forget_all(impl, NULL);

	cancel_transactions(impl, NULL, "owner_gone");
}

void certificate_impl_session_forget(CertificateImplSession* session)
{
	CertificateImpl* impl = certificate_impl_singleton;

	/* Session.Close() must also cancel the session's pending windows and operations. */
	if (impl != NULL)
		cancel_transactions(impl, session, "no_such_session");

	certificate_impl_session_unexport(session);

	if (impl == NULL || impl->sessions == NULL || session->id == NULL)
		return;

	if (g_hash_table_lookup(impl->sessions, session->id) == session)
		g_hash_table_remove(impl->sessions, session->id);
}

/* Defaults apply only to absent keys; mistyped constraints must fail. */
static gboolean option_take_string(GVariant* options, const char* key, char** out, gboolean* bad)
{
	g_autoptr(GVariant) value = g_variant_lookup_value(options, key, NULL);

	if (value == NULL)
		return FALSE;

	if (!g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
	{
		*bad = TRUE;
		return FALSE;
	}

	*out = g_variant_dup_string(value, NULL);
	return TRUE;
}

static gboolean option_take_uint32(GVariant* options, const char* key, guint32* out,
                                   gboolean* bad)
{
	g_autoptr(GVariant) value = g_variant_lookup_value(options, key, NULL);

	if (value == NULL)
		return FALSE;

	if (!g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
	{
		*bad = TRUE;
		return FALSE;
	}

	*out = g_variant_get_uint32(value);
	return TRUE;
}

static GVariant* option_take_vardict(GVariant* options, const char* key, gboolean* bad)
{
	g_autoptr(GVariant) value = g_variant_lookup_value(options, key, NULL);

	if (value == NULL)
		return NULL;

	if (!g_variant_is_of_type(value, G_VARIANT_TYPE_VARDICT))
	{
		*bad = TRUE;
		return NULL;
	}

	return g_steal_pointer(&value);
}

/* Reject unknown keys in security constraints; top-level keys remain extensible. */
static gboolean vardict_keys_known(GVariant* dict, const char* const* known)
{
	GVariantIter iter;
	const char* key = NULL;

	g_variant_iter_init(&iter, dict);
	while (g_variant_iter_next(&iter, "{&sv}", &key, NULL))
	{
		if (!g_strv_contains(known, key))
			return FALSE;
	}

	return TRUE;
}

typedef struct
{
	CertificateImpl* impl;
	XdpImplExperimentalCertificate1* object;
	GDBusMethodInvocation* invocation; /* Borrowed until completion. */
	CertificateImplRequest* request;
	CertificateImplSession* session; /* Owned reference. */
	gulong close_id;
	gboolean answered;
	gboolean registered;

	/* A non-user cancellation carries a wire diagnostic and response 2; user cancellation uses response 1. */
	const char* cancelled_code;

	CertificateCallerIdentity caller;
	CertificatePurpose purpose;
	CertificateFilter filter;
	char* parent_window;
	char* activation_token;
	char* reason;
	guint32 lifetime;
	gboolean may_sign;
	gboolean interaction_forbidden;
} Transaction;

typedef enum
{
	TRANSACTION_CREATE_SESSION,
	TRANSACTION_ACQUIRE,
	TRANSACTION_OPERATION
} TransactionKind;

static void transaction_free(Transaction* transaction)
{
	if (transaction->registered && transaction->impl != NULL &&
	    transaction->impl->transactions != NULL)
		g_ptr_array_remove_fast(transaction->impl->transactions, transaction);

	if (transaction->close_id != 0 && transaction->request != NULL)
		g_signal_handler_disconnect(transaction->request, transaction->close_id);

	certificate_caller_identity_clear(&transaction->caller);
	certificate_filter_clear(&transaction->filter);
	g_clear_object(&transaction->request);
	g_clear_object(&transaction->session);
	g_free(transaction->parent_window);
	g_free(transaction->activation_token);
	g_free(transaction->reason);
	g_free(transaction);
}

/* Track transactions while they can own windows so frontend loss cancels them. */
static void transaction_register(Transaction* transaction)
{
	g_ptr_array_add(transaction->impl->transactions, transaction);
	transaction->registered = TRUE;
}

/* Cancel all live transactions or only those belonging to the given session. */
static void cancel_transactions(CertificateImpl* impl, CertificateImplSession* session,
                                const char* code)
{
	g_autoptr(GPtrArray) doomed = g_ptr_array_new();

	if (impl->transactions == NULL)
		return;

	for (guint i = 0; i < impl->transactions->len; i++)
	{
		Transaction* transaction = g_ptr_array_index(impl->transactions, i);

		if (session != NULL && transaction->session != session)
			continue;

		g_ptr_array_add(doomed, transaction);
	}

	/* Use a copy because cancellation completion removes entries from impl->transactions. */
	for (guint i = 0; i < doomed->len; i++)
	{
		Transaction* transaction = g_ptr_array_index(doomed, i);

		transaction->cancelled_code = code;

		if (transaction->request != NULL)
			g_cancellable_cancel(certificate_impl_request_get_cancellable(transaction->request));
	}
}

/* Unexport before completing the invocation; response and Close() paths share the exported guard. */
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
			xdp_impl_experimental_certificate1_complete_create_session(
			    transaction->object, transaction->invocation, response, owned);
			break;
		case TRANSACTION_ACQUIRE:
			xdp_impl_experimental_certificate1_complete_acquire_credential(
			    transaction->object, transaction->invocation, response, owned);
			break;
		default:
			xdp_impl_experimental_certificate1_complete_sign(
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

	/* The frontend drops unknown result keys, so this diagnostic reaches only direct impl callers and the journal. */
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "error", g_variant_new_string(code));
	return g_variant_builder_end(&builder);
}

/* Answer a method before it has a transaction. */
static void answer_early(XdpImplExperimentalCertificate1* object,
                         GDBusMethodInvocation* invocation, TransactionKind kind,
                         guint32 response, GVariant* results)
{
	switch (kind)
	{
		case TRANSACTION_CREATE_SESSION:
			xdp_impl_experimental_certificate1_complete_create_session(object, invocation,
			                                                           response, results);
			return;
		case TRANSACTION_ACQUIRE:
			xdp_impl_experimental_certificate1_complete_acquire_credential(object, invocation,
			                                                               response, results);
			return;
		default:
			xdp_impl_experimental_certificate1_complete_sign(object, invocation, response,
			                                                 results);
			return;
	}
}

/* Return FALSE so the Request class closure alone answers Close(), unexports and cancels. */
static gboolean on_request_close(XdpImplRequest* object, GDBusMethodInvocation* invocation,
                                 gpointer user_data)
{
	/* Authorize before logging because this signal handler precedes the class closure's authorization check. */
	if (!certificate_impl_sender_is_frontend_default(
	        g_dbus_method_invocation_get_sender(invocation)))
		return FALSE;

	certificate_log_debug(CERTIFICATE_REASON_CHOOSER_CANCELLED, "close-from-frontend");
	return FALSE;
}

/* Return the named session after backend checks, or NULL with an error code. */
static CertificateImplSession* lookup_session(CertificateImpl* impl, const char* session_handle,
                                              const char* app_id, const char** code)
{
	CertificateImplSession* session = g_hash_table_lookup(impl->sessions, session_handle);

	*code = "no_such_session";

	if (session == NULL || session->closed)
		return NULL;

	/* Bind each session to its app_id to prevent cross-application key use. */
	if (g_strcmp0(session->app_id, app_id) != 0)
	{
		certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, app_id, NULL,
		                         "app-id-mismatch", FALSE);
		return NULL;
	}

	return session;
}

static gboolean handle_create_session(XdpImplExperimentalCertificate1* object,
                                      GDBusMethodInvocation* invocation, const char* arg_handle,
                                      const char* arg_session_handle, const char* arg_app_id,
                                      GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	CertificateImplSession* session = NULL;
	CertificateImplSession* existing = NULL;
	g_autoptr(GError) error = NULL;

	if (reject_stranger(impl, invocation))
		return TRUE;

	certificate_log_decision(CERTIFICATE_REASON_REQUEST_RECEIVED, arg_app_id, NULL,
	                         "create_session", TRUE);

	existing = g_hash_table_lookup(impl->sessions, arg_session_handle);
	if (existing != NULL && !existing->closed)
	{
		xdp_impl_experimental_certificate1_complete_create_session(
		    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("invalid_request"));
		return TRUE;
	}

	/* The frontend may reuse a closed session's path for the same session_handle_token. */
	if (existing != NULL)
	{
		certificate_impl_session_close(existing);
		certificate_impl_session_unexport(existing);
		g_hash_table_remove(impl->sessions, arg_session_handle);
	}

	/* CreateSession has no interactive work, but its Request must briefly exist at the returned handle path. */
	{
		g_autoptr(CertificateImplRequest) request = certificate_impl_request_new(
		    g_dbus_method_invocation_get_sender(invocation), arg_app_id, arg_handle);

		if (!certificate_impl_request_export(request, impl->connection, &error))
		{
			g_warning("Request export failed: %s", error->message);
			xdp_impl_experimental_certificate1_complete_create_session(
			    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("invalid_request"));
			return TRUE;
		}

		certificate_impl_request_unexport(request);
	}

	session = certificate_impl_session_new(arg_session_handle, arg_app_id);
	session->owner = g_strdup(g_dbus_method_invocation_get_sender(invocation));

	/* Abort creation on export failure because the frontend must be able to close retained sessions. */
	if (!certificate_impl_session_export(session, impl->connection, &error))
	{
		g_warning("Session export failed: %s", error->message);
		g_object_unref(session);
		xdp_impl_experimental_certificate1_complete_create_session(
		    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("invalid_request"));
		return TRUE;
	}

	g_hash_table_insert(impl->sessions, g_strdup(arg_session_handle), session);

	g_signal_connect(session, "invalidated", G_CALLBACK(on_session_invalidated), impl);

	xdp_impl_experimental_certificate1_complete_create_session(
	    object, invocation, CERTIFICATE_RESPONSE_SUCCESS, empty_results());

	return TRUE;
}

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

	/* Card serials would allow applications to correlate users across grants and are excluded from results. */

	return g_variant_builder_end(&builder);
}

static GVariant* bytes_to_variant(const GByteArray* bytes)
{
	return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes->data, bytes->len, 1);
}

GVariant* certificate_impl_acquire_results(CertificateCandidate* candidate, gboolean may_sign)
{
	GVariantBuilder builder;
	GVariantBuilder chain;
	g_auto(GStrv) operations = NULL;
	g_autoptr(GStrvBuilder) operations_builder = g_strv_builder_new();

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add(&builder, "{sv}", "certificate_der", bytes_to_variant(candidate->der));

	/* Only the leaf certificate is available; chain completeness is unknown. */
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

	if (may_sign && candidate->can_sign)
		g_strv_builder_add(operations_builder, "sign");
	operations = g_strv_builder_end(operations_builder);

	g_variant_builder_add(&builder, "{sv}", "permitted_operations",
	                      g_variant_new_strv((const char* const*) operations, -1));

	/* Lazy login means the first private-key operation may prompt. */
	g_variant_builder_add(&builder, "{sv}", "may_prompt_later", g_variant_new_boolean(TRUE));

	return g_variant_builder_end(&builder);
}

static void finish_acquire(Transaction* transaction, CertificateCandidate* candidate)
{
	CertificateImplSession* session = transaction->session;

	/* The session, frontend or token may disappear while the chooser is open. */
	if (session == NULL || session->closed)
	{
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("no_such_session"));
		return;
	}

	/* Tokens without serials cannot be rebound reliably at private-key use. */
	if (candidate->token->serial == NULL || *candidate->token->serial == '\0')
	{
		certificate_log_grant(CERTIFICATE_REASON_OPERATION_REFUSED, session->id,
		                      "token-without-serial");
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("device_error"));
		return;
	}

	/* The interface exposes Sign only, so no grant permits decryption. */
	certificate_impl_session_grant(session, candidate, transaction->purpose,
	                               transaction->may_sign && candidate->can_sign, FALSE,
	                               transaction->lifetime);

	certificate_log_decision(CERTIFICATE_REASON_GRANT_CREATED, transaction->caller.app_id,
	                         certificate_identity_level_to_string(transaction->caller.level),
	                         certificate_purpose_to_string(transaction->purpose), TRUE);

	transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_SUCCESS,
	                    certificate_impl_acquire_results(candidate, transaction->may_sign));
}

/* Response 1 is reserved for user cancellation; frontend loss requires a diagnostic failure. */
static gboolean respond_if_owner_gone(Transaction* transaction, TransactionKind kind)
{
	if (transaction->cancelled_code == NULL)
		return FALSE;

	transaction_respond(transaction, kind, CERTIFICATE_RESPONSE_OTHER,
	                    error_results(transaction->cancelled_code));
	return TRUE;
}

static void on_chooser_done(const CertificateChooserResult* result, gpointer user_data)
{
	Transaction* transaction = user_data;

	if (result->chosen == NULL)
	{
		if (respond_if_owner_gone(transaction, TRANSACTION_ACQUIRE))
			return;

		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_CANCELLED,
		                    empty_results());
		return;
	}

	finish_acquire(transaction, result->chosen);
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
			if (respond_if_owner_gone(transaction, TRANSACTION_ACQUIRE))
				return;

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
		const char* code = candidates->len == 0 ? "no_token" : "no_matching_certificate";

		certificate_log_counts(CERTIFICATE_REASON_NO_MATCHING_CERT, candidates->len, 0);
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results(code));
		return;
	}

	if (transaction->interaction_forbidden)
	{
		/* Acquisition always requires a chooser, including a single candidate or remembered selection. */
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
	request.may_decrypt = FALSE;
	request.lifetime_seconds = transaction->lifetime;
	request.reason = transaction->reason;

	certificate_chooser_show(transaction->parent_window, transaction->activation_token, matching,
	                         &request,
	                         certificate_impl_request_get_cancellable(transaction->request),
	                         on_chooser_done, transaction);
}

static gboolean parse_acquire_options(Transaction* transaction, GVariant* options,
                                      const char** code)
{
	static const char* const policy_keys[] = { "sign", NULL };
	g_autofree char* level = NULL;
	g_autofree char* interaction = NULL;
	g_autoptr(GVariant) policy = NULL;
	gboolean bad = FALSE;

	*code = "invalid_request";

	/* Identity arrives from the frontend; display names resolve only from desktop files. */
	if (option_take_string(options, "app_identity_level", &level, &bad))
	{
		if (g_strcmp0(level, CERTIFICATE_IDENTITY_LEVEL_VERIFIED) != 0 &&
		    g_strcmp0(level, CERTIFICATE_IDENTITY_LEVEL_DERIVED) != 0 &&
		    g_strcmp0(level, CERTIFICATE_IDENTITY_LEVEL_UNKNOWN) != 0)
			return FALSE;
	}
	if (bad)
		return FALSE;

	transaction->caller.level = certificate_identity_level_parse(level);

	if (!option_take_string(options, "reason", &transaction->reason, &bad) && bad)
		return FALSE;
	if (!option_take_string(options, "activation_token", &transaction->activation_token, &bad) &&
	    bad)
		return FALSE;

	if (option_take_string(options, "interaction_mode", &interaction, &bad))
	{
		if (g_strcmp0(interaction, "forbidden") == 0)
			transaction->interaction_forbidden = TRUE;
		else if (g_strcmp0(interaction, "required") != 0 && g_strcmp0(interaction, "allowed") != 0)
			return FALSE;
	}
	if (bad)
		return FALSE;

	/* The frontend supplies its allowed lifetime; backend limits may only narrow it. */
	if (option_take_uint32(options, "lifetime", &transaction->lifetime, &bad))
	{
		if (transaction->lifetime == 0)
			return FALSE;
	}
	else if (bad)
	{
		return FALSE;
	}
	else
	{
		transaction->lifetime = 300;
	}

	transaction->lifetime = MIN(transaction->lifetime, 3600u);

	transaction->may_sign = TRUE;
	policy = option_take_vardict(options, "operation_policy", &bad);
	if (bad)
		return FALSE;

	if (policy != NULL)
	{
		g_autoptr(GVariant) sign = NULL;

		if (!vardict_keys_known(policy, policy_keys))
			return FALSE;

		sign = g_variant_lookup_value(policy, "sign", NULL);

		if (sign != NULL)
		{
			if (!g_variant_is_of_type(sign, G_VARIANT_TYPE_BOOLEAN))
				return FALSE;
			transaction->may_sign = g_variant_get_boolean(sign);
		}
	}

	return TRUE;
}

static gboolean handle_acquire_credential(XdpImplExperimentalCertificate1* object,
                                          GDBusMethodInvocation* invocation,
                                          const char* arg_handle, const char* arg_session_handle,
                                          const char* arg_app_id, const char* arg_parent_window,
                                          GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	Transaction* transaction = NULL;
	CertificateImplSession* session = NULL;
	const char* text = NULL;
	const char* code = NULL;
	g_autoptr(GError) error = NULL;
	CertificatePurpose purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH;

	if (reject_stranger(impl, invocation))
		return TRUE;

	session = lookup_session(impl, arg_session_handle, arg_app_id, &code);
	if (session == NULL)
	{
		answer_early(object, invocation, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		             error_results(code));
		return TRUE;
	}

	if (!g_variant_lookup(arg_options, "purpose", "&s", &text) ||
	    !certificate_purpose_parse(text, &purpose))
	{
		answer_early(object, invocation, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		             error_results("invalid_purpose"));
		return TRUE;
	}

	transaction = g_new0(Transaction, 1);
	transaction->impl = impl;
	transaction->object = object;
	transaction->invocation = invocation;
	/* Hold a reference because frontend loss can clear the session table while the chooser is open. */
	transaction->session = g_object_ref(session);
	transaction->purpose = purpose;
	transaction->parent_window = g_strdup(arg_parent_window);
	transaction->caller.app_id = g_strdup(arg_app_id);

	if (!parse_acquire_options(transaction, arg_options, &code))
	{
		certificate_log_debug(CERTIFICATE_REASON_OPERATION_REFUSED, "malformed-options");
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results(code));
		return TRUE;
	}

	/* A session's identity level may fall but must never rise. */
	if (session->identity_seen && transaction->caller.level < session->identity_level)
	{
		certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, arg_app_id,
		                         certificate_identity_level_to_string(transaction->caller.level),
		                         "identity-level-raised", FALSE);
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("no_such_session"));
		return TRUE;
	}

	session->identity_level = transaction->caller.level;
	session->identity_seen = TRUE;

	transaction->caller.app_display_name = certificate_app_display_name(arg_app_id);

	if (!certificate_filter_parse(arg_options, purpose,
	                              transaction->may_sign ? CERTIFICATE_OPERATION_SIGN : 0,
	                              &transaction->filter, &error))
	{
		certificate_log_debug(CERTIFICATE_REASON_OPERATION_REFUSED, "malformed-filter");
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_filter"));
		return TRUE;
	}

	transaction->request = certificate_impl_request_new(
	    g_dbus_method_invocation_get_sender(invocation), arg_app_id, arg_handle);
	transaction->close_id = g_signal_connect(transaction->request, "handle-close",
	                                         G_CALLBACK(on_request_close), transaction);

	if (!certificate_impl_request_export(transaction->request, impl->connection, &error))
	{
		g_warning("Request export failed: %s", error->message);
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_request"));
		return TRUE;
	}

	transaction_register(transaction);

	certificate_log_decision(CERTIFICATE_REASON_DISCOVERY_STARTED, arg_app_id,
	                         certificate_identity_level_to_string(transaction->caller.level),
	                         certificate_purpose_to_string(purpose), FALSE);

	certificate_tokens_enumerate_async(impl->tokens,
	                                   certificate_impl_request_get_cancellable(
	                                       transaction->request),
	                                   on_enumerated, transaction);

	return TRUE;
}

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

		if (respond_if_owner_gone(transaction, TRANSACTION_OPERATION))
			return;

		/* Request cancellation takes precedence even if the token operation succeeds. */
		if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_CANCELLED) ||
		    g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
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
	g_variant_builder_add(&builder, "{sv}", "signature",
	                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, size, 1));

	transaction_respond(transaction, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_SUCCESS,
	                    g_variant_builder_end(&builder));
}

static gboolean handle_key_operation(CertificateImpl* impl,
                                     XdpImplExperimentalCertificate1* object,
                                     GDBusMethodInvocation* invocation, const char* arg_handle,
                                     const char* arg_session_handle, const char* arg_app_id,
                                     const char* arg_parent_window, GVariant* arg_options)
{
	Transaction* transaction = NULL;
	CertificateImplSession* session = NULL;
	const char* code = NULL;
	g_autofree char* mechanism = NULL;
	g_autofree char* operation_id = NULL;
	g_autoptr(GVariant) parameters = NULL;
	g_autoptr(GVariant) payload = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(GError) error = NULL;
	g_autofree char* caller_display = NULL;
	gboolean bad = FALSE;
	gsize size = 0;
	gconstpointer bytes = NULL;

	if (reject_stranger(impl, invocation))
		return TRUE;

	session = lookup_session(impl, arg_session_handle, arg_app_id, &code);
	if (session == NULL)
	{
		answer_early(object, invocation, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_OTHER,
		             error_results(code));
		return TRUE;
	}

	transaction = g_new0(Transaction, 1);
	transaction->impl = impl;
	transaction->object = object;
	transaction->invocation = invocation;
	transaction->session = g_object_ref(session);
	transaction->parent_window = g_strdup(arg_parent_window);

	option_take_string(arg_options, "operation_id", &operation_id, &bad);
	if (!option_take_string(arg_options, "mechanism", &mechanism, &bad) || bad)
	{
		transaction_respond(transaction, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_request"));
		return TRUE;
	}

	parameters = option_take_vardict(arg_options, "parameters", &bad);
	if (bad)
	{
		transaction_respond(transaction, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_request"));
		return TRUE;
	}

	payload = g_variant_lookup_value(arg_options, "data", G_VARIANT_TYPE_BYTESTRING);

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

	if (!certificate_impl_request_export(transaction->request, impl->connection, &error))
	{
		g_warning("Request export failed: %s", error->message);
		transaction_respond(transaction, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_request"));
		return TRUE;
	}

	transaction_register(transaction);

	caller_display = certificate_app_display_name(arg_app_id);

	certificate_broker_perform(
	    impl->tokens, session, FALSE, operation_id, mechanism, parameters, data, arg_parent_window,
	    caller_display != NULL ? caller_display : arg_app_id,
	    certificate_impl_request_get_cancellable(transaction->request), on_operation_done,
	    transaction);

	return TRUE;
}

static gboolean handle_sign(XdpImplExperimentalCertificate1* object,
                            GDBusMethodInvocation* invocation, const char* arg_handle,
                            const char* arg_session_handle, const char* arg_app_id,
                            const char* arg_parent_window, GVariant* arg_options,
                            gpointer user_data)
{
	return handle_key_operation(user_data, object, invocation, arg_handle, arg_session_handle,
	                            arg_app_id, arg_parent_window, arg_options);
}

typedef struct
{
	CertificateTokens* tokens;
	GStrv mechanisms;
	gboolean protected_path;
} CapabilitiesQuery;

static void capabilities_query_free(gpointer data)
{
	CapabilitiesQuery* query = data;

	g_strfreev(query->mechanisms);
	g_free(query);
}

/* Capability enumeration calls PKCS#11 and must run off the main thread. */
static void capabilities_thread(GTask* task, gpointer source, gpointer task_data,
                                GCancellable* cancellable)
{
	CapabilitiesQuery* query = task_data;

	certificate_tokens_capabilities(query->tokens, &query->mechanisms, &query->protected_path);
	g_task_return_boolean(task, TRUE);
}

static void on_capabilities(GObject* source, GAsyncResult* result, gpointer user_data)
{
	g_autoptr(GDBusMethodInvocation) invocation = user_data;
	CapabilitiesQuery* query = g_task_get_task_data(G_TASK(result));
	GVariantBuilder builder;
	static const char* const purposes[] = { "client_auth", "signing", "email", "ssh", NULL };
	/* The wire interface exposes Sign only; see docs/IMPL-INTERFACE.md. */
	static const char* const operations[] = { "sign", NULL };

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "purposes", g_variant_new_strv(purposes, -1));
	g_variant_builder_add(&builder, "{sv}", "operations", g_variant_new_strv(operations, -1));
	g_variant_builder_add(&builder, "{sv}", "mechanisms",
	                      g_variant_new_strv((const char* const*) query->mechanisms, -1));
	g_variant_builder_add(&builder, "{sv}", "protected_authentication_path",
	                      g_variant_new_boolean(query->protected_path));
	g_variant_builder_add(&builder, "{sv}", "has_display",
	                      g_variant_new_boolean(certificate_ui_has_display()));

	g_dbus_method_invocation_return_value(invocation,
	                                      g_variant_new("(@a{sv})",
	                                                    g_variant_builder_end(&builder)));
}

static gboolean handle_get_capabilities(XdpImplExperimentalCertificate1* object,
                                        GDBusMethodInvocation* invocation, const char* arg_app_id,
                                        GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	g_autoptr(GTask) task = NULL;
	CapabilitiesQuery* query = NULL;

	if (reject_stranger(impl, invocation))
		return TRUE;

	/* Capabilities disclose supported mechanisms without identifying present cards. */
	query = g_new0(CapabilitiesQuery, 1);
	query->tokens = impl->tokens;

	task = g_task_new(NULL, NULL, on_capabilities, g_object_ref(invocation));
	g_task_set_task_data(task, query, capabilities_query_free);
	g_task_run_in_thread(task, capabilities_thread);

	return TRUE;
}

/* Token presence is private; grant holders receive only SessionInvalidated. */
static void on_token_event(CertificateToken* token, gboolean added, gpointer user_data)
{
	CertificateImpl* impl = user_data;

	certificate_log_counts(added ? CERTIFICATE_REASON_DISCOVERY_RESULT
	                             : CERTIFICATE_REASON_TOKEN_REMOVED,
	                       1, 0);

	if (added)
		return;

	{
		GHashTableIter iter;
		gpointer value = NULL;
		/* Hold references because invalidation signal handlers can remove other sessions from the table. */
		g_autoptr(GPtrArray) doomed = g_ptr_array_new_with_free_func(g_object_unref);

		g_hash_table_iter_init(&iter, impl->sessions);
		while (g_hash_table_iter_next(&iter, NULL, &value))
		{
			CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(value);

			if (session->candidate != NULL &&
			    certificate_token_same(session->candidate->token, token))
				g_ptr_array_add(doomed, g_object_ref(session));
		}

		/* Keep invalidated sessions exported until the frontend answers with Session.Close(). */
		for (guint i = 0; i < doomed->len; i++)
			certificate_impl_session_invalidate(g_ptr_array_index(doomed, i), "token_removed");
	}
}

static void on_session_invalidated(CertificateImplSession* session, const char* reason,
                                   gpointer user_data)
{
	CertificateImpl* impl = user_data;

	xdp_impl_experimental_certificate1_emit_session_invalidated(impl->skeleton, session->id,
	                                                            reason);
}

CertificateImpl* certificate_impl_new(GDBusConnection* connection, CertificateTokens* tokens,
                                      GError** error)
{
	CertificateImpl* impl = g_new0(CertificateImpl, 1);

	impl->connection = g_object_ref(connection);
	impl->tokens = tokens;
	impl->sessions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_object_unref);
	impl->transactions = g_ptr_array_new();
	impl->skeleton = XDP_IMPL_EXPERIMENTAL_CERTIFICATE1(
	    xdp_impl_experimental_certificate1_skeleton_new());

	xdp_impl_experimental_certificate1_set_version(impl->skeleton,
	                                               CERTIFICATE_IMPL_INTERFACE_VERSION);

	g_signal_connect(impl->skeleton, "handle-create-session", G_CALLBACK(handle_create_session),
	                 impl);
	g_signal_connect(impl->skeleton, "handle-acquire-credential",
	                 G_CALLBACK(handle_acquire_credential), impl);
	g_signal_connect(impl->skeleton, "handle-sign", G_CALLBACK(handle_sign), impl);
	g_signal_connect(impl->skeleton, "handle-get-capabilities",
	                 G_CALLBACK(handle_get_capabilities), impl);

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(impl->skeleton), connection,
	                                      CERTIFICATE_IMPL_OBJECT_PATH, error))
	{
		certificate_impl_free(impl);
		return NULL;
	}

	certificate_impl_singleton = impl;

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

	g_hash_table_iter_init(&iter, impl->sessions);
	while (g_hash_table_iter_next(&iter, NULL, &value))
		certificate_impl_session_invalidate(CERTIFICATE_IMPL_SESSION(value), "backend_gone");

	close_and_forget_all(impl, NULL);

	cancel_transactions(impl, NULL, "backend_gone");

	certificate_tokens_stop_watch(impl->tokens);

	/* Bound shutdown's wait for worker logouts so an unresponsive reader cannot prevent exit. */
	certificate_impl_session_drain_releases(2000);
}

void certificate_impl_free(CertificateImpl* impl)
{
	if (impl == NULL)
		return;

	if (impl->frontend_watch != 0)
		g_bus_unwatch_name(impl->frontend_watch);

	if (certificate_impl_singleton == impl)
		certificate_impl_singleton = NULL;

	g_clear_pointer(&impl->sessions, g_hash_table_unref);
	g_clear_pointer(&impl->transactions, g_ptr_array_unref);
	g_clear_pointer(&impl->frontend_owner, g_free);
	g_clear_object(&impl->skeleton);
	g_clear_object(&impl->connection);
	g_free(impl);
}
