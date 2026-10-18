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
#include "core/chooser.h"
#include "core/pin.h"
#include "core/core.h"
#include "core/adapter.h"
#include "core/ui.h"
#include "core/dispatch-glib.h"
#include "xdp-impl-dbus.h"

static void on_session_invalidated(CertificateImplSession* session, const char* reason,
                                   gpointer user_data);

struct CertificateImpl
{
	GDBusConnection* connection;
	XdpImplExperimentalCertificate1* skeleton;
	XccContext* context;
	guint64 owner_generation;
	gboolean shutdown_complete;

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

	xcc_context_set_owner_generation(impl->context, ++impl->owner_generation);

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
			xcc_session_invalidate(session->core, reason);
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
	GDBusMethodInvocation* invocation;
	CertificateImplRequest* request;
	CertificateImplSession* session;
	XccRequest* core;
	gulong close_id, cancel_id;
	gboolean answered, registered;
	const char* cancelled_code;
	CertificateCallerIdentity caller;
	CertificatePurpose purpose;
	CertificateFilter filter;
	char* parent_window;
	char* activation_token;
	char* reason;
	guint32 lifetime;
	gboolean may_sign, interaction_forbidden;
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
	if (transaction->cancel_id != 0 && transaction->request != NULL)
		g_cancellable_disconnect(certificate_impl_request_get_cancellable(transaction->request),
								 transaction->cancel_id);
	xcc_request_unref(transaction->core);
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

		if (transaction->core != NULL)
		{
			XccCancelReason reason = g_strcmp0(code, "owner_gone") == 0 ? XCC_CANCEL_OWNER_GONE
									 : g_strcmp0(code, "backend_gone") == 0
										 ? XCC_CANCEL_BACKEND_GONE
										 : XCC_CANCEL_SESSION_CLOSED;
			xcc_request_cancel(transaction->core, reason);
		}
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

	if (session == NULL || xcc_session_is_closed(session->core))
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
	if (existing != NULL && !xcc_session_is_closed(existing->core))
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

	session = certificate_impl_session_new_for_context(impl->context, impl->owner_generation,
													   arg_session_handle, arg_app_id);
	if (session == NULL)
	{
		xdp_impl_experimental_certificate1_complete_create_session(
			object, invocation, 2, error_results("no_such_session"));
		return TRUE;
	}
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

static void core_done(XccRequest* request, const XccResult* result, void* data)
{
	Transaction* transaction = data;
	TransactionKind kind =
		result->kind == XCC_RESULT_ACQUIRE ? TRANSACTION_ACQUIRE : TRANSACTION_OPERATION;
	if (transaction->cancelled_code != NULL)
	{
		transaction_respond(transaction, kind, CERTIFICATE_RESPONSE_OTHER,
							error_results(transaction->cancelled_code));
		return;
	}
	if (result->error != XCC_OK)
	{
		GVariant* results = result->error == XCC_ERROR_CANCELLED && kind == TRANSACTION_ACQUIRE
								? empty_results()
								: error_results(xcc_error_wire_name(result->error));
		transaction_respond(transaction, kind, xcc_error_wire_response(result->error), results);
		return;
	}
	if (kind == TRANSACTION_ACQUIRE)
	{
		transaction_respond(transaction, kind, 0,
							certificate_impl_acquire_results(
								(CertificateCandidate*)xcc_candidate_internal(result->candidate),
								result->may_sign));
		return;
	}
	GVariantBuilder builder;
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "signature",
						  g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, result->signature.data,
													result->signature.size, 1));
	transaction_respond(transaction, kind, 0, g_variant_builder_end(&builder));
}
static void request_cancelled(GCancellable* cancellable, void* data)
{
	Transaction* transaction = data;
	xcc_request_cancel(transaction->core, XCC_CANCEL_USER);
}
static void bind_request(Transaction* transaction)
{
	transaction->cancel_id =
		g_cancellable_connect(certificate_impl_request_get_cancellable(transaction->request),
							  G_CALLBACK(request_cancelled), transaction, NULL);
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

static gboolean module_request_handle(const char* handle)
{
	static const char prefix[] = "/org/freedesktop/portal/desktop/request/";
	if (!g_str_has_prefix(handle, prefix))
		return FALSE;
	const char* token = strchr(handle + strlen(prefix), '/');
	return token != NULL && g_str_has_prefix(token + 1, "pkcs11a");
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

	XccPrincipal principal = {impl->owner_generation, arg_app_id, transaction->caller.level, TRUE};
	XccErrorCode identity_error = xcc_session_check_principal(session->core, &principal);
	if (identity_error != XCC_OK)
	{
		transaction_respond(transaction, TRANSACTION_ACQUIRE, 2,
							error_results(xcc_error_wire_name(identity_error)));
		return TRUE;
	}
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

	XccAcquireSpec spec = {
		.struct_size = sizeof(spec),
		.abi_version = XCC_ABI_VERSION,
		.principal = {impl->owner_generation, arg_app_id, transaction->caller.level, TRUE},
		.purpose = purpose,
		.generic_purpose_present = TRUE,
		.generic_purpose = module_request_handle(arg_handle),
		.parent_window = arg_parent_window,
		.activation_token = transaction->activation_token,
		.reason = transaction->reason,
		.lifetime_present = TRUE,
		.lifetime_seconds = transaction->lifetime,
		.sign_present = TRUE,
		.sign = transaction->may_sign,
		.interaction_present = TRUE,
		.interaction_forbidden = transaction->interaction_forbidden,
		.issuers_present = transaction->filter.issuers != NULL,
		.key_usage_present = transaction->filter.key_usage != NULL,
		.key_usage = (const char* const*)transaction->filter.key_usage,
		.eku_oids_present = transaction->filter.eku_oids != NULL,
		.eku_oids = (const char* const*)transaction->filter.eku_oids,
		.key_algorithms_present = transaction->filter.key_algorithms != NULL,
		.key_algorithms = (const char* const*)transaction->filter.key_algorithms,
		.token_label_present = transaction->filter.token_label != NULL,
		.token_label = transaction->filter.token_label,
		.piv_slot_present = transaction->filter.piv_slot != NULL,
		.piv_slot = transaction->filter.piv_slot};
	g_autofree XccBytes* issuers = NULL;
	if (spec.issuers_present)
	{
		spec.n_issuers = transaction->filter.issuers->len;
		issuers = g_new0(XccBytes, spec.n_issuers);
		for (guint i = 0; i < spec.n_issuers; i++)
			issuers[i].data = g_bytes_get_data(g_ptr_array_index(transaction->filter.issuers, i),
											   &issuers[i].size);
		spec.issuers = issuers;
	}
	transaction->core = xcc_acquire_async(session->core, &spec, core_done, transaction);
	bind_request(transaction);

	return TRUE;
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

	XccSignSpec spec = {
		.struct_size = sizeof(spec),
		.abi_version = XCC_ABI_VERSION,
		.principal = {impl->owner_generation, arg_app_id, CERTIFICATE_IDENTITY_UNKNOWN, FALSE},
		.parent_window = arg_parent_window,
		.operation_id = operation_id,
		.mechanism = mechanism,
		.data = {bytes, size}};
	g_autofree char* hash = NULL;
	g_autofree char* mgf = NULL;
	g_autofree char* encoding = NULL;
	static const char* const keys[] = {"hash", "mgf", "salt_length", "signature_encoding", NULL};
	if (parameters != NULL)
	{
		if (!vardict_keys_known(parameters, keys))
			bad = TRUE;
		spec.hash_present = option_take_string(parameters, "hash", &hash, &bad);
		spec.hash = hash;
		if (g_strcmp0(mechanism, "RSA_PSS") == 0)
		{
			spec.mgf_present = option_take_string(parameters, "mgf", &mgf, &bad);
			spec.mgf = mgf;
		}
		spec.encoding_present =
			option_take_string(parameters, "signature_encoding", &encoding, &bad);
		spec.signature_encoding = encoding;
		if (g_strcmp0(mechanism, "RSA_PSS") == 0)
			spec.salt_length_present =
				option_take_uint32(parameters, "salt_length", &spec.salt_length, &bad);
	}
	transaction->core = xcc_sign_async_parsed(session->core, &spec, !bad, core_done, transaction);
	bind_request(transaction);

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

static void on_capabilities(XccRequest* request, const XccResult* result, void* user_data)
{
	g_autoptr(GDBusMethodInvocation) invocation = user_data;
	GVariantBuilder builder;
	static const char* const purposes[] = { "client_auth", "signing", "email", "ssh", NULL };
	/* The wire interface exposes Sign only; see docs/IMPL-INTERFACE.md. */
	static const char* const operations[] = { "sign", NULL };

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "purposes", g_variant_new_strv(purposes, -1));
	g_variant_builder_add(&builder, "{sv}", "operations", g_variant_new_strv(operations, -1));
	g_variant_builder_add(&builder, "{sv}", "mechanisms",
						  g_variant_new_strv((const char* const*)result->mechanisms, -1));
	g_variant_builder_add(&builder, "{sv}", "protected_authentication_path",
						  g_variant_new_boolean(result->protected_path));
	g_variant_builder_add(&builder, "{sv}", "has_display",
						  g_variant_new_boolean(result->has_display));

	g_dbus_method_invocation_return_value(invocation,
	                                      g_variant_new("(@a{sv})",
	                                                    g_variant_builder_end(&builder)));
}

static gboolean handle_get_capabilities(XdpImplExperimentalCertificate1* object,
                                        GDBusMethodInvocation* invocation, const char* arg_app_id,
                                        GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;

	if (reject_stranger(impl, invocation))
		return TRUE;

	XccRequest* request =
		xcc_get_capabilities_async(impl->context, on_capabilities, g_object_ref(invocation));
	xcc_request_unref(request);

	return TRUE;
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
	XccConfig config = {.struct_size = sizeof(config),
						.abi_version = XCC_ABI_VERSION,
						.tokens = tokens,
						.has_display = certificate_ui_has_display()};
	XccDispatch dispatch = xcc_dispatch_glib(g_main_context_get_thread_default());
	XccError core_error;
	impl->context = xcc_context_new(&config, NULL, &dispatch, &core_error);
	if (impl->context == NULL)
	{
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Core initialization failed");
		g_clear_object(&impl->connection);
		g_free(impl);
		return NULL;
	}
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


	g_debug("providing %s", CERTIFICATE_IMPL_INTERFACE);

	return impl;
}

static void shutdown_done(XccContext* context, void* user)
{
	CertificateImpl* impl = user;
	impl->shutdown_complete = TRUE;
}
void certificate_impl_shutdown(CertificateImpl* impl)
{
	if (impl == NULL || impl->shutdown_complete)
		return;
	xcc_context_shutdown_async(impl->context, shutdown_done, impl);
	/* Drain UI deliveries and workers before releasing the receiver or borrowed modules. */
	while (!impl->shutdown_complete)
		g_main_context_iteration(NULL, TRUE);
	close_and_forget_all(impl, NULL);
}

void certificate_impl_free(CertificateImpl* impl)
{
	if (impl == NULL)
		return;

	certificate_impl_shutdown(impl);

	if (impl->frontend_watch != 0)
		g_bus_unwatch_name(impl->frontend_watch);

	if (certificate_impl_singleton == impl)
		certificate_impl_singleton = NULL;

	g_clear_pointer(&impl->sessions, g_hash_table_unref);
	g_clear_pointer(&impl->transactions, g_ptr_array_unref);
	g_clear_pointer(&impl->frontend_owner, g_free);
	g_clear_object(&impl->skeleton);
	g_clear_object(&impl->connection);
	xcc_context_unref(impl->context);
	g_free(impl);
}
