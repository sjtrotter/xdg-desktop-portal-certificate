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
	XdpImplExperimentalCertificate* skeleton;
	CertificateTokens* tokens;

	/* The unique name that currently owns org.freedesktop.portal.Desktop. NULL
	 * when nothing does, in which case every method is refused: with no
	 * frontend on the bus there is nobody who may legitimately call.
	 *
	 * IT IS A CACHE THAT MAY ONLY SAY NO. See
	 * certificate_impl_sender_is_frontend(). */
	char* frontend_owner;
	gboolean owner_resolved;
	guint frontend_watch;

	/* Every AcquireCredential, Sign and Decrypt that has a window or a worker
	 * still running. Borrowed pointers: a transaction removes itself when it
	 * answers, which is the only way one is destroyed. The list exists so that
	 * the frontend going away can take the windows down with it. */
	GPtrArray* transactions;

	GHashTable* sessions; /* char *object_path -> CertificateImplSession* (owned) */
};

/* ONE BACKEND PER PROCESS. The Request and Session skeletons are exported by
 * this object but are separate GObjects with their own default handlers, and
 * those handlers have to be able to ask the same question every Certificate
 * method asks: is this sender the frontend? Threading a CertificateImpl*
 * through two generated interfaces buys nothing over saying out loud that there
 * is exactly one of these. */
static CertificateImpl* certificate_impl_singleton = NULL;

/* ------------------------------------------------------------ peer identity */

static void invalidate_foreign_sessions(CertificateImpl* impl, const char* owner);
static void cancel_transactions(CertificateImpl* impl, CertificateImplSession* session,
                                const char* code);

static void set_frontend_owner(CertificateImpl* impl, const char* owner)
{
	if (g_strcmp0(impl->frontend_owner, owner) == 0)
		return;

	/* THE OLD OWNER'S SESSIONS GO FIRST. A grant belongs to the frontend
	 * connection that created it; a replacement portal is a different process
	 * with different callers, and it must not inherit a logged-in card session
	 * it never asked for. */
	invalidate_foreign_sessions(impl, owner);

	g_free(impl->frontend_owner);
	impl->frontend_owner = g_strdup(owner);

	certificate_log_debug(owner != NULL ? CERTIFICATE_REASON_IDENTITY_RESOLVED
	                                    : CERTIFICATE_REASON_IDENTITY_UNVERIFIED,
	                      owner != NULL ? "frontend-present" : "frontend-gone");
}

/* THE WATCHER IS FOR CLEANUP; THE BUS IS THE AUTHORITY. D-Bus does not order
 * NameOwnerChanged against the messages of the process that lost the name, so a
 * cached owner alone would accept calls from a former frontend that is still
 * connected.
 *
 * WHAT THIS STILL DOES NOT PROVIDE: the answer is a snapshot. A name can change
 * hands between the check and the work the call authorises, exactly as it can
 * for every other check-then-use on a bus. A deployment that wants more can
 * deny this backend's name to everything but the portal's uid in D-Bus policy;
 * see docs/IMPL-INTERFACE.md. */
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

	/* NameHasNoOwner, or a bus that did not answer: nobody may call. Failing
	 * closed is the only safe direction here. */
	if (reply != NULL)
		g_variant_get(reply, "(&s)", &owner);

	set_frontend_owner(impl, owner);

	return impl->frontend_owner;
}

/* A NEGATIVE MAY COME OUT OF THE CACHE. A POSITIVE MAY NOT.
 *
 * The asymmetry is the whole of the rule, and both halves are load-bearing:
 *
 *   ACCEPTING a sender is a decision that hands it AcquireCredential and Sign
 *   with an app id and an identity level of its choosing, so it is never made
 *   from a remembered answer. Every accept asks the bus who owns the name now.
 *
 *   REFUSING one is free and cannot be wrong in a dangerous direction, so it is
 *   made from the cached owner with no bus call at all. That matters because
 *   anything on the session bus can send this backend a message: a
 *   GetNameOwner round trip per stranger's message, on the main thread, IS the
 *   denial of service -- an open PIN window stops accepting input for the
 *   duration. A stranger's unique name cannot be the cached owner's (the bus
 *   assigns unique names and never reuses one), so a stranger never reaches the
 *   bus call at all.
 *
 * The cost of the asymmetry is one refused call at the moment a replacement
 * portal takes the name over before this process has processed
 * NameOwnerChanged. The frontend retries; the alternative is a bus call per
 * hostile message, which is worse. */
gboolean certificate_impl_sender_is_frontend(CertificateImpl* impl, const char* sender)
{
	if (impl == NULL || sender == NULL)
		return FALSE;

	/* Nothing has ever been resolved -- the watcher's first callback has not
	 * arrived yet -- so there is no cache to refuse from. */
	if (!impl->owner_resolved)
		resolve_frontend_owner(impl);

	if (impl->frontend_owner == NULL || g_strcmp0(sender, impl->frontend_owner) != 0)
		return FALSE;

	/* The cache says yes, which is exactly when it may not be believed. */
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

	/* Logged by reason code and never explained to the caller: a caller that is
	 * not the portal has no business learning why. */
	certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL, NULL, FALSE);

	g_dbus_method_invocation_return_error_literal(
	    invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
	    "Only xdg-desktop-portal may call this interface");

	return TRUE;
}

/* @reason is what to tell the bus on the way, or NULL to close silently.
 * Silence is right in exactly one case: the frontend has left the bus, so
 * there is nobody to tell and emitting is a message into a socket whose
 * listener is gone. */
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

/* Every session that was created by somebody other than @owner. With one
 * frontend on the bus that is "all of them" whenever the name changes hands,
 * which is the point: a grant does not survive the process it was made for. */
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
		/* Windows first: the transaction answers with owner_gone, and only then
		 * does the session it names go away. */
		cancel_transactions(impl, session, "owner_gone");
		/* owner_gone, not silence. The connection that created this grant no
		 * longer owns the portal name, and whoever owns it now is listening:
		 * a successor frontend that is told a session it does not know has
		 * ended learns nothing it can misuse, and one that IS somehow still
		 * tracking it learns the truth. */
		certificate_impl_session_invalidate(session, "owner_gone");
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

	/* The frontend going away takes every grant with it: nothing left on the
	 * bus can legitimately ask for an operation on one, and a logged-in card
	 * session held past that point is a capability nobody can account for. */
	set_frontend_owner(impl, NULL);
	impl->owner_resolved = TRUE;

	/* NULL: the name has no owner, so SessionInvalidated has no reader. The
	 * grants still go, because a logged-in card session held past the death of
	 * the only process allowed to ask for an operation on it is a capability
	 * nobody can account for. */
	close_and_forget_all(impl, NULL);

	/* AND THE WINDOWS GO WITH THEM. set_frontend_owner() above has already
	 * cancelled the transactions of the sessions it invalidated; this catches
	 * any that were left -- and is the belt to that braces, because a chooser
	 * still on screen asking the user to consent on behalf of a process that no
	 * longer exists is the worst thing this backend could leave behind. */
	cancel_transactions(impl, NULL, "owner_gone");
}

void certificate_impl_session_forget(CertificateImplSession* session)
{
	CertificateImpl* impl = certificate_impl_singleton;

	/* A CLOSED SESSION HAS NO WINDOWS. Session.Close() used to leave a chooser
	 * or a PIN prompt for that session on screen: the user could still type a
	 * PIN into it, and was then told the token had been removed, about a card
	 * that was in the reader. The pending call is answered no_such_session,
	 * which is what it now is. */
	if (impl != NULL)
		cancel_transactions(impl, session, "no_such_session");

	certificate_impl_session_unexport(session);

	if (impl == NULL || impl->sessions == NULL || session->id == NULL)
		return;

	if (g_hash_table_lookup(impl->sessions, session->id) == session)
		g_hash_table_remove(impl->sessions, session->id);
}

/* ------------------------------------------------------- option validation */

/* PRESENT WITH THE WRONG TYPE IS AN ERROR, NEVER "ABSENT". Treating a
 * mistyped option as missing is how a filter that should have narrowed the
 * offered set silently stops narrowing it, and how an interaction_mode nobody
 * recognised becomes "prompting is allowed". Defaults apply only to keys that
 * are genuinely not there. */
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

static gboolean option_take_boolean(GVariant* options, const char* key, gboolean* out,
                                    gboolean* bad)
{
	g_autoptr(GVariant) value = g_variant_lookup_value(options, key, NULL);

	if (value == NULL)
		return FALSE;

	if (!g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
	{
		*bad = TRUE;
		return FALSE;
	}

	*out = g_variant_get_boolean(value);
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

/* An unknown key in a SECURITY-RELEVANT nested vardict is refused rather than
 * ignored: operation_policy, certificate_filter and the mechanism parameters
 * all say what a grant may do, and a key nobody understood may have been the
 * one that said "less". Unknown keys at the TOP LEVEL are still ignored,
 * because that is where the frontend adds fields and a backend that refused
 * them could not be upgraded past. */
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

/* ------------------------------------------------------------- per-request */

typedef struct
{
	CertificateImpl* impl;
	XdpImplExperimentalCertificate* object;
	GDBusMethodInvocation* invocation; /* borrowed until completed */
	CertificateImplRequest* request;
	CertificateImplSession* session; /* a reference of our own */
	gulong close_id;
	gboolean answered;
	gboolean registered;

	/* Why this transaction was cancelled, when it was not the user: a static
	 * string from the interface's diagnostic vocabulary, or NULL for an
	 * ordinary Close()/Escape. It decides whether the pending call is answered
	 * 1 ("the user said no", which an application is entitled to act on) or 2
	 * with a code that says what actually happened. */
	const char* cancelled_code;

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
	gboolean allow_selection_memory;
	gboolean offer_selection_memory;
	/* The frontend says this exact consent already exists, for a process this
	 * caller's process descends from. The one request this backend answers
	 * without a window. */
	gboolean delegated;

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
	g_free(transaction->preselect);
	g_free(transaction);
}

/* A TRANSACTION IS TRACKED FOR EXACTLY AS LONG AS IT CAN HAVE A WINDOW UP.
 * Nothing else in this file needs the list; on_frontend_vanished does, because
 * a chooser or a PIN prompt that outlives the process that asked for it is a
 * trusted window with nobody behind it -- the single thing this repository
 * exists to make impossible. */
static void transaction_register(Transaction* transaction)
{
	g_ptr_array_add(transaction->impl->transactions, transaction);
	transaction->registered = TRUE;
}

/* Cancel every live transaction, or every one belonging to @session, and say
 * why. The cancellable is the Request's, which the chooser, the PIN window, the
 * discovery worker and the in-flight operation are all tied to, so one call
 * takes all of them down and each answers its own pending call. */
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

	/* Over a copy: answering a cancelled transaction destroys it, and with it
	 * its entry in impl->transactions. */
	for (guint i = 0; i < doomed->len; i++)
	{
		Transaction* transaction = g_ptr_array_index(doomed, i);

		transaction->cancelled_code = code;

		if (transaction->request != NULL)
			g_cancellable_cancel(certificate_impl_request_get_cancellable(transaction->request));
	}
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

/* Answer a method that has no transaction yet. */
static void answer_early(XdpImplExperimentalCertificate* object,
                         GDBusMethodInvocation* invocation, TransactionKind kind,
                         gboolean decrypt, guint32 response, GVariant* results)
{
	switch (kind)
	{
		case TRANSACTION_CREATE_SESSION:
			xdp_impl_experimental_certificate_complete_create_session(object, invocation,
			                                                          response, results);
			return;
		case TRANSACTION_ACQUIRE:
			xdp_impl_experimental_certificate_complete_acquire_credential(object, invocation,
			                                                              response, results);
			return;
		default:
			if (decrypt)
				xdp_impl_experimental_certificate_complete_decrypt(object, invocation, response,
				                                                   results);
			else
				xdp_impl_experimental_certificate_complete_sign(object, invocation, response,
				                                               results);
			return;
	}
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
	/* AUTHORISED BEFORE IT IS LOGGED, even though this handler decides nothing:
	 * signal emission reaches here before the class closure that refuses a
	 * stranger, so logging unconditionally let anything on the bus write
	 * "close-from-frontend" into the journal by calling a Close() it was then
	 * denied. A line in an audit trail that says the frontend did something the
	 * frontend did not do is worth less than no line. */
	if (!certificate_impl_sender_is_frontend_default(
	        g_dbus_method_invocation_get_sender(invocation)))
		return FALSE;

	certificate_log_debug(CERTIFICATE_REASON_CHOOSER_CANCELLED, "close-from-frontend");
	return FALSE;
}

/* The session a call names, with every check that is this backend's to make.
 * Returns NULL and the error code to answer with. */
static CertificateImplSession* lookup_session(CertificateImpl* impl, const char* session_handle,
                                              const char* app_id, const char** code)
{
	CertificateImplSession* session = g_hash_table_lookup(impl->sessions, session_handle);

	*code = "no_such_session";

	if (session == NULL || session->closed)
		return NULL;

	/* THE SESSION IS BOUND TO ITS APP ID. The frontend enforces this too, and
	 * that is the point: it is the check this backend can make for free, and a
	 * frontend regression or a second frontend implementation would otherwise
	 * turn a session handle into cross-application key use. */
	if (g_strcmp0(session->app_id, app_id) != 0)
	{
		certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, app_id, NULL,
		                         "app-id-mismatch", FALSE);
		return NULL;
	}

	return session;
}

/* ------------------------------------------------------------ CreateSession */

static gboolean handle_create_session(XdpImplExperimentalCertificate* object,
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
		/* A live session at this path already. Refusing is right; refusing a
		 * CLOSED one was not -- see below. */
		xdp_impl_experimental_certificate_complete_create_session(
		    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("invalid_request"));
		return TRUE;
	}

	/* THE PATH IS REUSED, SO THE TABLE ENTRY MUST BE. The frontend builds a
	 * session path out of the caller's unique name and its session_handle_token,
	 * and applications pass a fixed token: the same application asking a second
	 * time gets the identical path. A closed entry left in the table made every
	 * later CreateSession from that application fail for the life of the
	 * process. */
	if (existing != NULL)
	{
		certificate_impl_session_close(existing);
		certificate_impl_session_unexport(existing);
		g_hash_table_remove(impl->sessions, arg_session_handle);
	}

	/* The Request is exported and immediately taken down again: CreateSession
	 * shows no window, so there is nothing for a Close() to interrupt, but the
	 * object has to exist at the handle path for the moment the frontend could
	 * look for it. */
	{
		g_autoptr(CertificateImplRequest) request = certificate_impl_request_new(
		    g_dbus_method_invocation_get_sender(invocation), arg_app_id, arg_handle);

		if (!certificate_impl_request_export(request, impl->connection, &error))
		{
			g_warning("Could not export the request object: %s", error->message);
			xdp_impl_experimental_certificate_complete_create_session(
			    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("invalid_request"));
			return TRUE;
		}

		certificate_impl_request_unexport(request);
	}

	session = certificate_impl_session_new(arg_session_handle, arg_app_id);
	session->owner = g_strdup(g_dbus_method_invocation_get_sender(invocation));

	if (!certificate_impl_session_export(session, impl->connection, &error))
	{
		/* NOT INSERTED. A session that is not on the bus is one the frontend
		 * can never close, and one this backend would hold a card session for
		 * with nobody able to end it. */
		g_warning("Could not export the session object: %s", error->message);
		g_object_unref(session);
		xdp_impl_experimental_certificate_complete_create_session(
		    object, invocation, CERTIFICATE_RESPONSE_OTHER, error_results("invalid_request"));
		return TRUE;
	}

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

/* WHAT GOES ON THE SIGNALS IS PRESENCE, NOT IDENTITY. TokenAdded and
 * TokenRemoved are re-emitted by the frontend on its own public interface, to
 * every client on the bus, before anybody has consented to anything. A PIV
 * card's label is routinely the cardholder's name or an issuing agency, which
 * is exactly the correlation the serial was withheld to prevent -- delivered to
 * a strictly larger audience than a grant's token_display, which goes only to
 * the application that got the grant.
 *
 * THE TWO KEYS ARE THE WHOLE SIGNAL. The impl interface names token_id (`s`)
 * and protected_authentication_path (`b`) and says every other key is dropped,
 * so nothing else is put here -- not even for a frontend that would discard it,
 * because the next frontend might not.
 *
 * token_id IS NOT DERIVABLE FROM THE CARD, which the interface requires in as
 * many words: a serial, or a hash of one another party can recompute, is a
 * correlation handle across every application on the bus. It is a SHA-256 over
 * a salt this process generates at startup and never publishes, so it is stable
 * enough to pair an added token with its removal, stable for as long as the
 * token is present, and useless to anyone trying to recognise the same card in
 * another session or another process. */
GVariant* certificate_impl_token_presence(const CertificateToken* token)
{
	static char* salt = NULL;
	GVariantBuilder builder;
	g_autofree char* identity = NULL;
	g_autofree char* joined = NULL;
	g_autofree char* digest = NULL;

	if (salt == NULL)
		salt = g_uuid_string_random();

	identity = certificate_token_identity(token);
	joined = g_strconcat(salt, "\x1f", identity, NULL);
	digest = g_compute_checksum_for_string(G_CHECKSUM_SHA256, joined, -1);
	digest[32] = '\0';

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "token_id", g_variant_new_string(digest));
	g_variant_builder_add(&builder, "{sv}", "protected_authentication_path",
	                      g_variant_new_boolean(token->protected_authentication_path));

	return g_variant_builder_end(&builder);
}

static GVariant* bytes_to_variant(const GByteArray* bytes)
{
	return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes->data, bytes->len, 1);
}

GVariant* certificate_impl_acquire_results(CertificateCandidate* candidate, gboolean may_sign,
                                           gboolean may_decrypt, gboolean remember)
{
	GVariantBuilder builder;
	GVariantBuilder chain;
	g_auto(GStrv) operations = NULL;
	g_autoptr(GStrvBuilder) operations_builder = g_strv_builder_new();

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add(&builder, "{sv}", "certificate_der", bytes_to_variant(candidate->der));

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
	if (may_sign && candidate->can_sign)
		g_strv_builder_add(operations_builder, "sign");
	if (may_decrypt && candidate->can_decrypt)
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

	return g_variant_builder_end(&builder);
}

static void finish_acquire(Transaction* transaction, CertificateCandidate* candidate,
                           gboolean remember)
{
	CertificateImplSession* session = transaction->session;

	/* RE-CHECKED AFTER THE WINDOW. The user was looking at the chooser for as
	 * long as they wanted to, and in that time the frontend could have
	 * vanished, the session could have been closed, or the card could have been
	 * pulled. */
	if (session == NULL || session->closed)
	{
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("no_such_session"));
		return;
	}

	/* A TOKEN WITH NO SERIAL CANNOT BE RE-RESOLVED. Grants are re-bound to a
	 * token by its stable attributes, and a serial-less observation is
	 * deliberately never considered the same token twice -- so a grant on one
	 * would fail at the first Sign, after the user had already consented and
	 * typed a PIN. Say so now instead. */
	if (candidate->token->serial == NULL || *candidate->token->serial == '\0')
	{
		certificate_log_grant(CERTIFICATE_REASON_OPERATION_REFUSED, session->id,
		                      "token-without-serial");
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("device_error"));
		return;
	}

	certificate_impl_session_grant(session, candidate, transaction->purpose,
	                               transaction->may_sign && candidate->can_sign,
	                               transaction->may_decrypt && candidate->can_decrypt,
	                               transaction->lifetime);

	/* WHICH LINE SAYS A GRANT EXISTS SAYS HOW IT WAS MADE. A delegated grant
	 * had no window, so counting grant-created lines counts the windows the
	 * user actually answered. */
	certificate_log_decision(transaction->delegated ? CERTIFICATE_REASON_GRANT_DELEGATED
	                                                : CERTIFICATE_REASON_GRANT_CREATED,
	                         transaction->caller.app_id,
	                         certificate_identity_level_to_string(transaction->caller.level),
	                         certificate_purpose_to_string(transaction->purpose), TRUE);

	transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_SUCCESS,
	                    certificate_impl_acquire_results(candidate,
	                                                     transaction->may_sign,
	                                                     transaction->may_decrypt, remember));
}

/* A CANCELLATION THAT THE USER DID NOT ASK FOR IS NOT A CANCELLATION. When the
 * frontend leaves the bus this backend cancels every window it has up, and the
 * pending call has to say which of the two happened: response 1 means "the user
 * said no", and an application is entitled to treat it that way. */
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

	/* Clamped rather than trusted: the window is this backend's own code, but
	 * the answer it produces is reported to the frontend as the user's, and a
	 * true here that the frontend would discard is worse than useless. */
	finish_acquire(transaction, result->chosen,
	               result->remember_selection && transaction->offer_selection_memory);
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
		/* TWO DIFFERENT DIAGNOSES, and the user needs to know which: insert a
		 * card, or talk to whoever issued the one that is in the reader. */
		const char* code = candidates->len == 0 ? "no_token" : "no_matching_certificate";

		certificate_log_counts(CERTIFICATE_REASON_NO_MATCHING_CERT, candidates->len, 0);
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results(code));
		return;
	}

	/* NO WINDOW, BY THE FRONTEND'S ACCOUNT OF A CONSENT THAT ALREADY EXISTS:
	 * the same certificate, the same purpose, given by the user to a process
	 * this caller's process descends from, which asked for its descendants to
	 * be covered. See docs/IMPL-INTERFACE.md and ADR 0011.
	 *
	 * IT IS A BIND, NOT A CHOICE. If the named certificate is not among the
	 * ones matching this request the answer is a refusal; falling through to
	 * the chooser would ask the user a question the frontend has just said was
	 * already answered, and would do it with no window on screen to explain
	 * why. */
	if (transaction->delegated)
	{
		CertificateCandidate* named = NULL;

		for (guint i = 0; i < matching->len; i++)
		{
			CertificateCandidate* candidate = g_ptr_array_index(matching, i);

			if (g_strcmp0(candidate->certificate_id, transaction->preselect) == 0)
			{
				named = candidate;
				break;
			}
		}

		if (named == NULL)
		{
			certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED,
			                         transaction->caller.app_id, NULL, "delegated-certificate-gone",
			                         FALSE);
			transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
			                    error_results("no_matching_certificate"));
			return;
		}

		finish_acquire(transaction, named, FALSE);
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

static gboolean parse_acquire_options(Transaction* transaction, GVariant* options,
                                      const char** code)
{
	static const char* const policy_keys[] = { "sign", "decrypt", NULL };
	g_autofree char* level = NULL;
	g_autofree char* interaction = NULL;
	g_autoptr(GVariant) policy = NULL;
	gboolean bad = FALSE;

	*code = "invalid_request";

	/* app_id and app_identity_level ARRIVED AS ARGUMENTS. Nothing here derives
	 * either of them, and the display name comes from the desktop file the app
	 * id names, never from anything the caller sent. */
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
	if (!option_take_string(options, "preselect_certificate", &transaction->preselect, &bad) &&
	    bad)
		return FALSE;

	/* THE ONLY KEY THAT SKIPS A WINDOW, so it is parsed strictly and it is
	 * useless on its own: without a certificate to bind, "do not ask" would
	 * mean "choose for the user", which this backend does not do. */
	transaction->delegated = FALSE;
	if (!option_take_boolean(options, "delegated", &transaction->delegated, &bad) && bad)
		return FALSE;

	if (transaction->delegated && transaction->preselect == NULL)
		return FALSE;

	/* ABSENT MEANS NO. The key is the frontend's effective answer, so an older
	 * frontend that does not send it is one whose permission store this
	 * backend cannot reason about, and the safe reading of silence is that
	 * nothing would be stored. Present and not a boolean is a malformed
	 * request, not a default. */
	transaction->allow_selection_memory = FALSE;
	if (!option_take_boolean(options, "allow_selection_memory",
	                         &transaction->allow_selection_memory, &bad) &&
	    bad)
		return FALSE;

	if (option_take_string(options, "interaction_mode", &interaction, &bad))
	{
		/* An unknown interaction_mode used to mean "interactive", which is the
		 * permissive reading of a value nobody recognised. */
		if (g_strcmp0(interaction, "forbidden") == 0)
			transaction->interaction_forbidden = TRUE;
		else if (g_strcmp0(interaction, "required") != 0 && g_strcmp0(interaction, "allowed") != 0)
			return FALSE;
	}
	if (bad)
		return FALSE;

	/* `lifetime` is the frontend's DECISION, not the application's request. The
	 * backend clamps it again anyway: it is the side holding the card. */
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
	transaction->may_decrypt = FALSE;
	policy = option_take_vardict(options, "operation_policy", &bad);
	if (bad)
		return FALSE;

	if (policy != NULL)
	{
		g_autoptr(GVariant) sign = NULL;
		g_autoptr(GVariant) decrypt = NULL;

		if (!vardict_keys_known(policy, policy_keys))
			return FALSE;

		sign = g_variant_lookup_value(policy, "sign", NULL);
		decrypt = g_variant_lookup_value(policy, "decrypt", NULL);

		if (sign != NULL)
		{
			if (!g_variant_is_of_type(sign, G_VARIANT_TYPE_BOOLEAN))
				return FALSE;
			transaction->may_sign = g_variant_get_boolean(sign);
		}

		if (decrypt != NULL)
		{
			if (!g_variant_is_of_type(decrypt, G_VARIANT_TYPE_BOOLEAN))
				return FALSE;
			transaction->may_decrypt = g_variant_get_boolean(decrypt);
		}
	}

	return TRUE;
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
	const char* code = NULL;
	g_autoptr(GError) error = NULL;
	CertificatePurpose purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH;

	if (reject_stranger(impl, invocation))
		return TRUE;

	session = lookup_session(impl, arg_session_handle, arg_app_id, &code);
	if (session == NULL)
	{
		answer_early(object, invocation, TRANSACTION_ACQUIRE, FALSE, CERTIFICATE_RESPONSE_OTHER,
		             error_results(code));
		return TRUE;
	}

	/* THE PURPOSE IS PARSED AGAIN. The frontend validated it and an unknown
	 * purpose never reaches a backend -- but a backend that trusted a string
	 * because "the frontend checked" is a backend that will one day be called
	 * by something else. */
	if (!g_variant_lookup(arg_options, "purpose", "&s", &text) ||
	    !certificate_purpose_parse(text, &purpose))
	{
		answer_early(object, invocation, TRANSACTION_ACQUIRE, FALSE, CERTIFICATE_RESPONSE_OTHER,
		             error_results("invalid_purpose"));
		return TRUE;
	}

	transaction = g_new0(Transaction, 1);
	transaction->impl = impl;
	transaction->object = object;
	transaction->invocation = invocation;
	/* A REFERENCE, NOT A BORROWED POINTER. The chooser is on screen for as long
	 * as the user takes, and the table that owns sessions can be emptied under
	 * it by a frontend that went away. */
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

	/* THE IDENTITY LEVEL MAY FALL BUT NEVER RISE. A session created for a
	 * caller the frontend could not identify does not become a session for a
	 * verified one because a later call on the same handle said so. */
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

	if (!certificate_filter_parse(arg_options,
	                              purpose,
	                              (transaction->may_sign ? CERTIFICATE_OPERATION_SIGN : 0) |
	                                  (transaction->may_decrypt ? CERTIFICATE_OPERATION_DECRYPT
	                                                            : 0),
	                              &transaction->filter, &error))
	{
		certificate_log_debug(CERTIFICATE_REASON_OPERATION_REFUSED, "malformed-filter");
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_filter"));
		return TRUE;
	}

	/* THE CHECKBOX IS ONLY OFFERED WHERE IT CANNOT LIE. allow_selection_memory
	 * is the frontend's effective answer -- the application asked for it AND
	 * the identity level permits it -- and the frontend discards
	 * remember_selection when it is false, so an offer made anyway is a
	 * promise to the user that nothing will keep.
	 *
	 * The identity level is checked again here even though the frontend has
	 * already folded it in. It costs nothing, and this backend does not draw a
	 * "remember this for that application" checkbox on behalf of an
	 * application it cannot name. */
	transaction->offer_selection_memory =
	    transaction->allow_selection_memory &&
	    transaction->caller.level != CERTIFICATE_IDENTITY_UNKNOWN;

	transaction->request = certificate_impl_request_new(
	    g_dbus_method_invocation_get_sender(invocation), arg_app_id, arg_handle);
	transaction->close_id = g_signal_connect(transaction->request, "handle-close",
	                                         G_CALLBACK(on_request_close), transaction);

	if (!certificate_impl_request_export(transaction->request, impl->connection, &error))
	{
		g_warning("Could not export the request object: %s", error->message);
		transaction_respond(transaction, TRANSACTION_ACQUIRE, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_request"));
		return TRUE;
	}

	/* From here it can have a window, so from here the frontend going away has
	 * to be able to take it down. */
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

		if (respond_if_owner_gone(transaction, TRANSACTION_OPERATION))
			return;

		/* A CANCEL IS A CANCEL, not a device failure. The GTask carries the
		 * request's cancellable, so a Close() while the card is signing comes
		 * back as G_IO_ERROR_CANCELLED even when the signature itself
		 * succeeded -- and telling an application that cancelled its own
		 * request that the device failed is a lie it may act on. */
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
	const char* code = NULL;
	g_autofree char* mechanism = NULL;
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
		answer_early(object, invocation, TRANSACTION_OPERATION, decrypt,
		             CERTIFICATE_RESPONSE_OTHER, error_results(code));
		return TRUE;
	}

	transaction = g_new0(Transaction, 1);
	transaction->impl = impl;
	transaction->object = object;
	transaction->invocation = invocation;
	transaction->session = g_object_ref(session);
	transaction->decrypt = decrypt;
	transaction->parent_window = g_strdup(arg_parent_window);

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

	if (!certificate_impl_request_export(transaction->request, impl->connection, &error))
	{
		g_warning("Could not export the request object: %s", error->message);
		transaction_respond(transaction, TRANSACTION_OPERATION, CERTIFICATE_RESPONSE_OTHER,
		                    error_results("invalid_request"));
		return TRUE;
	}

	transaction_register(transaction);

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

/* OFF THE MAIN THREAD, like every other PKCS#11 call in this backend.
 * C_GetSlotList, C_GetTokenInfo and C_GetMechanismList for every slot of every
 * module, under the same lock a card enumeration holds for seconds, used to run
 * straight from the method handler -- so a caller could freeze the chooser, the
 * PIN window and the bus connection by asking what this backend can do in a
 * loop. */
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
	/* BOTH, now that there is an OAEP mechanism to decrypt with. `operations`
	 * says what this backend implements; whether a particular card can do it is
	 * `mechanisms` (RSA_OAEP appears only where a token really has
	 * CKM_RSA_PKCS_OAEP) and, per grant, `permitted_operations`. Advertising
	 * decrypt while refusing every request would have applications build a UI
	 * on a capability that answers invalid_request, which is why it was absent
	 * until the mechanism existed. See docs/IMPL-INTERFACE.md. */
	static const char* const operations[] = { "sign", "decrypt", NULL };

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

static gboolean handle_get_capabilities(XdpImplExperimentalCertificate* object,
                                        GDBusMethodInvocation* invocation, const char* arg_app_id,
                                        GVariant* arg_options, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	g_autoptr(GTask) task = NULL;
	CapabilitiesQuery* query = NULL;

	if (reject_stranger(impl, invocation))
		return TRUE;

	/* NO WINDOW IS SHOWN and nothing is authorised. This is a question about
	 * the backend, asked so that an application can adapt without provoking a
	 * dialog, and the answer discloses nothing about which cards are present:
	 * it is the mechanism vocabulary, not an inventory. */
	query = g_new0(CapabilitiesQuery, 1);
	query->tokens = impl->tokens;

	task = g_task_new(NULL, NULL, on_capabilities, g_object_ref(invocation));
	g_task_set_task_data(task, query, capabilities_query_free);
	g_task_run_in_thread(task, capabilities_thread);

	return TRUE;
}

/* ------------------------------------------------------------ token watching */

static void on_token_event(CertificateToken* token, gboolean added, gpointer user_data)
{
	CertificateImpl* impl = user_data;
	GVariant* presence = certificate_impl_token_presence(token);

	certificate_log_counts(added ? CERTIFICATE_REASON_DISCOVERY_RESULT
	                             : CERTIFICATE_REASON_TOKEN_REMOVED,
	                       1, 0);

	if (added)
	{
		xdp_impl_experimental_certificate_emit_token_added(impl->skeleton, presence);
		return;
	}

	xdp_impl_experimental_certificate_emit_token_removed(impl->skeleton, presence);

	/* A grant whose card has left the reader is over, and the frontend has to
	 * be told rather than letting the application discover it at the next
	 * Sign. */
	{
		GHashTableIter iter;
		gpointer value = NULL;
		/* REFERENCED, like the identical loop in invalidate_foreign_sessions():
		 * invalidating one session runs signal handlers and can close another,
		 * and a list of borrowed pointers into a table that is being modified
		 * is a bug waiting for the first deployment that has two grants on one
		 * card. */
		g_autoptr(GPtrArray) doomed = g_ptr_array_new_with_free_func(g_object_unref);

		g_hash_table_iter_init(&iter, impl->sessions);
		while (g_hash_table_iter_next(&iter, NULL, &value))
		{
			CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(value);

			if (session->candidate != NULL &&
			    certificate_token_same(session->candidate->token, token))
				g_ptr_array_add(doomed, g_object_ref(session));
		}

		/* Invalidated but NOT removed from the table: the frontend answers
		 * SessionInvalidated with Session.Close(), and a session that is gone
		 * by then turns that answer into a D-Bus error. */
		for (guint i = 0; i < doomed->len; i++)
			certificate_impl_session_invalidate(g_ptr_array_index(doomed, i), "token_removed");
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
	impl->transactions = g_ptr_array_new();
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

	certificate_impl_singleton = impl;

	/* WHO MAY CALL. The watcher is what closes grants when the frontend goes
	 * away; the authorisation check itself asks the bus, because
	 * NameOwnerChanged is not ordered against the former owner's messages. */
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
		certificate_impl_session_invalidate(CERTIFICATE_IMPL_SESSION(value), "service_shutdown");

	close_and_forget_all(impl, NULL);

	/* Anything still on screen is asking a question nobody is left to receive
	 * the answer to. */
	cancel_transactions(impl, NULL, "backend_gone");

	certificate_tokens_stop_watch(impl->tokens);

	/* THE ONE PLACE THIS PROCESS BLOCKS ITS MAIN THREAD ON THE CARD, and it is
	 * bounded: the closes above run on workers, and exiting before they have
	 * issued C_Logout would leave the token's login state to the module. Two
	 * seconds is far longer than a logout takes and far shorter than a wedged
	 * reader makes a user wait for a process to quit. */
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
