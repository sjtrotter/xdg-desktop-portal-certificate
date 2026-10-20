/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "context-private.h"
#include "../redact.h"
#include <string.h>
static void finish_acquire(XccRequest* transaction, CertificateCandidate* candidate)
{
	XccSession* session = transaction->session;
	if (g_atomic_int_get(&transaction->cancel_intent) != 0)
	{
		xcc_request_complete(transaction, XCC_ERROR_CANCELLED);
		return;
	}

	/* The session, frontend or token may disappear while the chooser is open. */
	if (session == NULL || xcc_session_is_closed(session))
	{
		xcc_request_complete(transaction, XCC_ERROR_NO_SUCH_SESSION);
		return;
	}

	/* Tokens without serials cannot be rebound reliably at private-key use. */
	if (candidate->token->serial == NULL || *candidate->token->serial == '\0')
	{
		certificate_log_grant(CERTIFICATE_REASON_OPERATION_REFUSED, session->id,
							  "token-without-serial");
		xcc_request_complete(transaction, XCC_ERROR_DEVICE);
		return;
	}

	/* The interface exposes Sign only, so no grant permits decryption. */
	g_atomic_int_set(&session->grant_pending, TRUE);
	xcc_session_grant(session, candidate, transaction->purpose,
					  transaction->may_sign && candidate->can_sign, FALSE, transaction->lifetime);
	session->generic_purpose = transaction->generic_purpose;

	certificate_log_decision(CERTIFICATE_REASON_GRANT_CREATED, transaction->caller.app_id,
							 certificate_identity_level_to_string(transaction->caller.level),
							 certificate_purpose_to_string(transaction->purpose), TRUE);

	transaction->candidate = xcc_candidate_snapshot(candidate);
	transaction->result.may_sign = transaction->may_sign;
	xcc_request_complete(transaction, XCC_OK);
}

void xcc_acquire_rollback(XccRequest* transaction)
{
	XccSession* session = transaction->session;

	/* Operations cannot use this grant before successful desktop delivery. */
	g_assert(g_atomic_int_get(&session->grant_pending));
	if (session->expiry_source != 0)
	{
		xcc_source_remove(session->expiry_source);
		session->expiry_source = 0;
	}
	session->granted = FALSE;
	g_clear_pointer(&session->candidate, certificate_candidate_unref);
	session->purpose = 0;
	session->generic_purpose = FALSE;
	session->may_sign = session->may_decrypt = FALSE;
	session->decrypt_count = session->lifetime = session->expires_at = 0;
	g_atomic_int_set(&session->grant_pending, FALSE);
	g_clear_pointer(&transaction->candidate, xcc_candidate_unref);
}

/* Response 1 is reserved for user cancellation; frontend loss requires a diagnostic failure. */
static gboolean respond_if_owner_gone(XccRequest* transaction)
{
	if (transaction->cancelled_code == XCC_OK)
		return FALSE;

	xcc_request_complete(transaction, transaction->cancelled_code);
	return TRUE;
}

static void on_chooser_done(const CertificateChooserResult* result, gpointer user_data)
{
	XccRequest* transaction = user_data;

	transaction->chooser = NULL;
	/* Record consent before draining so removals can reject its chosen token,
	 * including when no refresh is running. A refresh keeps this state alive. */
	if (!transaction->chooser_completed)
	{
		transaction->chooser_completed = TRUE;
		transaction->pending_error = result->error;
		transaction->pending_chosen =
			result->chosen != NULL ? certificate_candidate_ref(result->chosen) : NULL;
	}
	certificate_tokens_dispatch_pending(transaction->context->tokens);
	/* A refresh worker retains the transaction until its callback has run. */
	if (transaction->enumerating)
		return;

	if (result->error != XCC_OK)
	{
		xcc_request_complete(transaction, result->error);
		return;
	}

	if (respond_if_owner_gone(transaction))
		return;

	if (result->chosen == NULL || g_cancellable_is_cancelled(transaction->cancellable))
	{
		xcc_request_complete(transaction, XCC_ERROR_CANCELLED);
		return;
	}

	finish_acquire(transaction, result->chosen);
}

static void start_enumeration(XccRequest* transaction);

static void on_enumerated(GObject* source, GAsyncResult* result, gpointer user_data)
{
	XccRequest* transaction = user_data;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) candidates = NULL;
	g_autoptr(GPtrArray) matching = NULL;
	CertificateChooserRequest request;
	gboolean tokens_present = FALSE;

	candidates = certificate_tokens_enumerate_finish(NULL, result, &tokens_present, &error);
	/* Keep enumerating set while delivering events: they may request another
	 * snapshot, but must not start a second worker behind this callback. */
	certificate_tokens_dispatch_pending(transaction->context->tokens);
	transaction->enumerating = FALSE;
	if (g_atomic_int_get(&transaction->cancel_intent) != 0 && transaction->chooser == NULL)
	{
		xcc_request_complete(transaction, XCC_ERROR_CANCELLED);
		return;
	}

	if (transaction->chooser_completed)
	{
		CertificateChooserResult completed = {transaction->pending_chosen,
											  transaction->pending_error};

		if (transaction->cancelled_code != XCC_OK || completed.chosen == NULL ||
			g_cancellable_is_cancelled(transaction->cancellable))
		{
			on_chooser_done(&completed, transaction);
			return;
		}
		if (candidates == NULL)
		{
			xcc_request_complete(transaction, XCC_ERROR_DEVICE);
			return;
		}
		if (transaction->enumerate_again)
		{
			start_enumeration(transaction);
			return;
		}
		matching = certificate_filter_apply(candidates, &transaction->filter);
		for (guint i = 0; i < matching->len; i++)
		{
			CertificateCandidate* candidate = g_ptr_array_index(matching, i);

			if (certificate_candidate_same(completed.chosen, candidate))
			{
				completed.chosen = candidate;
				on_chooser_done(&completed, transaction);
				return;
			}
		}
		xcc_request_complete(transaction, XCC_ERROR_TOKEN_REMOVED);
		return;
	}

	if (transaction->chooser != NULL && candidates == NULL)
	{
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			transaction->cancelled_code = XCC_ERROR_DEVICE;
		g_cancellable_cancel(transaction->cancellable);
		return;
	}

	if (candidates == NULL)
	{
		if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		{
			if (respond_if_owner_gone(transaction))
				return;

			xcc_request_complete(transaction, XCC_ERROR_CANCELLED);
			return;
		}

		xcc_request_complete(transaction, XCC_ERROR_DEVICE);
		return;
	}

	if (transaction->interaction_forbidden)
	{
		/* Acquisition always requires a chooser, including a single candidate or remembered
		 * selection. */
		certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, transaction->caller.app_id,
								 NULL, NULL, FALSE);
		xcc_request_complete(transaction, XCC_ERROR_INTERACTION_REQUIRED);
		return;
	}

	if (!certificate_chooser_available())
	{
		xcc_request_complete(transaction, XCC_ERROR_NO_DISPLAY);
		return;
	}

	if (transaction->enumerate_again)
	{
		start_enumeration(transaction);
		return;
	}

	matching = certificate_filter_apply(candidates, &transaction->filter);
	if (matching->len == 0)
		certificate_log_counts(CERTIFICATE_REASON_NO_MATCHING_CERT, candidates->len, 0);

	if (transaction->chooser != NULL)
	{
		certificate_chooser_update(transaction->chooser, matching, tokens_present);
		return;
	}

	memset(&request, 0, sizeof(request));
	request.tokens_present = tokens_present;
	request.caller = &transaction->caller;
	request.purpose = transaction->purpose;
	request.may_sign = transaction->may_sign;
	request.may_decrypt = FALSE;
	request.lifetime_seconds = transaction->lifetime;
	request.reason = transaction->reason;
	request.generic_purpose = transaction->generic_purpose;

	transaction->chooser = certificate_chooser_show(
		transaction->parent_window, transaction->activation_token, matching, &request,
		transaction->cancellable, on_chooser_done, transaction);
}

static void start_enumeration(XccRequest* transaction)
{
	transaction->enumerating = TRUE;
	transaction->enumerate_again = FALSE;
	certificate_tokens_enumerate_async(transaction->context->tokens, transaction->cancellable,
									   on_enumerated, transaction);
}

static char** copy_strings(const char* const* values)
{
	return values != NULL ? g_strdupv((char**)values) : g_new0(char*, 1);
}
XccRequest* xcc_acquire_async(XccSession* session, const XccAcquireSpec* spec, XccDone done,
							  void* user)
{
	g_return_val_if_fail(session != NULL && session->context != NULL, NULL);
	XccRequest* r = xcc_request_new(session->context, session, XCC_RESULT_ACQUIRE, done, user);
	if (spec == NULL || spec->struct_size < sizeof(*spec) || spec->abi_version != XCC_ABI_VERSION ||
		spec->principal.struct_size < sizeof(XccPrincipal) ||
		spec->principal.abi_version != XCC_ABI_VERSION)
	{
		r->validation_error = XCC_ERROR_INVALID_REQUEST;
	}
	else
	{
		r->principal = spec->principal;
		r->caller.app_id = g_strdup(spec->principal.app_id);
		r->principal.app_id = r->caller.app_id;
		r->caller.level = spec->principal.identity_present ? spec->principal.identity_level
														   : CERTIFICATE_IDENTITY_UNKNOWN;
		r->principal.identity_present = TRUE;
		r->principal.identity_level = r->caller.level;
		r->purpose = spec->purpose;
		r->generic_purpose = spec->generic_purpose_present && spec->generic_purpose;
		r->parent_window = g_strdup(spec->parent_window);
		r->activation_token = g_strdup(spec->activation_token);
		r->reason = g_strdup(spec->reason);
		r->lifetime = spec->lifetime_present ? MIN(spec->lifetime_seconds, 3600u) : 300;
		r->may_sign = !spec->sign_present || spec->sign;
		r->interaction_forbidden = spec->interaction_present && spec->interaction_forbidden;
		r->filter.purpose = r->purpose;
		r->filter.operations = r->may_sign ? CERTIFICATE_OPERATION_SIGN : 0;
		if (spec->issuers_present)
		{
			r->filter.issuers = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
			for (size_t i = 0; i < spec->n_issuers; i++)
			{
				const XccBytes* issuer = xcc_acquire_spec_issuer(spec, i);
				if (issuer == NULL || issuer->struct_size < sizeof(XccBytes) ||
					issuer->abi_version != XCC_ABI_VERSION ||
					(issuer->size != 0 && issuer->data == NULL))
				{
					r->validation_error = XCC_ERROR_INVALID_FILTER;
					break;
				}
				g_ptr_array_add(r->filter.issuers, g_bytes_new(issuer->data, issuer->size));
			}
		}
		if (spec->key_usage_present)
			r->filter.key_usage = copy_strings(spec->key_usage);
		if (spec->eku_oids_present)
			r->filter.eku_oids = copy_strings(spec->eku_oids);
		if (spec->key_algorithms_present)
			r->filter.key_algorithms = copy_strings(spec->key_algorithms);
		if (spec->token_label_present)
			r->filter.token_label = g_strdup(spec->token_label);
		if (spec->piv_slot_present)
		{
			static const char* const slots[] = {"authentication", "signature", "key_management",
												"card_authentication", NULL};
			if (spec->piv_slot == NULL || !g_strv_contains(slots, spec->piv_slot))
				r->validation_error = XCC_ERROR_INVALID_FILTER;
			r->filter.piv_slot = g_strdup(spec->piv_slot);
		}
		if (spec->token_label_present && spec->token_label == NULL)
			r->validation_error = XCC_ERROR_INVALID_FILTER;
		if (r->lifetime == 0)
			r->validation_error = XCC_ERROR_INVALID_REQUEST;
		if (r->purpose > CERTIFICATE_PURPOSE_SSH)
			r->validation_error = XCC_ERROR_INVALID_PURPOSE;
	}
	xcc_request_schedule(r, xcc_acquire_start);
	return r;
}
void xcc_acquire_start(void* data)
{
	XccRequest* r = data;
	XccErrorCode error = xcc_request_validate(r);
	if (error != XCC_OK)
	{
		xcc_request_complete(r, error);
		return;
	}
	if (r->session->granted)
	{
		xcc_request_complete(r, XCC_ERROR_INVALID_REQUEST);
		return;
	}
	for (guint i = 0; i < r->context->requests->len; i++)
	{
		XccRequest* pending = g_ptr_array_index(r->context->requests, i);
		if (pending != r && pending->session == r->session &&
		    pending->result.kind == XCC_RESULT_ACQUIRE && !pending->answered)
		{
			xcc_request_complete(r, XCC_ERROR_INVALID_REQUEST);
			return;
		}
	}
	r->caller.app_display_name = certificate_app_display_name(r->caller.app_id);
	certificate_log_decision(CERTIFICATE_REASON_DISCOVERY_STARTED, r->caller.app_id,
							 certificate_identity_level_to_string(r->caller.level),
							 certificate_purpose_to_string(r->purpose), FALSE);
	start_enumeration(r);
}
void xcc_acquire_token_event(XccContext* c, CertificateToken* token, gboolean added)
{
	for (guint i = 0; i < c->requests->len; i++)
	{
		XccRequest* r = g_ptr_array_index(c->requests, i);
		if (r->answered || r->result.kind != XCC_RESULT_ACQUIRE)
			continue;
		if (r->chooser_completed)
		{
			if (!added && r->pending_chosen != NULL &&
				certificate_token_same(r->pending_chosen->token, token) &&
				!g_cancellable_is_cancelled(r->cancellable))
			{
				r->cancelled_code = XCC_ERROR_TOKEN_REMOVED;
				g_cancellable_cancel(r->cancellable);
			}
			else if (r->pending_chosen != NULL)
				r->enumerate_again = TRUE;
			continue;
		}
		if (r->chooser == NULL && !r->enumerating)
			continue;
		if (!added && r->chooser != NULL)
		{
			g_autoptr(GPtrArray) empty = g_ptr_array_new();
			certificate_chooser_update(r->chooser, empty, FALSE);
		}
		else if (added && r->chooser != NULL)
			certificate_chooser_set_tokens_reading(r->chooser, TRUE);
		if (r->enumerating)
			r->enumerate_again = TRUE;
		else
			start_enumeration(r);
	}
}
