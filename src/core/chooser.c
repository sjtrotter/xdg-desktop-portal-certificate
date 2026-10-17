/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "chooser.h"

#include "../redact.h"
#include "../ui/chooser-provider.h"
#include "pin.h"

typedef struct
{
	guint64 id;
	CertificateCandidate* candidate;
} Choice;

struct CertificateChooser
{
	gint refs;
	XccUiId id;
	guint64 next_candidate_id;
	CertificateChooserProvider provider;
	XccChooserView view;
	GPtrArray* choices;
	GPtrArray* text;
	GPtrArray* row_text;
	XccChooserCandidateView* rows;
	char* app_id;
	CertificateChooserDone done;
	gpointer user_data;
	GCancellable* cancellable;
	gulong cancel_id;
	guint cancel_idle;
	gboolean finished;
};

typedef CertificateChooser Chooser;

static CertificateChooserProvider chooser_provider;
static GHashTable* choosers;
static XccUiId next_ui_id;
static guint provider_depth;

void certificate_chooser_set_provider(const CertificateChooserProvider* provider)
{
	g_return_if_fail(provider != NULL);
	g_return_if_fail(provider->chooser_show != NULL && provider->chooser_update != NULL);
	g_return_if_fail(provider->close != NULL);

	chooser_provider = *provider;
}

gboolean certificate_chooser_available(void)
{
	return chooser_provider.chooser_show != NULL &&
	       (!chooser_provider.needs_display || certificate_ui_has_display());
}

static void choice_free(gpointer data)
{
	Choice* choice = data;

	certificate_candidate_unref(choice->candidate);
	g_free(choice);
}

static Chooser* chooser_ref(Chooser* chooser)
{
	g_atomic_int_inc(&chooser->refs);
	return chooser;
}

static void chooser_unref(gpointer data)
{
	Chooser* chooser = data;

	if (!g_atomic_int_dec_and_test(&chooser->refs))
		return;

	g_ptr_array_unref(chooser->choices);
	g_ptr_array_unref(chooser->text);
	g_ptr_array_unref(chooser->row_text);
	g_free(chooser->rows);
	g_free(chooser->app_id);
	g_clear_object(&chooser->cancellable);
	g_free(chooser);
}

static void chooser_finish(Chooser* chooser, CertificateCandidate* chosen)
{
	g_autoptr(CertificateCandidate) retained = chosen != NULL
	    ? certificate_candidate_ref(chosen) : NULL;
	CertificateChooserResult result = { retained };

	if (chooser->finished)
		return;

	chooser->finished = TRUE;
	g_hash_table_remove(choosers, &chooser->id);
	if (g_hash_table_size(choosers) == 0)
		g_clear_pointer(&choosers, g_hash_table_unref);

	/* Disconnect before removing the idle so cancellation cannot queue another source. */
	if (chooser->cancel_id != 0)
	{
		g_cancellable_disconnect(chooser->cancellable, chooser->cancel_id);
		chooser->cancel_id = 0;
	}
	if (chooser->cancel_idle != 0)
	{
		g_source_remove(chooser->cancel_idle);
		chooser->cancel_idle = 0;
	}

	provider_depth++;
	chooser->provider.close(chooser->provider.user_data, chooser->id);
	provider_depth--;
	certificate_log_decision(chosen != NULL ? CERTIFICATE_REASON_CONSENT_GRANTED
	                                        : CERTIFICATE_REASON_CHOOSER_CANCELLED,
	                         chooser->app_id,
	                         certificate_identity_level_to_string(chooser->view.identity_level),
	                         certificate_purpose_to_string(chooser->view.purpose), chosen != NULL);
	chooser->done(&result, chooser->user_data);
	chooser_unref(chooser);
}

typedef struct
{
	XccUiId id;
	guint64 revision;
	guint64 candidate_id;
} Reply;

static gboolean reply_idle(gpointer data)
{
	Reply* reply = data;

	if (reply->candidate_id != 0)
		xcc_choose(reply->id, reply->revision, reply->candidate_id);
	else
		xcc_ui_cancel(reply->id);
	return G_SOURCE_REMOVE;
}

static void defer_reply(XccUiId id, guint64 revision, guint64 candidate_id)
{
	Reply* reply = g_new(Reply, 1);

	*reply = (Reply) { id, revision, candidate_id };
	g_idle_add_full(G_PRIORITY_DEFAULT, reply_idle, reply, g_free);
}

void xcc_choose(XccUiId id, guint64 revision, guint64 candidate_id)
{
	Chooser* chooser = choosers != NULL ? g_hash_table_lookup(choosers, &id) : NULL;

	if (chooser == NULL || revision != chooser->view.revision || candidate_id == 0)
		return;
	if (provider_depth != 0)
	{
		defer_reply(id, revision, candidate_id);
		return;
	}
	for (guint i = 0; i < chooser->choices->len; i++)
	{
		Choice* choice = g_ptr_array_index(chooser->choices, i);

		if (choice->id == candidate_id)
		{
			chooser_finish(chooser, choice->candidate);
			return;
		}
	}
}

void xcc_ui_cancel(XccUiId id)
{
	Chooser* chooser = choosers != NULL ? g_hash_table_lookup(choosers, &id) : NULL;

	if (chooser == NULL)
		return;
	if (provider_depth != 0)
	{
		defer_reply(id, 0, 0);
		return;
	}
	chooser_finish(chooser, NULL);
}

static gboolean on_cancelled_idle(gpointer user_data)
{
	Chooser* chooser = user_data;

	chooser->cancel_idle = 0;
	chooser_finish(chooser, NULL);
	return G_SOURCE_REMOVE;
}

/* Cancellation may arrive off-thread; the idle retains the interaction. */
static void on_cancelled(GCancellable* cancellable, gpointer user_data)
{
	Chooser* chooser = user_data;

	if (chooser->cancel_idle != 0)
		return;
	chooser->cancel_idle = g_idle_add_full(G_PRIORITY_DEFAULT, on_cancelled_idle,
	                                       chooser_ref(chooser), chooser_unref);
}

static const char* own_text(GPtrArray* text, char* value)
{
	g_ptr_array_add(text, value);
	return value;
}

static const char* identity_detail(CertificateIdentityLevel level)
{
	switch (level)
	{
		case CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED:
			return "Sandboxed application, identity verified by the system";
		case CERTIFICATE_IDENTITY_DERIVED_HOST:
			return "Unsandboxed application. The name below was derived from the "
			       "running process and is a useful label, not proof.";
		default:
			return "This application could not be identified. Only continue if you "
			       "know what asked.";
	}
}

static void replace_candidates(Chooser* chooser, GPtrArray* candidates, gboolean tokens_present)
{
	GPtrArray* choices = g_ptr_array_new_with_free_func(choice_free);
	gint64 now = g_get_real_time() / G_USEC_PER_SEC;

	g_ptr_array_set_size(chooser->row_text, 0);
	g_free(chooser->rows);
	chooser->rows = g_new0(XccChooserCandidateView, candidates->len);
	for (guint i = 0; i < candidates->len; i++)
	{
		CertificateCandidate* candidate = g_ptr_array_index(candidates, i);
		Choice* choice = g_new0(Choice, 1);
		XccChooserCandidateView* row = &chooser->rows[i];
		GPtrArray* text = chooser->row_text;

		choice->candidate = certificate_candidate_ref(candidate);
		for (guint j = 0; j < chooser->choices->len; j++)
		{
			Choice* previous = g_ptr_array_index(chooser->choices, j);

			if (certificate_candidate_same(previous->candidate, candidate))
			{
				choice->id = previous->id;
				break;
			}
		}
		if (choice->id == 0)
			choice->id = ++chooser->next_candidate_id;
		g_ptr_array_add(choices, choice);
		row->id = choice->id;
		row->subject = own_text(text, certificate_display_text(
		    candidate->subject_display, CERTIFICATE_DISPLAY_MAX_SUBJECT, "Unnamed certificate"));
		row->issuer = own_text(text, certificate_display_text(
		    candidate->issuer_display, CERTIFICATE_DISPLAY_MAX_ISSUER, "an unnamed issuer"));
		row->token = own_text(text, certificate_display_text(
		    candidate->token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "unnamed token"));
		row->reader = own_text(text, certificate_display_text(
		    candidate->token->reader_name, CERTIFICATE_DISPLAY_MAX_READER, NULL));
		row->expiry = own_text(text, certificate_chooser_format_expiry(candidate, now));
		row->detail = own_text(text, certificate_chooser_format_detail(candidate, now));
		row->fingerprint = own_text(text, certificate_display_text(candidate->certificate_id, 64, NULL));
		row->invalid = certificate_candidate_is_expired(candidate, now) ||
		               certificate_candidate_is_not_yet_valid(candidate, now);
	}
	g_ptr_array_unref(chooser->choices);
	chooser->choices = choices;
	chooser->view.revision++;
	chooser->view.candidates = chooser->rows;
	chooser->view.n_candidates = candidates->len;
	chooser->view.tokens_present = tokens_present;
}

void certificate_chooser_update(CertificateChooser* chooser, GPtrArray* candidates,
                                gboolean tokens_present)
{
	if (chooser->finished)
		return;

	replace_candidates(chooser, candidates, tokens_present);
	provider_depth++;
	chooser->provider.chooser_update(chooser->provider.user_data, chooser->id, &chooser->view);
	provider_depth--;
}

CertificateChooser* certificate_chooser_show(const char* parent_window,
                                             const char* activation_token,
                                             GPtrArray* candidates,
                                             const CertificateChooserRequest* request,
                                             GCancellable* cancellable,
                                             CertificateChooserDone done, gpointer user_data)
{
	Chooser* chooser;
	XccChooserView* view;
	GPtrArray* text;

	if (!certificate_chooser_available())
	{
		CertificateChooserResult result = { NULL };

		done(&result, user_data);
		return NULL;
	}

	chooser = g_new0(Chooser, 1);
	chooser->refs = 1;
	chooser->id = ++next_ui_id;
	chooser->provider = chooser_provider;
	chooser->choices = g_ptr_array_new_with_free_func(choice_free);
	chooser->text = g_ptr_array_new_with_free_func(g_free);
	chooser->row_text = g_ptr_array_new_with_free_func(g_free);
	chooser->app_id = g_strdup(request->caller->app_id);
	chooser->done = done;
	chooser->user_data = user_data;
	chooser->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;
	text = chooser->text;
	view = &chooser->view;
	view->caller_name = own_text(text, certificate_chooser_display_name(request->caller));
	view->app_id = own_text(text, certificate_display_text(
	    request->caller->app_id, CERTIFICATE_DISPLAY_MAX_APP_ID, NULL));
	view->identity_level = request->caller->level;
	view->identity_detail = identity_detail(view->identity_level);
	view->purpose = request->purpose;
	view->purpose_text = own_text(text, certificate_chooser_format_purpose(request));
	view->purpose_detail = certificate_chooser_purpose_detail(request);
	view->may_sign = request->may_sign;
	view->may_decrypt = request->may_decrypt;
	view->operation_scope = request->may_sign && request->may_decrypt
	    ? "It allows signing and decryption."
	    : request->may_decrypt ? "It allows decryption only."
	    : request->may_sign    ? "It allows signing only." : "It allows no operations.";
	view->lifetime_seconds = request->lifetime_seconds;
	view->duration = own_text(text, certificate_chooser_format_lifetime(request->lifetime_seconds));
	view->later_prompt = "You will be asked for your PIN the first time the key is used.";
	view->reason_label = "The application says";
	view->untrusted_reason = own_text(text, certificate_sanitize_untrusted_text(request->reason, 160));
	view->parent_window = own_text(text, g_strdup(parent_window));
	view->activation_token = own_text(text, g_strdup(activation_token));
	replace_candidates(chooser, candidates, request->tokens_present);

	if (choosers == NULL)
		choosers = g_hash_table_new(g_int64_hash, g_int64_equal);
	g_hash_table_insert(choosers, &chooser->id, chooser);
	if (chooser->cancellable != NULL)
		chooser->cancel_id = g_cancellable_connect(
		    chooser->cancellable, G_CALLBACK(on_cancelled), chooser, NULL);

	certificate_log_decision(CERTIFICATE_REASON_CHOOSER_SHOWN, chooser->app_id,
	                         certificate_identity_level_to_string(view->identity_level),
	                         certificate_purpose_to_string(view->purpose), FALSE);
	provider_depth++;
	chooser->provider.chooser_show(chooser->provider.user_data, chooser->id, view);
	provider_depth--;
	/* Activation is consumed by the initial presentation. */
	view->activation_token = NULL;
	return chooser;
}
