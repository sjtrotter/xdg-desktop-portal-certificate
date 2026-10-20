/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */

#include <string.h>

#include "core/chooser.h"
#include "core/pin.h"
#include "fake-chooser-provider.h"
#include "fixture-util.h"

typedef struct
{
	guint calls;
	CertificateCandidate* chosen;
} Result;

static void on_done(const CertificateChooserResult* result, gpointer user_data)
{
	Result* received = user_data;

	received->calls++;
	received->chosen = result->chosen != NULL ? certificate_candidate_ref(result->chosen) : NULL;
}

static CertificateChooser* show(FakeChooserProvider* fake, GPtrArray* candidates,
                                gboolean tokens_present, GCancellable* cancellable, Result* result)
{
	char app_id[] = "org.example.App";
	char app_name[] = "Example\nApplication";
	CertificateCallerIdentity caller = {
		.level = CERTIFICATE_IDENTITY_DERIVED_HOST,
		.app_id = app_id,
		.app_display_name = app_name,
	};
	CertificateChooserRequest request = {
		.caller = &caller,
		.purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH,
		.may_sign = TRUE,
		.lifetime_seconds = 300,
		.reason = "Please\ncontinue",
		.tokens_present = tokens_present,
	};

	certificate_chooser_set_provider(&fake->provider);
	g_assert_true(certificate_chooser_available());
	return certificate_chooser_show("x11:123", "activate-once", candidates, &request,
	                                cancellable, on_done, result);
}

static CertificateCandidate* candidate_with_key(const char* key)
{
	CertificateCandidate* candidate = certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);

	candidate->cka_id = g_byte_array_new();
	g_byte_array_append(candidate->cka_id, (const guint8*) key, strlen(key));
	return candidate;
}

static void test_empty_insertion_and_ids(gconstpointer data)
{
	gboolean tokens_present = GPOINTER_TO_INT(data);
	FakeChooserProvider fake;
	Result result = { 0 };
	g_autoptr(GPtrArray) empty = g_ptr_array_new();
	g_autoptr(GPtrArray) candidates = g_ptr_array_new_with_free_func(
	    (GDestroyNotify) certificate_candidate_unref);
	g_autoptr(GPtrArray) refreshed = g_ptr_array_new_with_free_func(
	    (GDestroyNotify) certificate_candidate_unref);
	CertificateChooser* chooser;
	XccUiId id;
	guint64 revision;
	guint64 candidate_id;

	fake_chooser_provider_init(&fake);
	chooser = show(&fake, empty, tokens_present, NULL, &result);
	g_assert_nonnull(chooser);
	g_assert_cmpuint(fake.shows, ==, 1);
	g_assert_cmpuint(fake.view.n_candidates, ==, 0);
	g_assert_cmpint(fake.view.tokens_present, ==, tokens_present);
	g_assert_cmpint(fake.view.identity_level, ==, CERTIFICATE_IDENTITY_DERIVED_HOST);
	g_assert_cmpstr(fake.view.app_id, ==, "org.example.App");
	g_assert_null(strchr(fake.view.caller_name, '\n'));
	g_assert_null(strchr(fake.view.untrusted_reason, '\n'));
	g_assert_cmpstr(fake.view.reason_label, ==, "The application says");
	g_assert_cmpstr(fake.view.duration, ==, "5 minutes");
	g_assert_cmpstr(fake.view.operation_scope, ==, "It allows signing only.");
	g_assert_cmpstr(fake.view.identity_detail, ==,
	                "Unsandboxed application. The name above was derived from the "
	                "running process. Its identity has not been verified.");
	g_assert_null(fake.view.later_prompt);
	g_assert_false(fake.view.generic_purpose);
	g_assert_cmpuint(fake.view.display_flags, ==, 0);
	g_assert_cmpstr(fake.view.parent_window, ==, "x11:123");
	g_assert_cmpstr(fake.view.activation_token, ==, "activate-once");

	g_ptr_array_add(candidates, candidate_with_key("one"));
	certificate_chooser_update(chooser, candidates, TRUE);
	g_assert_cmpuint(fake.updates, ==, 1);
	g_assert_cmpuint(fake.view.n_candidates, ==, 1);
	g_assert_true(fake.view.tokens_present);
	g_assert_nonnull(fake.view.candidates[0].subject);
	g_assert_nonnull(fake.view.candidates[0].issuer);
	g_assert_nonnull(fake.view.candidates[0].detail);
	g_assert_null(fake.view.activation_token);
	id = fake.id;
	revision = fake.view.revision;
	candidate_id = fake.view.candidates[0].id;
	/* A fresh inventory snapshot preserves only the same key's ID. */
	g_ptr_array_add(refreshed, candidate_with_key("one"));
	certificate_chooser_update(chooser, refreshed, TRUE);
	g_assert_cmpuint(fake.view.candidates[0].id, ==, candidate_id);
	certificate_chooser_choose(id, revision, candidate_id);
	certificate_chooser_choose(id, fake.view.revision, candidate_id + 1);
	g_assert_cmpuint(result.calls, ==, 0);
	g_assert_cmpuint(fake.closes, ==, 0);
	fake_chooser_provider_choose(&fake, 0);
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_true(result.chosen == g_ptr_array_index(refreshed, 0));
	g_assert_cmpuint(fake.closes, ==, 1);
	certificate_chooser_choose(id, fake.view.revision, candidate_id);
	certificate_chooser_cancel(id);
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_cmpuint(fake.closes, ==, 1);
	certificate_candidate_unref(result.chosen);
	fake_chooser_provider_clear(&fake);
}

static void test_removal_and_cancel(void)
{
	FakeChooserProvider fake;
	Result result = { 0 };
	g_autoptr(GPtrArray) candidates = g_ptr_array_new_with_free_func(
	    (GDestroyNotify) certificate_candidate_unref);
	g_autoptr(GPtrArray) empty = g_ptr_array_new();
	CertificateChooser* chooser;
	guint64 removed_id;
	guint64 revision;

	fake_chooser_provider_init(&fake);
	g_ptr_array_add(candidates, candidate_with_key("one"));
	chooser = show(&fake, candidates, TRUE, NULL, &result);
	removed_id = fake.view.candidates[0].id;
	revision = fake.view.revision;
	certificate_chooser_update(chooser, empty, FALSE);
	g_assert_cmpuint(fake.view.n_candidates, ==, 0);
	g_assert_false(fake.view.tokens_present);
	certificate_chooser_choose(fake.id, revision, removed_id);
	certificate_chooser_choose(fake.id, fake.view.revision, removed_id);
	g_assert_cmpuint(result.calls, ==, 0);
	certificate_chooser_update(chooser, candidates, TRUE);
	g_assert_cmpuint(fake.view.candidates[0].id, !=, removed_id);
	certificate_chooser_choose(fake.id, fake.view.revision, removed_id);
	g_assert_cmpuint(result.calls, ==, 0);
	fake_chooser_provider_cancel(&fake);
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_null(result.chosen);
	g_assert_cmpuint(fake.closes, ==, 1);
	fake_chooser_provider_clear(&fake);
}

static void test_unknown_identity_wording(void)
{
	FakeChooserProvider fake;
	Result result = { 0 };
	g_autoptr(GPtrArray) empty = g_ptr_array_new();
	CertificateCallerIdentity caller = { .level = CERTIFICATE_IDENTITY_UNKNOWN };
	CertificateChooserRequest request = { .caller = &caller };

	fake_chooser_provider_init(&fake);
	certificate_chooser_set_provider(&fake.provider);
	g_assert_nonnull(certificate_chooser_show(NULL, NULL, empty, &request, NULL, on_done, &result));
	g_assert_cmpstr(fake.view.identity_detail, ==,
	                "This application could not be identified. Only continue if you "
	                "know which application made this request.");
	g_assert_null(fake.view.later_prompt);
	fake_chooser_provider_cancel(&fake);
	g_assert_cmpuint(result.calls, ==, 1);
	fake_chooser_provider_clear(&fake);
}

static void test_structured_fields(void)
{
	FakeChooserProvider fake;
	Result result = {0};
	g_autoptr(GPtrArray) candidates = g_ptr_array_new_with_free_func(
	    (GDestroyNotify)certificate_candidate_unref);
	CertificateCandidate* candidate = candidate_with_key("metadata");
	gint64 now = g_get_real_time() / G_USEC_PER_SEC;
	candidate->not_before = now - 3600;
	candidate->not_after = now + 3600;
	g_ptr_array_add(candidates, candidate);
	fake_chooser_provider_init(&fake);
	CertificateChooser* chooser = show(&fake, candidates, TRUE, NULL, &result);
	const XccChooserCandidateView* row = xcc_chooser_view_candidate(&fake.view, 0);
	g_assert_cmpuint(row->struct_size, ==, sizeof(*row));
	g_assert_cmpint(row->not_before, ==, candidate->not_before);
	g_assert_cmpint(row->not_after, ==, candidate->not_after);
	g_assert_cmpuint(row->validity, ==, XCC_VALIDITY_VALID);
	g_assert_cmpstr(row->key_type, ==, "RSA");
	g_assert_cmpuint(row->key_size, ==, candidate->key_size);
	g_assert_true(row->key_type != candidate->key_type);
	g_autofree char* expiry = certificate_chooser_format_expiry(candidate, now);
	g_autofree char* detail = certificate_chooser_format_detail(candidate, now);
	g_assert_cmpstr(row->expiry, ==, expiry);
	g_assert_cmpstr(row->detail, ==, detail);
	static const XccValidity states[] = {
	    XCC_VALIDITY_EXPIRED, XCC_VALIDITY_NOT_YET_VALID, XCC_VALIDITY_UNKNOWN
	};
	for (gsize i = 0; i < G_N_ELEMENTS(states); i++)
	{
		candidate->not_before = states[i] == XCC_VALIDITY_NOT_YET_VALID ? now + 3600 : now - 7200;
		candidate->not_after = states[i] == XCC_VALIDITY_EXPIRED ? now - 3600 : now + 7200;
		if (states[i] == XCC_VALIDITY_UNKNOWN)
			candidate->not_before = candidate->not_after = 0;
		certificate_chooser_update(chooser, candidates, TRUE);
		row = xcc_chooser_view_candidate(&fake.view, 0);
		g_assert_cmpuint(row->validity, ==, states[i]);
		g_assert_cmpint(row->invalid, ==, states[i] != XCC_VALIDITY_UNKNOWN);
	}
	g_clear_pointer(&candidate->subject_display, g_free);
	g_clear_pointer(&candidate->issuer_display, g_free);
	g_clear_pointer(&candidate->token->label, g_free);
	certificate_chooser_update(chooser, candidates, TRUE);
	row = xcc_chooser_view_candidate(&fake.view, 0);
	g_assert_cmpuint(row->display_flags, ==, XCC_DISPLAY_SUBJECT_FALLBACK |
	    XCC_DISPLAY_ISSUER_FALLBACK | XCC_DISPLAY_TOKEN_FALLBACK);
	/* A literal external name matching English is not an SDK placeholder. */
	candidate->token->label = g_strdup("unnamed token");
	certificate_chooser_update(chooser, candidates, TRUE);
	g_assert_false((fake.view.candidates[0].display_flags & XCC_DISPLAY_TOKEN_FALLBACK) != 0);
	fake_chooser_provider_cancel(&fake);
	fake_chooser_provider_clear(&fake);
}

static gpointer cancel_thread(gpointer data)
{
	g_cancellable_cancel(data);
	return NULL;
}

static void test_request_cancel(void)
{
	FakeChooserProvider fake;
	Result result = { 0 };
	g_autoptr(GCancellable) cancellable = g_cancellable_new();
	g_autoptr(GPtrArray) candidates = g_ptr_array_new_with_free_func(
	    (GDestroyNotify) certificate_candidate_unref);
	GThread* thread;
	XccUiId id;
	guint64 revision;
	guint64 candidate_id;

	fake_chooser_provider_init(&fake);
	g_ptr_array_add(candidates, candidate_with_key("one"));
	show(&fake, candidates, TRUE, cancellable, &result);
	id = fake.id;
	revision = fake.view.revision;
	candidate_id = fake.view.candidates[0].id;
	thread = g_thread_new("cancel", cancel_thread, cancellable);
	g_thread_join(thread);
	while (g_main_context_iteration(NULL, FALSE))
		;
	certificate_chooser_choose(id, revision, candidate_id);
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_null(result.chosen);
	g_assert_cmpuint(fake.closes, ==, 1);
	fake_chooser_provider_clear(&fake);
}

static void test_inline_cancel_and_late_reply(void)
{
	FakeChooserProvider fake;
	Result result = { 0 };
	g_autoptr(GPtrArray) empty = g_ptr_array_new();
	XccUiId old_id;

	fake_chooser_provider_init(&fake);
	fake.cancel_on_show = TRUE;
	g_assert_nonnull(show(&fake, empty, FALSE, NULL, &result));
	g_assert_cmpuint(result.calls, ==, 0);
	old_id = fake.id;
	while (g_main_context_iteration(NULL, FALSE))
		;
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_cmpuint(fake.closes, ==, 1);
	fake.cancel_on_show = FALSE;
	show(&fake, empty, FALSE, NULL, &result);
	g_assert_cmpuint(fake.id, !=, old_id);
	certificate_chooser_cancel(old_id);
	g_assert_cmpuint(result.calls, ==, 1);
	fake_chooser_provider_cancel(&fake);
	g_assert_cmpuint(result.calls, ==, 2);
	g_assert_cmpuint(fake.closes, ==, 2);
	fake_chooser_provider_clear(&fake);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	certificate_ui_set_has_display(FALSE);
	g_test_add_data_func("/chooser-policy/empty-insert", GINT_TO_POINTER(FALSE),
	                     test_empty_insertion_and_ids);
	g_test_add_data_func("/chooser-policy/no-match-insert", GINT_TO_POINTER(TRUE),
	                     test_empty_insertion_and_ids);
	g_test_add_func("/chooser-policy/removal-cancel", test_removal_and_cancel);
	g_test_add_func("/chooser-policy/structured-fields", test_structured_fields);
	g_test_add_func("/chooser-policy/unknown-identity-wording", test_unknown_identity_wording);
	g_test_add_func("/chooser-policy/request-cancel", test_request_cancel);
	g_test_add_func("/chooser-policy/inline-cancel-late-reply", test_inline_cancel_and_late_reply);
	return g_test_run();
}
