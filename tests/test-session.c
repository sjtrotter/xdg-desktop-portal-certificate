/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "core/session-private.h"
#include "broker/operations.h"

static gint64 now;
static guint timer_seconds;

gint64 __wrap_g_get_monotonic_time(void);
guint __wrap_g_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data);
guint __real_g_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data);

gint64 __wrap_g_get_monotonic_time(void)
{
	return now;
}

guint __wrap_g_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data)
{
	timer_seconds = interval;
	return __real_g_timeout_add_seconds(interval, function, data);
}

typedef struct
{
	guint calls;
	char* reason;
	gboolean reenter;
} Invalidation;

static void invalidated(XccSession* session, const char* reason, gpointer user_data)
{
	Invalidation* result = user_data;

	result->calls++;
	g_free(result->reason);
	result->reason = g_strdup(reason);
	if (result->reenter)
	{
		xcc_session_invalidate(session, "error");
		xcc_session_close(session);
	}
}

static CertificateCandidate* make_candidate(void)
{
	CertificateCandidate* candidate = g_new0(CertificateCandidate, 1);

	g_atomic_ref_count_init(&candidate->ref_count);
	return candidate;
}

typedef struct
{
	guint calls;
	const char* message;
} Refusal;

static void refused(GBytes* result, const GError* error, gpointer user_data)
{
	Refusal* refusal = user_data;

	refusal->calls++;
	g_assert_null(result);
	g_assert_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED);
	g_assert_cmpstr(error->message, ==, refusal->message);
}

static void assert_refused(XccSession* session, const char* message)
{
	Refusal refusal = { .message = message };

	/* Refusal must happen before any token access or PIN interaction. */
	certificate_broker_perform(NULL, session, FALSE, "sign-1", "RSA_PKCS1_V1_5", NULL,
	                           NULL, NULL, NULL, NULL, refused, &refusal);
	g_assert_cmpuint(refusal.calls, ==, 1);
}

static void test_deadline_and_grace(void)
{
	Invalidation result = { 0 };
	g_autoptr(CertificateCandidate) candidate = make_candidate();
	g_autoptr(XccSession) session = xcc_session_new_legacy("session-test", invalidated, &result);
	GSource* expiry;

	now = 100 * G_USEC_PER_SEC;
	g_assert_false(xcc_session_is_closed(session));
	g_assert_false(xcc_session_is_expired(session));
	assert_refused(session, "Session has no credential");

	xcc_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE, 5);
	g_assert_true(session->granted);
	g_assert_true(session->candidate == candidate);
	g_assert_true(session->may_sign);
	g_assert_false(session->may_decrypt);
	g_assert_cmpint(session->purpose, ==, CERTIFICATE_PURPOSE_CLIENT_AUTH);
	g_assert_cmpint(session->expires_at, ==, 105);
	g_assert_cmpuint(timer_seconds, ==, 5 + CERTIFICATE_EXPIRY_GRACE_SECONDS);

	now = 105 * G_USEC_PER_SEC - 1;
	g_assert_false(xcc_session_is_expired(session));
	now++;
	g_assert_true(xcc_session_is_expired(session));
	assert_refused(session, "Grant expired");
	g_assert_false(xcc_session_is_closed(session));
	g_assert_cmpuint(result.calls, ==, 0);

	/* Dispatch the real grace source without waiting on wall time. */
	now += CERTIFICATE_EXPIRY_GRACE_SECONDS * G_USEC_PER_SEC;
	expiry = g_main_context_find_source_by_id(NULL, session->expiry_source);
	g_assert_nonnull(expiry);
	g_source_set_ready_time(expiry, 0);
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "grant-invalidated session=session-test detail=lifetime-expired");
	g_main_context_iteration(NULL, FALSE);
	g_test_assert_expected_messages();
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_cmpstr(result.reason, ==, "expired");
	g_assert_true(xcc_session_is_closed(session));
	g_assert_cmpuint(session->expiry_source, ==, 0);
	assert_refused(session, "Session closed");

	xcc_session_invalidate(session, "token_removed");
	xcc_session_close(session);
	xcc_session_close(session);
	g_assert_cmpuint(result.calls, ==, 1);
	g_free(result.reason);
}

static void test_invalidation_reason(gconstpointer data)
{
	const char* reason = data;
	Invalidation result = { .reenter = TRUE };
	g_autoptr(CertificateCandidate) candidate = make_candidate();
	g_autoptr(XccSession) session = xcc_session_new_legacy("session-test", invalidated, &result);

	xcc_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE, 300);
	xcc_session_invalidate(session, reason);
	xcc_session_invalidate(session, "error");
	xcc_session_close(session);
	g_assert_true(xcc_session_is_closed(session));
	g_assert_cmpuint(session->expiry_source, ==, 0);
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_cmpstr(result.reason, ==, reason);
	assert_refused(session, "Session closed");
	g_free(result.reason);
}

static void test_invalid_reason(void)
{
	Invalidation result = { 0 };
	g_autoptr(XccSession) session = xcc_session_new_legacy("session-test", invalidated, &result);

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
	                      "Invalid SessionInvalidated reason: 'invalid'");
	xcc_session_invalidate(session, "invalid");
	g_test_assert_expected_messages();
	g_assert_cmpuint(result.calls, ==, 1);
	g_assert_cmpstr(result.reason, ==, "error");
	g_free(result.reason);
}

static void test_close(void)
{
	Invalidation result = { 0 };
	g_autoptr(CertificateCandidate) candidate = make_candidate();
	g_autoptr(XccSession) session = xcc_session_new_legacy("session-test", invalidated, &result);

	xcc_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE, 300);
	xcc_session_close(session);
	xcc_session_close(session);
	xcc_session_invalidate(session, "backend_gone");
	g_assert_true(xcc_session_is_closed(session));
	g_assert_cmpuint(session->expiry_source, ==, 0);
	g_assert_cmpuint(result.calls, ==, 0);
	assert_refused(session, "Session closed");
}

int main(int argc, char** argv)
{
	const char* reasons[] = { "expired", "token_removed", "policy", "backend_gone", "error" };

	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/session/deadline-and-grace", test_deadline_and_grace);
	g_test_add_func("/session/close", test_close);
	g_test_add_func("/session/invalid-reason", test_invalid_reason);
	for (guint i = 0; i < G_N_ELEMENTS(reasons); i++)
	{
		g_autofree char* path = g_strconcat("/session/invalidate/", reasons[i], NULL);
		g_test_add_data_func(path, reasons[i], test_invalidation_reason);
	}
	return g_test_run();
}
