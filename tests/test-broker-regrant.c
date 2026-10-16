/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <glib.h>
#include <gnutls/gnutls.h>
#include <string.h>

#include "broker/device.h"
#include "broker/operations.h"
#include "fixture-util.h"
#include "session-impl.h"
#include "ui/pin.h"

#define FIXTURE_PIN "123456"

typedef struct
{
	guint calls;
	GBytes* signature;
	gboolean failed;
} Probe;

static void on_done(GBytes* result, const GError* error, gpointer user_data)
{
	Probe* probe = user_data;

	probe->calls++;
	probe->failed = result == NULL;

	g_clear_pointer(&probe->signature, g_bytes_unref);
	if (result != NULL)
		probe->signature = g_bytes_ref(result);
}

static char* fixture_directory(void)
{
	const char* directory = g_getenv("SOFTHSM_FIXTURE_DIR");
	g_autofree char* fallback = NULL;

	if (directory != NULL)
		return g_strdup(directory);

	fallback = g_build_filename(g_get_tmp_dir(), "xdp-certificate-softhsm", NULL);
	if (g_file_test(fallback, G_FILE_TEST_IS_DIR))
		return g_steal_pointer(&fallback);

	return NULL;
}

static void run_and_wait(CertificateTokens* tokens, CertificateImplSession* session,
                         const char* mechanism, const char* hash, GBytes* data, Probe* probe)
{
	g_autofree char* text = g_strdup_printf("{'hash': <'%s'>}", hash);
	g_autoptr(GVariant) parameters =
	    g_variant_parse(G_VARIANT_TYPE_VARDICT, text, NULL, NULL, NULL);
	g_autofree char* operation_id = g_strdup("sign-1");
	gint64 deadline;

	probe->calls = 0;
	g_clear_pointer(&probe->signature, g_bytes_unref);

	certificate_broker_perform(tokens, session, FALSE, operation_id, mechanism, parameters, data, NULL,
	                           "Test application", NULL, on_done, probe);
	g_clear_pointer(&operation_id, g_free);

	deadline = g_get_monotonic_time() + 20 * G_TIME_SPAN_SECOND;
	while (probe->calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	g_assert_cmpuint(probe->calls, ==, 1);
}

static void test_regrant_signs_with_the_new_certificate(void)
{
	g_autofree char* directory = fixture_directory();
	g_autofree char* module = NULL;
	g_autoptr(CertificateTokens) tokens = NULL;
	g_autoptr(GPtrArray) candidates = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GBytes) data = NULL;
	CertificateImplSession* session = NULL;
	CertificateCandidate* first = NULL;
	CertificateCandidate* second = NULL;
	Probe probe = { 0 };
	const char* modules[2] = { NULL, NULL };
	guint8 digest[32];
	g_autoptr(GChecksum) checksum = g_checksum_new(G_CHECKSUM_SHA256);
	gsize digest_length = sizeof(digest);

	/* Disable display access so a required fresh login fails without opening a window. */
	certificate_ui_set_has_display(FALSE);

	if (directory == NULL)
	{
		g_test_skip("no SoftHSM fixture; run tools/softhsm-fixture.sh");
		return;
	}

	{
		g_autofree char* module_path = g_build_filename(directory, "module-path", NULL);
		g_autofree char* config = g_build_filename(directory, "softhsm2.conf", NULL);

		if (!g_file_get_contents(module_path, &module, NULL, NULL))
		{
			g_test_skip("the SoftHSM fixture has no module-path; rebuild it");
			return;
		}

		g_setenv("SOFTHSM2_CONF", config, TRUE);
	}

	modules[0] = module;
	tokens = certificate_tokens_new(modules, &error);
	g_assert_no_error(error);

	candidates = certificate_tokens_enumerate(tokens, NULL, &error);
	g_assert_no_error(error);

	for (guint i = 0; i < candidates->len; i++)
	{
		CertificateCandidate* item = g_ptr_array_index(candidates, i);

		if (g_strcmp0(item->key_type, "RSA") == 0)
			first = item;
		else if (g_strcmp0(item->key_type, "EC") == 0)
			second = item;
	}

	if (first == NULL || second == NULL)
	{
		g_test_skip("the fixture needs both an RSA and an EC key");
		return;
	}

	g_checksum_update(checksum, (const guchar*) "re-grant", 8);
	g_checksum_get_digest(checksum, digest, &digest_length);
	data = g_bytes_new(digest, digest_length);

	session = certificate_impl_session_new("/org/freedesktop/portal/desktop/session/t/regrant",
	                                       "org.example.App");

	certificate_impl_session_grant(session, first, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE,
	                               300);

	/* Simulate PIN entry directly because the test has no display. */
	g_assert_true(certificate_device_open(&session->device, tokens, first, &error));
	g_assert_true(certificate_device_login(&session->device, first, FIXTURE_PIN, &error));
	g_assert_no_error(error);

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "request-received session=/org/freedesktop/portal/desktop/session/t/regrant "
	                      "operation=sign-1 mechanism=RSA_PKCS1_V1_5");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "operation-completed session=/org/freedesktop/portal/desktop/session/t/regrant "
	                      "operation=sign-1 mechanism=RSA_PKCS1_V1_5");
	run_and_wait(tokens, session, "RSA_PKCS1_V1_5", "SHA256", data, &probe);
	g_test_assert_expected_messages();
	g_assert_false(probe.failed);
	g_assert_nonnull(probe.signature);
	certificate_test_verify_signature(first, GNUTLS_SIGN_RSA_SHA256, digest, digest_length,
	                                  probe.signature, FALSE);

	certificate_impl_session_grant(session, second, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE,
	                               300);

	run_and_wait(tokens, session, "ECDSA", "SHA256", data, &probe);
	g_assert_true(probe.failed);
	g_assert_null(probe.signature);

	g_mutex_lock(&session->device_lock);
	g_assert_false(session->device.logged_in);
	g_mutex_unlock(&session->device_lock);

	g_assert_true(certificate_device_login(&session->device, second, FIXTURE_PIN, &error));
	g_assert_no_error(error);

	run_and_wait(tokens, session, "ECDSA", "SHA256", data, &probe);
	g_assert_false(probe.failed);
	g_assert_nonnull(probe.signature);

	certificate_test_verify_signature(second, GNUTLS_SIGN_ECDSA_SHA256, digest, digest_length,
	                                  probe.signature, TRUE);

	{
		g_autoptr(GBytes) rsa_signature = NULL;

		run_and_wait(tokens, session, "ECDSA", "SHA256", data, &probe);
		rsa_signature = g_bytes_ref(probe.signature);
		g_assert_nonnull(rsa_signature);
		g_assert_cmpuint(g_bytes_get_size(rsa_signature), <, 200);
	}

	g_clear_pointer(&probe.signature, g_bytes_unref);
	certificate_impl_session_close(session);
	/* Drain asynchronous device closes before finalizing the module. */
	certificate_impl_session_drain_releases(2000);
	g_object_unref(session);
}

static void test_grant_expiry_is_monotonic(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	CertificateImplSession* session = certificate_impl_session_new(
	    "/org/freedesktop/portal/desktop/session/t/expiry", "org.example.App");
	gint64 monotonic;

	certificate_impl_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE,
	                               FALSE, 300);

	monotonic = g_get_monotonic_time() / G_USEC_PER_SEC;
	g_assert_cmpint(session->expires_at, >=, monotonic + 299);
	g_assert_cmpint(session->expires_at, <=, monotonic + 300);
	g_assert_false(certificate_impl_session_is_expired(session));

	certificate_impl_session_close(session);
	g_object_unref(session);
}

static void test_sign_logs_ids(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autoptr(CertificateImplSession) session = certificate_impl_session_new(
	    "/org/freedesktop/portal/desktop/session/t/logging", "org.example.App");
	g_autofree char* long_id = g_strnfill(200, 'x');
	g_autofree char* prefix = g_strnfill(128, 'x');
	g_autofree char* capped_id = g_strconcat(prefix, "...", NULL);
	struct
	{
		const char* operation_id;
		const char* logged_id;
	} cases[] = {
		{ NULL, "(none)" },
		{ "sign-1", "sign-1" },
		{ "sign-2\nMESSAGE: forged", "sign-2\\x0aMESSAGE: forged" },
		{ long_id, capped_id },
	};

	certificate_impl_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, FALSE,
	                               FALSE, 300);

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		Probe probe = { 0 };
		g_autofree char* expected = g_strdup_printf(
		    "operation-refused session=%s operation=%s mechanism=RSA_PKCS1_V1_5",
		    session->id, cases[i].logged_id);

		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, expected);
		certificate_broker_perform(NULL, session, FALSE, cases[i].operation_id, "RSA_PKCS1_V1_5",
		                           NULL, NULL, NULL, "Test application", NULL, on_done, &probe);
		g_test_assert_expected_messages();
		g_assert_cmpuint(probe.calls, ==, 1);
		g_assert_true(probe.failed);
	}

	certificate_impl_session_close(session);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/regrant/signs-with-the-new-certificate",
	                test_regrant_signs_with_the_new_certificate);
	g_test_add_func("/regrant/expiry-is-monotonic", test_grant_expiry_is_monotonic);
	g_test_add_func("/broker/sign-logs-ids", test_sign_logs_ids);

	return g_test_run();
}
