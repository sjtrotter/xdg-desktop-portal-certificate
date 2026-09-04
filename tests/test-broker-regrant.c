/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * A SECOND AcquireCredential ON A LIVE SESSION, end to end through the broker.
 *
 * The impl interface permits it and the frontend does not refuse it: an
 * application may ask again on the same session handle and the user may pick a
 * different certificate. What the backend used to do with that was open the
 * token session once and never look again -- so the application was handed
 * certificate B, and the next Sign went to certificate A's private key handle,
 * on A's login, with no PIN window. A signature that does not verify against
 * the certificate the portal returned is the one failure this whole repository
 * is meant to make impossible, and it was silent.
 *
 * WHAT IS ASSERTED HERE, in order:
 *
 *   1. the first grant signs, and the signature verifies against certificate A;
 *   2. after the re-grant, the very next operation does NOT produce a
 *      signature -- the login went with the old grant, so the backend asks for
 *      a PIN again (and there is no display in this suite, so it refuses);
 *   3. once the new grant is authenticated, the signature verifies against
 *      certificate B.
 *
 * Skipped without a SoftHSM fixture; tools/softhsm-fixture.sh builds one.
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
	/* g_variant_parse() already returns a FULL reference, so ref_sink()ing it
	 * would add a second one nothing ever drops. */
	g_autoptr(GVariant) parameters =
	    g_variant_parse(G_VARIANT_TYPE_VARDICT, text, NULL, NULL, NULL);
	gint64 deadline;

	probe->calls = 0;
	g_clear_pointer(&probe->signature, g_bytes_unref);

	certificate_broker_perform(tokens, session, FALSE, mechanism, parameters, data, NULL,
	                           "Test application", NULL, on_done, probe);

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

	/* No windows: a PIN prompt this suite cannot answer is exactly how step 2
	 * is observed. */
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

	/* ------------------------------------------------ the first grant */

	certificate_impl_session_grant(session, first, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE,
	                               300);

	/* Stands in for the user typing the PIN into the window this suite has no
	 * display for. */
	g_assert_true(certificate_device_open(&session->device, tokens, first, &error));
	g_assert_true(certificate_device_login(&session->device, first, FIXTURE_PIN, &error));
	g_assert_no_error(error);

	run_and_wait(tokens, session, "RSA_PKCS1_V1_5", "SHA256", data, &probe);
	g_assert_false(probe.failed);
	g_assert_nonnull(probe.signature);
	certificate_test_verify_signature(first, GNUTLS_SIGN_RSA_SHA256, digest, digest_length,
	                                  probe.signature, FALSE);

	/* ------------------------------------------------ the second grant */

	certificate_impl_session_grant(session, second, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE,
	                               300);

	/* THE OLD GRANT'S LOGIN DOES NOT CARRY OVER. The operation is refused --
	 * here because there is no display to ask on, in the real thing because a
	 * PIN window opens. What it must NOT be is a signature. */
	run_and_wait(tokens, session, "ECDSA", "SHA256", data, &probe);
	g_assert_true(probe.failed);
	g_assert_null(probe.signature);

	g_mutex_lock(&session->device_lock);
	g_assert_false(session->device.logged_in);
	g_mutex_unlock(&session->device_lock);

	/* ------------------------------------------------ and then it works */

	g_assert_true(certificate_device_login(&session->device, second, FIXTURE_PIN, &error));
	g_assert_no_error(error);

	run_and_wait(tokens, session, "ECDSA", "SHA256", data, &probe);
	g_assert_false(probe.failed);
	g_assert_nonnull(probe.signature);

	/* THE POINT OF THE WHOLE FILE: against certificate B, from the certificate
	 * the token handed back rather than from anything the fixture script
	 * remembers. */
	certificate_test_verify_signature(second, GNUTLS_SIGN_ECDSA_SHA256, digest, digest_length,
	                                  probe.signature, TRUE);

	/* And not against A, which is what the defect produced. */
	{
		g_autoptr(GBytes) rsa_signature = NULL;

		run_and_wait(tokens, session, "ECDSA", "SHA256", data, &probe);
		rsa_signature = g_bytes_ref(probe.signature);
		g_assert_nonnull(rsa_signature);
		g_assert_cmpuint(g_bytes_get_size(rsa_signature), <, 200);
	}

	g_clear_pointer(&probe.signature, g_bytes_unref);
	certificate_impl_session_close(session);
	/* The close runs on a worker; the module must not be finalised under it. */
	certificate_impl_session_drain_releases(2000);
	g_object_unref(session);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/regrant/signs-with-the-new-certificate",
	                test_regrant_signs_with_the_new_certificate);

	return g_test_run();
}
