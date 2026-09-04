/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * THE TWO PROPERTIES THAT MAKE DECRYPTION SAFE TO OFFER AT ALL, at the layer
 * that provides them: broker/operations.c.
 *
 * ONE ERROR. RSA_OAEP is not a padding oracle the way PKCS#1 v1.5 is, but that
 * is a property of OAEP and not of this code, and it survives only as long as
 * nobody rebuilds the distinction by hand. The module tells this backend
 * whether the encoding was malformed, whether the parameters were wrong for
 * the key, or whether the device faulted; the caller is told "the decryption
 * failed", in the same words, every time. The real reason goes to the journal,
 * where the user can read it and the caller cannot.
 *
 * A BUDGET. Every practical attack on RSA decryption -- padding oracles, fault
 * injection, timing -- is built on making a great many queries against one key,
 * and nothing on either side of the portal boundary counts them. One grant buys
 * CERTIFICATE_MAX_DECRYPTS_PER_GRANT of them and then the user has to be asked
 * again.
 *
 * Needs a SoftHSM fixture; skips itself without one. The card path is the
 * author's, in docs/TESTING.md.
 */

#include <glib.h>
#include <string.h>

#include "broker/device.h"
#include "broker/operations.h"
#include "session-impl.h"

#define FIXTURE_PIN "123456"

typedef struct
{
	CertificateTokens* tokens;
	GPtrArray* candidates;
	CertificateCandidate* rsa;
	CertificateImplSession* session;
} Fixture;

typedef struct
{
	guint calls;
	char* message;
	GQuark domain;
	int code;
	gboolean succeeded;
} Answer;

static void on_done(GBytes* result, const GError* error, gpointer user_data)
{
	Answer* answer = user_data;

	answer->calls++;
	answer->succeeded = result != NULL;

	g_clear_pointer(&answer->message, g_free);
	if (error != NULL)
	{
		answer->message = g_strdup(error->message);
		answer->domain = error->domain;
		answer->code = error->code;
	}
}

static void fixture_set_up(Fixture* fixture, gconstpointer user_data)
{
	const char* directory = g_getenv("SOFTHSM_FIXTURE_DIR");
	g_autofree char* fallback = NULL;
	g_autofree char* module = NULL;
	g_autoptr(GError) error = NULL;
	const char* modules[2] = { NULL, NULL };

	memset(fixture, 0, sizeof(*fixture));

	if (directory == NULL)
	{
		fallback = g_build_filename(g_get_tmp_dir(), "xdp-certificate-softhsm", NULL);
		if (g_file_test(fallback, G_FILE_TEST_IS_DIR))
			directory = fallback;
	}

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
	fixture->tokens = certificate_tokens_new(modules, &error);
	if (fixture->tokens == NULL)
	{
		g_test_skip(error->message);
		return;
	}

	fixture->candidates = certificate_tokens_enumerate(fixture->tokens, NULL, &error);
	g_assert_no_error(error);

	for (guint i = 0; i < fixture->candidates->len; i++)
	{
		CertificateCandidate* item = g_ptr_array_index(fixture->candidates, i);

		if (g_strcmp0(item->key_type, "RSA") == 0)
			fixture->rsa = item;
	}

	if (fixture->rsa == NULL)
	{
		g_test_skip("the fixture has no RSA key");
		return;
	}

	fixture->session = certificate_impl_session_new(
	    "/org/freedesktop/portal/desktop/session/decrypt/1", "org.example.App");
	certificate_impl_session_grant(fixture->session, fixture->rsa,
	                              CERTIFICATE_PURPOSE_CLIENT_AUTH, FALSE, TRUE, 300);

	/* Logged in up front: what is under test is the operation, and a PIN window
	 * would need a display. */
	g_assert_true(certificate_device_open(&fixture->session->device, fixture->tokens,
	                                      fixture->rsa, &error));
	g_assert_true(
	    certificate_device_login(&fixture->session->device, fixture->rsa, FIXTURE_PIN, &error));
	g_assert_no_error(error);
}

static void fixture_tear_down(Fixture* fixture, gconstpointer user_data)
{
	if (fixture->session != NULL)
	{
		certificate_impl_session_close(fixture->session);
		g_clear_object(&fixture->session);
	}

	g_clear_pointer(&fixture->candidates, g_ptr_array_unref);
	g_clear_pointer(&fixture->tokens, certificate_tokens_free);
}

/* One Decrypt, run to completion. @parameters_text and @ciphertext decide which
 * way it fails. */
static void decrypt(Fixture* fixture, const char* parameters_text, GBytes* ciphertext,
                    Answer* answer)
{
	g_autoptr(GVariant) parameters = g_variant_ref_sink(
	    g_variant_parse(G_VARIANT_TYPE_VARDICT, parameters_text, NULL, NULL, NULL));
	gint64 deadline;

	g_assert_nonnull(parameters);
	answer->calls = 0;

	certificate_broker_perform(fixture->tokens, fixture->session, TRUE, "RSA_OAEP", parameters,
	                           ciphertext, NULL, "Test application", NULL, on_done, answer);

	deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while (answer->calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	g_assert_cmpuint(answer->calls, ==, 1);
}

static GBytes* modulus_length_bytes(Fixture* fixture, guint8 fill)
{
	gsize length = fixture->rsa->key_size / 8;
	g_autofree guint8* bytes = g_malloc0(length);

	memset(bytes, fill, length);
	bytes[0] = 0x00; /* below the modulus, so the module gets as far as unpadding */

	return g_bytes_new(bytes, length);
}

/* TWO DIFFERENT INTERNAL CAUSES, ONE ANSWER. The first is a ciphertext of the
 * right length that is not a valid OAEP encoding; the second is a set of OAEP
 * parameters this module will not accept for this key. They come back from
 * PKCS#11 as different CKR_ values, and the caller must not be able to tell
 * them apart -- which is exactly the distinction that makes a v1.5 decryption
 * a Bleichenbacher oracle. */
static void test_every_failure_looks_the_same(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GBytes) garbage = NULL;
	Answer first = { 0 };
	Answer second = { 0 };

	if (fixture->session == NULL)
		return;

	garbage = modulus_length_bytes(fixture, 0x42);

	decrypt(fixture, "{'hash': <'SHA1'>}", garbage, &first);
	g_assert_false(first.succeeded);

	decrypt(fixture, "{'hash': <'SHA512'>}", garbage, &second);
	g_assert_false(second.succeeded);

	g_assert_cmpstr(first.message, ==, second.message);
	g_assert_cmpuint(first.domain, ==, second.domain);
	g_assert_cmpint(first.code, ==, second.code);

	/* And it says nothing about what the module said. */
	g_assert_null(strstr(first.message, "C_Decrypt"));
	g_assert_null(strstr(first.message, "CKR"));

	g_free(first.message);
	g_free(second.message);
}

/* THE BUDGET IS SPENT BY ATTEMPTS, NOT BY SUCCESSES. A failed decryption is
 * precisely the query an attacker wants; charging only for successful ones
 * would leave the budget unspent by the traffic it exists to bound. */
static void test_decrypt_budget(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GBytes) garbage = NULL;
	Answer answer = { 0 };

	if (fixture->session == NULL)
		return;

	garbage = modulus_length_bytes(fixture, 0x42);

	for (guint i = 0; i < CERTIFICATE_MAX_DECRYPTS_PER_GRANT; i++)
	{
		decrypt(fixture, "{'hash': <'SHA1'>}", garbage, &answer);
		g_assert_false(answer.succeeded);
		g_assert_cmpuint(fixture->session->decrypt_count, ==, i + 1);
	}

	/* One past the budget is refused with a DIFFERENT error, and it is
	 * supposed to be different: this one is not about the ciphertext, and a
	 * caller has to be able to tell "ask the user again" from "that did not
	 * decrypt". */
	decrypt(fixture, "{'hash': <'SHA1'>}", garbage, &answer);
	g_assert_false(answer.succeeded);
	g_assert_nonnull(strstr(answer.message, "new grant"));

	/* The card was never asked: the count did not move. */
	g_assert_cmpuint(fixture->session->decrypt_count, ==, CERTIFICATE_MAX_DECRYPTS_PER_GRANT);

	/* A fresh grant on the same session starts a fresh budget. Re-consenting
	 * is what buys more, which is the whole design: the user finds out. */
	certificate_impl_session_grant(fixture->session, fixture->rsa,
	                              CERTIFICATE_PURPOSE_CLIENT_AUTH, FALSE, TRUE, 300);
	g_assert_cmpuint(fixture->session->decrypt_count, ==, 0);

	decrypt(fixture, "{'hash': <'SHA1'>}", garbage, &answer);
	g_assert_false(answer.succeeded);
	g_assert_null(strstr(answer.message, "new grant"));

	g_free(answer.message);
}

/* A grant whose operation_policy did not include decrypt is refused before the
 * mechanism is even parsed, and that refusal is not charged to the budget. */
static void test_grant_without_decrypt(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GBytes) garbage = NULL;
	Answer answer = { 0 };

	if (fixture->session == NULL)
		return;

	garbage = modulus_length_bytes(fixture, 0x42);

	certificate_impl_session_grant(fixture->session, fixture->rsa,
	                              CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE, FALSE, 300);

	decrypt(fixture, "{'hash': <'SHA1'>}", garbage, &answer);
	g_assert_false(answer.succeeded);
	g_assert_cmpuint(fixture->session->decrypt_count, ==, 0);

	g_free(answer.message);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

#define ADD(path, function) \
	g_test_add(path, Fixture, NULL, fixture_set_up, function, fixture_tear_down)

	ADD("/decrypt/every-failure-looks-the-same", test_every_failure_looks_the_same);
	ADD("/decrypt/budget", test_decrypt_budget);
	ADD("/decrypt/grant-without-decrypt", test_grant_without_decrypt);

#undef ADD

	return g_test_run();
}
