/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * The cryptographic path, end to end, against a real PKCS#11 module: discovery,
 * C_OpenSession, C_Login, the mechanism mapping, C_Sign, and a verification of
 * the signature against the certificate the token handed back.
 *
 * SKIPPED unless a SoftHSM fixture exists. tools/softhsm-fixture.sh builds one;
 * docs/TESTING.md says how. A SOFTWARE TOKEN IS A REHEARSAL, NOT A TEST OF THE
 * HARDWARE -- the card path is the author's, in docs/TESTING.md -- but it is the
 * only automated coverage C_Sign can have, and it catches the whole class of
 * mistake where a DigestInfo prefix or a PSS parameter is wrong.
 */

#include <glib.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <string.h>

#include "broker/device.h"
#include "tokens/filter.h"

#define FIXTURE_PIN "123456"

typedef struct
{
	CertificateTokens* tokens;
	GPtrArray* candidates;
} Fixture;

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

static void fixture_set_up(Fixture* fixture, gconstpointer user_data)
{
	g_autofree char* directory = fixture_directory();
	g_autofree char* config = NULL;
	g_autofree char* module = NULL;
	g_autoptr(GError) error = NULL;
	const char* modules[2] = { NULL, NULL };

	fixture->tokens = NULL;
	fixture->candidates = NULL;

	if (directory == NULL)
	{
		g_test_skip("no SoftHSM fixture; run tools/softhsm-fixture.sh");
		return;
	}

	config = g_build_filename(directory, "softhsm2.conf", NULL);
	if (!g_file_get_contents(g_build_filename(directory, "module-path", NULL), &module, NULL,
	                         NULL))
	{
		g_test_skip("the SoftHSM fixture has no module-path; rebuild it");
		return;
	}

	g_setenv("SOFTHSM2_CONF", config, TRUE);

	modules[0] = module;
	fixture->tokens = certificate_tokens_new(modules, &error);
	if (fixture->tokens == NULL)
	{
		g_test_skip(error->message);
		return;
	}

	fixture->candidates = certificate_tokens_enumerate(fixture->tokens, NULL, &error);
	g_assert_no_error(error);
}

static void fixture_tear_down(Fixture* fixture, gconstpointer user_data)
{
	g_clear_pointer(&fixture->candidates, g_ptr_array_unref);
	g_clear_pointer(&fixture->tokens, certificate_tokens_free);
}

static CertificateCandidate* candidate_of_type(Fixture* fixture, const char* key_type)
{
	if (fixture->candidates == NULL)
		return NULL;

	for (guint i = 0; i < fixture->candidates->len; i++)
	{
		CertificateCandidate* candidate = g_ptr_array_index(fixture->candidates, i);

		if (g_strcmp0(candidate->key_type, key_type) == 0)
			return candidate;
	}

	return NULL;
}

/* Verify with GnuTLS, from the certificate the token handed back -- not from
 * the key the fixture script generated. If those two ever disagree, the wrong
 * key signed. */
static void verify_signature(CertificateCandidate* candidate, gnutls_sign_algorithm_t algorithm,
                             const guint8* digest, gsize digest_length, GBytes* signature,
                             gboolean ecdsa)
{
	gnutls_x509_crt_t crt = NULL;
	gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t der = { candidate->der->data, candidate->der->len };
	gnutls_datum_t hash = { (unsigned char*) digest, (unsigned int) digest_length };
	gnutls_datum_t sig;
	g_autoptr(GBytes) encoded = NULL;
	g_autoptr(GError) error = NULL;
	int rc;

	if (ecdsa)
	{
		gsize raw_length = 0;
		const guint8* raw = g_bytes_get_data(signature, &raw_length);

		/* PKCS#11 produces r||s; X.509 wants an ECDSA-Sig-Value. */
		encoded = certificate_ecdsa_raw_to_der(raw, raw_length, &error);
		g_assert_no_error(error);
		sig.data = (unsigned char*) g_bytes_get_data(encoded, NULL);
		sig.size = (unsigned int) g_bytes_get_size(encoded);
	}
	else
	{
		sig.data = (unsigned char*) g_bytes_get_data(signature, NULL);
		sig.size = (unsigned int) g_bytes_get_size(signature);
	}

	g_assert_cmpint(gnutls_x509_crt_init(&crt), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_import(crt, &der, GNUTLS_X509_FMT_DER), ==, 0);
	g_assert_cmpint(gnutls_pubkey_init(&pubkey), ==, 0);
	g_assert_cmpint(gnutls_pubkey_import_x509(pubkey, crt, 0), ==, 0);

	rc = gnutls_pubkey_verify_hash2(pubkey, algorithm, 0, &hash, &sig);

	gnutls_pubkey_deinit(pubkey);
	gnutls_x509_crt_deinit(crt);

	if (rc < 0)
		g_error("the signature did not verify: %s", gnutls_strerror(rc));
}

static void sign_and_verify(Fixture* fixture, const char* key_type, const char* mechanism_name,
                            const char* hash_name, gnutls_sign_algorithm_t algorithm)
{
	CertificateCandidate* candidate = candidate_of_type(fixture, key_type);
	CertificateDevice device = { 0 };
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) parameters = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(GBytes) payload = NULL;
	g_autoptr(GBytes) signature = NULL;
	g_autofree char* text = NULL;
	guint8 digest[64];
	gsize digest_length = sizeof(digest);
	g_autoptr(GChecksum) checksum = NULL;
	g_autofree char* parameters_text = NULL;

	if (fixture->tokens == NULL)
		return;

	if (candidate == NULL)
	{
		g_test_skip("the fixture has no key of this type");
		return;
	}

	parameters_text = g_strdup_printf("{'hash': <'%s'>}", hash_name);
	parameters = g_variant_parse(G_VARIANT_TYPE_VARDICT, parameters_text, NULL, NULL, NULL);
	g_assert_nonnull(parameters);

	g_assert_true(certificate_mechanism_parse(mechanism_name, parameters, candidate->key_type,
	                                          candidate->key_size, FALSE, &mechanism, &error));
	g_assert_no_error(error);

	text = g_strdup_printf("xdg-desktop-portal-certificate device test %" G_GINT64_FORMAT,
	                       g_get_real_time());
	checksum = g_checksum_new(g_strcmp0(hash_name, "SHA384") == 0 ? G_CHECKSUM_SHA384
	                                                              : G_CHECKSUM_SHA256);
	g_checksum_update(checksum, (const guchar*) text, strlen(text));
	g_checksum_get_digest(checksum, digest, &digest_length);

	data = g_bytes_new(digest, digest_length);
	payload = certificate_mechanism_prepare(&mechanism, data, &error);
	g_assert_no_error(error);

	g_assert_true(certificate_device_open(&device, fixture->tokens, candidate, &error));
	g_assert_no_error(error);

	/* The private key is invisible on SoftHSM until the login, which is exactly
	 * the case discovery has to survive. */
	g_assert_true(certificate_device_login(&device, candidate, FIXTURE_PIN, &error));
	g_assert_no_error(error);
	g_assert_cmpuint(device.private_key, !=, (guint) CK_INVALID_HANDLE);

	signature = certificate_device_perform(&device, FALSE, &mechanism, payload, &error);
	g_assert_no_error(error);
	g_assert_nonnull(signature);
	g_assert_cmpuint(g_bytes_get_size(signature), >, 0);

	verify_signature(candidate, algorithm, digest, digest_length, signature,
	                 g_strcmp0(mechanism_name, "ECDSA") == 0);

	certificate_device_close(&device);
	certificate_mechanism_clear(&mechanism);
}

static void test_rsa_pkcs1(Fixture* fixture, gconstpointer user_data)
{
	sign_and_verify(fixture, "RSA", "RSA_PKCS1_V1_5", "SHA256", GNUTLS_SIGN_RSA_SHA256);
}

static void test_rsa_pkcs1_sha384(Fixture* fixture, gconstpointer user_data)
{
	sign_and_verify(fixture, "RSA", "RSA_PKCS1_V1_5", "SHA384", GNUTLS_SIGN_RSA_SHA384);
}

static void test_rsa_pss(Fixture* fixture, gconstpointer user_data)
{
	sign_and_verify(fixture, "RSA", "RSA_PSS", "SHA256", GNUTLS_SIGN_RSA_PSS_SHA256);
}

static void test_ecdsa(Fixture* fixture, gconstpointer user_data)
{
	sign_and_verify(fixture, "EC", "ECDSA", "SHA256", GNUTLS_SIGN_ECDSA_SHA256);
}

/* Decrypt is on the interface and is implemented, so it gets exercised rather
 * than being a code path nobody has run. The ciphertext is made with the PUBLIC
 * key out of the certificate the token returned, so a wrong key would fail
 * here as loudly as a wrong signature does above. */
static void test_decrypt(Fixture* fixture, gconstpointer user_data)
{
	CertificateCandidate* candidate = NULL;
	CertificateDevice device = { 0 };
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) parameters = NULL;
	g_autoptr(GBytes) ciphertext = NULL;
	g_autoptr(GBytes) plaintext = NULL;
	gnutls_x509_crt_t crt = NULL;
	gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t der;
	gnutls_datum_t clear = { (unsigned char*) "portal decrypt test", 19 };
	gnutls_datum_t sealed = { NULL, 0 };

	if (fixture->tokens == NULL)
		return;

	candidate = candidate_of_type(fixture, "RSA");
	if (candidate == NULL || !candidate->can_decrypt)
	{
		g_test_skip("the fixture has no decrypt-capable RSA key");
		return;
	}

	der.data = candidate->der->data;
	der.size = candidate->der->len;

	g_assert_cmpint(gnutls_x509_crt_init(&crt), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_import(crt, &der, GNUTLS_X509_FMT_DER), ==, 0);
	g_assert_cmpint(gnutls_pubkey_init(&pubkey), ==, 0);
	g_assert_cmpint(gnutls_pubkey_import_x509(pubkey, crt, 0), ==, 0);
	g_assert_cmpint(gnutls_pubkey_encrypt_data(pubkey, 0, &clear, &sealed), ==, 0);
	gnutls_pubkey_deinit(pubkey);
	gnutls_x509_crt_deinit(crt);

	ciphertext = g_bytes_new(sealed.data, sealed.size);
	gnutls_free(sealed.data);

	parameters = g_variant_parse(G_VARIANT_TYPE_VARDICT, "{}", NULL, NULL, NULL);
	g_assert_true(certificate_mechanism_parse("RSA_PKCS1_V1_5", parameters, candidate->key_type,
	                                          candidate->key_size, TRUE, &mechanism, &error));
	g_assert_no_error(error);

	g_assert_true(certificate_device_open(&device, fixture->tokens, candidate, &error));
	g_assert_true(certificate_device_login(&device, candidate, FIXTURE_PIN, &error));

	plaintext = certificate_device_perform(&device, TRUE, &mechanism, ciphertext, &error);
	g_assert_no_error(error);
	g_assert_nonnull(plaintext);
	g_assert_cmpuint(g_bytes_get_size(plaintext), ==, clear.size);
	g_assert_cmpint(memcmp(g_bytes_get_data(plaintext, NULL), clear.data, clear.size), ==, 0);

	certificate_device_close(&device);
	certificate_mechanism_clear(&mechanism);
}

/* The wrong PIN must come back as PIN_INCORRECT and nothing else: collapsing
 * that into a generic failure is how a user blocks a card while being told
 * "authentication failed". This spends one of the token's attempts, which is
 * why it runs against a fixture and never against a card. */
static void test_wrong_pin(Fixture* fixture, gconstpointer user_data)
{
	CertificateCandidate* candidate = NULL;
	CertificateDevice device = { 0 };
	g_autoptr(GError) error = NULL;

	if (fixture->tokens == NULL)
		return;

	candidate = candidate_of_type(fixture, "RSA");
	if (candidate == NULL)
	{
		g_test_skip("the fixture has no RSA key");
		return;
	}

	g_assert_true(certificate_device_open(&device, fixture->tokens, candidate, &error));
	g_assert_false(certificate_device_login(&device, candidate, "000000", &error));
	g_assert_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT);
	g_clear_error(&error);

	/* And the right PIN still works afterwards: a failed attempt must not leave
	 * the session unusable. */
	g_assert_true(certificate_device_login(&device, candidate, FIXTURE_PIN, &error));
	g_assert_no_error(error);

	certificate_device_close(&device);
}

/* Discovery has to see both certificates on the token WITHOUT logging in. */
static void test_discovery_without_login(Fixture* fixture, gconstpointer user_data)
{
	gboolean saw_rsa = FALSE;
	gboolean saw_ec = FALSE;

	if (fixture->tokens == NULL)
		return;

	g_assert_nonnull(fixture->candidates);
	g_assert_cmpuint(fixture->candidates->len, >=, 2);

	for (guint i = 0; i < fixture->candidates->len; i++)
	{
		CertificateCandidate* candidate = g_ptr_array_index(fixture->candidates, i);

		g_assert_nonnull(candidate->certificate_id);
		g_assert_nonnull(candidate->subject_display);
		g_assert_nonnull(candidate->supported_mechanisms);
		g_assert_true(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH));

		if (g_strcmp0(candidate->key_type, "RSA") == 0)
			saw_rsa = TRUE;
		if (g_strcmp0(candidate->key_type, "EC") == 0)
			saw_ec = TRUE;
	}

	g_assert_true(saw_rsa);
	g_assert_true(saw_ec);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

#define ADD(path, function) \
	g_test_add(path, Fixture, NULL, fixture_set_up, function, fixture_tear_down)

	ADD("/device/discovery-without-login", test_discovery_without_login);
	ADD("/device/rsa-pkcs1-sha256", test_rsa_pkcs1);
	ADD("/device/rsa-pkcs1-sha384", test_rsa_pkcs1_sha384);
	ADD("/device/rsa-pss-sha256", test_rsa_pss);
	ADD("/device/ecdsa-sha256", test_ecdsa);
	ADD("/device/decrypt", test_decrypt);
	ADD("/device/wrong-pin", test_wrong_pin);

#undef ADD

	return g_test_run();
}
