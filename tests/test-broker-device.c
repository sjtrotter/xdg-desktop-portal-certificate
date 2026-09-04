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
#include <glib/gstdio.h>
#include <string.h>

#include "broker/device.h"
#include "fixture-util.h"
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

	{
		g_autofree char* module_path = g_build_filename(directory, "module-path", NULL);

		if (!g_file_get_contents(module_path, &module, NULL, NULL))
		{
			g_test_skip("the SoftHSM fixture has no module-path; rebuild it");
			return;
		}
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

	certificate_test_verify_signature(candidate, algorithm, digest, digest_length, signature,
	                                  g_strcmp0(mechanism_name, "ECDSA") == 0);

	certificate_device_close(&device);
	certificate_mechanism_clear(&mechanism);
}

/* A SECOND AcquireCredential ON A LIVE SESSION IS A NEW CREDENTIAL, and the
 * open device has to notice. It used to return early on "a module is loaded",
 * so the next Sign went to the PREVIOUS grant's private key handle -- with the
 * login state of the previous grant, so no PIN window either. The application
 * had been handed certificate B and got a signature only certificate A's key
 * could have made.
 *
 * This is the device half: rebinding closes the old session, forgets the key
 * handle and forgets the login. The end-to-end half -- that the signature then
 * verifies against certificate B -- is tests/test-broker-regrant.c. */
static void test_regrant_rebinds_the_device(Fixture* fixture, gconstpointer user_data)
{
	CertificateCandidate* first = candidate_of_type(fixture, "RSA");
	CertificateCandidate* second = candidate_of_type(fixture, "EC");
	CertificateDevice device = { 0 };
	g_autoptr(GError) error = NULL;
	CK_SESSION_HANDLE first_session;
	CK_OBJECT_HANDLE first_key;

	if (fixture->tokens == NULL)
		return;

	if (first == NULL || second == NULL)
	{
		g_test_skip("the fixture needs both an RSA and an EC key");
		return;
	}

	g_assert_true(certificate_device_open(&device, fixture->tokens, first, &error));
	g_assert_no_error(error);
	g_assert_true(certificate_device_login(&device, first, FIXTURE_PIN, &error));
	g_assert_no_error(error);
	g_assert_true(device.logged_in);
	g_assert_cmpuint(device.private_key, !=, (guint) CK_INVALID_HANDLE);

	first_session = device.session;
	first_key = device.private_key;

	/* Opening for the SAME candidate is still a no-op: the login is not thrown
	 * away by every operation, which is the whole point of "one PIN per
	 * grant". */
	g_assert_true(certificate_device_open(&device, fixture->tokens, first, &error));
	g_assert_no_error(error);
	g_assert_true(device.logged_in);
	g_assert_cmpuint(device.session, ==, first_session);
	g_assert_cmpuint(device.private_key, ==, first_key);

	/* Opening for a DIFFERENT one is a rebind. */
	g_assert_true(certificate_device_open(&device, fixture->tokens, second, &error));
	g_assert_no_error(error);
	g_assert_false(device.logged_in);
	g_assert_cmpuint(device.session, !=, first_session);
	g_assert_cmpuint(device.private_key, !=, first_key);

	/* And the new grant's own login finds the new grant's key. */
	g_assert_true(certificate_device_login(&device, second, FIXTURE_PIN, &error));
	g_assert_no_error(error);
	g_assert_cmpuint(device.private_key, !=, (guint) CK_INVALID_HANDLE);
	g_assert_cmpuint(device.private_key, !=, first_key);

	certificate_device_close(&device);
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

/* Encrypt to the certificate's public key with RSA-OAEP, using openssl(1).
 *
 * WHY A SUBPROCESS AND NOT GNUTLS. The ciphertext has to come from something
 * that is not this backend -- if the two disagree about how OAEP is spelled,
 * the round trip has to fail rather than agree with itself. GnuTLS is here
 * already and would have done, except that its RSA-OAEP will not use SHA-1 and
 * SoftHSM 2.x will not use anything else, so the two cannot meet. openssl
 * does both, is present wherever a card is being tested, and being a separate
 * implementation is the property that was wanted in the first place.
 *
 * Returns NULL and skips the test when openssl is not installed or refuses. */
static GBytes* oaep_encrypt(CertificateCandidate* candidate, const char* hash_name,
                            const guint8* label, gsize label_length, const char* plaintext)
{
	g_autofree char* directory = NULL;
	g_autofree char* certificate_path = NULL;
	g_autofree char* pubkey_path = NULL;
	g_autofree char* plaintext_path = NULL;
	g_autofree char* ciphertext_path = NULL;
	g_autofree char* md_option = NULL;
	g_autofree char* mgf_option = NULL;
	g_autofree char* label_option = NULL;
	g_autoptr(GError) error = NULL;
	g_autofree char* contents = NULL;
	gsize length = 0;
	GBytes* out = NULL;
	int status = 0;

	{
		g_autofree char* openssl = g_find_program_in_path("openssl");

		if (openssl != NULL)
			goto have_openssl;
	}

	{
		g_test_skip("openssl(1) is not installed; it is what produces the OAEP ciphertext");
		return NULL;
	}

have_openssl:

	directory = g_dir_make_tmp("xdp-certificate-oaep-XXXXXX", &error);
	g_assert_no_error(error);

	certificate_path = g_build_filename(directory, "certificate.der", NULL);
	pubkey_path = g_build_filename(directory, "public.pem", NULL);
	plaintext_path = g_build_filename(directory, "plaintext.bin", NULL);
	ciphertext_path = g_build_filename(directory, "ciphertext.bin", NULL);

	g_assert_true(g_file_set_contents(certificate_path, (const char*) candidate->der->data,
	                                  candidate->der->len, &error));
	g_assert_no_error(error);
	g_assert_true(g_file_set_contents(plaintext_path, plaintext, (gssize) strlen(plaintext),
	                                  &error));
	g_assert_no_error(error);

	{
		const char* argv[] = { "openssl",     "x509", "-inform", "DER",  "-in",
			                   certificate_path, "-pubkey", "-noout", "-out", pubkey_path,
			                   NULL };

		g_assert_true(g_spawn_sync(NULL, (char**) argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
		                           NULL, NULL, &status, &error));
		g_assert_no_error(error);
		g_assert_cmpint(status, ==, 0);
	}

	md_option = g_strdup_printf("rsa_oaep_md:%s", hash_name);
	mgf_option = g_strdup_printf("rsa_mgf1_md:%s", hash_name);

	if (label != NULL && label_length > 0)
	{
		GString* hex = g_string_new("rsa_oaep_label:");

		for (gsize i = 0; i < label_length; i++)
			g_string_append_printf(hex, "%02x", label[i]);

		label_option = g_string_free(hex, FALSE);
	}

	{
		const char* argv[] = { "openssl",
			                   "pkeyutl",
			                   "-encrypt",
			                   "-pubin",
			                   "-inkey",
			                   pubkey_path,
			                   "-pkeyopt",
			                   "rsa_padding_mode:oaep",
			                   "-pkeyopt",
			                   md_option,
			                   "-pkeyopt",
			                   mgf_option,
			                   label_option != NULL ? "-pkeyopt" : "-in",
			                   label_option != NULL ? label_option : plaintext_path,
			                   label_option != NULL ? "-in" : "-out",
			                   label_option != NULL ? plaintext_path : ciphertext_path,
			                   label_option != NULL ? "-out" : NULL,
			                   label_option != NULL ? ciphertext_path : NULL,
			                   NULL };

		if (!g_spawn_sync(NULL, (char**) argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL,
		                  &status, &error) ||
		    status != 0)
		{
			g_test_skip_printf("openssl would not encrypt with RSA-OAEP/%s%s", hash_name,
			                   label_option != NULL ? " and a label" : "");
			g_clear_error(&error);
			goto out;
		}
	}

	if (g_file_get_contents(ciphertext_path, &contents, &length, &error))
		out = g_bytes_new(contents, length);
	else
		g_assert_no_error(error);

out:
	g_unlink(certificate_path);
	g_unlink(pubkey_path);
	g_unlink(plaintext_path);
	g_unlink(ciphertext_path);
	g_rmdir(directory);

	return out;
}

/* Set up the RSA candidate's device, logged in, or skip. */
static CertificateCandidate* logged_in_rsa(Fixture* fixture, CertificateDevice* device)
{
	CertificateCandidate* candidate = NULL;
	g_autoptr(GError) error = NULL;

	if (fixture->tokens == NULL)
		return NULL;

	candidate = candidate_of_type(fixture, "RSA");
	if (candidate == NULL)
	{
		g_test_skip("the fixture has no RSA key");
		return NULL;
	}

	g_assert_true(certificate_device_open(device, fixture->tokens, candidate, &error));
	g_assert_no_error(error);
	g_assert_true(certificate_device_login(device, candidate, FIXTURE_PIN, &error));
	g_assert_no_error(error);

	return candidate;
}

static CertificateMechanism oaep_mechanism(CertificateCandidate* candidate, const char* parameters_text)
{
	g_autoptr(GVariant) parameters =
	    g_variant_parse(G_VARIANT_TYPE_VARDICT, parameters_text, NULL, NULL, NULL);
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;

	g_assert_nonnull(parameters);
	g_assert_true(certificate_mechanism_parse("RSA_OAEP", parameters, candidate->key_type,
	                                          candidate->key_size, TRUE, &mechanism, &error));
	g_assert_no_error(error);

	return mechanism;
}

/* THE ROUND TRIP. GnuTLS encrypts with RSA-OAEP to the public key in the
 * certificate the token handed back; this backend decrypts with the private key
 * on the token; the plaintext has to come back byte for byte. The ciphertext
 * comes from an implementation that is not this one, which is the point: if the
 * two disagree about how OAEP is spelled, the round trip fails.
 *
 * SHA-1 AND NO LABEL, because that is all SoftHSM 2.x implements -- it refuses
 * any other hashAlg, any other mgf, and any pSourceData at C_DecryptInit. That
 * is a limitation of the software token and not of this backend or of the
 * interface, and it is why the SHA-256 mapping and the label are covered by
 * tests/test-mechanism.c against CK_RSA_PKCS_OAEP_PARAMS rather than against a
 * module. A card that implements the rest is docs/TESTING.md tier 3.
 *
 * The labelled half runs anyway and skips itself if the module says no, so it
 * starts covering the label the day it runs against something that has one. */
static void test_oaep_round_trip(Fixture* fixture, gconstpointer user_data)
{
	static const char* const plaintext = "a session key would go here";
	static const guint8 label[] = { 'x', 'd', 'p', '-', 'c', 'e', 'r', 't' };
	CertificateDevice device = { 0 };
	CertificateCandidate* candidate = logged_in_rsa(fixture, &device);
	CertificateMechanism mechanism;
	g_autoptr(GBytes) ciphertext = NULL;
	g_autoptr(GBytes) labelled_ciphertext = NULL;
	g_autoptr(GBytes) payload = NULL;
	g_autoptr(GBytes) plain = NULL;
	g_autoptr(GError) error = NULL;

	if (candidate == NULL)
		return;

	ciphertext = oaep_encrypt(candidate, "sha1", NULL, 0, plaintext);
	if (ciphertext == NULL)
	{
		certificate_device_close(&device);
		return;
	}

	mechanism = oaep_mechanism(candidate, "{'hash': <'SHA1'>}");
	payload = certificate_mechanism_prepare(&mechanism, ciphertext, &error);
	g_assert_no_error(error);

	plain = certificate_device_perform(&device, TRUE, &mechanism, payload, &error);
	g_assert_no_error(error);
	g_assert_nonnull(plain);
	g_assert_cmpuint(g_bytes_get_size(plain), ==, strlen(plaintext));
	g_assert_cmpint(memcmp(g_bytes_get_data(plain, NULL), plaintext, strlen(plaintext)), ==, 0);
	certificate_mechanism_clear(&mechanism);
	g_clear_pointer(&payload, g_bytes_unref);
	g_clear_pointer(&plain, g_bytes_unref);

	/* And with a label on both sides, where the module has one. */
	labelled_ciphertext = oaep_encrypt(candidate, "sha1", label, sizeof(label), plaintext);
	if (labelled_ciphertext != NULL)
	{
		mechanism = oaep_mechanism(
		    candidate, "{'hash': <'SHA1'>, 'label': <[byte 0x78, 0x64, 0x70, 0x2d, "
		               "0x63, 0x65, 0x72, 0x74]>}");
		payload = certificate_mechanism_prepare(&mechanism, labelled_ciphertext, &error);
		g_assert_no_error(error);

		plain = certificate_device_perform(&device, TRUE, &mechanism, payload, &error);
		if (plain == NULL)
		{
			g_test_message("this module does not implement a labelled OAEP: %s",
			               error->message);
			g_clear_error(&error);
		}
		else
		{
			g_assert_cmpint(memcmp(g_bytes_get_data(plain, NULL), plaintext, strlen(plaintext)),
			                ==, 0);
		}

		certificate_mechanism_clear(&mechanism);
	}

	certificate_device_close(&device);
}

/* A ciphertext that is not one modulus long never reaches the card, and one
 * that is the right length but is not a valid OAEP encoding comes back as a
 * failure rather than as a plaintext.
 *
 * The length check is the one the frontend cannot make: it does not know the
 * modulus. Making the two failures INDISTINGUISHABLE TO THE CALLER is
 * broker/operations.c's job, not this layer's, and tests/test-broker-decrypt.c
 * is what asserts it. */
static void test_oaep_bad_input_is_refused(Fixture* fixture, gconstpointer user_data)
{
	static const char* const plaintext = "a session key would go here";
	CertificateDevice device = { 0 };
	CertificateCandidate* candidate = logged_in_rsa(fixture, &device);
	CertificateMechanism mechanism;
	g_autoptr(GBytes) ciphertext = NULL;
	g_autoptr(GBytes) payload = NULL;
	g_autoptr(GError) error = NULL;

	if (candidate == NULL)
		return;

	ciphertext = oaep_encrypt(candidate, "sha1", NULL, 0, plaintext);
	if (ciphertext == NULL)
	{
		certificate_device_close(&device);
		return;
	}

	/* The right length, and not a ciphertext. */
	{
		gsize length = candidate->key_size / 8;
		g_autofree guint8* garbage = g_malloc0(length);
		g_autoptr(GBytes) not_a_ciphertext = NULL;

		memset(garbage, 0x42, length);
		garbage[0] = 0x00; /* keep it below the modulus */
		not_a_ciphertext = g_bytes_new(garbage, length);

		mechanism = oaep_mechanism(candidate, "{'hash': <'SHA1'>}");
		payload = certificate_mechanism_prepare(&mechanism, not_a_ciphertext, &error);
		g_assert_no_error(error);
		g_assert_null(certificate_device_perform(&device, TRUE, &mechanism, payload, &error));
		g_assert_nonnull(error);
		g_clear_error(&error);
		certificate_mechanism_clear(&mechanism);
		g_clear_pointer(&payload, g_bytes_unref);
	}

	/* A byte short. Refused while the payload is prepared; the card is never
	 * asked. */
	{
		g_autoptr(GBytes) truncated =
		    g_bytes_new_from_bytes(ciphertext, 0, g_bytes_get_size(ciphertext) - 1);

		mechanism = oaep_mechanism(candidate, "{'hash': <'SHA1'>}");
		g_assert_null(certificate_mechanism_prepare(&mechanism, truncated, &error));
		g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
		g_clear_error(&error);
		certificate_mechanism_clear(&mechanism);
	}

	certificate_device_close(&device);
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
		g_assert_true(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH,
		                                          CERTIFICATE_OPERATION_SIGN));

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
	ADD("/device/oaep-round-trip", test_oaep_round_trip);
	ADD("/device/oaep-bad-input-is-refused", test_oaep_bad_input_is_refused);
	ADD("/device/wrong-pin", test_wrong_pin);
	ADD("/device/regrant-rebinds", test_regrant_rebinds_the_device);

#undef ADD

	return g_test_run();
}
