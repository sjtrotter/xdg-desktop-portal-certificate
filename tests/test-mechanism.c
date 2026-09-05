/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * The mechanism mapping and its parameter validation. The frontend cannot do
 * these checks: it does not know the modulus size, so it cannot know that a
 * salt does not fit.
 */

#include <glib.h>
#include <string.h>

#include "broker/mechanism.h"

static GVariant* params(const char* text)
{
	GVariant* value = g_variant_parse(G_VARIANT_TYPE_VARDICT, text, NULL, NULL, NULL);

	g_assert_nonnull(value);
	return value;
}

static void test_rsa_pkcs1_maps_and_wraps(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	guint8 digest[32];
	g_autoptr(GBytes) data = NULL;
	g_autoptr(GBytes) prepared = NULL;
	gsize size = 0;
	const guint8* bytes = NULL;
	static const guint8 sha256_prefix[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
		                                    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
		                                    0x01, 0x05, 0x00, 0x04, 0x20 };

	g_assert_true(certificate_mechanism_parse("RSA_PKCS1_V1_5", parameters, "RSA", 2048, FALSE,
	                                          &mechanism, &error));
	g_assert_no_error(error);
	g_assert_cmpuint(mechanism.type, ==, CKM_RSA_PKCS);

	memset(digest, 0xab, sizeof(digest));
	data = g_bytes_new(digest, sizeof(digest));

	/* THE DIGESTINFO IS BUILT HERE. The caller supplies the bare digest and
	 * never a DigestInfo, which is what makes "data is always the digest" a
	 * rule rather than a convention. */
	prepared = certificate_mechanism_prepare(&mechanism, data, &error);
	g_assert_no_error(error);
	g_assert_nonnull(prepared);

	bytes = g_bytes_get_data(prepared, &size);
	g_assert_cmpuint(size, ==, sizeof(sha256_prefix) + sizeof(digest));
	g_assert_cmpint(memcmp(bytes, sha256_prefix, sizeof(sha256_prefix)), ==, 0);
	g_assert_cmpint(memcmp(bytes + sizeof(sha256_prefix), digest, sizeof(digest)), ==, 0);

	certificate_mechanism_clear(&mechanism);
}

/* A digest that is not the length the named hash produces is refused. Raw v1.5
 * padding of an arbitrary blob is a much larger thing to consent to than a
 * signature over a digest of known length. */
static void test_wrong_digest_length_is_refused(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	guint8 digest[20];
	g_autoptr(GBytes) data = NULL;
	GBytes* prepared = NULL;

	g_assert_true(certificate_mechanism_parse("RSA_PKCS1_V1_5", parameters, "RSA", 2048, FALSE,
	                                          &mechanism, &error));

	memset(digest, 0, sizeof(digest));
	data = g_bytes_new(digest, sizeof(digest));

	prepared = certificate_mechanism_prepare(&mechanism, data, &error);
	g_assert_null(prepared);
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);

	certificate_mechanism_clear(&mechanism);
}

/* `hash` is REQUIRED. Without it there is no way to know what the bytes are, and
 * guessing from their length is how a SHA-256 digest becomes a SHA3-256 one. */
static void test_hash_is_required(void)
{
	g_autoptr(GVariant) parameters = params("{}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;

	g_assert_false(certificate_mechanism_parse("RSA_PKCS1_V1_5", parameters, "RSA", 2048, FALSE,
	                                           &mechanism, &error));
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
}

static void test_mechanism_must_match_the_key(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) rsa_on_ec = NULL;
	g_autoptr(GError) ecdsa_on_rsa = NULL;

	g_assert_false(certificate_mechanism_parse("RSA_PKCS1_V1_5", parameters, "EC", 256, FALSE,
	                                           &mechanism, &rsa_on_ec));
	g_assert_error(rsa_on_ec, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);

	g_assert_false(certificate_mechanism_parse("ECDSA", parameters, "RSA", 2048, FALSE, &mechanism,
	                                           &ecdsa_on_rsa));
	g_assert_error(ecdsa_on_rsa, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
}

static void test_unknown_mechanism_and_hash(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	g_autoptr(GVariant) bad_hash = params("{'hash': <'MD5'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) unknown = NULL;
	g_autoptr(GError) hash_error = NULL;

	g_assert_false(certificate_mechanism_parse("RSA_RAW", parameters, "RSA", 2048, FALSE,
	                                           &mechanism, &unknown));
	g_assert_error(unknown, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);

	g_assert_false(certificate_mechanism_parse("RSA_PSS", bad_hash, "RSA", 2048, FALSE, &mechanism,
	                                           &hash_error));
	g_assert_error(hash_error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
}

static void test_pss_defaults_and_limits(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	g_autoptr(GVariant) big_salt = params("{'hash': <'SHA512'>, 'salt_length': <uint32 200>}");
	g_autoptr(GVariant) explicit_mgf = params("{'hash': <'SHA256'>, 'mgf': <'MGF1-SHA1'>}");
	g_autoptr(GVariant) bad_mgf = params("{'hash': <'SHA256'>, 'mgf': <'MGF2'>}");
	g_autoptr(GVariant) bad_salt_type = params("{'hash': <'SHA256'>, 'salt_length': <'32'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	g_autoptr(GError) too_big = NULL;
	g_autoptr(GError) mgf_error = NULL;
	g_autoptr(GError) salt_error = NULL;

	/* Default salt length is the hash length, and MGF1 over the same hash. */
	g_assert_true(
	    certificate_mechanism_parse("RSA_PSS", parameters, "RSA", 2048, FALSE, &mechanism, &error));
	g_assert_no_error(error);
	g_assert_cmpuint(mechanism.type, ==, CKM_RSA_PKCS_PSS);
	g_assert_true(mechanism.has_pss);
	g_assert_cmpuint(mechanism.pss.hashAlg, ==, CKM_SHA256);
	g_assert_cmpuint(mechanism.pss.mgf, ==, CKG_MGF1_SHA256);
	g_assert_cmpuint(mechanism.pss.sLen, ==, 32);
	certificate_mechanism_clear(&mechanism);

	/* RFC 8017 9.1.1 step 3: emLen >= hLen + sLen + 2. A 1024-bit key holds
	 * 128 bytes; 64 + 200 + 2 does not fit. THE FRONTEND CANNOT CHECK THIS. */
	g_assert_false(certificate_mechanism_parse("RSA_PSS", big_salt, "RSA", 1024, FALSE, &mechanism,
	                                           &too_big));
	g_assert_error(too_big, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);

	g_assert_true(certificate_mechanism_parse("RSA_PSS", explicit_mgf, "RSA", 2048, FALSE,
	                                          &mechanism, &error));
	g_assert_cmpuint(mechanism.pss.mgf, ==, CKG_MGF1_SHA1);
	certificate_mechanism_clear(&mechanism);

	/* An MGF this backend does not know is refused, not forwarded: pParameter
	 * goes straight into the module. */
	g_assert_false(certificate_mechanism_parse("RSA_PSS", bad_mgf, "RSA", 2048, FALSE, &mechanism,
	                                           &mgf_error));
	g_assert_error(mgf_error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);

	g_assert_false(certificate_mechanism_parse("RSA_PSS", bad_salt_type, "RSA", 2048, FALSE,
	                                           &mechanism, &salt_error));
	g_assert_error(salt_error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);

	/* THE SPELLING IS THE INTERFACE'S: "MGF1-<hash>", or plain "MGF1" meaning
	 * MGF1 over `hash`. A bare hash name used to be accepted, which was
	 * leniency the interface does not describe and a second backend would not
	 * implement -- so a caller that relied on it here would have found its
	 * requests refused elsewhere. */
	{
		g_autoptr(GVariant) plain = params("{'hash': <'SHA384'>, 'mgf': <'mgf1'>}");
		g_autoptr(GVariant) bare_hash = params("{'hash': <'SHA256'>, 'mgf': <'SHA256'>}");
		g_autoptr(GError) plain_error = NULL;
		g_autoptr(GError) bare_error = NULL;

		g_assert_true(certificate_mechanism_parse("RSA_PSS", plain, "RSA", 2048, FALSE,
		                                          &mechanism, &plain_error));
		g_assert_cmpuint(mechanism.pss.mgf, ==, CKG_MGF1_SHA384);
		certificate_mechanism_clear(&mechanism);

		g_assert_false(certificate_mechanism_parse("RSA_PSS", bare_hash, "RSA", 2048, FALSE,
		                                           &mechanism, &bare_error));
		g_assert_error(bare_error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	}
}

static void test_rsa_key_too_small(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA512'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;

	/* 512 bits is 64 bytes; a SHA-512 DigestInfo plus the digest plus the
	 * minimum padding does not fit. */
	g_assert_false(certificate_mechanism_parse("RSA_PKCS1_V1_5", parameters, "RSA", 512, FALSE,
	                                           &mechanism, &error));
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
}

static void test_ecdsa_passes_the_digest_through(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	guint8 digest[32];
	g_autoptr(GBytes) data = NULL;
	g_autoptr(GBytes) prepared = NULL;

	g_assert_true(
	    certificate_mechanism_parse("ECDSA", parameters, "EC", 256, FALSE, &mechanism, &error));
	g_assert_cmpuint(mechanism.type, ==, CKM_ECDSA);
	g_assert_cmpint(mechanism.encoding, ==, CERTIFICATE_SIGNATURE_RAW);

	memset(digest, 0x5a, sizeof(digest));
	data = g_bytes_new(digest, sizeof(digest));
	prepared = certificate_mechanism_prepare(&mechanism, data, &error);

	g_assert_no_error(error);
	g_assert_cmpuint(g_bytes_get_size(prepared), ==, sizeof(digest));
	g_assert_cmpint(
	    memcmp(g_bytes_get_data(prepared, NULL), digest, sizeof(digest)), ==, 0);

	certificate_mechanism_clear(&mechanism);
}

static void test_signature_encoding_option(void)
{
	g_autoptr(GVariant) der = params("{'hash': <'SHA256'>, 'signature_encoding': <'der'>}");
	g_autoptr(GVariant) bad = params("{'hash': <'SHA256'>, 'signature_encoding': <'pem'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	g_autoptr(GError) bad_error = NULL;

	g_assert_true(certificate_mechanism_parse("ECDSA", der, "EC", 256, FALSE, &mechanism, &error));
	g_assert_cmpint(mechanism.encoding, ==, CERTIFICATE_SIGNATURE_DER);
	certificate_mechanism_clear(&mechanism);

	g_assert_false(
	    certificate_mechanism_parse("ECDSA", bad, "EC", 256, FALSE, &mechanism, &bad_error));
	g_assert_error(bad_error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
}

/* RSA_OAEP IS THE ONLY DECRYPTION MECHANISM, and the three signing mechanisms
 * are refused for Decrypt by name. PKCS#1 v1.5 is the one that matters: a
 * decryption whose outcome the caller can observe is a Bleichenbacher oracle
 * over the card's key, which is the capability the digest-only Sign policy
 * exists to withhold, offered through a different door. */
static void test_only_oaep_may_decrypt(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	CertificateMechanism mechanism;
	static const char* const refused_names[] = { "RSA_PKCS1_V1_5", "RSA_PSS", "ECDSA",
		                                         "RSA_SOMETHING", NULL };
	g_autoptr(GError) error = NULL;

	for (gsize i = 0; refused_names[i] != NULL; i++)
	{
		g_autoptr(GError) refused = NULL;

		g_assert_false(certificate_mechanism_parse(refused_names[i], parameters, "RSA", 2048,
		                                           TRUE, &mechanism, &refused));
		g_assert_error(refused, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	}

	/* And the one that is allowed to decrypt may not sign. */
	{
		g_autoptr(GError) refused = NULL;

		g_assert_false(certificate_mechanism_parse("RSA_OAEP", parameters, "RSA", 2048, FALSE,
		                                           &mechanism, &refused));
		g_assert_error(refused, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	}

	g_assert_true(certificate_mechanism_parse("RSA_OAEP", parameters, "RSA", 2048, TRUE,
	                                          &mechanism, &error));
	g_assert_no_error(error);
	g_assert_cmpuint(mechanism.type, ==, CKM_RSA_PKCS_OAEP);
	g_assert_true(mechanism.has_oaep);
	g_assert_cmpuint(mechanism.oaep.hashAlg, ==, CKM_SHA256);
	g_assert_cmpuint(mechanism.oaep.mgf, ==, CKG_MGF1_SHA256);
	g_assert_cmpuint(mechanism.oaep.source, ==, CKZ_DATA_SPECIFIED);
	g_assert_null(mechanism.oaep.pSourceData);
	g_assert_cmpuint(mechanism.oaep.ulSourceDataLen, ==, 0);
	certificate_mechanism_clear(&mechanism);
}

/* THE CIPHERTEXT IS EXACTLY ONE MODULUS. It is the only length an RSA
 * ciphertext can have, and the frontend cannot check it because it does not
 * know the modulus size. */
static void test_oaep_ciphertext_length(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	guint8 buffer[256];
	g_autoptr(GBytes) exact = NULL;
	g_autoptr(GBytes) prepared = NULL;

	g_assert_true(certificate_mechanism_parse("RSA_OAEP", parameters, "RSA", 2048, TRUE,
	                                          &mechanism, &error));
	g_assert_no_error(error);
	g_assert_cmpuint(mechanism.expected_input, ==, 256);

	memset(buffer, 0x5a, sizeof(buffer));
	exact = g_bytes_new(buffer, sizeof(buffer));
	prepared = certificate_mechanism_prepare(&mechanism, exact, &error);
	g_assert_no_error(error);

	/* PASSED THROUGH UNCHANGED: nothing wraps or pads a ciphertext. */
	g_assert_cmpuint(g_bytes_get_size(prepared), ==, sizeof(buffer));
	g_assert_true(g_bytes_equal(prepared, exact));

	for (gsize length = 0; length < sizeof(buffer); length += 85)
	{
		g_autoptr(GError) refused = NULL;
		g_autoptr(GBytes) wrong = g_bytes_new(buffer, length);

		g_assert_null(certificate_mechanism_prepare(&mechanism, wrong, &refused));
		g_assert_error(refused, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	}

	certificate_mechanism_clear(&mechanism);
}

/* The OAEP parameters are validated rather than forwarded: pParameter goes
 * straight into the module. */
static void test_oaep_parameters(void)
{
	CertificateMechanism mechanism;
	static const char* const refused[] = {
		"{}",                                            /* no hash */
		"{'hash': <'SHA3-256'>}",                        /* not a hash this backend knows */
		"{'hash': <'SHA256'>, 'mgf1_hash': <'SHA1'>}",   /* must be the same hash */
		"{'hash': <'SHA256'>, 'mgf1_hash': <'nope'>}",   /* not a hash at all */
		"{'hash': <'SHA256'>, 'label': <'a string'>}",   /* must be a byte array */
		"{'hash': <'SHA256'>, 'salt_length': <uint32 8>}", /* a signing parameter */
		"{'hash': <'SHA256'>, 'signature_encoding': <'der'>}",
		NULL,
	};

	for (gsize i = 0; refused[i] != NULL; i++)
	{
		g_autoptr(GVariant) parameters = params(refused[i]);
		g_autoptr(GError) error = NULL;

		if (certificate_mechanism_parse("RSA_OAEP", parameters, "RSA", 2048, TRUE, &mechanism,
		                                &error))
			g_error("RSA_OAEP accepted %s", refused[i]);

		g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	}

	/* A label longer than the interface's 256 bytes. Built rather than parsed,
	 * because a 257-byte literal in a table is unreadable. */
	{
		g_autofree guint8* big = g_malloc0(257);
		g_autoptr(GVariant) parameters = NULL;
		GVariantBuilder builder;
		g_autoptr(GError) error = NULL;

		g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_add(&builder, "{sv}", "hash", g_variant_new_string("SHA256"));
		g_variant_builder_add(&builder, "{sv}", "label",
		                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, big, 257, 1));
		parameters = g_variant_ref_sink(g_variant_builder_end(&builder));

		g_assert_false(certificate_mechanism_parse("RSA_OAEP", parameters, "RSA", 2048, TRUE,
		                                           &mechanism, &error));
		g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	}

	/* Accepted: the SHA-256 spelling, a matching mgf1_hash, and a label that
	 * reaches the mechanism parameter as the module will see it. */
	{
		/* The label is written out as bytes rather than as b'...', which
		 * would carry a trailing NUL into the mechanism parameter. */
		static const guint8 label[] = { 0x63, 0x74, 0x78 };
		g_autoptr(GVariant) parameters = params("{'hash': <'SHA-256'>, 'mgf1_hash': <'sha256'>, "
		                                        "'label': <[byte 0x63, 0x74, 0x78]>}");
		g_autoptr(GError) error = NULL;

		g_assert_true(certificate_mechanism_parse("RSA_OAEP", parameters, "RSA", 2048, TRUE,
		                                          &mechanism, &error));
		g_assert_no_error(error);
		g_assert_cmpuint(mechanism.oaep.hashAlg, ==, CKM_SHA256);
		g_assert_cmpuint(mechanism.oaep.ulSourceDataLen, ==, sizeof(label));
		g_assert_nonnull(mechanism.oaep.pSourceData);
		g_assert_cmpint(memcmp(mechanism.oaep.pSourceData, label, sizeof(label)), ==, 0);

		/* The CK_MECHANISM points at the struct's own storage. */
		{
			CK_MECHANISM ck;

			certificate_mechanism_to_ck(&mechanism, &ck);
			g_assert_cmpuint(ck.mechanism, ==, CKM_RSA_PKCS_OAEP);
			g_assert_true(ck.pParameter == &mechanism.oaep);
			g_assert_cmpuint(ck.ulParameterLen, ==, sizeof(mechanism.oaep));
		}

		certificate_mechanism_clear(&mechanism);
	}

	/* A key too small to hold 2*hLen+2 for the named hash. */
	{
		g_autoptr(GVariant) parameters = params("{'hash': <'SHA512'>}");
		g_autoptr(GError) error = NULL;

		g_assert_false(certificate_mechanism_parse("RSA_OAEP", parameters, "RSA", 1024, TRUE,
		                                           &mechanism, &error));
		g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	}

	/* And OAEP needs an RSA key. */
	{
		g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>}");
		g_autoptr(GError) error = NULL;

		g_assert_false(certificate_mechanism_parse("RSA_OAEP", parameters, "EC", 256, TRUE,
		                                           &mechanism, &error));
		g_assert_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
	}
}

/* An unknown parameter is refused rather than ignored: a caller that spelled
 * `salt_len` and got the default salt length would have been told nothing. */
static void test_unknown_parameter(void)
{
	g_autoptr(GVariant) parameters = params("{'hash': <'SHA256'>, 'salt_len': <uint32 8>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;

	g_assert_false(certificate_mechanism_parse("RSA_PSS", parameters, "RSA", 2048, FALSE,
	                                           &mechanism, &error));
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
}

static void test_ecdsa_raw_to_der(void)
{
	g_autoptr(GError) error = NULL;
	/* r has its top bit set, so DER has to prepend a zero byte; s does not. */
	static const guint8 raw[] = { 0xf0, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44 };
	static const guint8 expected[] = { 0x30, 0x0d, 0x02, 0x05, 0x00, 0xf0, 0x01,
		                               0x02, 0x03, 0x02, 0x04, 0x11, 0x22, 0x33, 0x44 };
	g_autoptr(GBytes) der = certificate_ecdsa_raw_to_der(raw, sizeof(raw), &error);
	g_autoptr(GBytes) odd = NULL;
	g_autoptr(GError) odd_error = NULL;
	static const guint8 leading_zero[] = { 0x00, 0x01, 0x00, 0x02 };
	static const guint8 leading_zero_der[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
	g_autoptr(GBytes) stripped = NULL;

	g_assert_no_error(error);
	g_assert_cmpuint(g_bytes_get_size(der), ==, sizeof(expected));
	g_assert_cmpint(memcmp(g_bytes_get_data(der, NULL), expected, sizeof(expected)), ==, 0);

	/* Leading zeroes are stripped, because a DER integer is not a fixed-width
	 * field. */
	stripped = certificate_ecdsa_raw_to_der(leading_zero, sizeof(leading_zero), &error);
	g_assert_no_error(error);
	g_assert_cmpuint(g_bytes_get_size(stripped), ==, sizeof(leading_zero_der));
	g_assert_cmpint(
	    memcmp(g_bytes_get_data(stripped, NULL), leading_zero_der, sizeof(leading_zero_der)), ==,
	    0);

	odd = certificate_ecdsa_raw_to_der(raw, 7, &odd_error);
	g_assert_null(odd);
	g_assert_error(odd_error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
}

/* PRESENT WITH THE WRONG TYPE IS AN ERROR, NEVER "ABSENT". Every one of these
 * used to be silently discarded and replaced by the default, because
 * g_variant_lookup(..., "&s", ...) cannot tell a missing key from one holding a
 * uint32. None of the defaults is dangerous by itself, which is exactly why it
 * had to be caught by a test rather than by an incident: a caller whose
 * parameters vanished got an answer computed from parameters it did not send. */
static void test_mistyped_parameters_are_refused(void)
{
	static const struct
	{
		const char* name;
		const char* parameters;
		gboolean for_decrypt;
	} cases[] = {
		{ "RSA_PSS", "{'hash': <'SHA256'>, 'signature_encoding': <uint32 1>}", FALSE },
		{ "RSA_PKCS1_V1_5", "{'hash': <'SHA256'>, 'signature_encoding': <true>}", FALSE },
		{ "ECDSA", "{'hash': <'SHA256'>, 'signature_encoding': <b'der'>}", FALSE },
		{ "RSA_PSS", "{'hash': <'SHA256'>, 'mgf': <true>}", FALSE },
		{ "RSA_PSS", "{'hash': <'SHA256'>, 'mgf': <uint32 1>}", FALSE },
		{ "RSA_OAEP", "{'hash': <'SHA256'>, 'mgf1_hash': <uint32 1>}", TRUE },
		{ "RSA_OAEP", "{'hash': <'SHA256'>, 'mgf1_hash': <b'SHA256'>}", TRUE },
		/* And the hash itself, which was already right and is a control. */
		{ "RSA_PSS", "{'hash': <uint32 256>}", FALSE },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		g_autoptr(GVariant) parameters = params(cases[i].parameters);
		CertificateMechanism mechanism;
		g_autoptr(GError) error = NULL;
		const char* key_type = g_str_has_prefix(cases[i].name, "RSA") ? "RSA" : "EC";

		if (certificate_mechanism_parse(cases[i].name, parameters, key_type, 2048,
		                                cases[i].for_decrypt, &mechanism, &error))
			g_error("%s %s was accepted", cases[i].name, cases[i].parameters);

		g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	}
}

/* THE SPELLING IS THE INTERFACE'S: "MGF1-<hash>", or bare "MGF1" meaning MGF1
 * over `hash`. It is enforced only here -- the frontend passes `parameters`
 * through with no validator for `mgf` -- so this is the only place the
 * interface's claim about the vocabulary is checked at all. */
static void test_pss_mgf_vocabulary(void)
{
	static const struct
	{
		const char* parameters;
		gboolean accepted;
	} cases[] = {
		{ "{'hash': <'SHA256'>, 'mgf': <'MGF1'>}", TRUE },
		{ "{'hash': <'SHA256'>, 'mgf': <'MGF1-SHA256'>}", TRUE },
		{ "{'hash': <'SHA256'>, 'mgf': <'mgf1-sha256'>}", TRUE },
		/* A DIFFERENT hash is permitted by PKCS#1 and accepted here: the pairing
		 * is what goes into pParameter, and both halves come out of one table so
		 * they cannot disagree with each other. */
		{ "{'hash': <'SHA256'>, 'mgf': <'MGF1-SHA384'>}", TRUE },
		/* A bare hash name is NOT the spelling. It used to be accepted, which
		 * was leniency the interface does not describe. */
		{ "{'hash': <'SHA256'>, 'mgf': <'SHA256'>}", FALSE },
		{ "{'hash': <'SHA256'>, 'mgf': <'MGF1-SHA3-256'>}", FALSE },
		{ "{'hash': <'SHA256'>, 'mgf': <'MGF2-SHA256'>}", FALSE },
		{ "{'hash': <'SHA256'>, 'mgf': <'MGF1-'>}", FALSE },
		{ "{'hash': <'SHA256'>, 'mgf': <''>}", FALSE },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		g_autoptr(GVariant) parameters = params(cases[i].parameters);
		CertificateMechanism mechanism;
		g_autoptr(GError) error = NULL;
		gboolean ok = certificate_mechanism_parse("RSA_PSS", parameters, "RSA", 2048, FALSE,
		                                          &mechanism, &error);

		if (ok != cases[i].accepted)
			g_error("RSA_PSS %s was %s", cases[i].parameters, ok ? "accepted" : "refused");

		if (ok)
		{
			g_assert_true(mechanism.has_pss);
			g_assert_cmpuint(mechanism.pss.mgf, !=, 0);
			certificate_mechanism_clear(&mechanism);
		}
	}

	/* The pairing that reaches the module: MGF1-SHA384 over a SHA-256 signature
	 * sets the SHA-384 mask function and leaves hashAlg alone. */
	{
		g_autoptr(GVariant) parameters =
		    params("{'hash': <'SHA256'>, 'mgf': <'MGF1-SHA384'>}");
		CertificateMechanism mechanism;
		g_autoptr(GError) error = NULL;

		g_assert_true(certificate_mechanism_parse("RSA_PSS", parameters, "RSA", 2048, FALSE,
		                                          &mechanism, &error));
		g_assert_cmpuint(mechanism.pss.hashAlg, ==, (guint) CKM_SHA256);
		g_assert_cmpuint(mechanism.pss.mgf, ==, (guint) CKG_MGF1_SHA384);
		certificate_mechanism_clear(&mechanism);
	}
}

/* An mgf1_hash that names a different hash than `hash` is refused: the two go
 * into one CK_RSA_PKCS_OAEP_PARAMS and the interface says they must agree. */
static void test_oaep_mgf1_hash_must_match(void)
{
	g_autoptr(GVariant) mismatched =
	    params("{'hash': <'SHA256'>, 'mgf1_hash': <'SHA1'>}");
	g_autoptr(GVariant) matching = params("{'hash': <'SHA256'>, 'mgf1_hash': <'SHA256'>}");
	CertificateMechanism mechanism;
	g_autoptr(GError) error = NULL;
	g_autoptr(GError) ok_error = NULL;

	g_assert_false(certificate_mechanism_parse("RSA_OAEP", mismatched, "RSA", 2048, TRUE,
	                                           &mechanism, &error));
	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);

	g_assert_true(certificate_mechanism_parse("RSA_OAEP", matching, "RSA", 2048, TRUE, &mechanism,
	                                          &ok_error));
	g_assert_cmpuint(mechanism.oaep.hashAlg, ==, (guint) CKM_SHA256);
	g_assert_cmpuint(mechanism.oaep.mgf, ==, (guint) CKG_MGF1_SHA256);
	certificate_mechanism_clear(&mechanism);
}

static void test_hash_spellings(void)
{
	CertificateHash hash;

	g_assert_true(certificate_hash_parse("SHA256", &hash));
	g_assert_cmpint(hash, ==, CERTIFICATE_HASH_SHA256);
	g_assert_true(certificate_hash_parse("sha-256", &hash));
	g_assert_cmpint(hash, ==, CERTIFICATE_HASH_SHA256);
	g_assert_cmpuint(certificate_hash_length(CERTIFICATE_HASH_SHA384), ==, 48);
	g_assert_false(certificate_hash_parse("SHA3-256", &hash));
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/mechanism/rsa-pkcs1-maps-and-wraps", test_rsa_pkcs1_maps_and_wraps);
	g_test_add_func("/mechanism/wrong-digest-length", test_wrong_digest_length_is_refused);
	g_test_add_func("/mechanism/hash-is-required", test_hash_is_required);
	g_test_add_func("/mechanism/must-match-the-key", test_mechanism_must_match_the_key);
	g_test_add_func("/mechanism/unknown", test_unknown_mechanism_and_hash);
	g_test_add_func("/mechanism/pss-defaults-and-limits", test_pss_defaults_and_limits);
	g_test_add_func("/mechanism/rsa-key-too-small", test_rsa_key_too_small);
	g_test_add_func("/mechanism/ecdsa-digest-passthrough", test_ecdsa_passes_the_digest_through);
	g_test_add_func("/mechanism/signature-encoding", test_signature_encoding_option);
	g_test_add_func("/mechanism/only-oaep-may-decrypt", test_only_oaep_may_decrypt);
	g_test_add_func("/mechanism/oaep-ciphertext-length", test_oaep_ciphertext_length);
	g_test_add_func("/mechanism/oaep-parameters", test_oaep_parameters);
	g_test_add_func("/mechanism/unknown-parameter", test_unknown_parameter);
	g_test_add_func("/mechanism/ecdsa-raw-to-der", test_ecdsa_raw_to_der);
	g_test_add_func("/mechanism/mistyped-parameters", test_mistyped_parameters_are_refused);
	g_test_add_func("/mechanism/pss-mgf-vocabulary", test_pss_mgf_vocabulary);
	g_test_add_func("/mechanism/oaep-mgf1-hash-must-match", test_oaep_mgf1_hash_must_match);
	g_test_add_func("/mechanism/hash-spellings", test_hash_spellings);

	return g_test_run();
}
