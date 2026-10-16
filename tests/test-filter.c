/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <glib.h>
#include <gnutls/x509.h>
#include <string.h>

#include "fixture-util.h"
#include "module/constants.h"
#include "tokens/discovery.h"
#include "tokens/filter.h"

typedef struct
{
	const char* fixture;
	gboolean client_auth;
	gboolean signing;
	gboolean email;
	gboolean ssh;
} PurposeCase;

/* The default operation policy permits signing only. */
static void test_purposes(void)
{
	static const PurposeCase cases[] = {
		{ "client-auth-rsa.pem", TRUE, TRUE, FALSE, TRUE },
		{ "email-ec.pem", FALSE, TRUE, TRUE, TRUE },
		{ "no-eku-rsa.pem", TRUE, TRUE, TRUE, TRUE },
		{ "server-auth-only.pem", FALSE, FALSE, FALSE, TRUE },
		{ "encipherment-only.pem", FALSE, FALSE, FALSE, TRUE },
		{ "email-encipherment-only.pem", FALSE, FALSE, FALSE, TRUE },
		{ "email-sign-and-encipher.pem", FALSE, TRUE, TRUE, TRUE },
		{ "expired-client-auth.pem", TRUE, TRUE, FALSE, TRUE },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		g_autoptr(CertificateCandidate) candidate =
		    certificate_test_candidate(cases[i].fixture, TRUE, FALSE);

		g_test_message("%s", cases[i].fixture);
		g_assert_cmpint(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH,
		                                           CERTIFICATE_OPERATION_SIGN),
		                ==, cases[i].client_auth);
		g_assert_cmpint(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SIGNING,
		                                           CERTIFICATE_OPERATION_SIGN),
		                ==, cases[i].signing);
		g_assert_cmpint(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
		                                           CERTIFICATE_OPERATION_SIGN),
		                ==, cases[i].email);
		g_assert_cmpint(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SSH,
		                                           CERTIFICATE_OPERATION_SIGN),
		                ==, cases[i].ssh);
	}
}

static void test_key_that_will_not_sign(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", FALSE, TRUE);

	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                          CERTIFICATE_OPERATION_SIGN));
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SSH,
	                                          CERTIFICATE_OPERATION_SIGN));

	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                          CERTIFICATE_OPERATION_SIGN |
	                                              CERTIFICATE_OPERATION_DECRYPT));
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SIGNING,
	                                          CERTIFICATE_OPERATION_SIGN |
	                                              CERTIFICATE_OPERATION_DECRYPT));
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SSH,
	                                          CERTIFICATE_OPERATION_SIGN |
	                                              CERTIFICATE_OPERATION_DECRYPT));
}

static void test_decryption_only_certificate(void)
{
	static const char* const fixtures[] = { "email-encipherment-only.pem",
		                                    "encipherment-only.pem", NULL };

	for (gsize i = 0; fixtures[i] != NULL; i++)
	{
		g_autoptr(CertificateCandidate) candidate =
		    certificate_test_candidate(fixtures[i], FALSE, TRUE);

		g_test_message("%s", fixtures[i]);

		g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_EMAIL), ==,
		                CERTIFICATE_OPERATION_DECRYPT);

		g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
		                                          CERTIFICATE_OPERATION_SIGN));
		g_assert_true(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
		                                         CERTIFICATE_OPERATION_DECRYPT));
		g_assert_true(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
		                                         CERTIFICATE_OPERATION_SIGN |
		                                             CERTIFICATE_OPERATION_DECRYPT));

		g_assert_cmpint(certificate_purpose_operations(candidate,
		                                              CERTIFICATE_PURPOSE_CLIENT_AUTH),
		                ==, CERTIFICATE_OPERATION_NONE);
		g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_SIGNING),
		                ==, CERTIFICATE_OPERATION_NONE);
		g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_SSH), ==,
		                CERTIFICATE_OPERATION_NONE);
	}
}

static void test_signing_email_certificate_is_not_offered_for_decryption(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("email-ec.pem", TRUE, FALSE);

	g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_EMAIL), ==,
	                CERTIFICATE_OPERATION_SIGN);
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
	                                          CERTIFICATE_OPERATION_DECRYPT));
}

static void test_certificate_that_signs_and_decrypts(void)
{
	g_autoptr(CertificateCandidate) both =
	    certificate_test_candidate("email-sign-and-encipher.pem", TRUE, TRUE);
	g_autoptr(CertificateCandidate) signing_key_only =
	    certificate_test_candidate("email-sign-and-encipher.pem", TRUE, FALSE);

	g_assert_cmpint(certificate_purpose_operations(both, CERTIFICATE_PURPOSE_EMAIL), ==,
	                CERTIFICATE_OPERATION_SIGN | CERTIFICATE_OPERATION_DECRYPT);
	g_assert_cmpint(certificate_purpose_operations(both, CERTIFICATE_PURPOSE_CLIENT_AUTH), ==,
	                CERTIFICATE_OPERATION_NONE);

	g_assert_cmpint(certificate_purpose_operations(signing_key_only, CERTIFICATE_PURPOSE_EMAIL),
	                ==, CERTIFICATE_OPERATION_SIGN);
}

static void test_key_usage_restricts_a_token_that_claims_everything(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("email-encipherment-only.pem", TRUE, TRUE);

	g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_EMAIL), ==,
	                CERTIFICATE_OPERATION_DECRYPT);
	g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_SIGNING), ==,
	                CERTIFICATE_OPERATION_NONE);
}

static void test_filter_offers_decryption_certificate_for_email(void)
{
	static const char* const fixtures[] = { "client-auth-rsa.pem", "email-ec.pem",
		                                    "email-encipherment-only.pem", NULL };
	g_autoptr(GPtrArray) candidates =
	    g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);
	CertificateFilter filter = { 0 };
	g_autoptr(GPtrArray) decrypting = NULL;
	g_autoptr(GPtrArray) signing = NULL;

	for (gsize i = 0; fixtures[i] != NULL; i++)
	{
		gboolean encipherment = g_str_has_prefix(fixtures[i], "email-encipherment");

		g_ptr_array_add(candidates,
		                certificate_test_candidate(fixtures[i], !encipherment, encipherment));
	}

	filter.purpose = CERTIFICATE_PURPOSE_EMAIL;
	filter.operations = CERTIFICATE_OPERATION_DECRYPT;
	decrypting = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(decrypting->len, ==, 1);
	g_assert_cmpstr(((CertificateCandidate*) g_ptr_array_index(decrypting, 0))->subject_display,
	                ==, "Ada Lovelace (key management)");

	filter.operations = CERTIFICATE_OPERATION_SIGN;
	signing = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(signing->len, ==, 1);
	g_assert_cmpstr(((CertificateCandidate*) g_ptr_array_index(signing, 0))->subject_display, !=,
	                "Ada Lovelace (key management)");
}

static void test_expiry_flags(void)
{
	g_autoptr(CertificateCandidate) expired =
	    certificate_test_candidate("expired-client-auth.pem", TRUE, FALSE);
	g_autoptr(CertificateCandidate) future =
	    certificate_test_candidate("not-yet-valid.pem", TRUE, FALSE);
	g_autoptr(CertificateCandidate) good =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	gint64 now = g_get_real_time() / G_USEC_PER_SEC;

	g_assert_true(certificate_candidate_is_expired(expired, now));
	g_assert_false(certificate_candidate_is_not_yet_valid(expired, now));

	g_assert_true(certificate_candidate_is_not_yet_valid(future, now));
	g_assert_false(certificate_candidate_is_expired(future, now));

	g_assert_false(certificate_candidate_is_expired(good, now));
	g_assert_false(certificate_candidate_is_not_yet_valid(good, now));
}

static GPtrArray* candidate_list(const char* const* fixtures)
{
	GPtrArray* list =
	    g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);

	for (gsize i = 0; fixtures[i] != NULL; i++)
		g_ptr_array_add(list, certificate_test_candidate(fixtures[i], TRUE, FALSE));

	return list;
}

static void test_expired_is_offered_but_sorts_last(void)
{
	static const char* const fixtures[] = { "expired-client-auth.pem", "client-auth-rsa.pem",
		                                    NULL };
	g_autoptr(GPtrArray) candidates = candidate_list(fixtures);
	CertificateFilter filter = { 0 };
	g_autoptr(GPtrArray) matching = NULL;
	CertificateCandidate* first = NULL;

	filter.purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH;
	filter.operations = CERTIFICATE_OPERATION_SIGN;
	matching = certificate_filter_apply(candidates, &filter);

	g_assert_cmpuint(matching->len, ==, 2);

	first = g_ptr_array_index(matching, 0);
	g_assert_false(
	    certificate_candidate_is_expired(first, g_get_real_time() / G_USEC_PER_SEC));
}

static void test_filter_token_label(void)
{
	static const char* const fixtures[] = { "client-auth-rsa.pem", NULL };
	g_autoptr(GPtrArray) candidates = candidate_list(fixtures);
	CertificateFilter filter = { 0 };
	g_autoptr(GPtrArray) hit = NULL;
	g_autoptr(GPtrArray) miss = NULL;

	filter.purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH;
	filter.operations = CERTIFICATE_OPERATION_SIGN;

	filter.token_label = (char*) "Test Token";
	hit = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(hit->len, ==, 1);

	filter.token_label = (char*) "Some Other Token";
	miss = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(miss->len, ==, 0);
}

static void test_filter_piv_slot(void)
{
	static const char* const fixtures[] = { "client-auth-rsa.pem", NULL };
	g_autoptr(GPtrArray) candidates = candidate_list(fixtures);
	CertificateFilter filter = { 0 };
	g_autoptr(GPtrArray) unknown_slot = NULL;
	g_autoptr(GPtrArray) matching = NULL;
	g_autoptr(GPtrArray) other = NULL;

	filter.purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH;
	filter.operations = CERTIFICATE_OPERATION_SIGN;
	filter.piv_slot = (char*) "authentication";

	unknown_slot = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(unknown_slot->len, ==, 0);

	certificate_test_attach_token(g_ptr_array_index(candidates, 0), "Test Token",
	                              "authentication");
	matching = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(matching->len, ==, 1);

	filter.piv_slot = (char*) "signature";
	other = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(other->len, ==, 0);
}

static void test_filter_key_algorithms(void)
{
	static const char* const fixtures[] = { "client-auth-rsa.pem", "email-ec.pem", NULL };
	g_autoptr(GPtrArray) candidates = candidate_list(fixtures);
	CertificateFilter filter = { 0 };
	char* rsa[] = { (char*) "RSA", NULL };
	char* tls_names[] = { (char*) "ecdsa_secp256r1_sha256", NULL };
	g_autoptr(GPtrArray) only_rsa = NULL;
	g_autoptr(GPtrArray) only_ec = NULL;

	filter.purpose = CERTIFICATE_PURPOSE_SIGNING;
	filter.operations = CERTIFICATE_OPERATION_SIGN;

	filter.key_algorithms = rsa;
	only_rsa = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(only_rsa->len, ==, 1);
	g_assert_cmpstr(((CertificateCandidate*) g_ptr_array_index(only_rsa, 0))->key_type, ==, "RSA");

	filter.key_algorithms = tls_names;
	only_ec = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(only_ec->len, ==, 1);
	g_assert_cmpstr(((CertificateCandidate*) g_ptr_array_index(only_ec, 0))->key_type, ==, "EC");
}

static void test_filter_eku_and_key_usage(void)
{
	static const char* const fixtures[] = { "client-auth-rsa.pem", "email-ec.pem", NULL };
	g_autoptr(GPtrArray) candidates = candidate_list(fixtures);
	CertificateFilter filter = { 0 };
	char* email_eku[] = { (char*) CERTIFICATE_EKU_EMAIL_PROTECTION, NULL };
	char* usage[] = { (char*) "digital_signature", NULL };
	char* impossible_usage[] = { (char*) "crl_sign", NULL };
	g_autoptr(GPtrArray) by_eku = NULL;
	g_autoptr(GPtrArray) by_usage = NULL;
	g_autoptr(GPtrArray) by_impossible = NULL;

	filter.purpose = CERTIFICATE_PURPOSE_SIGNING;
	filter.operations = CERTIFICATE_OPERATION_SIGN;

	filter.eku_oids = email_eku;
	by_eku = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(by_eku->len, ==, 1);
	filter.eku_oids = NULL;

	filter.key_usage = usage;
	by_usage = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(by_usage->len, ==, 2);

	filter.key_usage = impossible_usage;
	by_impossible = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(by_impossible->len, ==, 0);
}

static void test_filter_issuer_dn(void)
{
	static const char* const fixtures[] = { "client-auth-rsa.pem", "email-ec.pem", NULL };
	g_autoptr(GPtrArray) candidates = candidate_list(fixtures);
	CertificateCandidate* first = g_ptr_array_index(candidates, 0);
	CertificateFilter filter = { 0 };
	g_autoptr(GPtrArray) issuers = g_ptr_array_new_with_free_func((GDestroyNotify) g_bytes_unref);
	g_autoptr(GPtrArray) matching = NULL;

	g_ptr_array_add(issuers, g_bytes_new(first->issuer_der->data, first->issuer_der->len));

	filter.purpose = CERTIFICATE_PURPOSE_SIGNING;
	filter.operations = CERTIFICATE_OPERATION_SIGN;
	filter.issuers = issuers;

	matching = certificate_filter_apply(candidates, &filter);
	g_assert_cmpuint(matching->len, ==, 1);
	g_assert_cmpstr(((CertificateCandidate*) g_ptr_array_index(matching, 0))->certificate_id, ==,
	                first->certificate_id);
}

static void test_filter_parse_rejects_malformed(void)
{
	static const char* const bad[] = {
		"{'certificate_filter': <{'issuers': <['not-a-byte-array']>}>}",
		"{'certificate_filter': <{'key_usage': <'digital_signature'>}>}",
		"{'certificate_filter': <{'eku': <uint32 3>}>}",
		"{'certificate_filter': <{'token_label': <uint32 3>}>}",
		"{'certificate_filter': <{'piv_slot': <'not_a_piv_slot'>}>}",
		NULL,
	};

	for (gsize i = 0; bad[i] != NULL; i++)
	{
		g_autoptr(GVariant) options = g_variant_parse(G_VARIANT_TYPE_VARDICT, bad[i], NULL, NULL,
		                                              NULL);
		CertificateFilter filter = { 0 };
		g_autoptr(GError) error = NULL;

		g_assert_nonnull(options);
		g_test_message("%s", bad[i]);
		g_assert_false(certificate_filter_parse(options, CERTIFICATE_PURPOSE_SIGNING,
		                                        CERTIFICATE_OPERATION_SIGN, &filter, &error));
		g_assert_nonnull(error);
		certificate_filter_clear(&filter);
	}
}

static void test_filter_parse_accepts_wellformed(void)
{
	g_autoptr(GVariant) options = g_variant_parse(
	    G_VARIANT_TYPE_VARDICT,
	    "{'certificate_filter': <{'key_usage': <['digital_signature']>, "
	    "'eku': <['1.3.6.1.5.5.7.3.2']>, 'token_label': <'Test Token'>, "
	    "'piv_slot': <'authentication'>, 'key_algorithms': <['RSA']>, "
	    "'issuers': <[b'abc']>}>}",
	    NULL, NULL, NULL);
	CertificateFilter filter = { 0 };
	g_autoptr(GError) error = NULL;

	g_assert_nonnull(options);
	g_assert_true(certificate_filter_parse(options, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                       CERTIFICATE_OPERATION_SIGN, &filter, &error));
	g_assert_no_error(error);
	g_assert_cmpint(filter.purpose, ==, CERTIFICATE_PURPOSE_CLIENT_AUTH);
	g_assert_cmpstr(filter.token_label, ==, "Test Token");
	g_assert_cmpstr(filter.piv_slot, ==, "authentication");
	g_assert_nonnull(filter.eku_oids);
	g_assert_nonnull(filter.issuers);
	certificate_filter_clear(&filter);
}

static void test_filter_parse_absent(void)
{
	g_autoptr(GVariant) options = g_variant_parse(G_VARIANT_TYPE_VARDICT, "{}", NULL, NULL, NULL);
	CertificateFilter filter = { 0 };
	g_autoptr(GError) error = NULL;

	g_assert_true(certificate_filter_parse(options, CERTIFICATE_PURPOSE_SSH,
	                                       CERTIFICATE_OPERATION_SIGN, &filter, &error));
	g_assert_no_error(error);
	g_assert_cmpint(filter.purpose, ==, CERTIFICATE_PURPOSE_SSH);
	g_assert_cmpint(filter.operations, ==, CERTIFICATE_OPERATION_SIGN);
	g_assert_null(filter.token_label);
	certificate_filter_clear(&filter);
}

static void test_portal_module_is_refused(void)
{
	g_autoptr(GError) error = NULL;
	const char* explicit_module[] = { "/usr/lib64/pkcs11/" PKCS11_PORTAL_MODULE_BASENAME, NULL };

	g_assert_true(certificate_module_is_portal_module(PKCS11_PORTAL_MODULE_NAME, NULL));
	g_assert_true(certificate_module_is_portal_module("XDG-Desktop-Portal-Certificate", NULL));
	g_assert_true(
	    certificate_module_is_portal_module(NULL, "/usr/lib64/pkcs11/lib" PKCS11_PORTAL_MODULE_BASENAME));
	g_assert_true(certificate_module_is_portal_module(NULL, PKCS11_PORTAL_MODULE_BASENAME));

	g_assert_false(certificate_module_is_portal_module("opensc", NULL));
	g_assert_false(certificate_module_is_portal_module(NULL, "/usr/lib64/opensc-pkcs11.so"));
	g_assert_false(certificate_module_is_portal_module(NULL, NULL));

	g_assert_null(certificate_tokens_new(explicit_module, &error));
	g_assert_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED);
}

/* Fixture extensions use short-form OCTET STRING lengths and an optional critical BOOLEAN. */
static gsize extension_value_offset(const GByteArray* der, const guint8* oid, gsize oid_length)
{
	for (gsize i = 0; i + oid_length + 4 < der->len; i++)
	{
		gsize at = i + oid_length;

		if (memcmp(der->data + i, oid, oid_length) != 0)
			continue;

		if (der->data[at] == 0x01)
			at += 3;

		g_assert_cmpuint(der->data[at], ==, 0x04);
		g_assert_cmpuint(der->data[at + 1], <, 0x80);
		return at + 2;
	}

	g_assert_not_reached();
}

/* Corrupt the extension after issuance because certtool will not generate this malformed certificate. */
static GByteArray* der_with_broken_extension(const GByteArray* der, const guint8* oid,
                                             gsize oid_length)
{
	GByteArray* copy = g_byte_array_sized_new(der->len);
	gsize at;

	g_byte_array_append(copy, der->data, der->len);
	at = extension_value_offset(copy, oid, oid_length);

	copy->data[at] = 0x2a;
	return copy;
}

static void test_undecodable_extension_is_not_unrestricted(void)
{
	static const guint8 eku_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };
	static const guint8 key_usage_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f };
	const guint8* oids[] = { eku_oid, key_usage_oid };
	g_autoptr(CertificateCandidate) absent =
	    certificate_test_candidate("no-eku-rsa.pem", TRUE, FALSE);
	g_autoptr(CertificateCandidate) matching =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autoptr(CertificateCandidate) other =
	    certificate_test_candidate("server-auth-only.pem", TRUE, FALSE);

	g_assert_null(absent->eku_oids);
	g_assert_true(certificate_purpose_matches(absent, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                          CERTIFICATE_OPERATION_SIGN));

	g_assert_nonnull(matching->eku_oids);
	g_assert_true(certificate_purpose_matches(matching, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                          CERTIFICATE_OPERATION_SIGN));
	g_assert_nonnull(other->eku_oids);
	g_assert_false(certificate_purpose_matches(other, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                           CERTIFICATE_OPERATION_SIGN));

	for (gsize i = 0; i < G_N_ELEMENTS(oids); i++)
	{
		g_autoptr(GByteArray) broken =
		    der_with_broken_extension(other->der, oids[i], sizeof(eku_oid));
		g_autoptr(GError) error = NULL;
		CertificateCandidate* candidate =
		    certificate_candidate_new_from_der(broken->data, broken->len, &error);

		g_assert_null(candidate);
		g_assert_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED);
	}
}

/* Rewriting EKU invalidates the fixture signature; this test exercises decoding without signature verification. */
static GByteArray* der_with_eku_value(const GByteArray* der, const guint8* value, gsize length)
{
	gnutls_x509_crt_t crt = NULL;
	gnutls_datum_t input = { der->data, der->len };
	gnutls_datum_t out = { NULL, 0 };
	GByteArray* copy = NULL;

	g_assert_cmpint(gnutls_x509_crt_init(&crt), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_import(crt, &input, GNUTLS_X509_FMT_DER), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_set_extension_by_oid(crt, "2.5.29.37", value, length, 0), ==,
	                0);
	g_assert_cmpint(gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &out), ==, 0);

	copy = g_byte_array_sized_new(out.size);
	g_byte_array_append(copy, out.data, out.size);

	gnutls_free(out.data);
	gnutls_x509_crt_deinit(crt);
	return copy;
}

static void test_empty_eku_is_restricted_to_nothing(void)
{
	static const guint8 empty_sequence[] = { 0x30, 0x00 };
	g_autoptr(CertificateCandidate) source =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autoptr(GByteArray) der =
	    der_with_eku_value(source->der, empty_sequence, sizeof(empty_sequence));
	g_autoptr(GError) error = NULL;
	g_autoptr(CertificateCandidate) candidate =
	    certificate_candidate_new_from_der(der->data, der->len, &error);

	g_assert_no_error(error);
	g_assert_nonnull(candidate);
	candidate->can_sign = TRUE;

	g_assert_nonnull(candidate->eku_oids);
	g_assert_null(candidate->eku_oids[0]);

	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                           CERTIFICATE_OPERATION_SIGN));
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SIGNING,
	                                           CERTIFICATE_OPERATION_SIGN));
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
	                                           CERTIFICATE_OPERATION_SIGN |
	                                               CERTIFICATE_OPERATION_DECRYPT));

	g_assert_true(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SSH,
	                                          CERTIFICATE_OPERATION_SIGN));
}

static void test_oversized_eku_oid_is_not_unrestricted(void)
{
	guint8 value[132];
	g_autoptr(CertificateCandidate) source =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autoptr(GByteArray) der = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(CertificateCandidate) candidate = NULL;

	/* This OID's DER is 127 bytes but its dotted text is 255 characters. */
	value[0] = 0x30;
	value[1] = 0x81;
	value[2] = 129;
	value[3] = 0x06;
	value[4] = 127;
	value[5] = 0x2b;
	for (gsize i = 6; i < sizeof(value); i++)
		value[i] = 0x01;

	der = der_with_eku_value(source->der, value, sizeof(value));
	candidate = certificate_candidate_new_from_der(der->data, der->len, &error);

	if (candidate == NULL)
	{
		g_assert_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED);
		return;
	}

	candidate->can_sign = TRUE;
	g_assert_nonnull(candidate->eku_oids);
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                           CERTIFICATE_OPERATION_SIGN));
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SIGNING,
	                                           CERTIFICATE_OPERATION_SIGN));
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/filter/purposes", test_purposes);
	g_test_add_func("/filter/key-that-will-not-sign", test_key_that_will_not_sign);
	g_test_add_func("/filter/decryption-only-certificate", test_decryption_only_certificate);
	g_test_add_func("/filter/signing-email-certificate-is-not-a-decryption-one",
	                test_signing_email_certificate_is_not_offered_for_decryption);
	g_test_add_func("/filter/certificate-that-signs-and-decrypts",
	                test_certificate_that_signs_and_decrypts);
	g_test_add_func("/filter/key-usage-restricts-a-token-that-claims-everything",
	                test_key_usage_restricts_a_token_that_claims_everything);
	g_test_add_func("/filter/offers-decryption-certificate-for-email",
	                test_filter_offers_decryption_certificate_for_email);
	g_test_add_func("/filter/expiry-flags", test_expiry_flags);
	g_test_add_func("/filter/expired-is-offered-but-sorts-last",
	                test_expired_is_offered_but_sorts_last);
	g_test_add_func("/filter/token-label", test_filter_token_label);
	g_test_add_func("/filter/piv-slot", test_filter_piv_slot);
	g_test_add_func("/filter/key-algorithms", test_filter_key_algorithms);
	g_test_add_func("/filter/eku-and-key-usage", test_filter_eku_and_key_usage);
	g_test_add_func("/filter/issuer-dn", test_filter_issuer_dn);
	g_test_add_func("/filter/parse-rejects-malformed", test_filter_parse_rejects_malformed);
	g_test_add_func("/filter/parse-accepts-wellformed", test_filter_parse_accepts_wellformed);
	g_test_add_func("/filter/parse-absent", test_filter_parse_absent);
	g_test_add_func("/filter/undecodable-extension", test_undecodable_extension_is_not_unrestricted);
	g_test_add_func("/filter/empty-eku", test_empty_eku_is_restricted_to_nothing);
	g_test_add_func("/filter/oversized-eku-oid", test_oversized_eku_oid_is_not_unrestricted);
	g_test_add_func("/discovery/portal-module-is-refused", test_portal_module_is_refused);

	return g_test_run();
}
