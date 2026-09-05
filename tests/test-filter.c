/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * The purpose and certificate_filter rules, against real certificates rather
 * than against a mock of them. Every fixture in tests/fixtures is a certificate
 * certtool actually issued, so a change in how GnuTLS reports an extension
 * fails a test here rather than silently changing which credentials a user is
 * offered.
 */

#include <glib.h>

#include "fixture-util.h"
#include "tokens/filter.h"

typedef struct
{
	const char* fixture;
	gboolean client_auth;
	gboolean signing;
	gboolean email;
	gboolean ssh;
} PurposeCase;

/* The ordinary request: operation_policy defaults to {'sign': true}. */
static void test_purposes(void)
{
	static const PurposeCase cases[] = {
		/* clientAuth EKU, digitalSignature: everything but email. */
		{ "client-auth-rsa.pem", TRUE, TRUE, FALSE, TRUE },
		/* emailProtection EKU on an EC key: email and signing, not client
		 * authentication -- an EKU that names something else is a restriction,
		 * not a suggestion. */
		{ "email-ec.pem", FALSE, TRUE, TRUE, TRUE },
		/* NO EKU EXTENSION AT ALL is not the same as an empty one: X.509 says
		 * the key is unrestricted, so every purpose matches. */
		{ "no-eku-rsa.pem", TRUE, TRUE, TRUE, TRUE },
		/* serverAuth only. Not a credential to offer a user for signing in. */
		{ "server-auth-only.pem", FALSE, FALSE, FALSE, TRUE },
		/* keyEncipherment only, no EKU: the key usage rules out signing, and
		 * ssh still matches because SSH never looks at the certificate. */
		{ "encipherment-only.pem", FALSE, FALSE, FALSE, TRUE },
		/* emailProtection EKU, keyEncipherment only -- the S/MIME decryption
		 * half of a PIV card. Nothing here matches, because this candidate is
		 * asked about with a sign-only policy. */
		{ "email-encipherment-only.pem", FALSE, FALSE, FALSE, TRUE },
		/* emailProtection EKU with both bits set: the ordinary single-
		 * certificate S/MIME setup, which signs as well as decrypts. */
		{ "email-sign-and-encipher.pem", FALSE, TRUE, TRUE, TRUE },
		/* Expired is STILL A MATCH. It is offered and marked, never hidden. */
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

/* A key the card will not sign with is not a candidate for anything: every
 * purpose here ends in a signature. */
static void test_key_that_will_not_sign(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", FALSE, TRUE);

	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                          CERTIFICATE_OPERATION_SIGN));
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_SSH,
	                                          CERTIFICATE_OPERATION_SIGN));

	/* Not even when the caller would take a decryption: none of the three
	 * signing purposes has a decryption to offer. */
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

/* THE S/MIME DECRYPTION HALF. A PIV key-management certificate is
 * keyEncipherment with no digitalSignature, behind a key that will decrypt and
 * never sign. It used to match no purpose at all, which made brokered Decrypt
 * unreachable for the case it exists for. */
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

		/* Offered for email ONLY when the request said it would decrypt. */
		g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
		                                          CERTIFICATE_OPERATION_SIGN));
		g_assert_true(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
		                                         CERTIFICATE_OPERATION_DECRYPT));
		g_assert_true(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
		                                         CERTIFICATE_OPERATION_SIGN |
		                                             CERTIFICATE_OPERATION_DECRYPT));

		/* And for nothing else, however much the caller would accept: a key
		 * that will not sign cannot authenticate, sign or serve ssh. */
		g_assert_cmpint(certificate_purpose_operations(candidate,
		                                              CERTIFICATE_PURPOSE_CLIENT_AUTH),
		                ==, CERTIFICATE_OPERATION_NONE);
		g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_SIGNING),
		                ==, CERTIFICATE_OPERATION_NONE);
		g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_SSH), ==,
		                CERTIFICATE_OPERATION_NONE);
	}
}

/* The S/MIME SIGNING half is not a decryption credential either, and a mail
 * client asking only to decrypt must not be offered it. */
static void test_signing_email_certificate_is_not_offered_for_decryption(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("email-ec.pem", TRUE, FALSE);

	g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_EMAIL), ==,
	                CERTIFICATE_OPERATION_SIGN);
	g_assert_false(certificate_purpose_matches(candidate, CERTIFICATE_PURPOSE_EMAIL,
	                                          CERTIFICATE_OPERATION_DECRYPT));
}

/* A certificate whose key does both, with the key usage to match, is offered
 * for either half -- and the operations it is offered for are the ones the
 * request permits, not everything the key can do. */
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

	/* The card is still the authority on what the key will do: a certificate
	 * whose key usage permits both, on a key whose CKA_DECRYPT is clear, is a
	 * signing credential only. */
	g_assert_cmpint(certificate_purpose_operations(signing_key_only, CERTIFICATE_PURPOSE_EMAIL),
	                ==, CERTIFICATE_OPERATION_SIGN);
}

/* THE KEY USAGE RESTRICTS THE CARD, TOO. A token that sets CKA_SIGN on every
 * key it has -- some do -- must not turn a key-management certificate into a
 * signing credential, or the grant would carry an operation the certificate
 * itself forbids. */
static void test_key_usage_restricts_a_token_that_claims_everything(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("email-encipherment-only.pem", TRUE, TRUE);

	g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_EMAIL), ==,
	                CERTIFICATE_OPERATION_DECRYPT);
	g_assert_cmpint(certificate_purpose_operations(candidate, CERTIFICATE_PURPOSE_SIGNING), ==,
	                CERTIFICATE_OPERATION_NONE);
}

/* End to end through the filter: a decrypt-only request offers the
 * key-management certificate and nothing else on the card. */
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

/* RULE 1: an expired certificate is offered and marked, never hidden -- but it
 * sorts below the ones that work, so a working credential is never buried under
 * a broken one. */
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

/* A candidate whose PIV slot could not be determined is NOT a match for a
 * request that named one: guessing would offer the wrong key. */
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

	/* A TLS-flavoured scheme name is understood by its prefix. */
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

/* A MALFORMED FILTER IS REJECTED, NOT HALF-APPLIED. A filter that silently
 * ignored the part it did not understand would offer credentials the caller
 * said it could not use. */
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

/* No certificate_filter at all is a valid request, and matches on purpose
 * alone. */
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

	return g_test_run();
}
