/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "fixture-util.h"

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "broker/mechanism.h"

static GByteArray* load_der(const char* name)
{
	g_autofree char* path = g_build_filename(CERTIFICATE_FIXTURE_DIR, name, NULL);
	g_autofree char* pem = NULL;
	gsize length = 0;
	g_autoptr(GError) error = NULL;
	gnutls_x509_crt_t crt = NULL;
	gnutls_datum_t datum;
	gnutls_datum_t out = { NULL, 0 };
	GByteArray* der = NULL;

	if (!g_file_get_contents(path, &pem, &length, &error))
		g_error("could not read the fixture %s: %s", path, error->message);

	datum.data = (unsigned char*) pem;
	datum.size = (unsigned int) length;

	g_assert_cmpint(gnutls_x509_crt_init(&crt), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_PEM), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &out), ==, 0);

	der = g_byte_array_sized_new(out.size);
	g_byte_array_append(der, out.data, out.size);

	gnutls_free(out.data);
	gnutls_x509_crt_deinit(crt);

	return der;
}

CertificateCandidate* certificate_test_candidate(const char* name, gboolean can_sign,
                                                 gboolean can_decrypt)
{
	g_autoptr(GByteArray) der = load_der(name);
	g_autoptr(GError) error = NULL;
	CertificateCandidate* candidate =
	    certificate_candidate_new_from_der(der->data, der->len, &error);

	if (candidate == NULL)
		g_error("could not parse the fixture %s: %s", name, error->message);

	candidate->can_sign = can_sign;
	candidate->can_decrypt = can_decrypt;

	/* What a token would have reported for a key of this type. */
	if (g_strcmp0(candidate->key_type, "RSA") == 0)
	{
		const char* mechanisms[] = { "RSA_PKCS1_V1_5", "RSA_PSS", NULL };

		candidate->supported_mechanisms = g_strdupv((char**) mechanisms);
	}
	else if (g_strcmp0(candidate->key_type, "EC") == 0)
	{
		const char* mechanisms[] = { "ECDSA", NULL };

		candidate->supported_mechanisms = g_strdupv((char**) mechanisms);
	}

	certificate_test_attach_token(candidate, "Test Token", NULL);

	return candidate;
}

void certificate_test_attach_token(CertificateCandidate* candidate, const char* label,
                                   const char* piv_slot)
{
	g_clear_pointer(&candidate->token, certificate_token_unref);
	g_clear_pointer(&candidate->piv_slot, g_free);

	/* CertificateToken has no public constructor: it is only ever produced from
	 * a slot. The test builds one by hand, which is the one place that is
	 * legitimate, and is why the struct is in the header. */
	candidate->token = g_new0(CertificateToken, 1);
	g_atomic_ref_count_init(&candidate->token->ref_count);
	candidate->token->label = g_strdup(label);
	candidate->token->manufacturer = g_strdup("Test");
	candidate->token->model = g_strdup("Test");
	candidate->token->serial = g_strdup("0123456789abcdef");
	candidate->token->reader_name = g_strdup("Test reader");

	if (piv_slot != NULL)
		candidate->piv_slot = g_strdup(piv_slot);
}

void certificate_test_verify_signature(CertificateCandidate* candidate,
                                       gnutls_sign_algorithm_t algorithm, const guint8* digest,
                                       gsize digest_length, GBytes* signature, gboolean ecdsa)
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
