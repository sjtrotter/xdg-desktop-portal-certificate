/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * The client-side PKCS#11 module's rules, with no D-Bus and no portal: the
 * DigestInfo parser, the mechanism map, the object model, the attribute
 * protocol and template matching. These are the parts a hostile or merely
 * unusual consumer reaches first, and none of them needs a bus to be wrong.
 */

#include <string.h>

#include <glib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "module/der.h"
#include "module/mechanism.h"
#include "module/objects.h"
#include "module/constants.h"

#ifndef CERTIFICATE_FIXTURE_DIR
#define CERTIFICATE_FIXTURE_DIR "tests/fixtures"
#endif

/* ---------------------------------------------------------------- fixtures */

static GBytes* fixture_der(const char* name)
{
	g_autofree char* path = g_build_filename(CERTIFICATE_FIXTURE_DIR, name, NULL);
	g_autofree char* pem = NULL;
	gsize length = 0;
	gnutls_x509_crt_t certificate = NULL;
	gnutls_datum_t input;
	gnutls_datum_t der = { NULL, 0 };
	GBytes* bytes = NULL;

	g_assert_true(g_file_get_contents(path, &pem, &length, NULL));

	input.data = (unsigned char*) pem;
	input.size = (unsigned int) length;

	g_assert_cmpint(gnutls_x509_crt_init(&certificate), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_import(certificate, &input, GNUTLS_X509_FMT_PEM), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_export2(certificate, GNUTLS_X509_FMT_DER, &der), ==, 0);

	bytes = g_bytes_new(der.data, der.size);
	gnutls_free(der.data);
	gnutls_x509_crt_deinit(certificate);

	return bytes;
}

static PortalGrant* fixture_grant(const char* name, const char* key_type, guint key_size,
                                  gboolean may_sign, gboolean may_decrypt)
{
	PortalGrant* grant = g_new0(PortalGrant, 1);
	const char* mechanisms[] = { "RSA_PKCS1_V1_5", "RSA_PSS", "ECDSA", "RSA_OAEP", NULL };

	grant->session_handle = g_strdup("/org/freedesktop/portal/desktop/session/x/y");
	grant->certificate_der = fixture_der(name);
	grant->key_type = g_strdup(key_type);
	grant->key_size = key_size;
	grant->may_sign = may_sign;
	grant->may_decrypt = may_decrypt;
	grant->supported_mechanisms = g_strdupv((char**) mechanisms);

	return grant;
}

/* ---------------------------------------------------------------------- DER */

static void test_der_reads_definite_lengths(void)
{
	static const guint8 short_form[] = { 0x04, 0x03, 0x01, 0x02, 0x03 };
	static const guint8 long_form[] = { 0x04, 0x81, 0x80 };
	static const guint8 non_minimal[] = { 0x04, 0x81, 0x01, 0x00 };
	static const guint8 indefinite[] = { 0x30, 0x80, 0x00, 0x00 };
	static const guint8 overrun[] = { 0x04, 0x05, 0x01 };
	static const guint8 high_tag[] = { 0x1f, 0x01, 0x01, 0x00 };
	guint8 padded[131];
	PortalDerTlv tlv;

	g_assert_true(portal_der_read(short_form, sizeof(short_form), &tlv));
	g_assert_cmpint(tlv.tag, ==, PORTAL_DER_OCTET_STRING);
	g_assert_cmpuint(tlv.length, ==, 3);
	g_assert_cmpuint(tlv.consumed, ==, 5);

	memset(padded, 0, sizeof(padded));
	memcpy(padded, long_form, sizeof(long_form));
	g_assert_true(portal_der_read(padded, sizeof(padded), &tlv));
	g_assert_cmpuint(tlv.length, ==, 128);
	g_assert_cmpuint(tlv.consumed, ==, 131);

	/* A one-byte long form under 0x80 is the short form spelled wastefully, and
	 * accepting it would accept two encodings of one value. */
	g_assert_false(portal_der_read(non_minimal, sizeof(non_minimal), &tlv));
	g_assert_false(portal_der_read(indefinite, sizeof(indefinite), &tlv));
	g_assert_false(portal_der_read(overrun, sizeof(overrun), &tlv));
	g_assert_false(portal_der_read(high_tag, sizeof(high_tag), &tlv));
	g_assert_false(portal_der_read(NULL, 0, &tlv));
}

static void test_der_encodes_both_length_forms(void)
{
	guint8 value[300];
	g_autoptr(GBytes) small = NULL;
	g_autoptr(GBytes) large = NULL;
	const guint8* data;
	gsize size = 0;

	memset(value, 0x41, sizeof(value));

	small = portal_der_encode(PORTAL_DER_INTEGER, value, 3);
	data = g_bytes_get_data(small, &size);
	g_assert_cmpuint(size, ==, 5);
	g_assert_cmpint(data[0], ==, 0x02);
	g_assert_cmpint(data[1], ==, 3);

	large = portal_der_encode(PORTAL_DER_OCTET_STRING, value, sizeof(value));
	data = g_bytes_get_data(large, &size);
	g_assert_cmpuint(size, ==, sizeof(value) + 4);
	g_assert_cmpint(data[1], ==, 0x82);
	g_assert_cmpint(data[2], ==, 1);
	g_assert_cmpint(data[3], ==, 44);
}

/* --------------------------------------------------------------- DigestInfo */

static GBytes* digest_info(const char* hash, gsize digest_length, gboolean with_null)
{
	static const guint8 oid_sha256[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
	static const guint8 oid_sha1[] = { 0x2b, 0x0e, 0x03, 0x02, 0x1a };
	static const guint8 oid_sha512[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
	const guint8* oid = oid_sha256;
	gsize oid_length = sizeof(oid_sha256);
	g_autoptr(GBytes) oid_der = NULL;
	g_autoptr(GBytes) algorithm = NULL;
	g_autoptr(GBytes) digest = NULL;
	g_autoptr(GByteArray) inner = g_byte_array_new();
	g_autoptr(GByteArray) body = g_byte_array_new();
	guint8 value[64];
	gsize size = 0;
	const guint8* data;

	if (strcmp(hash, "SHA1") == 0)
	{
		oid = oid_sha1;
		oid_length = sizeof(oid_sha1);
	}
	else if (strcmp(hash, "SHA512") == 0)
	{
		oid = oid_sha512;
		oid_length = sizeof(oid_sha512);
	}

	memset(value, 0x5a, sizeof(value));

	oid_der = portal_der_encode(PORTAL_DER_OID, oid, oid_length);
	data = g_bytes_get_data(oid_der, &size);
	g_byte_array_append(inner, data, (guint) size);
	if (with_null)
	{
		static const guint8 der_null[] = { 0x05, 0x00 };

		g_byte_array_append(inner, der_null, sizeof(der_null));
	}

	algorithm = portal_der_encode(PORTAL_DER_SEQUENCE, inner->data, inner->len);
	data = g_bytes_get_data(algorithm, &size);
	g_byte_array_append(body, data, (guint) size);

	digest = portal_der_encode(PORTAL_DER_OCTET_STRING, value, digest_length);
	data = g_bytes_get_data(digest, &size);
	g_byte_array_append(body, data, (guint) size);

	return portal_der_encode(PORTAL_DER_SEQUENCE, body->data, body->len);
}

static void test_digestinfo_accepts_the_five_digests(void)
{
	static const struct
	{
		const char* hash;
		gsize length;
	} cases[] = { { "SHA1", 20 }, { "SHA256", 32 }, { "SHA512", 64 } };

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		for (int with_null = 0; with_null < 2; with_null++)
		{
			g_autoptr(GBytes) encoded =
			    digest_info(cases[i].hash, cases[i].length, with_null != 0);
			const char* hash = NULL;
			const guint8* digest = NULL;
			gsize length = 0;
			gsize size = 0;
			const guint8* data = g_bytes_get_data(encoded, &size);

			g_assert_true(portal_digestinfo_parse(data, size, &hash, &digest, &length));
			g_assert_cmpstr(hash, ==, cases[i].hash);
			g_assert_cmpuint(length, ==, cases[i].length);
			g_assert_cmpint(digest[0], ==, 0x5a);
		}
	}
}

static void test_digestinfo_refuses_everything_else(void)
{
	g_autoptr(GBytes) valid = digest_info("SHA256", 32, TRUE);
	g_autoptr(GBytes) wrong_length = digest_info("SHA256", 31, TRUE);
	guint8 md5_sha1[36];
	guint8 truncated[8];
	g_autoptr(GByteArray) trailing = g_byte_array_new();
	const guint8* data;
	gsize size = 0;

	/* TLS 1.0 and 1.1 sign MD5 || SHA1 with CKM_RSA_PKCS. It is not a
	 * DigestInfo and there is no hash name to send. */
	memset(md5_sha1, 0x11, sizeof(md5_sha1));
	g_assert_false(portal_digestinfo_parse(md5_sha1, sizeof(md5_sha1), NULL, NULL, NULL));

	data = g_bytes_get_data(wrong_length, &size);
	g_assert_false(portal_digestinfo_parse(data, size, NULL, NULL, NULL));

	data = g_bytes_get_data(valid, &size);
	memcpy(truncated, data, sizeof(truncated));
	g_assert_false(portal_digestinfo_parse(truncated, sizeof(truncated), NULL, NULL, NULL));

	g_byte_array_append(trailing, data, (guint) size);
	g_byte_array_append(trailing, (const guint8*) "\x00", 1);
	g_assert_false(portal_digestinfo_parse(trailing->data, trailing->len, NULL, NULL, NULL));

	g_assert_false(portal_digestinfo_parse(NULL, 0, NULL, NULL, NULL));
}

/* --------------------------------------------------------------- mechanisms */

static void test_mechanism_map(void)
{
	const PortalMechanism* mechanism;

	mechanism = portal_mechanism_lookup(CKM_RSA_PKCS);
	g_assert_nonnull(mechanism);
	g_assert_cmpstr(mechanism->portal_mechanism, ==, "RSA_PKCS1_V1_5");
	g_assert_true(mechanism->digest_info);
	g_assert_false(mechanism->hash_locally);

	mechanism = portal_mechanism_lookup(CKM_SHA256_RSA_PKCS);
	g_assert_cmpstr(mechanism->hash, ==, "SHA256");
	g_assert_true(mechanism->hash_locally);

	mechanism = portal_mechanism_lookup(CKM_RSA_PKCS_PSS);
	g_assert_true(mechanism->pss);
	g_assert_null(mechanism->hash);

	mechanism = portal_mechanism_lookup(CKM_ECDSA);
	g_assert_true(mechanism->infer_hash);
	g_assert_cmpstr(mechanism->portal_mechanism, ==, "ECDSA");

	mechanism = portal_mechanism_lookup(CKM_RSA_PKCS_OAEP);
	g_assert_true(mechanism->can_decrypt);
	g_assert_false(mechanism->can_sign);

	/* Nothing else is offered, whatever the token behind the portal can do. */
	g_assert_null(portal_mechanism_lookup(CKM_RSA_X_509));
	g_assert_null(portal_mechanism_lookup(CKM_AES_CBC));
	g_assert_null(portal_mechanism_lookup(CKM_SHA256));
}

static void test_mechanism_list_follows_the_portal(void)
{
	static const char* const only_ecdsa[] = { "ECDSA", NULL };
	static const char* const everything[] = { "RSA_PKCS1_V1_5", "RSA_PSS", "ECDSA", "RSA_OAEP",
		                                      NULL };
	static const char* const nothing[] = { NULL };
	g_autoptr(GArray) list = portal_mechanism_list(only_ecdsa);
	g_autoptr(GArray) full = portal_mechanism_list(everything);
	g_autoptr(GArray) empty = portal_mechanism_list(nothing);
	g_autoptr(GArray) unset = portal_mechanism_list(NULL);
	gboolean saw_ecdsa = FALSE;

	g_assert_cmpuint(list->len, ==, 6);
	for (guint i = 0; i < list->len; i++)
	{
		CK_MECHANISM_TYPE type = g_array_index(list, CK_MECHANISM_TYPE, i);

		g_assert_cmpstr(portal_mechanism_lookup(type)->portal_mechanism, ==, "ECDSA");
		if (type == CKM_ECDSA)
			saw_ecdsa = TRUE;
	}
	g_assert_true(saw_ecdsa);

	g_assert_cmpuint(full->len, ==, 19);
	g_assert_cmpuint(empty->len, ==, 0);
	g_assert_cmpuint(unset->len, ==, 0);
}

static void test_hash_names(void)
{
	g_assert_cmpuint(portal_hash_length("SHA256"), ==, 32);
	g_assert_cmpuint(portal_hash_length("SHA-256"), ==, 0);
	g_assert_cmpstr(portal_hash_for_length(48), ==, "SHA384");
	g_assert_null(portal_hash_for_length(36));
	g_assert_cmpstr(portal_hash_from_ck_digest(CKM_SHA512), ==, "SHA512");
	g_assert_null(portal_hash_from_ck_digest(CKM_MD5));
	g_assert_cmpstr(portal_mgf_name(CKG_MGF1_SHA256), ==, "MGF1-SHA256");
	g_assert_cmpstr(portal_mgf_hash(CKG_MGF1_SHA384), ==, "SHA384");
	g_assert_null(portal_mgf_name(0x9999));
}

/* ------------------------------------------------------------------ objects */

static PortalObject* object_of_class(PortalObjects* objects, CK_OBJECT_CLASS wanted)
{
	for (guint i = 0; i < objects->objects->len; i++)
	{
		PortalObject* object = g_ptr_array_index(objects->objects, i);

		if (object->object_class == wanted)
			return object;
	}

	return NULL;
}

static GBytes* attribute_of(PortalObject* object, CK_ATTRIBUTE_TYPE type)
{
	CK_ATTRIBUTE query = { type, NULL, 0 };
	GBytes* value;

	g_assert_cmpint(portal_object_get_attributes(object, &query, 1), ==, CKR_OK);
	g_assert_cmpuint(query.ulValueLen, !=, CK_UNAVAILABLE_INFORMATION);

	query.pValue = g_malloc(query.ulValueLen + 1);
	g_assert_cmpint(portal_object_get_attributes(object, &query, 1), ==, CKR_OK);
	value = g_bytes_new(query.pValue, query.ulValueLen);
	g_free(query.pValue);

	return value;
}

static void test_objects_are_three(void)
{
	g_autoptr(PortalGrant) grant = fixture_grant("client-auth-rsa.pem", "RSA", 2048, TRUE, FALSE);
	g_autoptr(PortalObjects) objects = portal_objects_new(grant, 1, NULL);
	PortalObject* certificate;
	PortalObject* private_key;
	g_autoptr(GBytes) certificate_id = NULL;
	g_autoptr(GBytes) key_id = NULL;
	g_autoptr(GBytes) value = NULL;

	g_assert_nonnull(objects);
	g_assert_cmpuint(objects->objects->len, ==, 3);

	certificate = object_of_class(objects, CKO_CERTIFICATE);
	private_key = object_of_class(objects, CKO_PRIVATE_KEY);
	g_assert_nonnull(certificate);
	g_assert_nonnull(private_key);
	g_assert_nonnull(object_of_class(objects, CKO_PUBLIC_KEY));

	/* Handles carry the generation, so a handle from a released grant does not
	 * name an object of the next one. */
	g_assert_cmpuint(certificate->handle, !=, 0);
	g_assert_cmpuint(certificate->handle >> 4, ==, 1);

	certificate_id = attribute_of(certificate, CKA_ID);
	key_id = attribute_of(private_key, CKA_ID);
	g_assert_cmpuint(g_bytes_get_size(certificate_id), ==, 20);
	g_assert_true(g_bytes_equal(certificate_id, key_id));

	value = attribute_of(certificate, CKA_VALUE);
	g_assert_true(g_bytes_equal(value, grant->certificate_der));
}

static void test_private_key_never_yields_key_material(void)
{
	g_autoptr(PortalGrant) grant = fixture_grant("client-auth-rsa.pem", "RSA", 2048, TRUE, FALSE);
	g_autoptr(PortalObjects) objects = portal_objects_new(grant, 2, NULL);
	PortalObject* private_key = object_of_class(objects, CKO_PRIVATE_KEY);
	CK_ATTRIBUTE sensitive[] = { { CKA_VALUE, NULL, 0 }, { CKA_PRIVATE_EXPONENT, NULL, 0 },
		                         { CKA_PRIME_1, NULL, 0 } };
	CK_ATTRIBUTE mixed[] = { { CKA_ID, NULL, 0 }, { CKA_VALUE, NULL, 0 } };
	g_autoptr(GBytes) sign = NULL;
	g_autoptr(GBytes) decrypt = NULL;
	g_autoptr(GBytes) extractable = NULL;

	g_assert_cmpint(portal_object_get_attributes(private_key, sensitive, 3), ==,
	                CKR_ATTRIBUTE_SENSITIVE);
	for (gsize i = 0; i < 3; i++)
		g_assert_cmpuint(sensitive[i].ulValueLen, ==, CK_UNAVAILABLE_INFORMATION);

	/* One sensitive attribute in a template does not stop the readable ones
	 * being answered. */
	g_assert_cmpint(portal_object_get_attributes(private_key, mixed, 2), ==,
	                CKR_ATTRIBUTE_SENSITIVE);
	g_assert_cmpuint(mixed[0].ulValueLen, ==, 20);
	g_assert_cmpuint(mixed[1].ulValueLen, ==, CK_UNAVAILABLE_INFORMATION);

	sign = attribute_of(private_key, CKA_SIGN);
	decrypt = attribute_of(private_key, CKA_DECRYPT);
	extractable = attribute_of(private_key, CKA_EXTRACTABLE);
	g_assert_cmpint(*(const CK_BBOOL*) g_bytes_get_data(sign, NULL), ==, CK_TRUE);
	g_assert_cmpint(*(const CK_BBOOL*) g_bytes_get_data(decrypt, NULL), ==, CK_FALSE);
	g_assert_cmpint(*(const CK_BBOOL*) g_bytes_get_data(extractable, NULL), ==, CK_FALSE);
}

static void test_permitted_operations_reach_the_key(void)
{
	g_autoptr(PortalGrant) grant =
	    fixture_grant("email-encipherment-only.pem", "RSA", 2048, FALSE, TRUE);
	g_autoptr(PortalObjects) objects = portal_objects_new(grant, 3, NULL);
	PortalObject* private_key = object_of_class(objects, CKO_PRIVATE_KEY);
	g_autoptr(GBytes) sign = attribute_of(private_key, CKA_SIGN);
	g_autoptr(GBytes) decrypt = attribute_of(private_key, CKA_DECRYPT);

	g_assert_cmpint(*(const CK_BBOOL*) g_bytes_get_data(sign, NULL), ==, CK_FALSE);
	g_assert_cmpint(*(const CK_BBOOL*) g_bytes_get_data(decrypt, NULL), ==, CK_TRUE);
}

static void test_ec_key_carries_its_curve(void)
{
	g_autoptr(PortalGrant) grant = fixture_grant("email-ec.pem", "EC", 256, TRUE, FALSE);
	g_autoptr(PortalObjects) objects = portal_objects_new(grant, 4, NULL);
	PortalObject* public_key = object_of_class(objects, CKO_PUBLIC_KEY);
	g_autoptr(GBytes) parameters = attribute_of(public_key, CKA_EC_PARAMS);
	g_autoptr(GBytes) point = attribute_of(public_key, CKA_EC_POINT);
	g_autoptr(GBytes) key_type = attribute_of(public_key, CKA_KEY_TYPE);
	const guint8* data = g_bytes_get_data(parameters, NULL);
	const guint8* point_data = g_bytes_get_data(point, NULL);

	g_assert_cmpint(*(const CK_KEY_TYPE*) g_bytes_get_data(key_type, NULL), ==, CKK_EC);
	/* CKA_EC_PARAMS is the curve OID as it appears in the SubjectPublicKeyInfo. */
	g_assert_cmpint(data[0], ==, PORTAL_DER_OID);
	/* CKA_EC_POINT is the point wrapped in an OCTET STRING, uncompressed. */
	g_assert_cmpint(point_data[0], ==, PORTAL_DER_OCTET_STRING);
	g_assert_cmpint(point_data[2], ==, 0x04);
}

static void test_attribute_size_protocol(void)
{
	g_autoptr(PortalGrant) grant = fixture_grant("client-auth-rsa.pem", "RSA", 2048, TRUE, FALSE);
	g_autoptr(PortalObjects) objects = portal_objects_new(grant, 5, NULL);
	PortalObject* certificate = object_of_class(objects, CKO_CERTIFICATE);
	CK_ATTRIBUTE query = { CKA_ID, NULL, 0 };
	CK_ATTRIBUTE unknown = { CKA_URL, NULL, 0 };
	guint8 small[4];

	g_assert_cmpint(portal_object_get_attributes(certificate, &query, 1), ==, CKR_OK);
	g_assert_cmpuint(query.ulValueLen, ==, 20);

	query.pValue = small;
	query.ulValueLen = sizeof(small);
	g_assert_cmpint(portal_object_get_attributes(certificate, &query, 1), ==,
	                CKR_BUFFER_TOO_SMALL);
	g_assert_cmpuint(query.ulValueLen, ==, CK_UNAVAILABLE_INFORMATION);

	g_assert_cmpint(portal_object_get_attributes(certificate, &unknown, 1), ==,
	                CKR_ATTRIBUTE_TYPE_INVALID);
	g_assert_cmpuint(unknown.ulValueLen, ==, CK_UNAVAILABLE_INFORMATION);

	g_assert_cmpint(portal_object_get_attributes(certificate, NULL, 0), ==, CKR_OK);
}

/* ----------------------------------------------------------------- matching */

static void test_template_matching(void)
{
	g_autoptr(PortalGrant) grant = fixture_grant("client-auth-rsa.pem", "RSA", 2048, TRUE, FALSE);
	g_autoptr(PortalObjects) objects = portal_objects_new(grant, 6, NULL);
	PortalObject* certificate = object_of_class(objects, CKO_CERTIFICATE);
	g_autoptr(GBytes) identifier = attribute_of(certificate, CKA_ID);
	CK_OBJECT_CLASS want_private = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS want_secret = CKO_SECRET_KEY;
	gsize size = 0;
	gpointer identifier_data = (gpointer) g_bytes_get_data(identifier, &size);
	guint8 other[20];
	CK_ATTRIBUTE by_class[] = { { CKA_CLASS, &want_private, sizeof(want_private) } };
	CK_ATTRIBUTE by_identifier[] = { { CKA_ID, identifier_data, size } };
	CK_ATTRIBUTE by_wrong_identifier[] = { { CKA_ID, other, sizeof(other) } };
	CK_ATTRIBUTE by_secret[] = { { CKA_CLASS, &want_secret, sizeof(want_secret) } };
	g_autoptr(GArray) all = portal_objects_find(objects, NULL, 0);
	g_autoptr(GArray) privates = portal_objects_find(objects, by_class, 1);
	g_autoptr(GArray) matching = portal_objects_find(objects, by_identifier, 1);
	g_autoptr(GArray) missing = portal_objects_find(objects, by_wrong_identifier, 1);
	g_autoptr(GArray) secrets = portal_objects_find(objects, by_secret, 1);

	memset(other, 0xee, sizeof(other));

	g_assert_cmpuint(all->len, ==, 3);
	g_assert_cmpuint(privates->len, ==, 1);
	g_assert_cmpuint(matching->len, ==, 3);
	g_assert_cmpuint(missing->len, ==, 0);
	g_assert_cmpuint(secrets->len, ==, 0);

	g_assert_nonnull(portal_objects_lookup(objects, certificate->handle));
	g_assert_null(portal_objects_lookup(objects, certificate->handle + 0x1000));
	g_assert_null(portal_objects_lookup(objects, 0));
}

static void test_only_a_credential_search_provokes_a_chooser(void)
{
	CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
	CK_OBJECT_CLASS private_key = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS data_object = CKO_DATA;
	CK_ATTRIBUTE want_certificate[] = { { CKA_CLASS, &certificate, sizeof(certificate) } };
	CK_ATTRIBUTE want_private[] = { { CKA_CLASS, &private_key, sizeof(private_key) } };
	CK_ATTRIBUTE want_data[] = { { CKA_CLASS, &data_object, sizeof(data_object) } };
	CK_ATTRIBUTE malformed[] = { { CKA_CLASS, NULL, 0 } };

	g_assert_true(portal_template_wants_credential(NULL, 0));
	g_assert_true(portal_template_wants_credential(want_certificate, 1));
	g_assert_true(portal_template_wants_credential(want_private, 1));
	/* A trust lookup or a data search must never put a window up. */
	g_assert_false(portal_template_wants_credential(want_data, 1));
	g_assert_false(portal_template_wants_credential(malformed, 1));
}

static void test_refusal_fingerprint_ignores_the_class(void)
{
	CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
	CK_OBJECT_CLASS private_key = CKO_PRIVATE_KEY;
	guint8 identifier[4] = { 1, 2, 3, 4 };
	guint8 other[4] = { 4, 3, 2, 1 };
	CK_ATTRIBUTE certificate_search[] = { { CKA_CLASS, &certificate, sizeof(certificate) },
		                                  { CKA_ID, identifier, sizeof(identifier) } };
	CK_ATTRIBUTE key_search[] = { { CKA_CLASS, &private_key, sizeof(private_key) },
		                          { CKA_ID, identifier, sizeof(identifier) } };
	CK_ATTRIBUTE different[] = { { CKA_CLASS, &private_key, sizeof(private_key) },
		                         { CKA_ID, other, sizeof(other) } };

	/* One handshake looks for the certificate and then for its key. A refusal
	 * has to cover both, or cancelling the chooser prompts again immediately. */
	g_assert_cmpuint(portal_template_fingerprint(certificate_search, 2), ==,
	                 portal_template_fingerprint(key_search, 2));
	g_assert_cmpuint(portal_template_fingerprint(certificate_search, 2), !=,
	                 portal_template_fingerprint(different, 2));
}

static void test_token_constants_match_the_uris(void)
{
	g_autofree char* escaped =
	    g_uri_escape_string(XDG_PORTAL_CERTIFICATE_TOKEN_LABEL, NULL, FALSE);
	g_autofree char* expected =
	    g_strdup_printf("pkcs11:model=%s;manufacturer=%s;token=%s",
	                    XDG_PORTAL_CERTIFICATE_TOKEN_MODEL,
	                    XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER, escaped);
	g_autoptr(PortalGrant) grant = fixture_grant("client-auth-rsa.pem", "RSA", 2048, TRUE, FALSE);
	g_autoptr(PortalObjects) objects = portal_objects_new(grant, 7, NULL);
	g_autoptr(GBytes) label = attribute_of(object_of_class(objects, CKO_CERTIFICATE), CKA_LABEL);
	g_autofree char* label_text =
	    g_strndup(g_bytes_get_data(label, NULL), g_bytes_get_size(label));
	g_autofree char* object_attribute =
	    g_strdup_printf(";object=%s", escaped);

	/* portal-token.h is shared with another repository and the URI in it is
	 * what that repository builds. If this assertion fails, the two sides have
	 * stopped naming the same token. */
	g_assert_cmpstr(XDG_PORTAL_CERTIFICATE_TOKEN_URI, ==, expected);
	g_assert_true(g_str_has_prefix(XDG_PORTAL_CERTIFICATE_CERT_URI,
	                               XDG_PORTAL_CERTIFICATE_TOKEN_URI));
	g_assert_true(g_str_has_suffix(XDG_PORTAL_CERTIFICATE_KEY_URI, ";type=private"));

	/* CKA_LABEL is a constant, and the attribute a single-object import has to
	 * append is built from it. */
	g_assert_cmpstr(label_text, ==, PKCS11_PORTAL_OBJECT_LABEL);
	g_assert_cmpstr(PKCS11_PORTAL_URI_OBJECT_ATTRIBUTE, ==, object_attribute);

	/* CK_TOKEN_INFO's fields are fixed width and are not NUL terminated. */
	g_assert_cmpuint(strlen(XDG_PORTAL_CERTIFICATE_TOKEN_LABEL), <=, 32);
	g_assert_cmpuint(strlen(XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER), <=, 32);
	g_assert_cmpuint(strlen(XDG_PORTAL_CERTIFICATE_TOKEN_MODEL), <=, 16);
	g_assert_cmpuint(strlen(PKCS11_PORTAL_TOKEN_SERIAL_PREFIX), <, 16);

	/* The p11-kit module NAME is the configuration file's basename without the
	 * extension, and src/tokens/discovery.c refuses to load a module with that
	 * name. If the contract renames the file, the refusal must follow. */
	g_assert_true(g_str_has_prefix(XDG_PORTAL_CERTIFICATE_MODULE_CONFIG,
	                              PKCS11_PORTAL_MODULE_NAME));
	g_assert_cmpstr(XDG_PORTAL_CERTIFICATE_MODULE_CONFIG, ==,
	                PKCS11_PORTAL_MODULE_NAME ".module");
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/module/der/definite-lengths", test_der_reads_definite_lengths);
	g_test_add_func("/module/der/encode", test_der_encodes_both_length_forms);
	g_test_add_func("/module/digestinfo/accepted", test_digestinfo_accepts_the_five_digests);
	g_test_add_func("/module/digestinfo/refused", test_digestinfo_refuses_everything_else);
	g_test_add_func("/module/mechanism/map", test_mechanism_map);
	g_test_add_func("/module/mechanism/list", test_mechanism_list_follows_the_portal);
	g_test_add_func("/module/mechanism/hashes", test_hash_names);
	g_test_add_func("/module/objects/three", test_objects_are_three);
	g_test_add_func("/module/objects/sensitive", test_private_key_never_yields_key_material);
	g_test_add_func("/module/objects/operations", test_permitted_operations_reach_the_key);
	g_test_add_func("/module/objects/ec", test_ec_key_carries_its_curve);
	g_test_add_func("/module/objects/attribute-protocol", test_attribute_size_protocol);
	g_test_add_func("/module/objects/matching", test_template_matching);
	g_test_add_func("/module/objects/credential-search",
	                test_only_a_credential_search_provokes_a_chooser);
	g_test_add_func("/module/objects/refusal-fingerprint",
	                test_refusal_fingerprint_ignores_the_class);
	g_test_add_func("/module/token/constants", test_token_constants_match_the_uris);

	return g_test_run();
}
