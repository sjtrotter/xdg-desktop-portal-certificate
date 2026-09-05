/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "objects.h"

#include <string.h>

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "der.h"
#include "constants.h"

G_DEFINE_QUARK(pkcs11-portal-certificate, portal_module_error)

/* Handles are (generation << 4) | index, so that a handle from a released grant
 * does not name an object of the next one. */
#define HANDLE_CERTIFICATE 1u
#define HANDLE_PUBLIC_KEY 2u
#define HANDLE_PRIVATE_KEY 3u

void portal_grant_free(PortalGrant* grant)
{
	if (grant == NULL)
		return;

	g_free(grant->session_handle);
	g_free(grant->grant_id);
	g_clear_pointer(&grant->certificate_der, g_bytes_unref);
	g_free(grant->key_type);
	g_free(grant->key_curve);
	g_strfreev(grant->supported_mechanisms);
	g_free(grant);
}

/* ------------------------------------------------------------- attributes */

static void attribute_clear(gpointer data)
{
	PortalAttribute* attribute = data;

	g_clear_pointer(&attribute->value, g_bytes_unref);
}

static void add_bytes(PortalObject* object, CK_ATTRIBUTE_TYPE type, GBytes* value)
{
	PortalAttribute attribute = { type, value, FALSE };

	g_array_append_val(object->attributes, attribute);
}

static void add_data(PortalObject* object, CK_ATTRIBUTE_TYPE type, const void* data, gsize size)
{
	add_bytes(object, type, g_bytes_new(data, size));
}

static void add_ulong(PortalObject* object, CK_ATTRIBUTE_TYPE type, CK_ULONG value)
{
	add_data(object, type, &value, sizeof(value));
}

static void add_bool(PortalObject* object, CK_ATTRIBUTE_TYPE type, gboolean value)
{
	CK_BBOOL byte = value ? CK_TRUE : CK_FALSE;

	add_data(object, type, &byte, sizeof(byte));
}

static void add_string(PortalObject* object, CK_ATTRIBUTE_TYPE type, const char* value)
{
	add_data(object, type, value, strlen(value));
}

static void add_sensitive(PortalObject* object, CK_ATTRIBUTE_TYPE type)
{
	PortalAttribute attribute = { type, NULL, TRUE };

	g_array_append_val(object->attributes, attribute);
}

static const PortalAttribute* find_attribute(const PortalObject* object, CK_ATTRIBUTE_TYPE type)
{
	for (guint i = 0; i < object->attributes->len; i++)
	{
		const PortalAttribute* attribute =
		    &g_array_index(object->attributes, PortalAttribute, i);

		if (attribute->type == type)
			return attribute;
	}

	return NULL;
}

static PortalObject* object_new(PortalObjects* objects, guint generation, guint index,
                                CK_OBJECT_CLASS object_class)
{
	PortalObject* object = g_new0(PortalObject, 1);

	object->handle = (CK_OBJECT_HANDLE) ((generation << 4) | index);
	object->object_class = object_class;
	object->attributes = g_array_new(FALSE, FALSE, sizeof(PortalAttribute));
	g_array_set_clear_func(object->attributes, attribute_clear);

	g_ptr_array_add(objects->objects, object);
	add_ulong(object, CKA_CLASS, object_class);

	return object;
}

static void object_free(gpointer data)
{
	PortalObject* object = data;

	g_array_free(object->attributes, TRUE);
	g_free(object);
}

/* ----------------------------------------------------------------- parsing */

/* SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE { OID, params OPTIONAL },
 *                                     subjectPublicKey BIT STRING } */
static gboolean spki_split(GBytes* spki, GBytes** parameters, GBytes** key_bits)
{
	gsize size = 0;
	const guint8* data = g_bytes_get_data(spki, &size);
	PortalDerTlv outer;
	PortalDerTlv algorithm;
	PortalDerTlv oid;
	PortalDerTlv bits;

	if (!portal_der_read_tag(data, size, PORTAL_DER_SEQUENCE, &outer))
		return FALSE;
	if (!portal_der_read_tag(outer.value, outer.length, PORTAL_DER_SEQUENCE, &algorithm))
		return FALSE;
	if (!portal_der_read_tag(algorithm.value, algorithm.length, PORTAL_DER_OID, &oid))
		return FALSE;
	if (!portal_der_read_tag(outer.value + algorithm.consumed, outer.length - algorithm.consumed,
	                         PORTAL_DER_BIT_STRING, &bits))
		return FALSE;
	if (bits.length < 1 || bits.value[0] != 0)
		return FALSE;

	if (parameters != NULL)
	{
		*parameters = oid.consumed < algorithm.length
		                  ? g_bytes_new(algorithm.value + oid.consumed,
		                                algorithm.length - oid.consumed)
		                  : NULL;
	}

	if (key_bits != NULL)
		*key_bits = g_bytes_new(bits.value + 1, bits.length - 1);

	return TRUE;
}

static GBytes* strip_leading_zeros(const gnutls_datum_t* datum)
{
	gsize offset = 0;

	while (offset + 1 < datum->size && datum->data[offset] == 0)
		offset++;

	return g_bytes_new(datum->data + offset, datum->size - offset);
}

typedef struct
{
	gnutls_x509_crt_t certificate;
	gnutls_pubkey_t public_key;
	GBytes* spki;
	GBytes* identifier;
	GBytes* subject;
	GBytes* issuer;
	GBytes* serial;
} ParsedCertificate;

static void parsed_certificate_clear(ParsedCertificate* parsed)
{
	if (parsed->certificate != NULL)
		gnutls_x509_crt_deinit(parsed->certificate);
	if (parsed->public_key != NULL)
		gnutls_pubkey_deinit(parsed->public_key);
	g_clear_pointer(&parsed->spki, g_bytes_unref);
	g_clear_pointer(&parsed->identifier, g_bytes_unref);
	g_clear_pointer(&parsed->subject, g_bytes_unref);
	g_clear_pointer(&parsed->issuer, g_bytes_unref);
	g_clear_pointer(&parsed->serial, g_bytes_unref);
}

static gboolean parse_certificate(GBytes* der, ParsedCertificate* parsed, GError** error)
{
	gnutls_datum_t input;
	gnutls_datum_t raw = { NULL, 0 };
	gsize der_size = 0;
	guint8 serial[128];
	size_t serial_size = sizeof(serial);
	guint8 digest[20];
	gsize spki_size = 0;
	const guint8* spki_data = NULL;
	int rc;

	memset(parsed, 0, sizeof(*parsed));

	input.data = (unsigned char*) g_bytes_get_data(der, &der_size);
	input.size = (unsigned int) der_size;

	if (gnutls_x509_crt_init(&parsed->certificate) < 0)
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		                    "Could not allocate a certificate");
		return FALSE;
	}

	if (gnutls_x509_crt_import(parsed->certificate, &input, GNUTLS_X509_FMT_DER) < 0)
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		                    "The portal returned a certificate that will not parse");
		parsed_certificate_clear(parsed);
		return FALSE;
	}

	if (gnutls_pubkey_init(&parsed->public_key) < 0 ||
	    gnutls_pubkey_import_x509(parsed->public_key, parsed->certificate, 0) < 0)
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		                    "The certificate has no usable public key");
		parsed_certificate_clear(parsed);
		return FALSE;
	}

	if (gnutls_pubkey_export2(parsed->public_key, GNUTLS_X509_FMT_DER, &raw) < 0)
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		                    "The public key will not export");
		parsed_certificate_clear(parsed);
		return FALSE;
	}
	parsed->spki = g_bytes_new(raw.data, raw.size);
	gnutls_free(raw.data);

	spki_data = g_bytes_get_data(parsed->spki, &spki_size);
	if (gnutls_hash_fast(GNUTLS_DIG_SHA1, spki_data, spki_size, digest) < 0)
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		                    "Could not derive an object identifier");
		parsed_certificate_clear(parsed);
		return FALSE;
	}
	parsed->identifier = g_bytes_new(digest, sizeof(digest));

	if (gnutls_x509_crt_get_raw_dn(parsed->certificate, &raw) >= 0)
	{
		parsed->subject = g_bytes_new(raw.data, raw.size);
		gnutls_free(raw.data);
	}
	else
	{
		parsed->subject = g_bytes_new(NULL, 0);
	}

	if (gnutls_x509_crt_get_raw_issuer_dn(parsed->certificate, &raw) >= 0)
	{
		parsed->issuer = g_bytes_new(raw.data, raw.size);
		gnutls_free(raw.data);
	}
	else
	{
		parsed->issuer = g_bytes_new(NULL, 0);
	}

	rc = gnutls_x509_crt_get_serial(parsed->certificate, serial, &serial_size);
	parsed->serial = rc >= 0 ? portal_der_encode(PORTAL_DER_INTEGER, serial, serial_size)
	                         : g_bytes_new(NULL, 0);

	return TRUE;
}

/* ------------------------------------------------------------ construction */

static void add_key_public_parts(PortalObject* object, const ParsedCertificate* parsed,
                                 gboolean is_rsa)
{
	if (is_rsa)
	{
		gnutls_datum_t modulus = { NULL, 0 };
		gnutls_datum_t exponent = { NULL, 0 };

		if (gnutls_pubkey_export_rsa_raw(parsed->public_key, &modulus, &exponent) >= 0)
		{
			g_autoptr(GBytes) modulus_bytes = strip_leading_zeros(&modulus);
			g_autoptr(GBytes) exponent_bytes = strip_leading_zeros(&exponent);

			add_bytes(object, CKA_MODULUS, g_bytes_ref(modulus_bytes));
			add_ulong(object, CKA_MODULUS_BITS,
			          (CK_ULONG) (g_bytes_get_size(modulus_bytes) * 8));
			add_bytes(object, CKA_PUBLIC_EXPONENT, g_bytes_ref(exponent_bytes));

			gnutls_free(modulus.data);
			gnutls_free(exponent.data);
		}
	}
	else
	{
		GBytes* parameters = NULL;
		GBytes* key_bits = NULL;

		if (spki_split(parsed->spki, &parameters, &key_bits))
		{
			if (parameters != NULL)
				add_bytes(object, CKA_EC_PARAMS, parameters);

			if (key_bits != NULL)
			{
				gsize size = 0;
				const guint8* data = g_bytes_get_data(key_bits, &size);

				add_bytes(object, CKA_EC_POINT,
				          portal_der_encode(PORTAL_DER_OCTET_STRING, data, size));
				g_bytes_unref(key_bits);
			}
		}
	}
}

PortalObjects* portal_objects_new(const PortalGrant* grant, guint generation, GError** error)
{
	ParsedCertificate parsed;
	PortalObjects* objects;
	PortalObject* object;
	gboolean is_rsa;
	CK_KEY_TYPE key_type;

	g_return_val_if_fail(grant != NULL, NULL);
	g_return_val_if_fail(grant->certificate_der != NULL, NULL);

	if (!parse_certificate(grant->certificate_der, &parsed, error))
		return NULL;

	is_rsa = g_strcmp0(grant->key_type, "EC") != 0;
	key_type = is_rsa ? CKK_RSA : CKK_EC;

	objects = g_new0(PortalObjects, 1);
	objects->objects = g_ptr_array_new_with_free_func(object_free);

	object = object_new(objects, generation, HANDLE_CERTIFICATE, CKO_CERTIFICATE);
	add_bool(object, CKA_TOKEN, TRUE);
	add_bool(object, CKA_PRIVATE, FALSE);
	add_bool(object, CKA_MODIFIABLE, FALSE);
	add_bool(object, CKA_DESTROYABLE, FALSE);
	add_bool(object, CKA_TRUSTED, FALSE);
	add_ulong(object, CKA_CERTIFICATE_TYPE, CKC_X_509);
	add_ulong(object, CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER);
	add_string(object, CKA_LABEL, PKCS11_PORTAL_OBJECT_LABEL);
	add_bytes(object, CKA_ID, g_bytes_ref(parsed.identifier));
	add_bytes(object, CKA_SUBJECT, g_bytes_ref(parsed.subject));
	add_bytes(object, CKA_ISSUER, g_bytes_ref(parsed.issuer));
	add_bytes(object, CKA_SERIAL_NUMBER, g_bytes_ref(parsed.serial));
	add_bytes(object, CKA_VALUE, g_bytes_ref(grant->certificate_der));

	object = object_new(objects, generation, HANDLE_PUBLIC_KEY, CKO_PUBLIC_KEY);
	add_bool(object, CKA_TOKEN, TRUE);
	add_bool(object, CKA_PRIVATE, FALSE);
	add_bool(object, CKA_MODIFIABLE, FALSE);
	add_bool(object, CKA_DESTROYABLE, FALSE);
	add_bool(object, CKA_LOCAL, FALSE);
	add_ulong(object, CKA_KEY_TYPE, key_type);
	add_string(object, CKA_LABEL, PKCS11_PORTAL_OBJECT_LABEL);
	add_bytes(object, CKA_ID, g_bytes_ref(parsed.identifier));
	add_bytes(object, CKA_SUBJECT, g_bytes_ref(parsed.subject));
	add_bool(object, CKA_VERIFY, TRUE);
	add_bool(object, CKA_VERIFY_RECOVER, FALSE);
	add_bool(object, CKA_ENCRYPT, grant->may_decrypt);
	add_bool(object, CKA_WRAP, FALSE);
	add_bool(object, CKA_DERIVE, FALSE);
	add_key_public_parts(object, &parsed, is_rsa);

	object = object_new(objects, generation, HANDLE_PRIVATE_KEY, CKO_PRIVATE_KEY);
	add_bool(object, CKA_TOKEN, TRUE);
	add_bool(object, CKA_PRIVATE, TRUE);
	add_bool(object, CKA_MODIFIABLE, FALSE);
	add_bool(object, CKA_DESTROYABLE, FALSE);
	add_bool(object, CKA_LOCAL, FALSE);
	add_ulong(object, CKA_KEY_TYPE, key_type);
	add_string(object, CKA_LABEL, PKCS11_PORTAL_OBJECT_LABEL);
	add_bytes(object, CKA_ID, g_bytes_ref(parsed.identifier));
	add_bytes(object, CKA_SUBJECT, g_bytes_ref(parsed.subject));
	add_bool(object, CKA_SIGN, grant->may_sign);
	add_bool(object, CKA_SIGN_RECOVER, FALSE);
	add_bool(object, CKA_DECRYPT, grant->may_decrypt);
	add_bool(object, CKA_UNWRAP, FALSE);
	add_bool(object, CKA_DERIVE, FALSE);
	add_bool(object, CKA_SENSITIVE, TRUE);
	add_bool(object, CKA_ALWAYS_SENSITIVE, TRUE);
	add_bool(object, CKA_EXTRACTABLE, FALSE);
	add_bool(object, CKA_NEVER_EXTRACTABLE, TRUE);
	add_bool(object, CKA_ALWAYS_AUTHENTICATE, FALSE);
	add_key_public_parts(object, &parsed, is_rsa);

	/* The attributes that would carry key material exist and refuse. */
	add_sensitive(object, CKA_VALUE);
	if (is_rsa)
	{
		add_sensitive(object, CKA_PRIVATE_EXPONENT);
		add_sensitive(object, CKA_PRIME_1);
		add_sensitive(object, CKA_PRIME_2);
		add_sensitive(object, CKA_EXPONENT_1);
		add_sensitive(object, CKA_EXPONENT_2);
		add_sensitive(object, CKA_COEFFICIENT);
	}

	parsed_certificate_clear(&parsed);
	return objects;
}

void portal_objects_free(PortalObjects* objects)
{
	if (objects == NULL)
		return;

	g_ptr_array_free(objects->objects, TRUE);
	g_free(objects);
}

PortalObject* portal_objects_lookup(PortalObjects* objects, CK_OBJECT_HANDLE handle)
{
	if (objects == NULL)
		return NULL;

	for (guint i = 0; i < objects->objects->len; i++)
	{
		PortalObject* object = g_ptr_array_index(objects->objects, i);

		if (object->handle == handle)
			return object;
	}

	return NULL;
}

/* ---------------------------------------------------------------- matching */

gboolean portal_object_matches(const PortalObject* object, CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	if (count == 0)
		return TRUE;
	if (templ == NULL)
		return FALSE;

	for (CK_ULONG i = 0; i < count; i++)
	{
		const PortalAttribute* attribute = find_attribute(object, templ[i].type);
		gsize size = 0;
		const guint8* data = NULL;

		if (attribute == NULL || attribute->value == NULL)
			return FALSE;
		if (templ[i].ulValueLen == CK_UNAVAILABLE_INFORMATION)
			return FALSE;

		data = g_bytes_get_data(attribute->value, &size);
		if (size != (gsize) templ[i].ulValueLen)
			return FALSE;
		if (size == 0)
			continue;
		if (templ[i].pValue == NULL)
			return FALSE;
		if (memcmp(data, templ[i].pValue, size) != 0)
			return FALSE;
	}

	return TRUE;
}

GArray* portal_objects_find(PortalObjects* objects, CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	GArray* handles = g_array_new(FALSE, FALSE, sizeof(CK_OBJECT_HANDLE));

	if (objects == NULL)
		return handles;

	for (guint i = 0; i < objects->objects->len; i++)
	{
		PortalObject* object = g_ptr_array_index(objects->objects, i);

		if (portal_object_matches(object, templ, count))
			g_array_append_val(handles, object->handle);
	}

	return handles;
}

CK_RV portal_object_get_attributes(const PortalObject* object, CK_ATTRIBUTE_PTR templ,
                                   CK_ULONG count)
{
	gboolean sensitive = FALSE;
	gboolean invalid = FALSE;
	gboolean too_small = FALSE;

	if (count == 0)
		return CKR_OK;
	if (templ == NULL)
		return CKR_ARGUMENTS_BAD;

	for (CK_ULONG i = 0; i < count; i++)
	{
		const PortalAttribute* attribute = find_attribute(object, templ[i].type);
		gsize size = 0;
		const guint8* data = NULL;

		if (attribute == NULL)
		{
			templ[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			invalid = TRUE;
			continue;
		}

		if (attribute->sensitive || attribute->value == NULL)
		{
			templ[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			sensitive = TRUE;
			continue;
		}

		data = g_bytes_get_data(attribute->value, &size);

		if (templ[i].pValue == NULL)
		{
			templ[i].ulValueLen = (CK_ULONG) size;
			continue;
		}

		if ((gsize) templ[i].ulValueLen < size)
		{
			templ[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			too_small = TRUE;
			continue;
		}

		if (size > 0)
			memcpy(templ[i].pValue, data, size);
		templ[i].ulValueLen = (CK_ULONG) size;
	}

	if (sensitive)
		return CKR_ATTRIBUTE_SENSITIVE;
	if (invalid)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	if (too_small)
		return CKR_BUFFER_TOO_SMALL;

	return CKR_OK;
}

gboolean portal_template_wants_credential(CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	if (count == 0)
		return TRUE;
	if (templ == NULL)
		return FALSE;

	for (CK_ULONG i = 0; i < count; i++)
	{
		CK_OBJECT_CLASS object_class;

		if (templ[i].type != CKA_CLASS)
			continue;
		if (templ[i].pValue == NULL || templ[i].ulValueLen != sizeof(object_class))
			return FALSE;

		memcpy(&object_class, templ[i].pValue, sizeof(object_class));

		return object_class == CKO_CERTIFICATE || object_class == CKO_PUBLIC_KEY ||
		       object_class == CKO_PRIVATE_KEY;
	}

	return TRUE;
}

guint portal_template_fingerprint(CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	guint hash = 5381;

	if (templ == NULL)
		return hash;

	for (CK_ULONG i = 0; i < count; i++)
	{
		const guint8* data = templ[i].pValue;

		if (templ[i].type == CKA_CLASS)
			continue;

		hash = (hash * 33) ^ (guint) templ[i].type;

		if (data == NULL || templ[i].ulValueLen == CK_UNAVAILABLE_INFORMATION)
			continue;

		for (CK_ULONG byte = 0; byte < templ[i].ulValueLen; byte++)
			hash = (hash * 33) ^ data[byte];
	}

	return hash;
}
