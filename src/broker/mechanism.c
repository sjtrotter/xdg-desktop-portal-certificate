/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "mechanism.h"

#include <string.h>

/* RFC 8017 section 9.2, the DigestInfo prefixes for EMSA-PKCS1-v1_5. They are
 * constants, not something to derive at run time. */
static const guint8 digest_info_sha1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	                                       0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
static const guint8 digest_info_sha224[] = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
	                                         0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
	                                         0x04, 0x05, 0x00, 0x04, 0x1c };
static const guint8 digest_info_sha256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
	                                         0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
	                                         0x01, 0x05, 0x00, 0x04, 0x20 };
static const guint8 digest_info_sha384[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
	                                         0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
	                                         0x02, 0x05, 0x00, 0x04, 0x30 };
static const guint8 digest_info_sha512[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
	                                         0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
	                                         0x03, 0x05, 0x00, 0x04, 0x40 };

typedef struct
{
	const char* name;
	CertificateHash hash;
	gsize length;
	CK_MECHANISM_TYPE ck_hash;
	CK_RSA_PKCS_MGF_TYPE mgf;
	const guint8* digest_info;
	gsize digest_info_length;
} HashEntry;

static const HashEntry hash_table[] = {
	{ "SHA1", CERTIFICATE_HASH_SHA1, 20, CKM_SHA_1, CKG_MGF1_SHA1, digest_info_sha1,
	  sizeof(digest_info_sha1) },
	{ "SHA224", CERTIFICATE_HASH_SHA224, 28, CKM_SHA224, CKG_MGF1_SHA224, digest_info_sha224,
	  sizeof(digest_info_sha224) },
	{ "SHA256", CERTIFICATE_HASH_SHA256, 32, CKM_SHA256, CKG_MGF1_SHA256, digest_info_sha256,
	  sizeof(digest_info_sha256) },
	{ "SHA384", CERTIFICATE_HASH_SHA384, 48, CKM_SHA384, CKG_MGF1_SHA384, digest_info_sha384,
	  sizeof(digest_info_sha384) },
	{ "SHA512", CERTIFICATE_HASH_SHA512, 64, CKM_SHA512, CKG_MGF1_SHA512, digest_info_sha512,
	  sizeof(digest_info_sha512) },
};

static const HashEntry* hash_entry(CertificateHash hash)
{
	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		if (hash_table[i].hash == hash)
			return &hash_table[i];
	}

	return NULL;
}

gboolean certificate_hash_parse(const char* name, CertificateHash* out)
{
	if (name == NULL)
		return FALSE;

	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		/* Accept "SHA-256" as well as "SHA256": the two spellings are both in
		 * wide use and refusing one of them is a papercut, not a check. */
		g_autofree char* dashed = g_strdup_printf("SHA-%s", hash_table[i].name + 3);

		if (g_ascii_strcasecmp(name, hash_table[i].name) == 0 ||
		    g_ascii_strcasecmp(name, dashed) == 0)
		{
			if (out != NULL)
				*out = hash_table[i].hash;
			return TRUE;
		}
	}

	return FALSE;
}

const char* certificate_hash_to_string(CertificateHash hash)
{
	const HashEntry* entry = hash_entry(hash);

	return entry != NULL ? entry->name : "NONE";
}

gsize certificate_hash_length(CertificateHash hash)
{
	const HashEntry* entry = hash_entry(hash);

	return entry != NULL ? entry->length : 0;
}

void certificate_mechanism_clear(CertificateMechanism* mechanism)
{
	if (mechanism == NULL)
		return;

	g_clear_pointer(&mechanism->name, g_free);
	memset(&mechanism->pss, 0, sizeof(mechanism->pss));
	mechanism->has_pss = FALSE;
	mechanism->digest_info = NULL;
	mechanism->digest_info_length = 0;
}

static gboolean parse_encoding(GVariant* parameters, CertificateSignatureEncoding* out,
                               GError** error)
{
	const char* text = NULL;

	*out = CERTIFICATE_SIGNATURE_RAW;

	if (parameters == NULL)
		return TRUE;

	if (!g_variant_lookup(parameters, "signature_encoding", "&s", &text))
		return TRUE;

	if (g_strcmp0(text, "raw") == 0)
		return TRUE;

	if (g_strcmp0(text, "der") == 0)
	{
		*out = CERTIFICATE_SIGNATURE_DER;
		return TRUE;
	}

	g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
	            "Unknown signature_encoding '%s'; expected 'raw' or 'der'", text);
	return FALSE;
}

static gboolean parse_hash(GVariant* parameters, CertificateHash* out, GError** error)
{
	const char* text = NULL;

	if (parameters == NULL || !g_variant_lookup(parameters, "hash", "&s", &text))
	{
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		                    "A 'hash' parameter is required: this backend signs a digest, "
		                    "never a message, and has to be told which digest it is");
		return FALSE;
	}

	if (!certificate_hash_parse(text, out))
	{
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Unknown hash '%s'", text);
		return FALSE;
	}

	return TRUE;
}

gboolean certificate_mechanism_parse(const char* name, GVariant* parameters, const char* key_type,
                                     guint key_size, gboolean for_decrypt,
                                     CertificateMechanism* out, GError** error)
{
	memset(out, 0, sizeof(*out));

	if (name == NULL)
	{
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		                    "A mechanism is required");
		return FALSE;
	}

	if (for_decrypt)
	{
		/* The frontend's allow list is RSA_PKCS1_V1_5, RSA_PSS and ECDSA. Of
		 * those, exactly one decrypts anything. Naming a signature mechanism in
		 * a Decrypt call is refused rather than reinterpreted. */
		if (g_strcmp0(name, "RSA_PKCS1_V1_5") != 0)
		{
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			            "'%s' is not a decryption mechanism", name);
			return FALSE;
		}

		if (g_strcmp0(key_type, "RSA") != 0)
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			                    "RSA_PKCS1_V1_5 decryption needs an RSA key");
			return FALSE;
		}

		out->name = g_strdup(name);
		out->type = CKM_RSA_PKCS;
		out->hash = CERTIFICATE_HASH_NONE;
		out->encoding = CERTIFICATE_SIGNATURE_RAW;
		return TRUE;
	}

	if (!parse_encoding(parameters, &out->encoding, error))
		return FALSE;

	if (g_strcmp0(name, "RSA_PKCS1_V1_5") == 0)
	{
		const HashEntry* entry = NULL;

		if (g_strcmp0(key_type, "RSA") != 0)
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			                    "RSA_PKCS1_V1_5 needs an RSA key");
			return FALSE;
		}

		if (!parse_hash(parameters, &out->hash, error))
			return FALSE;

		entry = hash_entry(out->hash);
		g_assert(entry != NULL);

		/* RFC 8017 9.2 step 3: the encoded message must fit, with at least
		 * eight bytes of padding and the leading 0x00 0x01. */
		if ((gsize) (key_size / 8) < entry->digest_info_length + entry->length + 11)
		{
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "A %u-bit RSA key is too small for a %s PKCS#1 v1.5 signature",
			            key_size, entry->name);
			return FALSE;
		}

		out->name = g_strdup(name);
		out->type = CKM_RSA_PKCS;
		out->digest_info = entry->digest_info;
		out->digest_info_length = entry->digest_info_length;
		return TRUE;
	}

	if (g_strcmp0(name, "RSA_PSS") == 0)
	{
		const HashEntry* entry = NULL;
		const char* mgf_name = NULL;
		CertificateHash mgf_hash;
		guint32 salt_length = 0;
		gsize em_length;

		if (g_strcmp0(key_type, "RSA") != 0)
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			                    "RSA_PSS needs an RSA key");
			return FALSE;
		}

		if (!parse_hash(parameters, &out->hash, error))
			return FALSE;

		entry = hash_entry(out->hash);
		g_assert(entry != NULL);
		mgf_hash = out->hash;

		/* An MGF that is not MGF1-over-a-hash-this-backend-knows is refused,
		 * not passed through: pParameter goes straight into the module. */
		if (parameters != NULL && g_variant_lookup(parameters, "mgf", "&s", &mgf_name))
		{
			const char* rest = mgf_name;

			if (g_ascii_strncasecmp(rest, "MGF1-", 5) == 0)
				rest += 5;
			else if (g_ascii_strncasecmp(rest, "MGF1", 4) == 0 && rest[4] == '\0')
				rest = entry->name;

			if (!certificate_hash_parse(rest, &mgf_hash))
			{
				g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
				            "Unknown mask generation function '%s'", mgf_name);
				return FALSE;
			}
		}

		salt_length = (guint32) entry->length;
		if (parameters != NULL)
		{
			g_autoptr(GVariant) value = g_variant_lookup_value(parameters, "salt_length", NULL);

			if (value != NULL)
			{
				if (!g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
				{
					g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
					                    "salt_length must be a uint32");
					return FALSE;
				}

				salt_length = g_variant_get_uint32(value);
			}
		}

		/* RFC 8017 9.1.1 step 3: emLen >= hLen + sLen + 2, with
		 * emLen = ceil((modBits - 1) / 8). The frontend cannot check this: it
		 * does not know the modulus size. */
		em_length = (key_size - 1 + 7) / 8;
		if (em_length < entry->length + salt_length + 2)
		{
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "A salt of %u bytes does not fit in a %u-bit RSA-PSS signature over %s",
			            salt_length, key_size, entry->name);
			return FALSE;
		}

		out->name = g_strdup(name);
		out->type = CKM_RSA_PKCS_PSS;
		out->has_pss = TRUE;
		out->pss.hashAlg = entry->ck_hash;
		out->pss.mgf = hash_entry(mgf_hash)->mgf;
		out->pss.sLen = salt_length;
		return TRUE;
	}

	if (g_strcmp0(name, "ECDSA") == 0)
	{
		if (g_strcmp0(key_type, "EC") != 0)
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			                    "ECDSA needs an EC key");
			return FALSE;
		}

		if (!parse_hash(parameters, &out->hash, error))
			return FALSE;

		out->name = g_strdup(name);
		out->type = CKM_ECDSA;
		return TRUE;
	}

	g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Unknown mechanism '%s'", name);
	return FALSE;
}

void certificate_mechanism_to_ck(CertificateMechanism* mechanism, CK_MECHANISM* out)
{
	out->mechanism = mechanism->type;

	if (mechanism->has_pss)
	{
		out->pParameter = &mechanism->pss;
		out->ulParameterLen = sizeof(mechanism->pss);
	}
	else
	{
		out->pParameter = NULL;
		out->ulParameterLen = 0;
	}
}

GBytes* certificate_mechanism_prepare(const CertificateMechanism* mechanism, GBytes* data,
                                      GError** error)
{
	gsize size = 0;
	const guint8* bytes = g_bytes_get_data(data, &size);
	gsize expected = certificate_hash_length(mechanism->hash);

	if (mechanism->hash == CERTIFICATE_HASH_NONE)
	{
		/* Decryption: the ciphertext is whatever the key produced. */
		return g_bytes_ref(data);
	}

	if (size != expected)
	{
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		            "Expected a %" G_GSIZE_FORMAT "-byte %s digest, got %" G_GSIZE_FORMAT
		            " bytes",
		            expected, certificate_hash_to_string(mechanism->hash), size);
		return NULL;
	}

	if (mechanism->digest_info == NULL)
		return g_bytes_ref(data);

	{
		g_autofree guint8* buffer = g_malloc(mechanism->digest_info_length + size);

		memcpy(buffer, mechanism->digest_info, mechanism->digest_info_length);
		memcpy(buffer + mechanism->digest_info_length, bytes, size);

		return g_bytes_new_take(g_steal_pointer(&buffer), mechanism->digest_info_length + size);
	}
}

/* DER INTEGER from a big-endian unsigned value: strip leading zeroes, then add
 * one back if the top bit is set, because DER integers are signed. */
static void append_der_integer(GByteArray* out, const guint8* value, gsize length)
{
	gsize start = 0;

	while (start + 1 < length && value[start] == 0)
		start++;

	g_byte_array_append(out, (const guint8[]){ 0x02 }, 1);

	if (value[start] & 0x80)
	{
		guint8 header[2] = { (guint8) (length - start + 1), 0x00 };

		g_byte_array_append(out, header, 2);
	}
	else
	{
		guint8 header[1] = { (guint8) (length - start) };

		g_byte_array_append(out, header, 1);
	}

	g_byte_array_append(out, value + start, length - start);
}

GBytes* certificate_ecdsa_raw_to_der(const guint8* raw, gsize length, GError** error)
{
	g_autoptr(GByteArray) body = NULL;
	g_autoptr(GByteArray) out = NULL;
	gsize half = length / 2;

	if (length == 0 || length % 2 != 0)
	{
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		            "A raw ECDSA signature must be an even number of bytes, got %" G_GSIZE_FORMAT,
		            length);
		return NULL;
	}

	body = g_byte_array_new();
	append_der_integer(body, raw, half);
	append_der_integer(body, raw + half, half);

	out = g_byte_array_new();
	g_byte_array_append(out, (const guint8[]){ 0x30 }, 1);

	if (body->len < 0x80)
	{
		guint8 header[1] = { (guint8) body->len };

		g_byte_array_append(out, header, 1);
	}
	else
	{
		/* A P-521 signature body is over 127 bytes, so the long form is
		 * reachable with the curves this backend supports. */
		guint8 header[2] = { 0x81, (guint8) body->len };

		g_byte_array_append(out, header, 2);
	}

	g_byte_array_append(out, body->data, body->len);

	return g_byte_array_free_to_bytes(g_steal_pointer(&out));
}
