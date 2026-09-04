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

/* An OAEP label is a domain separator, not a payload. The same number the
 * frontend uses, so that a request it accepted is not refused here for a
 * reason it could have applied itself. */
#define CERTIFICATE_MAX_LABEL_SIZE 256

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
	memset(&mechanism->oaep, 0, sizeof(mechanism->oaep));
	mechanism->has_oaep = FALSE;
	g_clear_pointer(&mechanism->label, g_free);
	mechanism->label_length = 0;
	mechanism->expected_input = 0;
	mechanism->digest_info = NULL;
	mechanism->digest_info_length = 0;
}

/* PRESENT WITH THE WRONG TYPE IS AN ERROR, NEVER "ABSENT" -- the same rule the
 * option parsing in certificate-impl.c applies, and for the same reason.
 * g_variant_lookup(..., "&s", ...) cannot tell a missing key from one holding a
 * uint32, so every optional string in this file goes through here: a mistyped
 * `signature_encoding` used to mean "raw", a mistyped `mgf` used to mean "MGF1
 * over the signature hash", and a mistyped `mgf1_hash` used to mean "no need to
 * check it against `hash`". None of those defaults is dangerous on its own; a
 * caller whose parameters were silently discarded rather than refused is.
 *
 * Returns FALSE with @error set for a present non-string. @out is left NULL for
 * a key that is genuinely absent. */
static gboolean lookup_string(GVariant* parameters, const char* key, GVariant** holder,
                              const char** out, GError** error)
{
	*out = NULL;

	if (parameters == NULL)
		return TRUE;

	*holder = g_variant_lookup_value(parameters, key, NULL);
	if (*holder == NULL)
		return TRUE;

	if (!g_variant_is_of_type(*holder, G_VARIANT_TYPE_STRING))
	{
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		            "The '%s' parameter must be a string", key);
		return FALSE;
	}

	*out = g_variant_get_string(*holder, NULL);
	return TRUE;
}

static gboolean parse_encoding(GVariant* parameters, CertificateSignatureEncoding* out,
                               GError** error)
{
	g_autoptr(GVariant) holder = NULL;
	const char* text = NULL;

	*out = CERTIFICATE_SIGNATURE_RAW;

	if (!lookup_string(parameters, "signature_encoding", &holder, &text, error))
		return FALSE;

	if (text == NULL)
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
		                    "never a message, and OAEP is a hash's worth of padding, so "
		                    "either way it has to be told which hash");
		return FALSE;
	}

	if (!certificate_hash_parse(text, out))
	{
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Unknown hash '%s'", text);
		return FALSE;
	}

	return TRUE;
}

/* An unknown key in `parameters` is refused rather than ignored, and the
 * vocabulary is PER OPERATION: a key that means something for a signature
 * means nothing for a decryption, and a caller sending `salt_length` to
 * Decrypt is either expecting a constraint this backend does not apply or
 * probing for one. Both lists are the whole vocabulary of their side. */
static gboolean parameters_are_known(GVariant* parameters, gboolean for_decrypt, GError** error)
{
	static const char* const sign_keys[] = { "hash", "mgf", "salt_length", "signature_encoding",
		                                     NULL };
	static const char* const decrypt_keys[] = { "hash", "mgf1_hash", "label", NULL };
	const char* const* known = for_decrypt ? decrypt_keys : sign_keys;
	GVariantIter iter;
	const char* key = NULL;

	if (parameters == NULL)
		return TRUE;

	g_variant_iter_init(&iter, parameters);
	while (g_variant_iter_next(&iter, "{&sv}", &key, NULL))
	{
		if (g_strv_contains(known, key))
			continue;

		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		            "Unknown parameter '%s'", key);
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

	if (!parameters_are_known(parameters, for_decrypt, error))
		return FALSE;

	if (for_decrypt)
	{
		const HashEntry* entry = NULL;
		const char* mgf1_name = NULL;
		CertificateHash mgf1_hash;
		g_autoptr(GVariant) mgf1_holder = NULL;
		g_autoptr(GVariant) label = NULL;

		/* RSA_OAEP AND NOTHING ELSE, and the refusal names the reason rather
		 * than pretending the mechanism is unknown -- it is not unknown, it is
		 * a signing mechanism, and a caller that asked for PKCS#1 v1.5
		 * decryption should be told what it asked for.
		 *
		 * WHY V1.5 IS NOT AN OPTION. C_Decrypt answers "padding valid, here is
		 * the plaintext" or "that failed", and those two answers are
		 * distinguishable on the wire. Repeated against a key the user
		 * consented to once, that is Bleichenbacher's attack: it recovers
		 * plaintext and can forge a signature with the same key, for as long as
		 * the grant lasts, with no further consent. Sign is constrained to a
		 * digest of a named length precisely so that it cannot be used that
		 * way; letting Decrypt hand over the equivalent capability through a
		 * different door would make that constraint decorative. The interface
		 * says a backend must not implement v1.5 decryption behind some other
		 * mechanism name either, and this is the only branch that decrypts. */
		if (g_strcmp0(name, "RSA_OAEP") != 0)
		{
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			            "'%s' may not be used to decrypt; RSA_OAEP is the only decryption "
			            "mechanism on this interface, because a PKCS#1 v1.5 decryption whose "
			            "outcome the caller can observe is a padding oracle over the card's key",
			            name);
			return FALSE;
		}

		if (g_strcmp0(key_type, "RSA") != 0)
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			                    "RSA_OAEP needs an RSA key");
			return FALSE;
		}

		if (!parse_hash(parameters, &out->hash, error))
			return FALSE;

		entry = hash_entry(out->hash);
		g_assert(entry != NULL);

		/* PKCS#1 lets MGF1 use a different hash than OAEP itself. Nothing asks
		 * for that on purpose, the value goes straight into the module's
		 * mechanism parameter, and the frontend already refuses a mismatch --
		 * so this refuses it too rather than trusting that it did. */
		if (!lookup_string(parameters, "mgf1_hash", &mgf1_holder, &mgf1_name, error))
			return FALSE;

		if (mgf1_name != NULL)
		{
			if (!certificate_hash_parse(mgf1_name, &mgf1_hash))
			{
				g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
				            "Unknown mgf1_hash '%s'", mgf1_name);
				return FALSE;
			}

			if (mgf1_hash != out->hash)
			{
				g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
				            "The 'mgf1_hash' must name the same hash as 'hash', not '%s'",
				            mgf1_name);
				return FALSE;
			}
		}

		/* The OAEP label is a domain separator, not a payload: 256 bytes is
		 * the frontend's cap and there is no reason to allow more here. */
		if (parameters != NULL)
		{
			label = g_variant_lookup_value(parameters, "label", NULL);

			if (label != NULL && !g_variant_is_of_type(label, G_VARIANT_TYPE_BYTESTRING))
			{
				g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
				                    "The 'label' must be a byte array");
				return FALSE;
			}

			if (label != NULL && g_variant_get_size(label) > CERTIFICATE_MAX_LABEL_SIZE)
			{
				g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
				            "A 'label' of %" G_GSIZE_FORMAT " bytes is longer than the %d this "
				            "interface allows",
				            g_variant_get_size(label), CERTIFICATE_MAX_LABEL_SIZE);
				return FALSE;
			}
		}

		/* RFC 8017 7.1.2 step 1b: an OAEP ciphertext is exactly one modulus
		 * long, and mLen <= k - 2hLen - 2 has to be satisfiable at all. The
		 * frontend can check neither: it does not know the modulus size. */
		if ((gsize) (key_size / 8) < 2 * entry->length + 2)
		{
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "A %u-bit RSA key is too small for RSA-OAEP over %s", key_size,
			            entry->name);
			return FALSE;
		}

		out->name = g_strdup(name);
		out->type = CKM_RSA_PKCS_OAEP;
		out->has_oaep = TRUE;
		out->expected_input = key_size / 8;
		out->oaep.hashAlg = entry->ck_hash;
		out->oaep.mgf = entry->mgf;

		/* CKZ_DATA_SPECIFIED is the only source type PKCS#11 defines, and it
		 * is correct with no label too: pSourceData NULL and a length of zero
		 * is the empty label, which is what OAEP's default is. */
		out->oaep.source = CKZ_DATA_SPECIFIED;
		if (label != NULL && g_variant_get_size(label) > 0)
		{
			gsize size = 0;
			const guint8* bytes = g_variant_get_fixed_array(label, &size, 1);

			out->label = g_memdup2(bytes, size);
			out->label_length = size;
			out->oaep.pSourceData = out->label;
			out->oaep.ulSourceDataLen = (CK_ULONG) out->label_length;
		}

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
		out->expected_input = entry->length;
		out->digest_info = entry->digest_info;
		out->digest_info_length = entry->digest_info_length;
		return TRUE;
	}

	if (g_strcmp0(name, "RSA_PSS") == 0)
	{
		const HashEntry* entry = NULL;
		const char* mgf_name = NULL;
		CertificateHash mgf_hash;
		g_autoptr(GVariant) mgf_holder = NULL;
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
		if (!lookup_string(parameters, "mgf", &mgf_holder, &mgf_name, error))
			return FALSE;

		if (mgf_name != NULL)
		{
			const char* rest = NULL;

			/* THE SPELLING IS THE INTERFACE'S: "MGF1-<hash>", or plain "MGF1"
			 * meaning MGF1 over `hash`. A bare hash name used to be accepted
			 * too, which was leniency the interface does not describe and a
			 * second backend would not implement. */
			if (g_ascii_strncasecmp(mgf_name, "MGF1-", 5) == 0)
				rest = mgf_name + 5;
			else if (g_ascii_strcasecmp(mgf_name, "MGF1") == 0)
				rest = entry->name;

			if (rest == NULL || !certificate_hash_parse(rest, &mgf_hash))
			{
				g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
				            "Unknown mask generation function '%s'; expected MGF1-<hash>",
				            mgf_name);
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
		/* gsize on BOTH sides. entry->length + salt_length + 2 in the operands'
		 * own types wraps on a 32-bit build for salt_length near G_MAXUINT32,
		 * and a wrapped sum passes the check and sends sLen = 0xFFFFFFFF into
		 * the module. */
		em_length = (key_size - 1 + 7) / 8;
		if (em_length < (gsize) entry->length + (gsize) salt_length + 2)
		{
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "A salt of %u bytes does not fit in a %u-bit RSA-PSS signature over %s",
			            salt_length, key_size, entry->name);
			return FALSE;
		}

		out->name = g_strdup(name);
		out->type = CKM_RSA_PKCS_PSS;
		out->expected_input = entry->length;
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
		out->expected_input = certificate_hash_length(out->hash);
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
	else if (mechanism->has_oaep)
	{
		out->pParameter = &mechanism->oaep;
		out->ulParameterLen = sizeof(mechanism->oaep);
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

	if (mechanism->expected_input != 0 && size != mechanism->expected_input)
	{
		/* An RSA ciphertext is exactly one modulus long -- there is no other
		 * length one can have -- and a digest is exactly the length its hash
		 * produces. Neither fact is secret, so saying which was expected leaks
		 * nothing; what must not be distinguishable is which way a decryption
		 * of the RIGHT length failed, and that is handled in broker/operations.c
		 * where the module's answer comes back. */
		if (mechanism->has_oaep)
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "An RSA-OAEP ciphertext must be exactly %" G_GSIZE_FORMAT
			            " bytes for this key, not %" G_GSIZE_FORMAT,
			            mechanism->expected_input, size);
		else
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "Expected a %" G_GSIZE_FORMAT "-byte %s digest, got %" G_GSIZE_FORMAT
			            " bytes",
			            mechanism->expected_input, certificate_hash_to_string(mechanism->hash),
			            size);
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
	else if (body->len <= 0xff)
	{
		/* A P-521 signature body is over 127 bytes, so the one-byte long form
		 * is reachable with the curves this backend supports. */
		guint8 header[2] = { 0x81, (guint8) body->len };

		g_byte_array_append(out, header, 2);
	}
	else
	{
		/* Not reachable with any curve in use, but truncating a length into a
		 * guint8 here would silently produce malformed DER the first time a
		 * module returned an oversized raw signature. */
		guint8 header[3] = { 0x82, (guint8) (body->len >> 8), (guint8) (body->len & 0xff) };

		g_byte_array_append(out, header, 3);
	}

	g_byte_array_append(out, body->data, body->len);

	return g_byte_array_free_to_bytes(g_steal_pointer(&out));
}
