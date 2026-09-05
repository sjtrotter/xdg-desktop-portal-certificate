/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "mechanism.h"

#include <string.h>

#include <gnutls/gnutls.h>

#include "der.h"

typedef struct
{
	const char* name;
	gsize length;
	int gnutls_digest;
	CK_MECHANISM_TYPE ck_digest;
	CK_RSA_PKCS_MGF_TYPE mgf;
	const guint8* oid;
	gsize oid_length;
} HashEntry;

/* The digest OIDs as they appear inside a DigestInfo AlgorithmIdentifier. */
static const guint8 oid_sha1[] = { 0x2b, 0x0e, 0x03, 0x02, 0x1a };
static const guint8 oid_sha224[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 };
static const guint8 oid_sha256[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const guint8 oid_sha384[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const guint8 oid_sha512[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

static const HashEntry hash_table[] = {
	{ "SHA1", 20, GNUTLS_DIG_SHA1, CKM_SHA_1, CKG_MGF1_SHA1, oid_sha1, sizeof(oid_sha1) },
	{ "SHA224", 28, GNUTLS_DIG_SHA224, CKM_SHA224, CKG_MGF1_SHA224, oid_sha224,
	  sizeof(oid_sha224) },
	{ "SHA256", 32, GNUTLS_DIG_SHA256, CKM_SHA256, CKG_MGF1_SHA256, oid_sha256,
	  sizeof(oid_sha256) },
	{ "SHA384", 48, GNUTLS_DIG_SHA384, CKM_SHA384, CKG_MGF1_SHA384, oid_sha384,
	  sizeof(oid_sha384) },
	{ "SHA512", 64, GNUTLS_DIG_SHA512, CKM_SHA512, CKG_MGF1_SHA512, oid_sha512,
	  sizeof(oid_sha512) },
};

#define RSA_V15 "RSA_PKCS1_V1_5"
#define RSA_PSS "RSA_PSS"
#define ECDSA "ECDSA"
#define RSA_OAEP "RSA_OAEP"

static const PortalMechanism mechanism_table[] = {
	{ CKM_RSA_PKCS, RSA_V15, NULL, FALSE, TRUE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_SHA1_RSA_PKCS, RSA_V15, "SHA1", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_SHA224_RSA_PKCS, RSA_V15, "SHA224", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_SHA256_RSA_PKCS, RSA_V15, "SHA256", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_SHA384_RSA_PKCS, RSA_V15, "SHA384", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_SHA512_RSA_PKCS, RSA_V15, "SHA512", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },

	{ CKM_RSA_PKCS_PSS, RSA_PSS, NULL, FALSE, FALSE, FALSE, TRUE, TRUE, FALSE },
	{ CKM_SHA1_RSA_PKCS_PSS, RSA_PSS, "SHA1", TRUE, FALSE, FALSE, TRUE, TRUE, FALSE },
	{ CKM_SHA224_RSA_PKCS_PSS, RSA_PSS, "SHA224", TRUE, FALSE, FALSE, TRUE, TRUE, FALSE },
	{ CKM_SHA256_RSA_PKCS_PSS, RSA_PSS, "SHA256", TRUE, FALSE, FALSE, TRUE, TRUE, FALSE },
	{ CKM_SHA384_RSA_PKCS_PSS, RSA_PSS, "SHA384", TRUE, FALSE, FALSE, TRUE, TRUE, FALSE },
	{ CKM_SHA512_RSA_PKCS_PSS, RSA_PSS, "SHA512", TRUE, FALSE, FALSE, TRUE, TRUE, FALSE },

	{ CKM_ECDSA, ECDSA, NULL, FALSE, FALSE, TRUE, FALSE, TRUE, FALSE },
	{ CKM_ECDSA_SHA1, ECDSA, "SHA1", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_ECDSA_SHA224, ECDSA, "SHA224", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_ECDSA_SHA256, ECDSA, "SHA256", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_ECDSA_SHA384, ECDSA, "SHA384", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },
	{ CKM_ECDSA_SHA512, ECDSA, "SHA512", TRUE, FALSE, FALSE, FALSE, TRUE, FALSE },

	{ CKM_RSA_PKCS_OAEP, RSA_OAEP, NULL, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE },
};

static const HashEntry* hash_entry(const char* hash)
{
	if (hash == NULL)
		return NULL;

	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		if (strcmp(hash_table[i].name, hash) == 0)
			return &hash_table[i];
	}

	return NULL;
}

const PortalMechanism* portal_mechanism_lookup(CK_MECHANISM_TYPE type)
{
	for (gsize i = 0; i < G_N_ELEMENTS(mechanism_table); i++)
	{
		if (mechanism_table[i].type == type)
			return &mechanism_table[i];
	}

	return NULL;
}

gboolean portal_mechanism_available(const PortalMechanism* mechanism, const char* const* names)
{
	if (mechanism == NULL || names == NULL)
		return FALSE;

	for (gsize i = 0; names[i] != NULL; i++)
	{
		if (strcmp(names[i], mechanism->portal_mechanism) == 0)
			return TRUE;
	}

	return FALSE;
}

GArray* portal_mechanism_list(const char* const* names)
{
	GArray* list = g_array_new(FALSE, FALSE, sizeof(CK_MECHANISM_TYPE));

	for (gsize i = 0; i < G_N_ELEMENTS(mechanism_table); i++)
	{
		if (portal_mechanism_available(&mechanism_table[i], names))
			g_array_append_val(list, mechanism_table[i].type);
	}

	return list;
}

gsize portal_hash_length(const char* hash)
{
	const HashEntry* entry = hash_entry(hash);

	return entry != NULL ? entry->length : 0;
}

const char* portal_hash_for_length(gsize length)
{
	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		if (hash_table[i].length == length)
			return hash_table[i].name;
	}

	return NULL;
}

int portal_hash_gnutls(const char* hash)
{
	const HashEntry* entry = hash_entry(hash);

	return entry != NULL ? entry->gnutls_digest : GNUTLS_DIG_UNKNOWN;
}

CK_MECHANISM_TYPE portal_hash_ck_digest(const char* hash)
{
	const HashEntry* entry = hash_entry(hash);

	return entry != NULL ? entry->ck_digest : 0;
}

const char* portal_hash_from_ck_digest(CK_MECHANISM_TYPE digest)
{
	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		if (hash_table[i].ck_digest == digest)
			return hash_table[i].name;
	}

	return NULL;
}

gboolean portal_digestinfo_parse(const guint8* data, gsize size, const char** hash,
                                 const guint8** digest, gsize* digest_length)
{
	PortalDerTlv outer;
	PortalDerTlv algorithm;
	PortalDerTlv oid;
	PortalDerTlv value;
	const HashEntry* entry = NULL;

	if (data == NULL || size == 0)
		return FALSE;

	if (!portal_der_read_tag(data, size, PORTAL_DER_SEQUENCE, &outer))
		return FALSE;
	/* Trailing bytes after the DigestInfo are not a DigestInfo. */
	if (outer.consumed != size)
		return FALSE;

	if (!portal_der_read_tag(outer.value, outer.length, PORTAL_DER_SEQUENCE, &algorithm))
		return FALSE;

	if (!portal_der_read_tag(algorithm.value, algorithm.length, PORTAL_DER_OID, &oid))
		return FALSE;

	/* The parameters are absent or explicit NULL; anything else is not one of
	 * the five digests this module can name. */
	if (oid.consumed != algorithm.length)
	{
		PortalDerTlv parameters;

		if (!portal_der_read_tag(algorithm.value + oid.consumed, algorithm.length - oid.consumed,
		                         PORTAL_DER_NULL, &parameters))
			return FALSE;
		if (parameters.length != 0 || oid.consumed + parameters.consumed != algorithm.length)
			return FALSE;
	}

	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		if (oid.length == hash_table[i].oid_length &&
		    memcmp(oid.value, hash_table[i].oid, oid.length) == 0)
		{
			entry = &hash_table[i];
			break;
		}
	}

	if (entry == NULL)
		return FALSE;

	if (!portal_der_read_tag(outer.value + algorithm.consumed, outer.length - algorithm.consumed,
	                         PORTAL_DER_OCTET_STRING, &value))
		return FALSE;
	if (algorithm.consumed + value.consumed != outer.length)
		return FALSE;
	if (value.length != entry->length)
		return FALSE;

	if (hash != NULL)
		*hash = entry->name;
	if (digest != NULL)
		*digest = value.value;
	if (digest_length != NULL)
		*digest_length = value.length;

	return TRUE;
}

const char* portal_mgf_hash(CK_RSA_PKCS_MGF_TYPE mgf)
{
	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		if (hash_table[i].mgf == mgf)
			return hash_table[i].name;
	}

	return NULL;
}

const char* portal_mgf_name(CK_RSA_PKCS_MGF_TYPE mgf)
{
	static const char* const names[] = { "MGF1-SHA1", "MGF1-SHA224", "MGF1-SHA256",
		                                 "MGF1-SHA384", "MGF1-SHA512" };

	for (gsize i = 0; i < G_N_ELEMENTS(hash_table); i++)
	{
		if (hash_table[i].mgf == mgf)
			return names[i];
	}

	return NULL;
}
