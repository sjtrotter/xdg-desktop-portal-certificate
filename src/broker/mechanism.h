/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_BROKER_MECHANISM_H
#define CERTIFICATE_BROKER_MECHANISM_H

#include <gio/gio.h>
#include <glib.h>

#include "../tokens/pkcs11-util.h"

/** Validate mechanisms against the key; digest input and decryption constraints are documented in docs/IMPL-INTERFACE.md. */

typedef enum
{
	CERTIFICATE_HASH_NONE,
	CERTIFICATE_HASH_SHA1,
	CERTIFICATE_HASH_SHA224,
	CERTIFICATE_HASH_SHA256,
	CERTIFICATE_HASH_SHA384,
	CERTIFICATE_HASH_SHA512
} CertificateHash;

gboolean certificate_hash_parse(const char* name, CertificateHash* out);
const char* certificate_hash_to_string(CertificateHash hash);
gsize certificate_hash_length(CertificateHash hash);

/** ECDSA defaults to raw r||s; parameters.signature_encoding may request DER. */
typedef enum
{
	CERTIFICATE_SIGNATURE_RAW,
	CERTIFICATE_SIGNATURE_DER
} CertificateSignatureEncoding;

typedef struct
{
	char* name;
	CK_MECHANISM_TYPE type;
	CertificateHash hash;
	CertificateSignatureEncoding encoding;

	/* CK_MECHANISM.pParameter points into this storage. */
	CK_RSA_PKCS_PSS_PARAMS pss;
	gboolean has_pss;
	CK_RSA_PKCS_OAEP_PARAMS oaep;
	gboolean has_oaep;

	/* Owns the label referenced by oaep.pSourceData. */
	guint8* label;
	gsize label_length;

	/* Required digest or ciphertext length; zero means unconstrained. */
	gsize expected_input;

	const guint8* digest_info;
	gsize digest_info_length;
} CertificateMechanism;

void certificate_mechanism_clear(CertificateMechanism* mechanism);

/** @key_type is RSA or EC; @key_size is the RSA modulus size or EC curve size in bits. */
gboolean certificate_mechanism_parse(const char* name, GVariant* parameters, const char* key_type,
                                     guint key_size, gboolean for_decrypt,
                                     CertificateMechanism* out, GError** error);

/** The returned CK_MECHANISM borrows @mechanism's storage. */
void certificate_mechanism_to_ck(CertificateMechanism* mechanism, CK_MECHANISM* out);

/** Wraps RSA_PKCS1_V1_5 digests in DigestInfo and validates input length for every mechanism. */
GBytes* certificate_mechanism_prepare(const CertificateMechanism* mechanism, GBytes* data,
                                      GError** error);

GBytes* certificate_ecdsa_raw_to_der(const guint8* raw, gsize length, GError** error);

#endif
