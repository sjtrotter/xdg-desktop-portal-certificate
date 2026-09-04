/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_BROKER_MECHANISM_H
#define CERTIFICATE_BROKER_MECHANISM_H

#include <gio/gio.h>
#include <glib.h>

#include "../tokens/pkcs11-util.h"

/** @file
 *  Turning the frontend's mechanism NAME plus its parameters vardict into a
 *  CK_MECHANISM, and validating both against the key.
 *
 *  RE-VALIDATED, NOT FORWARDED. The frontend has already checked that the
 *  mechanism name is in its allow list and that the grant permits it. This
 *  module checks everything again against the actual key, because two checks
 *  against a hostile caller is the correct number, and because the frontend
 *  cannot check what it cannot see: it does not know the modulus size, so it
 *  cannot know that a 480-bit salt does not fit in a 2048-bit signature.
 *
 *  RSA-PSS hash, MGF and salt length are the case that matters: a caller that
 *  can choose them freely can choose badly.
 *
 *  DECRYPTION IS RSA_OAEP AND NOTHING ELSE. PKCS#1 v1.5 decryption tells the
 *  caller whether the padding was well formed -- response 0 with a plaintext,
 *  or a failure -- and that is a Bleichenbacher oracle over the key on the
 *  card, worth more than the signing oracle every other rule in this file
 *  exists to prevent. The interface refuses v1.5 for Decrypt and says a backend
 *  must not implement it behind another mechanism name either. This one does
 *  not: certificate_mechanism_parse() with @for_decrypt accepts one name.
 *
 *  OAEP itself is not an oracle -- a failure says nothing an attacker can
 *  iterate on -- but this module still reports EVERY decryption failure as one
 *  error, because "which failure" is exactly the thing that made v1.5
 *  dangerous and it costs nothing to never build the habit.
 *
 *  WHAT `data` IS. The public interface says "the digest or the message, as the
 *  mechanism requires" and leaves it there. This backend resolves that
 *  ambiguity one way, for every mechanism, and docs/IMPL-INTERFACE.md records
 *  it: `data` IS ALWAYS THE DIGEST, and `parameters.hash` is REQUIRED and names
 *  which digest it is. Nothing is hashed here.
 *
 *   - RSA_PKCS1_V1_5: this module builds the PKCS#1 v1.5 DigestInfo around the
 *     digest and calls CKM_RSA_PKCS. The caller supplies the bare digest, not a
 *     DigestInfo, and never the message.
 *   - RSA_PSS: CKM_RSA_PKCS_PSS with CK_RSA_PKCS_PSS_PARAMS built from the
 *     parameters. The caller supplies the bare digest.
 *   - ECDSA: CKM_ECDSA over the bare digest, which is what PKCS#11 wants.
 *   - RSA_OAEP (decryption only): CKM_RSA_PKCS_OAEP with
 *     CK_RSA_PKCS_OAEP_PARAMS built from the parameters. `data` is the
 *     CIPHERTEXT here, and its length must be exactly one modulus -- the only
 *     length an RSA ciphertext can have, and a check the frontend cannot make
 *     because it does not know the modulus.
 *
 *  Refusing to sign a caller-supplied blob of arbitrary length under a raw
 *  mechanism is deliberate: a signing oracle over unstructured bytes is a
 *  different and much larger thing to consent to than a signature over a
 *  digest of known length.
 */

/** The digest algorithms this backend will build a signature around. */
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

/** How an ECDSA signature is handed back. PKCS#11 produces the raw r||s pair;
 *  X.509 and TLS want it DER encoded as an ECDSA-Sig-Value. The interface does
 *  not say which, so this backend returns the PKCS#11-native form by default
 *  and lets a caller ask for the other one with
 *  parameters.signature_encoding = "der". See docs/IMPL-INTERFACE.md. */
typedef enum
{
	CERTIFICATE_SIGNATURE_RAW,
	CERTIFICATE_SIGNATURE_DER
} CertificateSignatureEncoding;

typedef struct
{
	char* name; /**< the portal mechanism name, for logs */
	CK_MECHANISM_TYPE type;
	CertificateHash hash;
	CertificateSignatureEncoding encoding;

	/* Storage the CK_MECHANISM's pParameter points into. */
	CK_RSA_PKCS_PSS_PARAMS pss;
	gboolean has_pss;
	CK_RSA_PKCS_OAEP_PARAMS oaep;
	gboolean has_oaep;

	/* The OAEP label, owned here because oaep.pSourceData points at it. */
	guint8* label;
	gsize label_length;

	/* How long the input has to be: the digest length for a signature, one
	 * modulus for an OAEP ciphertext. Zero means unconstrained, which nothing
	 * currently is. */
	gsize expected_input;

	/* For RSA_PKCS1_V1_5 signing: the DigestInfo prefix this module puts in
	 * front of the caller's digest. */
	const guint8* digest_info;
	gsize digest_info_length;
} CertificateMechanism;

void certificate_mechanism_clear(CertificateMechanism* mechanism);

/** Parse and validate. @key_type is "RSA" or "EC"; @key_size is the modulus
 *  size in bits for RSA and the curve size for EC. @for_decrypt selects the
 *  decryption vocabulary, which is much smaller. */
gboolean certificate_mechanism_parse(const char* name, GVariant* parameters, const char* key_type,
                                     guint key_size, gboolean for_decrypt,
                                     CertificateMechanism* out, GError** error);

/** Fill in a CK_MECHANISM pointing at @mechanism's own storage. */
void certificate_mechanism_to_ck(CertificateMechanism* mechanism, CK_MECHANISM* out);

/** The bytes actually handed to C_Sign or C_Decrypt: the caller's digest for
 *  ECDSA and PSS, the DigestInfo-wrapped digest for RSA_PKCS1_V1_5, the
 *  ciphertext unchanged for RSA_OAEP. Fails when the input is not the length
 *  the mechanism requires -- the named hash's digest, or one modulus. */
GBytes* certificate_mechanism_prepare(const CertificateMechanism* mechanism, GBytes* data,
                                      GError** error);

/** Re-encode a raw PKCS#11 ECDSA signature (r||s) as a DER ECDSA-Sig-Value.
 *  Exported for the unit tests. */
GBytes* certificate_ecdsa_raw_to_der(const guint8* raw, gsize length, GError** error);

#endif /* CERTIFICATE_BROKER_MECHANISM_H */
