/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_MECHANISM_H
#define PKCS11_PORTAL_MECHANISM_H

#include <glib.h>

#include <p11-kit/pkcs11.h>

/** @file
 *  The map between a PKCS#11 mechanism and the portal's `Sign`/`Decrypt`
 *  vocabulary.
 *
 *  The portal only ever signs a DIGEST, and the digest's length must match the
 *  `hash` named in the parameters. That constrains the map in three ways:
 *
 *   - `CKM_RSA_PKCS` arrives as an EMSA-PKCS1-v1_5 DigestInfo, which is parsed
 *     to (hash, digest). Input that is not a DigestInfo is refused; the TLS 1.0
 *     and 1.1 MD5+SHA1 concatenation has no hash name to send and is refused
 *     with CKR_MECHANISM_INVALID;
 *   - the `CKM_SHA*_` mechanisms hash locally and then send the digest;
 *   - `CKM_ECDSA` arrives as a bare digest, so the hash is inferred from its
 *     length.
 */

typedef struct
{
	CK_MECHANISM_TYPE type;
	const char* portal_mechanism; /**< RSA_PKCS1_V1_5, RSA_PSS, ECDSA or RSA_OAEP */
	const char* hash;             /**< NULL when the input decides it */
	gboolean hash_locally;        /**< the caller passes a message, not a digest */
	gboolean digest_info;         /**< the input is a DigestInfo to parse */
	gboolean infer_hash;          /**< the input is a bare digest of known length */
	gboolean pss;                 /**< takes CK_RSA_PKCS_PSS_PARAMS */
	gboolean can_sign;
	gboolean can_decrypt;
} PortalMechanism;

/** The mechanism table entry for @type, or NULL if this module has none. */
const PortalMechanism* portal_mechanism_lookup(CK_MECHANISM_TYPE type);

/** Whether @type is usable given the portal mechanism names @names from
 *  GetCapabilities or from a grant's supported_mechanisms. */
gboolean portal_mechanism_available(const PortalMechanism* mechanism, const char* const* names);

/** Every CK_MECHANISM_TYPE this module offers given @names, in table order. The
 *  array is CK_MECHANISM_TYPE and is owned by the caller. */
GArray* portal_mechanism_list(const char* const* names);

/** Digest length in bytes for a portal hash name, or 0. */
gsize portal_hash_length(const char* hash);

/** The portal hash name whose digest is @length bytes, or NULL. */
const char* portal_hash_for_length(gsize length);

/** gnutls_digest_algorithm_t for @hash, or GNUTLS_DIG_UNKNOWN (0). */
int portal_hash_gnutls(const char* hash);

/** CKM_* digest mechanism for @hash, for CK_RSA_PKCS_PSS_PARAMS validation. */
CK_MECHANISM_TYPE portal_hash_ck_digest(const char* hash);

/** The portal hash name a CKM_* digest mechanism spells, or NULL. */
const char* portal_hash_from_ck_digest(CK_MECHANISM_TYPE digest);

/** Parse an EMSA-PKCS1-v1_5 DigestInfo. On success @hash names the digest
 *  algorithm and @digest points into @data. */
gboolean portal_digestinfo_parse(const guint8* data, gsize size, const char** hash,
                                 const guint8** digest, gsize* digest_length);

/** The portal's spelling of a mask generation function, `MGF1-<hash>`, or NULL
 *  for a CKG_MGF1_* value this module does not offer. */
const char* portal_mgf_name(CK_RSA_PKCS_MGF_TYPE mgf);

/** The hash CKG_MGF1_* names, or NULL. */
const char* portal_mgf_hash(CK_RSA_PKCS_MGF_TYPE mgf);

#endif /* PKCS11_PORTAL_MECHANISM_H */
