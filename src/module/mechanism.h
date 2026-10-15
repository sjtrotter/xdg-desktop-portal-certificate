/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_MECHANISM_H
#define PKCS11_PORTAL_MECHANISM_H

#include <glib.h>

#include <p11-kit/pkcs11.h>

/** Portal signing requires a named digest; CKM_RSA_PKCS input must be DigestInfo and legacy MD5+SHA1 is unsupported. */

typedef struct
{
	CK_MECHANISM_TYPE type;
	const char* portal_mechanism;
	const char* hash;             /**< NULL when inferred from input. */
	gboolean hash_locally;        /**< Input requires local hashing. */
	gboolean digest_info;
	gboolean infer_hash;
	gboolean pss;
	gboolean can_sign;
	gboolean can_decrypt;
} PortalMechanism;

const PortalMechanism* portal_mechanism_lookup(CK_MECHANISM_TYPE type);

gboolean portal_mechanism_available(const PortalMechanism* mechanism, const char* const* names);

/** The caller owns the CK_MECHANISM_TYPE array. */
GArray* portal_mechanism_list(const char* const* names);

/** Unknown hashes return zero. */
gsize portal_hash_length(const char* hash);

/** Unknown lengths return NULL. */
const char* portal_hash_for_length(gsize length);

/** Unknown hashes return GNUTLS_DIG_UNKNOWN. */
int portal_hash_gnutls(const char* hash);

CK_MECHANISM_TYPE portal_hash_ck_digest(const char* hash);

const char* portal_hash_from_ck_digest(CK_MECHANISM_TYPE digest);

/** The returned digest borrows @data. */
gboolean portal_digestinfo_parse(const guint8* data, gsize size, const char** hash,
                                 const guint8** digest, gsize* digest_length);

const char* portal_mgf_name(CK_RSA_PKCS_MGF_TYPE mgf);

const char* portal_mgf_hash(CK_RSA_PKCS_MGF_TYPE mgf);

#endif
