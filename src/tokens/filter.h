/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_TOKENS_FILTER_H
#define CERTIFICATE_TOKENS_FILTER_H

#include <glib.h>

#include "../certificate.h"
#include "discovery.h"

/** Filtering never skips consent; expired certificates remain selectable and marked in words. See docs/IMPL-INTERFACE.md. */

#define CERTIFICATE_EKU_ANY "2.5.29.37.0"
#define CERTIFICATE_EKU_SERVER_AUTH "1.3.6.1.5.5.7.3.1"
#define CERTIFICATE_EKU_CLIENT_AUTH "1.3.6.1.5.5.7.3.2"
#define CERTIFICATE_EKU_CODE_SIGNING "1.3.6.1.5.5.7.3.3"
#define CERTIFICATE_EKU_EMAIL_PROTECTION "1.3.6.1.5.5.7.3.4"
/* Treat Microsoft smart-card logon as client authentication. */
#define CERTIFICATE_EKU_SMARTCARD_LOGON "1.3.6.1.4.1.311.20.2.2"

/** Candidate operations must overlap the request's permitted operations. */
typedef enum
{
	CERTIFICATE_OPERATION_NONE = 0,
	CERTIFICATE_OPERATION_SIGN = 1 << 0,
	CERTIFICATE_OPERATION_DECRYPT = 1 << 1
} CertificateOperations;

/** Optional filter fields are intersected and can only narrow the offered credentials. */
typedef struct
{
	CertificatePurpose purpose;
	CertificateOperations operations;
	GPtrArray* issuers;    /**< GBytes elements containing DER issuer DNs. */
	char** key_usage;      /**< Required X.509 key-usage bits. */
	char** eku_oids;
	char** key_algorithms; /**< Key types and signature schemes supported by the caller. */
	char* token_label;
	char* piv_slot;
} CertificateFilter;

/** Email may permit signing or decryption; the other purposes require signing. */
CertificateOperations certificate_purpose_operations(const CertificateCandidate* candidate,
                                                     CertificatePurpose purpose);

gboolean certificate_purpose_matches(const CertificateCandidate* candidate,
                                     CertificatePurpose purpose,
                                     CertificateOperations permitted);

gboolean certificate_filter_matches(const CertificateCandidate* candidate,
                                    const CertificateFilter* filter);

/** Preserve discovery order within validity groups, with currently valid certificates first. */
GPtrArray* certificate_filter_apply(GPtrArray* candidates, const CertificateFilter* filter);

/** Reject malformed or unknown filter constraints as a whole. */
gboolean certificate_filter_parse(GVariant* options, CertificatePurpose purpose,
                                  CertificateOperations operations, CertificateFilter* out,
                                  GError** error);

void certificate_filter_clear(CertificateFilter* filter);

#endif
