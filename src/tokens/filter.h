/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_TOKENS_FILTER_H
#define CERTIFICATE_TOKENS_FILTER_H

#include <glib.h>

#include "../certificate.h"
#include "discovery.h"

/** @file
 *  Reducing the discovered certificates to the ones that can satisfy the
 *  request.
 *
 *  FILTERING IS THE BACKEND'S because only the backend can see the
 *  certificates. The frontend validated the SHAPE of the caller's
 *  certificate_filter -- and rejected a malformed one before any backend was
 *  called -- but it has never read a card and never will. This is the clean
 *  half of the device/policy split: the frontend says what may be asked for,
 *  the backend answers from the hardware.
 *
 *  Filtering happens BEFORE anything is shown, so the chooser offers only
 *  credentials that would actually work. It is a usability mechanism with a
 *  security consequence, not a security mechanism: the authorisation decision
 *  is the chooser and the consent policy, not this.
 *
 *  TWO RULES ARE NOT NEGOTIABLE.
 *
 *  1. Expired and not-yet-valid certificates are SHOWN, MARKED, and SELECTABLE.
 *     An expired certificate is a diagnosis the user needs; hiding it produces
 *     "my card is empty" bug reports and a user who cannot see why sign-in
 *     fails. The marking must not rely on colour alone.
 *
 *  2. Filtering to exactly one candidate DOES NOT skip the chooser. The chooser
 *     is where the verified caller, the sandbox status and the purpose are
 *     shown; skipping it because there was only one certificate turns a consent
 *     dialog into a PIN dialog, which is the failure mode this project exists
 *     to end. See docs/IMPL-INTERFACE.md, "interaction_mode".
 */

/** EKU OIDs the purposes map to. "any" does not exist as a purpose; see
 *  CertificatePurpose in ../certificate.h. */
#define CERTIFICATE_EKU_ANY "2.5.29.37.0"
#define CERTIFICATE_EKU_SERVER_AUTH "1.3.6.1.5.5.7.3.1"
#define CERTIFICATE_EKU_CLIENT_AUTH "1.3.6.1.5.5.7.3.2"
#define CERTIFICATE_EKU_CODE_SIGNING "1.3.6.1.5.5.7.3.3"
#define CERTIFICATE_EKU_EMAIL_PROTECTION "1.3.6.1.5.5.7.3.4"
/* Microsoft smart-card logon, which PIV authentication certificates carry and
 * which means the same thing as clientAuth for this backend's purposes. */
#define CERTIFICATE_EKU_SMARTCARD_LOGON "1.3.6.1.4.1.311.20.2.2"

/** The operations a candidate can serve, as a set. A purpose is matched when
 *  the operations the candidate could serve it with overlap the ones the
 *  request's operation_policy permits -- which is how a certificate that will
 *  only decrypt is offered for `email` to a mail client asking to decrypt, and
 *  to nobody else. */
typedef enum
{
	CERTIFICATE_OPERATION_NONE = 0,
	CERTIFICATE_OPERATION_SIGN = 1 << 0,
	CERTIFICATE_OPERATION_DECRYPT = 1 << 1
} CertificateOperations;

/** All fields optional, all AND-ed. Supplied by the caller and therefore
 *  untrusted as to INTENT -- but harmless, because narrowing the offered set
 *  can only reduce what the user is asked to consent to. A filter matching
 *  nothing is reported distinctly from "no token at all": the user needs to
 *  know whether to insert a card or to talk to whoever issued it. */
typedef struct
{
	CertificatePurpose purpose;
	CertificateOperations operations; /**< what the caller's operation_policy permits */
	GPtrArray* issuers;    /**< GBytes, DER issuer DNs as a TLS CertificateRequest supplies them */
	char** key_usage;      /**< X.509 key-usage bits that must be present */
	char** eku_oids;       /**< explicit OIDs, where the purpose shorthand is not enough */
	char** key_algorithms; /**< key types and signature schemes the CALLER can use */
	char* token_label;
	char* piv_slot;
} CertificateFilter;

/** Which operations could @candidate serve @purpose with, ignoring what the
 *  caller asked for?
 *
 *  `client_auth`, `signing` and `ssh` are signing purposes and yield at most
 *  CERTIFICATE_OPERATION_SIGN. `email` is not: S/MIME splits mail between a
 *  signing certificate and a decryption certificate, and on a card those are
 *  separate keys -- a PIV key-management certificate is `keyEncipherment` with
 *  no `digitalSignature`, and the key behind it will decrypt and never sign.
 *  So `email` yields SIGN, DECRYPT, or both, and a certificate that yields
 *  only DECRYPT is a credential a mail client can still use.
 *
 *  Exported for `--list-tokens`, which prints what each certificate is good
 *  for, and for the unit tests. */
CertificateOperations certificate_purpose_operations(const CertificateCandidate* candidate,
                                                     CertificatePurpose purpose);

/** Does @candidate fit @purpose for at least one of the @permitted operations?
 *  Exported for the unit tests, which run it against fixture certificates with
 *  no token in sight. */
gboolean certificate_purpose_matches(const CertificateCandidate* candidate,
                                     CertificatePurpose purpose,
                                     CertificateOperations permitted);

/** Does @candidate satisfy every field of @filter, including the purpose? */
gboolean certificate_filter_matches(const CertificateCandidate* candidate,
                                    const CertificateFilter* filter);

/** Apply @filter to @candidates, returning a new array of the survivors in the
 *  order they should be offered. Never reorders by "likely" or "last used" in a
 *  way that could be mistaken for a recommendation this service is not
 *  qualified to make: the order is the order they were discovered in, with
 *  usable certificates before unusable ones so that an expired certificate does
 *  not sit above the one that works. */
GPtrArray* certificate_filter_apply(GPtrArray* candidates, const CertificateFilter* filter);

/** Parse the caller's certificate_filter vardict, which arrives inside the
 *  AcquireCredential options. Rejects a malformed filter rather than silently
 *  ignoring the parts it did not understand -- a filter that half-applied would
 *  offer credentials the caller said it could not use. */
gboolean certificate_filter_parse(GVariant* options, CertificatePurpose purpose,
                                  CertificateOperations operations, CertificateFilter* out,
                                  GError** error);

void certificate_filter_clear(CertificateFilter* filter);

#endif /* CERTIFICATE_TOKENS_FILTER_H */
