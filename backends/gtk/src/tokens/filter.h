/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_TOKENS_FILTER_H
#define SMARTCARD_TOKENS_FILTER_H

#include <glib.h>

#include "../smartcard.h"
#include "discovery.h"

/** @file
 *  Reducing the discovered certificates to the ones that can satisfy the request.
 *
 *  FILTERING IS THE BACKEND'S because only the backend can see the certificates. The
 *  frontend validated the SHAPE of the caller's certificate_filter -- and rejected a
 *  malformed one before any backend was called -- but it has never read a card and never
 *  will. This is the clean half of the device/policy split: the frontend says what may be
 *  asked for, the backend answers from the hardware.
 *
 *  Filtering happens BEFORE anything is shown, so the chooser offers only credentials
 *  that would actually work. It is a usability mechanism with a security consequence,
 *  not a security mechanism: the authorisation decision is the chooser and the consent
 *  policy, not this.
 *
 *  TWO RULES ARE NOT NEGOTIABLE.
 *
 *  1. Expired and not-yet-valid certificates are SHOWN, MARKED, and SELECTABLE. An
 *     expired certificate is a diagnosis the user needs; hiding it produces "my card is
 *     empty" bug reports and a user who cannot see why sign-in fails. The marking must
 *     not rely on colour alone (docs/INTERFACE.md, accessibility).
 *
 *  2. Filtering to exactly one candidate DOES NOT skip the chooser. The chooser is
 *     where the verified caller, the sandbox status and the purpose are shown; skipping
 *     it because there was only one certificate turns a consent dialog into a PIN
 *     dialog, which is the failure mode this project exists to end.
 *
 *  Sketch only; nothing here is implemented.
 */

/** EKU OIDs the purposes map to. "any" does not exist as a purpose; see
 *  SmartcardPurpose in ../smartcard.h. */
#define SMARTCARD_EKU_CLIENT_AUTH "1.3.6.1.5.5.7.3.2"
#define SMARTCARD_EKU_CODE_SIGNING "1.3.6.1.5.5.7.3.3"
#define SMARTCARD_EKU_EMAIL_PROTECTION "1.3.6.1.5.5.7.3.4"

/** All fields optional, all AND-ed. Supplied by the caller and therefore untrusted as
 *  to INTENT -- but harmless, because narrowing the offered set can only reduce what the
 *  user is asked to consent to. A filter matching nothing is reported as
 *  NoMatchingCertificate, which is deliberately distinct from NoToken: the user needs to
 *  know whether to insert a card or to talk to whoever issued it. */
typedef struct
{
	SmartcardPurpose purpose;
	GPtrArray* issuers;    /**< DER issuer DNs, as a TLS CertificateRequest supplies them */
	char** key_usage;      /**< X.509 key-usage bits that must be present */
	char** eku_oids;       /**< explicit OIDs, where the purpose shorthand is not enough */
	char** key_algorithms; /**< key types and signature schemes the CALLER can use */
	char* token_label;
	char* piv_slot;
} SmartcardFilter;

/** Apply @filter to @candidates, returning a new array of the survivors in the order
 *  they should be offered. Never reorders by "likely" or "last used" in a way that could
 *  be mistaken for a recommendation this service is not qualified to make. */
GPtrArray* smartcard_filter_apply(GPtrArray* candidates, const SmartcardFilter* filter);

/** Parse the caller's certificate_filter vardict. Rejects a malformed filter rather than
 *  silently ignoring the parts it did not understand -- a filter that half-applied would
 *  offer credentials the caller said it could not use. */
gboolean smartcard_filter_parse(GVariant* options, SmartcardFilter* out, GError** error);

void smartcard_filter_clear(SmartcardFilter* filter);

#endif /* SMARTCARD_TOKENS_FILTER_H */
