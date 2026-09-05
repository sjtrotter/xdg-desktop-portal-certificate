/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#ifndef CERTIFICATE_REDACT_H
#define CERTIFICATE_REDACT_H

#include <glib.h>

/** @file
 *  Structured logging that cannot emit a secret, because it is never handed one.
 *
 *  THIS BACKEND'S HALF ONLY. The rules are identical on the two sides of the impl
 *  boundary, but only one side lives here now: the frontend is xdg-desktop-portal, and
 *  its logging is upstream's. The two sides log DIFFERENT THINGS:
 *
 *    FRONTEND (xdg-desktop-portal): which application asked, at which honesty level, for
 *              which purpose, granted or refused, which backend was selected, which
 *              grant, which operation id. It has no card facts to leak.
 *    BACKEND (here): token PRESENCE, mechanism names, PIN outcome codes, facade
 *              refusals. It has no application identity of its own to leak, only the app
 *              id string the portal handed it -- which is exactly what may be logged.
 *
 *  This file was shared/redact.h while this repository also held a frontend. It is now
 *  src/redact.h and the frontend's obligations below are recorded as the OTHER side's,
 *  not as this binary's. See docs/decisions/0010-backend-only-frontend-lives-upstream.md.
 *
 *  REDACTION IS STRUCTURAL, NOT A FILTER. These functions accept only the fields they
 *  are allowed to emit. There is deliberately no certificate_log_printf(): a filter that
 *  must RECOGNISE a secret in a formatted string has already been handed the secret, and
 *  the first unrecognised shape leaks it.
 *
 *  ALLOWED: counts, stable reason codes, purposes, resolved caller identity and its
 *  honesty level, grant and operation ids, mechanism names, token PRESENCE, timings,
 *  decisions.
 *
 *  NEVER: PINs, PKCS#11 URIs, object labels, key ids, card serials, certificate
 *  subjects, signed data, plaintext, or the contents of the caller's `reason` string.
 *  (`context` is gone: the branch interface has no such option.)
 *
 *  ERROR TEXT FROM LIBRARIES IS TRUNCATED BEFORE ANY EMBEDDED URI. p11-kit, OpenSC and
 *  GnuTLS all put PKCS#11 URIs in error strings, and a URI may carry a pin-value
 *  attribute. Truncating at the first "pkcs11:" is cheap and correct; passing library
 *  error text through unmodified is how a PIN reaches a journal.
 *
 *  The default level records DECISIONS, not data: which caller, which honesty level,
 *  which purpose, granted or refused, and why. That is enough for a user to answer "what
 *  used my card, and when" -- and answering it needs BOTH JOURNALS, because the decision
 *  is in xdg-desktop-portal's and the card event is in this backend's; the grant id and
 *  the operation id are what join them -- which is one of the things this project is for
 *  -- without becoming a record of what they signed.
 *
 *  IMPLEMENTED. The negative test -- that a library error string carrying a
 *  pkcs11: URI with a pin-value attribute is truncated before the URI -- lives
 *  in tests/test-redact.c.
 */

/** Stable reason codes. Machine-greppable, translation-independent, and safe to log. */
#define CERTIFICATE_REASON_REQUEST_RECEIVED "request-received"
#define CERTIFICATE_REASON_IDENTITY_RESOLVED "identity-resolved"
#define CERTIFICATE_REASON_IDENTITY_UNVERIFIED "identity-unverified"
#define CERTIFICATE_REASON_DISCOVERY_STARTED "discovery-started"
#define CERTIFICATE_REASON_DISCOVERY_RESULT "discovery-result"
#define CERTIFICATE_REASON_NO_MATCHING_CERT "no-matching-certificate"
#define CERTIFICATE_REASON_CHOOSER_SHOWN "chooser-shown"
#define CERTIFICATE_REASON_CHOOSER_CANCELLED "chooser-cancelled"
#define CERTIFICATE_REASON_CONSENT_GRANTED "consent-granted"
#define CERTIFICATE_REASON_PIN_PROMPTED "pin-prompted"
#define CERTIFICATE_REASON_PIN_INCORRECT "pin-incorrect"
#define CERTIFICATE_REASON_PIN_LOCKED "pin-locked"
/* A C_Login that never came back. The window is gone and the interaction is
 * failed; the module call itself cannot be withdrawn. See --login-timeout. */
#define CERTIFICATE_REASON_PIN_TIMEOUT "pin-timeout"
#define CERTIFICATE_REASON_LOGIN_OK "login-ok"
#define CERTIFICATE_REASON_GRANT_CREATED "grant-created"
#define CERTIFICATE_REASON_GRANT_INVALIDATED "grant-invalidated"
#define CERTIFICATE_REASON_OPERATION_REFUSED "operation-refused"
#define CERTIFICATE_REASON_OPERATION_COMPLETED "operation-completed"
#define CERTIFICATE_REASON_RATE_LIMITED "rate-limited"
#define CERTIFICATE_REASON_TOKEN_REMOVED "token-removed"
#define CERTIFICATE_REASON_ENDPOINT_OPENED "endpoint-opened"
#define CERTIFICATE_REASON_ENDPOINT_POISONED "endpoint-poisoned"
#define CERTIFICATE_REASON_FACADE_CALL_REFUSED "facade-call-refused"
/* Not a request: which colour scheme the windows follow, and where it came
 * from. It was logged as "request-received" and was unreadable there. */
#define CERTIFICATE_REASON_COLOUR_SCHEME "colour-scheme"

/** A decision about a request. @app_id and @level come from identity resolution and are
 *  the only caller-derived strings that may be logged; the caller's own reason and
 *  context are not among them. */
void certificate_log_decision(const char* reason_code, const char* app_id, const char* level,
                            const char* purpose, gboolean granted);

/** An event about a grant. No certificate, no token identity, no URI. */
void certificate_log_grant(const char* reason_code, const char* grant_id, const char* detail_code);

/** An operation. @mechanism is a mechanism NAME. There is no parameter for the data, the
 *  digest, or the signature, and there will not be one. */
void certificate_log_operation(const char* reason_code, const char* grant_id,
                             const char* operation_id, const char* mechanism);

/** Counts only. The number of tokens and candidates found, never which. */
void certificate_log_counts(const char* reason_code, guint tokens, guint candidates);

/** Truncate library error text at the first PKCS#11 URI. Returns a newly allocated
 *  string safe to log. Every GError message from p11-kit, OpenSC or GnuTLS passes
 *  through this before it reaches a log or a D-Bus error_message. */
char* certificate_redact_error_text(const char* text);

/** A token serial reduced to its last four characters. Token PRESENCE may be
 *  logged; token IDENTITY may not, and a card serial is an identity. */
char* certificate_redact_serial(const char* serial);

/** A debug breadcrumb, emitted only under --verbose. Two stable codes, no
 *  free-form text, for the same reason the entry points above take no format
 *  string. */
void certificate_log_debug(const char* reason_code, const char* detail_code);

void certificate_log_set_verbose(gboolean verbose);
gboolean certificate_log_get_verbose(void);

#endif /* CERTIFICATE_REDACT_H */
