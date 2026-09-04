/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_LOG_REDACT_H
#define SMARTCARD_LOG_REDACT_H

#include <glib.h>

/** @file
 *  Structured logging that cannot emit a secret, because it is never handed one.
 *
 *  REDACTION IS STRUCTURAL, NOT A FILTER. These functions accept only the fields they
 *  are allowed to emit. There is deliberately no smartcard_log_printf(): a filter that
 *  must RECOGNISE a secret in a formatted string has already been handed the secret, and
 *  the first unrecognised shape leaks it.
 *
 *  ALLOWED: counts, stable reason codes, purposes, resolved caller identity and its
 *  honesty level, grant and operation ids, mechanism names, token PRESENCE, timings,
 *  decisions.
 *
 *  NEVER: PINs, PKCS#11 URIs, object labels, key ids, card serials, certificate
 *  subjects, signed data, plaintext, or the contents of the caller's reason and context
 *  strings.
 *
 *  ERROR TEXT FROM LIBRARIES IS TRUNCATED BEFORE ANY EMBEDDED URI. p11-kit, OpenSC and
 *  GnuTLS all put PKCS#11 URIs in error strings, and a URI may carry a pin-value
 *  attribute. Truncating at the first "pkcs11:" is cheap and correct; passing library
 *  error text through unmodified is how a PIN reaches a journal.
 *
 *  The default level records DECISIONS, not data: which caller, which honesty level,
 *  which purpose, granted or refused, and why. That is enough for a user to answer "what
 *  used my card, and when" -- which is one of the things this project is for -- without
 *  becoming a record of what they signed.
 *
 *  Sketch only; nothing here is implemented.
 */

/** Stable reason codes. Machine-greppable, translation-independent, and safe to log. */
#define SMARTCARD_REASON_REQUEST_RECEIVED "request-received"
#define SMARTCARD_REASON_IDENTITY_RESOLVED "identity-resolved"
#define SMARTCARD_REASON_IDENTITY_UNVERIFIED "identity-unverified"
#define SMARTCARD_REASON_DISCOVERY_STARTED "discovery-started"
#define SMARTCARD_REASON_DISCOVERY_RESULT "discovery-result"
#define SMARTCARD_REASON_NO_MATCHING_CERT "no-matching-certificate"
#define SMARTCARD_REASON_CHOOSER_SHOWN "chooser-shown"
#define SMARTCARD_REASON_CHOOSER_CANCELLED "chooser-cancelled"
#define SMARTCARD_REASON_CONSENT_GRANTED "consent-granted"
#define SMARTCARD_REASON_PIN_PROMPTED "pin-prompted"
#define SMARTCARD_REASON_PIN_INCORRECT "pin-incorrect"
#define SMARTCARD_REASON_PIN_LOCKED "pin-locked"
#define SMARTCARD_REASON_LOGIN_OK "login-ok"
#define SMARTCARD_REASON_GRANT_CREATED "grant-created"
#define SMARTCARD_REASON_GRANT_INVALIDATED "grant-invalidated"
#define SMARTCARD_REASON_OPERATION_REFUSED "operation-refused"
#define SMARTCARD_REASON_OPERATION_COMPLETED "operation-completed"
#define SMARTCARD_REASON_RATE_LIMITED "rate-limited"
#define SMARTCARD_REASON_TOKEN_REMOVED "token-removed"
#define SMARTCARD_REASON_ENDPOINT_OPENED "endpoint-opened"
#define SMARTCARD_REASON_ENDPOINT_POISONED "endpoint-poisoned"
#define SMARTCARD_REASON_FACADE_CALL_REFUSED "facade-call-refused"

/** A decision about a request. @app_id and @level come from identity resolution and are
 *  the only caller-derived strings that may be logged; the caller's own reason and
 *  context are not among them. */
void smartcard_log_decision(const char* reason_code, const char* app_id, const char* level,
                            const char* purpose, gboolean granted);

/** An event about a grant. No certificate, no token identity, no URI. */
void smartcard_log_grant(const char* reason_code, const char* grant_id, const char* detail_code);

/** An operation. @mechanism is a mechanism NAME. There is no parameter for the data, the
 *  digest, or the signature, and there will not be one. */
void smartcard_log_operation(const char* reason_code, const char* grant_id,
                             const char* operation_id, const char* mechanism);

/** Counts only. The number of tokens and candidates found, never which. */
void smartcard_log_counts(const char* reason_code, guint tokens, guint candidates);

/** Truncate library error text at the first PKCS#11 URI. Returns a newly allocated
 *  string safe to log. Every GError message from p11-kit, OpenSC or GnuTLS passes
 *  through this before it reaches a log or a D-Bus error_message. */
char* smartcard_redact_error_text(const char* text);

#endif /* SMARTCARD_LOG_REDACT_H */
