/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#ifndef CERTIFICATE_REDACT_H
#define CERTIFICATE_REDACT_H

#include <glib.h>

/** Logging accepts restricted fields to keep secrets out; see docs/SECURITY.md for the logging boundary. */

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
/* A timed-out C_Login cannot be withdrawn; see --login-timeout. */
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
#define CERTIFICATE_REASON_COLOUR_SCHEME "colour-scheme"

/** Only frontend-resolved identity strings may identify callers in logs. */
void certificate_log_decision(const char* reason_code, const char* app_id, const char* level,
                            const char* purpose, gboolean granted);

void certificate_log_grant(const char* reason_code, const char* grant_id, const char* detail_code);

void certificate_log_operation(const char* reason_code, const char* grant_id,
                             const char* operation_id, const char* mechanism);

void certificate_log_counts(const char* reason_code, guint tokens, guint candidates);

/** Truncate library errors before URI or PIN markers, then cap and escape; the caller owns the result. */
char* certificate_redact_error_text(const char* text);

char* certificate_redact_serial(const char* serial);

void certificate_log_debug(const char* reason_code, const char* detail_code);

void certificate_log_set_verbose(gboolean verbose);
gboolean certificate_log_get_verbose(void);

#endif
