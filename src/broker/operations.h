/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_BROKER_OPERATIONS_H
#define CERTIFICATE_BROKER_OPERATIONS_H

#include <glib.h>

#include "../certificate.h"

/** @file
 *  The broker. THE CORE CONTRACT: the SYSTEM holds the key and performs the operation,
 *  and "the system" means this process -- the backend -- because the backend is the side
 *  that owns the token session.
 *
 *  The frontend has already established who is asking, that the grant exists, that it is
 *  live, that it is owned by the caller, that the operation is inside it, and that the
 *  caller is not over its rate limit. What arrives here is (session_handle, app_id,
 *  operation_id, mechanism, parameters, data). Everything below is checked AGAIN anyway.
 *
 *  An application never receives key material, never receives the PIN, and never holds a
 *  PKCS#11 handle unless it explicitly asks for the experimental compatibility endpoint
 *  (export/facade.h). It asks for a signature and gets a signature.
 *
 *  WHY THIS AND NOT A FORWARDED MODULE. A sign-capable PKCS#11 session IS a signing
 *  capability, and one with almost no accounting: it cannot be counted, expired per
 *  operation, consented to per operation, or revoked cleanly mid-handshake. A brokered
 *  call can be all of those. See docs/decisions/0007-brokered-operations-are-the-core.md.
 *
 *  WHAT THIS DOES NOT DO: attest purpose. A Sign call cannot be shown to have come from a
 *  TLS handshake rather than from a PDF, a challenge string, or nothing. purpose
 *  constrains certificate SELECTION and the words in the consent dialog. Anyone reading
 *  it as a guarantee about later use has misread it, and every document in this
 *  repository says so.
 *
 *  Sketch only; nothing here is implemented.
 */

/** Consent policy, per purpose. Applied per operation, not once at grant time.
 *
 *   CLIENT_AUTH  one consent per short-lived grant, bound to one verified application,
 *                one certificate and preferably one destination context; expires after
 *                the authentication attempt or a few minutes.
 *   SIGNING      PER-OPERATION CONSENT BY DEFAULT, showing the application context and a
 *                digest or fingerprint of what is being signed when the content cannot
 *                safely be rendered. High-volume or unattended signing needs separately
 *                configured policy, never a checkbox.
 *   EMAIL        a session grant is defensible for sending or reading mail; bulk
 *                behaviour must be explicit.
 *   SSH          its own purpose and its own policy. Not "signing with extra steps".
 *
 *  Decryption, whatever the purpose, is per-operation or tightly bounded: it exposes
 *  confidential data rather than producing an authentication artefact.
 *
 *  A CACHED TOKEN LOGIN MUST NEVER SILENTLY AUTHORISE A DIFFERENT APPLICATION OR A
 *  DIFFERENT PURPOSE. Login is a hardware state; consent is a decision. */
typedef enum
{
	CERTIFICATE_CONSENT_PER_GRANT,
	CERTIFICATE_CONSENT_PER_OPERATION
} CertificateConsentPolicy;

CertificateConsentPolicy certificate_consent_policy_for(CertificatePurpose purpose, gboolean decrypt);

/** A mechanism the allow-list permits, with its parameters ALREADY VALIDATED against the
 *  mechanism and the key -- not forwarded. RSA-PSS hash, MGF and salt length are the
 *  case that matters: a caller that can choose them freely can choose badly. */
typedef struct
{
	char* mechanism;   /**< from the grant's supported_mechanisms */
	GVariant* params;  /**< validated, not trusted */
} CertificateMechanism;

typedef struct CertificateBroker CertificateBroker;

typedef void (*CertificateSignDone)(GByteArray* signature, const GError* error, gpointer user_data);

/** Sign @data with the grant's key.
 *
 *  MAY PROMPT. The first private-key use triggers this service's own lazy login
 *  (ui/pin.h), and some purposes require per-operation consent, so this is
 *  asynchronous and callers were told may_prompt_later at grant time.
 *
 *  Order of checks, all of which must pass: the session exists in this backend and is
 *  bound to this app_id; the caller owns org.freedesktop.portal.Desktop;
 *  operation is in permitted_operations; mechanism is in the allow-list; parameters
 *  validate against mechanism and key; rate limit not exceeded; consent policy satisfied
 *  (which may show a window); token still present; login performed on THIS SERVICE'S
 *  session.
 *
 *  @operation_id is caller-chosen and lets a cancellation, a result and a log line be
 *  correlated without correlating them by content. */
void certificate_broker_sign(CertificateBroker* broker, const char* session_handle,
                           const char* operation_id, const CertificateMechanism* mechanism,
                           GBytes* data, GCancellable* cancellable, CertificateSignDone done,
                           gpointer user_data);

/** Decrypt. Refused unless the grant's permitted_operations includes decrypt. Not in v1;
 *  see docs/ROADMAP.md. */
void certificate_broker_decrypt(CertificateBroker* broker, const char* session_handle,
                              const char* operation_id, const CertificateMechanism* mechanism,
                              GBytes* ciphertext, GCancellable* cancellable,
                              CertificateSignDone done, gpointer user_data);

/** Ensure this service is logged in on its OWN session for @grant_id, prompting if
 *  necessary. Called at first private-key use, from both the brokered path and the
 *  facade's lazy-login path -- so that both share one login model and one serialised
 *  prompt per token. */
void certificate_broker_ensure_login(CertificateBroker* broker, const char* session_handle,
                                   GCancellable* cancellable, CertificateSignDone done,
                                   gpointer user_data);

#endif /* CERTIFICATE_BROKER_OPERATIONS_H */
