/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_BROKER_OPERATIONS_H
#define CERTIFICATE_BROKER_OPERATIONS_H

#include <gio/gio.h>
#include <glib.h>

#include "../certificate.h"
#include "../session-impl.h"
#include "../tokens/discovery.h"
#include "mechanism.h"

/** @file
 *  The broker. THE CORE CONTRACT: the SYSTEM holds the key and performs the
 *  operation, and "the system" means this process -- the backend -- because the
 *  backend is the side that owns the token session.
 *
 *  The frontend has already established who is asking, that the grant exists,
 *  that it is live, that it is owned by the caller, that the operation is inside
 *  it, and that the mechanism is one it allows. What arrives here is
 *  (session_handle, app_id, mechanism, parameters, data). EVERYTHING BELOW IS
 *  CHECKED AGAIN ANYWAY.
 *
 *  An application never receives key material, never receives the PIN, and never
 *  holds a PKCS#11 handle. It asks for a signature and gets a signature.
 *
 *  WHY THIS AND NOT A FORWARDED MODULE. A sign-capable PKCS#11 session IS a
 *  signing capability, and one with almost no accounting: it cannot be counted,
 *  expired per operation, consented to per operation, or revoked cleanly
 *  mid-handshake. A brokered call can be all of those. See
 *  docs/decisions/0007-brokered-operations-are-the-core.md.
 *
 *  WHAT THIS DOES NOT DO: attest purpose. A Sign call cannot be shown to have
 *  come from a TLS handshake rather than from a PDF, a challenge string, or
 *  nothing. purpose constrains certificate SELECTION and the words in the
 *  consent dialog. Anyone reading it as a guarantee about later use has misread
 *  it, and every document in this repository says so.
 *
 *  MAY PROMPT. The first private-key use triggers this backend's own lazy login
 *  (ui/pin.h), which is why every grant reports may_prompt_later = true.
 *
 *  NOTHING BLOCKS THE MAIN THREAD. C_OpenSession, C_FindObjects, C_Login,
 *  C_Sign and C_Decrypt all run on worker threads; the main loop stays free to
 *  draw the window that the login is waiting on and to answer a Close().
 */

typedef void (*CertificateBrokerDone)(GBytes* result, const GError* error, gpointer user_data);

/** Perform one brokered operation on @session's grant.
 *
 *  Order of checks, all of which must pass: the session exists in this backend
 *  and holds a grant; the grant has not expired; the operation is in the
 *  grant's permitted operations; the mechanism and its parameters validate
 *  against the mechanism AND THE KEY; the token is still present; this
 *  backend's own session is logged in, prompting if it is not. */
void certificate_broker_perform(CertificateTokens* tokens, CertificateImplSession* session,
                                gboolean decrypt, const char* mechanism_name,
                                GVariant* parameters, GBytes* data, const char* parent_window,
                                const char* caller_display, GCancellable* cancellable,
                                CertificateBrokerDone done, gpointer user_data);

#endif /* CERTIFICATE_BROKER_OPERATIONS_H */
