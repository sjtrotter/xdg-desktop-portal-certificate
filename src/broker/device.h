/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_BROKER_DEVICE_H
#define CERTIFICATE_BROKER_DEVICE_H

#include <glib.h>

#include "../tokens/discovery.h"
#include "mechanism.h"

/** @file
 *  The four things this backend does to a token, with no windows and no D-Bus
 *  anywhere near them: open a session on the token behind a grant, log in,
 *  perform one operation, close.
 *
 *  SEPARATED FROM broker/operations.c ON PURPOSE. Everything here blocks, and
 *  every caller runs it on a worker thread; keeping it free of GTK and GDBus is
 *  what lets tests/test-broker-device.c drive the whole cryptographic path
 *  against a software token with no display and no bus, which is the only
 *  automated coverage the sign path can have.
 *
 *  NOTHING HERE PROMPTS. The PIN arrives as an argument from ui/pin.c, which is
 *  the only thing that ever holds one, and is not copied, stored or logged.
 */

typedef struct
{
	CK_FUNCTION_LIST* module;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE private_key;
	gboolean logged_in;

	/* THE CREDENTIAL THIS OPEN SESSION IS BOUND TO, and the whole of the answer
	 * to "which key is device.private_key". A grant can change under a live
	 * session -- the frontend does not refuse a second AcquireCredential on one
	 * -- and an open device that did not remember what it was opened for would
	 * go on signing with the previous grant's key while the application had been
	 * handed the new grant's certificate. A reference, because the session's
	 * candidate pointer is replaced at the moment of the re-grant. */
	CertificateCandidate* candidate;
} CertificateDevice;

/** Open a read-only session on the token behind @candidate.
 *
 *  THE TOKEN IS RE-RESOLVED BY IDENTITY, not by the slot it was discovered at:
 *  a different card in the same slot is a different token, and this fails with
 *  CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED rather than quietly using it.
 *
 *  The private key is looked for immediately, and may not be found: on tokens
 *  where CKA_PRIVATE hides it, it only becomes visible after the login. That is
 *  not an error here.
 *
 *  AN OPEN DEVICE IS REUSED ONLY FOR THE CANDIDATE IT WAS OPENED FOR. A second
 *  AcquireCredential on a live session replaces the grant, and this is where
 *  that is noticed: a candidate that is not the bound one closes the PKCS#11
 *  session (C_Logout first, where the token permits) and opens a new one, so
 *  the next operation uses the new certificate's key and asks for the PIN
 *  again. Returning early on "a module is loaded" was how the backend came to
 *  sign with the previous grant's key, silently, with no prompt. */
gboolean certificate_device_open(CertificateDevice* device, CertificateTokens* tokens,
                                 const CertificateCandidate* candidate, GError** error);

/** C_Login as the user. @pin is NULL for a token with a protected
 *  authentication path, where the token or the reader collects the secret and
 *  this process never sees it. Looks for the private key again afterwards,
 *  because on some tokens this is when it appears. */
gboolean certificate_device_login(CertificateDevice* device,
                                  const CertificateCandidate* candidate, const char* pin,
                                  GError** error);

/** C_Sign or C_Decrypt. @payload is what certificate_mechanism_prepare()
 *  produced -- the DigestInfo-wrapped digest for RSA_PKCS1_V1_5, the bare
 *  digest otherwise. The returned bytes are exactly what the module produced;
 *  re-encoding an ECDSA signature is the caller's business. */
GBytes* certificate_device_perform(CertificateDevice* device, gboolean decrypt,
                                   CertificateMechanism* mechanism, GBytes* payload,
                                   GError** error);

/** C_Logout where the token permits, then C_CloseSession. Idempotent.
 *  NOTHING HERE MAY CLAIM THE CARD HAS FORGOTTEN: some tokens and middleware
 *  cache authentication at a level this process does not control. */
void certificate_device_close(CertificateDevice* device);

#endif /* CERTIFICATE_BROKER_DEVICE_H */
