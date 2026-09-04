/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_IMPL_CERTIFICATE_H
#define CERTIFICATE_IMPL_CERTIFICATE_H

#include <gio/gio.h>
#include <glib.h>

#include "certificate.h"
#include "session-impl.h"
#include "tokens/discovery.h"

/** @file
 *  This backend's implementation of
 *  org.freedesktop.impl.portal.experimental.Certificate.
 *
 *  One file per portal, exactly as xdg-desktop-portal-gtk does it
 *  (src/filechooser.c, src/account.c, ...) and as every out-of-tree backend
 *  does. The interface it implements is defined by the xdg-desktop-portal
 *  branch experimental/certificate-webauthentication, and the copy of the XML in
 *  data/ tracks that branch verbatim; see docs/IMPL-INTERFACE.md.
 *
 *  WHAT THE BACKEND OWNS: the UI and the device. The chooser (ui/chooser.h), the
 *  PIN prompt (ui/pin.h), PKCS#11 module loading and token discovery (tokens/),
 *  and the token session and the operations performed on it
 *  (broker/operations.h).
 *
 *  WHAT IT MUST NEVER DO:
 *
 *   - DERIVE THE CALLER'S IDENTITY. app_id is an argument. There is no code
 *     here that asks the bus who is calling, reads /proc, or consults Flatpak
 *     metadata, because the answer would describe xdg-desktop-portal.
 *   - DECIDE POLICY. Whether a purpose may ask for decrypt, how long a grant
 *     lives, whether a caller has made too many requests: all frontend. The
 *     `lifetime` option arrives as the number of seconds the frontend has
 *     DECIDED to allow, after applying its 3600 s ceiling. The backend enforces
 *     what it is told plus its own hard limits, and never widens.
 *   - TOUCH THE PERMISSION STORE. Selection memory is keyed by app id, and the
 *     app id is the frontend's. This backend reports `certificate_id` and
 *     `remember_selection` and receives `preselect_certificate`.
 *   - TRUST THE CALLER DIRECTLY. The only legitimate caller is
 *     xdg-desktop-portal.
 *
 *  WHAT IT MUST ALWAYS DO: display what it was told about the caller INCLUDING
 *  HOW WELL THE CALLER IS KNOWN, render the purpose in its own words, keep
 *  caller-supplied text out of the trusted identity position, and re-validate
 *  every mechanism and parameter even though the frontend already did. Two
 *  checks against a hostile caller is the correct number.
 *
 *  REFUSING EVERYONE BUT THE PORTAL. Upstream relies on the impl bus names
 *  simply not being interesting to applications and not being proxied into
 *  sandboxes. This backend does that AND CHECKS: EVERY method -- including
 *  Request.Close() and Session.Close() on the objects this one exports --
 *  compares the sender against the unique name that currently owns
 *  org.freedesktop.portal.Desktop, and refuses anything else with
 *  AccessDenied, logged by reason code.
 *
 *  A CACHED OWNER MAY ONLY SAY NO. Every ACCEPT resolves the owner from the bus
 *  with GetNameOwner, because NameOwnerChanged is not ordered against the
 *  messages of the process that lost the name and a remembered "yes" is exactly
 *  the answer that admits a replaced frontend which is still connected. Every
 *  REFUSAL is decided from the cached owner with no bus call at all: anything on
 *  the session bus can send this backend a message, and a synchronous round trip
 *  per stranger's message is a main-thread stall an open PIN window feels. A
 *  stranger's unique name can never equal the cached owner's, so a stranger
 *  never reaches the bus call.
 *
 *  The failure the check prevents -- an application handing itself an app id --
 *  destroys the entire consent model. See docs/IMPL-INTERFACE.md, "Why an
 *  application cannot call this".
 */

typedef struct CertificateImpl CertificateImpl;

/** Claim the impl bus name and export the impl interface. @module_paths is the
 *  --module allow-list, or NULL for p11-kit's configured modules. */
CertificateImpl* certificate_impl_new(GDBusConnection* connection, CertificateTokens* tokens,
                                      GError** error);

/** True if @sender currently owns CERTIFICATE_FRONTEND_BUS_NAME. Every method
 *  calls this first. A refusal is logged as a reason code and never explains
 *  itself to the caller beyond AccessDenied. */
gboolean certificate_impl_sender_is_frontend(CertificateImpl* impl, const char* sender);

/** The same question, for the Request and Session skeletons this object
 *  exports: they are separate GObjects with their own Close() handlers and
 *  there is exactly one backend in a process. */
gboolean certificate_impl_sender_is_frontend_default(const char* sender);

/** Take @session out of the backend's table and off the bus. Called by
 *  Session.Close(), which is the frontend saying it is finished with it; every
 *  other end of a session leaves the object exported so that a Close() arriving
 *  afterwards is still answered. */
void certificate_impl_session_forget(CertificateImplSession* session);

/** Build the TokenAdded/TokenRemoved vardict for @token: the opaque token_id
 *  and protected_authentication_path, and nothing else. Exposed so that a test
 *  can assert exactly that -- the frontend re-emits these signals to every
 *  client on the session bus, so a third key here is a broadcast leak. */
GVariant* certificate_impl_token_presence(const CertificateToken* token);

/** Build the AcquireCredential results vardict for @candidate. Exposed so that
 *  a test can assert the D-Bus type of every key: the frontend type-checks only
 *  `signature`/`plaintext` and passes the rest through, so a wrong type here
 *  reaches applications. */
GVariant* certificate_impl_acquire_results(CertificateCandidate* candidate, gboolean may_sign,
                                           gboolean may_decrypt, gboolean remember);

/** Shut down: close every token session, and emit SessionInvalidated with
 *  "service_shutdown" for each one so the frontend can tell its callers the
 *  truth rather than letting them discover it at the next Sign. */
void certificate_impl_shutdown(CertificateImpl* impl);

void certificate_impl_free(CertificateImpl* impl);

#endif /* CERTIFICATE_IMPL_CERTIFICATE_H */
