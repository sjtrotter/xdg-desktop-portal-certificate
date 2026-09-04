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
 *  sandboxes. This backend does that AND CHECKS: every method compares the
 *  sender against the unique name that currently owns
 *  org.freedesktop.portal.Desktop, and refuses anything else with
 *  AccessDenied, logged by reason code. That check is cheap, and the failure it
 *  prevents -- an application handing itself an app id -- destroys the entire
 *  consent model. See docs/IMPL-INTERFACE.md, "Why an application cannot call
 *  this".
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

/** Shut down: close every token session, and emit SessionInvalidated with
 *  "backend_shutdown" for each one so the frontend can tell its callers the
 *  truth rather than letting them discover it at the next Sign. */
void certificate_impl_shutdown(CertificateImpl* impl);

void certificate_impl_free(CertificateImpl* impl);

#endif /* CERTIFICATE_IMPL_CERTIFICATE_H */
