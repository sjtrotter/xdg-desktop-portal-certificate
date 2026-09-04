/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_IMPL_CERTIFICATE_H
#define CERTIFICATE_IMPL_CERTIFICATE_H

#include <glib.h>

/** @file
 *  The BACKEND's implementation of io.github.sjtrotter.impl.portal.Certificate1.
 *
 *  One file per portal, exactly as xdg-desktop-portal-gtk does it (src/filechooser.c,
 *  src/account.c, ...). At upstreaming this file becomes
 *  xdg-desktop-portal-gtk/src/certificate.c, or the same file in a backend package of its
 *  own; see docs/UPSTREAMING.md.
 *
 *  WHAT THE BACKEND OWNS: the UI and the device. The chooser (ui/chooser.h), the PIN
 *  prompt (ui/pin.h), PKCS#11 module loading and token discovery (tokens/), the token
 *  session and the operations performed on it (broker/operations.h), and the synthetic
 *  PKCS#11 facade (export/facade.h).
 *
 *  WHAT IT MUST NEVER DO:
 *
 *   - DERIVE THE CALLER'S IDENTITY. app_id is an argument. There is no code here that
 *     asks the bus who is calling, reads /proc, or consults Flatpak metadata, because
 *     the answer would describe the frontend.
 *   - DECIDE POLICY. Whether a purpose may ask for decrypt, how long a grant lives,
 *     whether a caller has made too many requests: all frontend. The backend enforces
 *     what it is told plus its own hard limits, and never widens.
 *   - TOUCH THE PERMISSION STORE. Selection memory is keyed by app id, and the app id is
 *     the frontend's.
 *   - TRUST THE CALLER DIRECTLY. The only legitimate caller is the frontend. See
 *     "Refusing everyone but the frontend" below and docs/IMPL-INTERFACE.md.
 *
 *  WHAT IT MUST ALWAYS DO: display what it was told about the caller INCLUDING HOW WELL
 *  THE CALLER IS KNOWN, render the purpose in its own words, keep caller-supplied text
 *  out of the trusted identity position, and re-validate every mechanism and parameter
 *  even though the frontend already did. Two checks against a hostile caller is the
 *  correct number.
 *
 *  REFUSING EVERYONE BUT THE FRONTEND. Upstream relies on the impl bus names simply not
 *  being interesting to applications and not being proxied into sandboxes. This backend
 *  does that AND checks: every method compares the sender against the unique name that
 *  owns the frontend's well-known bus name, and refuses anything else with
 *  NotPermitted, logged by reason code. That check is cheap, and the failure it prevents
 *  -- an application handing itself an app id -- destroys the entire consent model.
 *
 *  Sketch only; nothing here is implemented.
 */

#define CERTIFICATE_IMPL_BUS_NAME "io.github.sjtrotter.impl.portal.Certificate.gtk"
#define CERTIFICATE_IMPL_OBJECT_PATH "/io/github/sjtrotter/portal/Certificate"
#define CERTIFICATE_IMPL_INTERFACE "io.github.sjtrotter.impl.portal.Certificate1"
#define CERTIFICATE_IMPL_INTERFACE_VERSION 1u

/** The only bus name whose owner may call this backend. */
#define CERTIFICATE_FRONTEND_BUS_NAME "io.github.sjtrotter.portal.Certificate"

/** How well the frontend knows the caller, as it arrives on the wire. The backend does
 *  not compute this and cannot improve it; it DISPLAYS it. */
#define CERTIFICATE_IDENTITY_LEVEL_VERIFIED "verified_sandboxed"
#define CERTIFICATE_IDENTITY_LEVEL_DERIVED "derived_host"
#define CERTIFICATE_IDENTITY_LEVEL_UNKNOWN "unidentified"

/** The four purposes, parsed from the string the frontend sent. The frontend has already
 *  validated it -- an unknown purpose never reaches a backend -- and the backend parses
 *  it again, because a backend that trusted a string because "the frontend checked" is a
 *  backend that will one day be called by something else. Each purpose has its own
 *  consent policy; see broker/operations.h. There is no "any". */
typedef enum
{
	CERTIFICATE_PURPOSE_CLIENT_AUTH, /**< one consent per short grant, bound to app+cert+context */
	CERTIFICATE_PURPOSE_SIGNING,     /**< per-operation consent by default, digest shown */
	CERTIFICATE_PURPOSE_EMAIL,       /**< session grant defensible; bulk behaviour must be explicit */
	CERTIFICATE_PURPOSE_SSH          /**< its own policy; NOT "signing with extra steps" */
} CertificatePurpose;

gboolean certificate_impl_purpose_parse(const char* text, CertificatePurpose* out);

/** The purpose IN THIS BACKEND'S OWN WORDS, for the chooser and the PIN window: "sign in
 *  to a website", "sign a document". Never the caller's words, and never the frontend's
 *  either -- the words belong to whoever draws the window. Translatable. */
const char* certificate_impl_purpose_display(CertificatePurpose purpose);

typedef struct CertificateImpl CertificateImpl;

/** Claim the impl bus name and export the impl interface plus the impl Request and
 *  Session objects. Fails with exit code 40 when there is no session bus, no p11-kit, or
 *  no usable module configuration -- checked at startup so the frontend gets
 *  BackendUnavailable early and clearly rather than mid-handshake. */
CertificateImpl* certificate_impl_new(gboolean replace, GError** error);

/** True if @sender currently owns CERTIFICATE_FRONTEND_BUS_NAME. Every method calls this
 *  first. A refusal is logged as a reason code and never explains itself to the caller
 *  beyond NotPermitted. */
gboolean certificate_impl_sender_is_frontend(CertificateImpl* impl, const char* sender);

/** Run the GTK main loop. Exits when idle with no live sessions: a backend that never
 *  exits is a backend holding a card session nobody asked it to hold. */
int certificate_impl_run(CertificateImpl* impl);

/** Shut down: close every token session, log out where the token permits, poison every
 *  facade endpoint, reap every helper, and emit SessionInvalidated with
 *  "backend_shutdown" for each session so the frontend can tell its callers the truth
 *  rather than letting them discover it at the next Sign. */
void certificate_impl_shutdown(CertificateImpl* impl);

#endif /* CERTIFICATE_IMPL_CERTIFICATE_H */
