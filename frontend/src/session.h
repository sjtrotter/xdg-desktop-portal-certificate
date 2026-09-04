/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_FRONTEND_SESSION_H
#define CERTIFICATE_FRONTEND_SESSION_H

#include <glib.h>

/** @file
 *  io.github.sjtrotter.portal.Session -- one grant, frontend side.
 *
 *  Copied closely from org.freedesktop.portal.Session and from xdg-desktop-portal's
 *  desktop-portal/xdp-session.c. The object path is
 *  /io/github/sjtrotter/portal/Certificate/session/<sender>/<session_handle_token>, built
 *  the same way as a Request path.
 *
 *  THE SESSION HANDLE IS THE GRANT HANDLE. Before the split, a grant was named by an
 *  opaque grant_id string. It is now an object path, because that is what a long-lived
 *  portal capability is: an object the caller can watch, close, and lose when it
 *  disconnects. grant_id survives as an opaque id for LOGS and for GrantInvalidated,
 *  where an object path would be a caller-derived string in a log line.
 *
 *  A client vanishing from the bus is equivalent to closing all its sessions, as
 *  org.freedesktop.portal.Session specifies -- subject to the delegation rules in
 *  grant-registry.h, which are the one place this design deliberately differs: a
 *  browser's network subprocess may still be mid-handshake on an endpoint the owner
 *  opened, so the frontend runs an orphan grace period instead of tearing down
 *  immediately.
 *
 *  ONE FRONTEND SESSION, ONE BACKEND SESSION. The frontend creates the object path,
 *  exports its own Session on it, and asks the backend to create an
 *  io.github.sjtrotter.impl.portal.Session at the SAME path on the backend's
 *  connection. Closing the frontend's closes the backend's. The backend closing its own
 *  (card removed, device error, shutting down) arrives as SessionInvalidated and the
 *  frontend turns it into Closed and GrantInvalidated for the application.
 *
 *  Sketch only; nothing here is implemented.
 */

typedef struct CertificateSession CertificateSession;

/** Create and export the session object for @invocation's caller. The grant does not
 *  exist yet: AcquireCredential fills it in. An empty session that never becomes a
 *  grant is reaped on the same orphan grace period as an unclaimed one. */
CertificateSession* certificate_session_new(GDBusMethodInvocation* invocation,
                                        const char* session_handle_token, GError** error);

/** Look up a session and check that @sender is entitled to act on it. Only the OWNER may
 *  sign, renew, release or open an endpoint; a delegated endpoint holder may only use
 *  the endpoint it was given. A caller naming another caller's session gets NotPermitted
 *  and a rate-limit strike, not a hint about whether the path existed. */
CertificateSession* certificate_session_lookup(const char* session_handle, const char* sender,
                                           GError** error);

/** Close: release the grant, close the backend's session, emit Closed with @reason in
 *  the details vardict, and emit GrantInvalidated. Idempotent. */
void certificate_session_close(CertificateSession* session, const char* reason);

#endif /* CERTIFICATE_FRONTEND_SESSION_H */
