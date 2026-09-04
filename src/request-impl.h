/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_IMPL_REQUEST_H
#define CERTIFICATE_IMPL_REQUEST_H

#include <glib.h>

/** @file
 *  org.freedesktop.impl.portal.Request -- one interactive transaction, BACKEND side.
 *
 *  The mirror image of xdg-desktop-portal-gtk's src/request.c. xdg-desktop-portal
 *  chooses the object path and passes it as @handle; this BACKEND exports a Request
 *  object there for the duration of the user interaction; the portal calls Close() on it
 *  to end that interaction. The interface is upstream's own and is not redefined here.
 *
 *  It has ONE METHOD, Close(), and NO Response signal. The result of an impl call comes
 *  back as the method's own (response, results) return value, not as a signal. This is
 *  not an oversight in the upstream design and must not be "improved": it is what makes
 *  the backend a plain RPC target and keeps exactly one object -- the frontend's --
 *  responsible for the at-most-one-terminal-response rule.
 *
 *  THE APPLICATION CANNOT REACH THIS OBJECT. It holds the portal's Request, on
 *  org.freedesktop.portal.Desktop, and Close() is forwarded. That is the whole reason the
 *  split helps: a cancel arrives here having already been attributed to the caller that
 *  is allowed to send it. The frontend's side of this is
 *  xdg-desktop-portal's desktop-portal/xdp-request-dex.c, and note the trap recorded in
 *  the branch write-up: xdp_request_dex_new() does not export the frontend Request,
 *  xdp_request_dex_export() must be called separately.
 *
 *  Everything a transaction owns hangs off this object so that one destructor closes all
 *  of it: the chooser window, the PIN window, the discovery cancellable, the in-flight
 *  PKCS#11 operation. Closed on exactly one of: the method returning, Close() from the
 *  frontend, the frontend vanishing from the bus, or backend shutdown. A cancelled
 *  transaction must never leave a PIN dialog on screen for the next one to inherit.
 *
 *  Sketch only; nothing here is implemented.
 */

typedef struct CertificateImplRequest CertificateImplRequest;

/** Export a Request object at @handle for the duration of one impl call. */
CertificateImplRequest* certificate_impl_request_new(const char* handle, const char* app_id,
                                                 GError** error);

/** Close(): tear down every window and cancellable this transaction owns. Idempotent.
 *  After this the impl method returns response 1 (cancelled) if it has not already
 *  returned. */
void certificate_impl_request_close(CertificateImplRequest* request);

/** Unexport and free. The response has already been returned by the method call. */
void certificate_impl_request_finish(CertificateImplRequest* request);

#endif /* CERTIFICATE_IMPL_REQUEST_H */
