/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * The shape of this file -- a GObject deriving from the generated
 * XdpImplRequestSkeleton, exported at the handle path, with a default
 * handle_close that unexports and completes -- is xdg-desktop-portal-gtk's
 * src/request.h, LGPL-2.1-or-later, Copyright (C) 2016 Red Hat, Inc,
 * by Alexander Larsson and Matthias Clasen. Reused under the "or later" clause
 * into this GPL-2.0-or-later project; see docs/decisions/0004-license.md.
 */
#ifndef CERTIFICATE_IMPL_REQUEST_H
#define CERTIFICATE_IMPL_REQUEST_H

#include <gio/gio.h>
#include <glib.h>

#include "xdp-impl-dbus.h"

/** @file
 *  org.freedesktop.impl.portal.Request -- one interactive transaction, BACKEND
 *  side.
 *
 *  xdg-desktop-portal chooses the object path and passes it as @handle; this
 *  BACKEND exports a Request object there for the duration of the user
 *  interaction; the portal calls Close() on it to end that interaction. The
 *  interface is upstream's own and is not redefined here.
 *
 *  It has ONE METHOD, Close(), and NO Response signal. The result of an impl
 *  call comes back as the method's own (response, results) return value, not as
 *  a signal. This is not an oversight in the upstream design and must not be
 *  "improved": it is what makes the backend a plain RPC target and keeps
 *  exactly one object -- the frontend's -- responsible for the
 *  at-most-one-terminal-response rule.
 *
 *  THE APPLICATION CANNOT REACH THIS OBJECT. It holds the portal's Request, on
 *  org.freedesktop.portal.Desktop, and Close() is forwarded. That is the whole
 *  reason the split helps: a cancel arrives here having already been attributed
 *  to the caller that is allowed to send it.
 *
 *  EVERYTHING A TRANSACTION OWNS HANGS OFF THE CANCELLABLE, so that one
 *  cancellation closes all of it: the chooser window, the PIN window, the
 *  discovery worker and the in-flight PKCS#11 operation. Closed on exactly one
 *  of: the method returning, Close() from the frontend, or backend shutdown. A
 *  cancelled transaction must never leave a PIN dialog on screen for the next
 *  one to inherit.
 */

#define CERTIFICATE_TYPE_IMPL_REQUEST (certificate_impl_request_get_type())
G_DECLARE_FINAL_TYPE(CertificateImplRequest, certificate_impl_request, CERTIFICATE, IMPL_REQUEST,
                     XdpImplRequestSkeleton)

/** Create a Request for @handle. It is not on the bus until it is exported. */
CertificateImplRequest* certificate_impl_request_new(const char* sender, const char* app_id,
                                                     const char* handle);

/** Put it on the bus at its handle path. Takes a reference that
 *  certificate_impl_request_unexport() drops, exactly as upstream's does, so a
 *  racing Close() always finds a live object. */
void certificate_impl_request_export(CertificateImplRequest* request,
                                     GDBusConnection* connection);

/** Take it off the bus. Idempotent. */
void certificate_impl_request_unexport(CertificateImplRequest* request);

/** The cancellable every part of this transaction is tied to. Cancelled by
 *  Close() from the frontend and by backend shutdown. */
GCancellable* certificate_impl_request_get_cancellable(CertificateImplRequest* request);

const char* certificate_impl_request_get_app_id(CertificateImplRequest* request);
gboolean certificate_impl_request_is_exported(CertificateImplRequest* request);

#endif /* CERTIFICATE_IMPL_REQUEST_H */
