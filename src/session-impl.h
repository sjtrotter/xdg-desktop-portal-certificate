/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_IMPL_SESSION_H
#define CERTIFICATE_IMPL_SESSION_H

#include <glib.h>

/** @file
 *  org.freedesktop.impl.portal.Session -- the backend side of one grant.
 *
 *  The mirror image of xdg-desktop-portal-gtk's src/session.c. xdg-desktop-portal
 *  chooses the object path; this backend exports a Session there and hangs the DEVICE
 *  STATE off it. The interface is upstream's own and is not redefined here.
 *
 *  WHAT THE BACKEND'S SESSION HOLDS -- and this is the whole of the ownership split in
 *  one list:
 *
 *    the PKCS#11 session and its login state
 *    the selected token, identified by every stable attribute available
 *    the underlying object handles for the certificate and the private key
 *    the mechanism allow-list as the KEY supports it
 *
 *  WHAT IT DOES NOT HOLD: the grant's identity, its expiry, its owner, its operation
 *  budget, or which application it belongs to beyond the app id string it was told.
 *  Those are the frontend's, and the frontend is xdg-desktop-portal itself: see
 *  desktop-portal/certificate.c on the branch, which owns the grant table, the expiry and
 *  RenewGrant (decided entirely frontend-side -- the backend is never asked and no window
 *  appears). The backend cannot expire a grant and cannot renew one. It can only report
 *  that the hardware behind one has gone, with SessionInvalidated.
 *
 *  Close() from the portal: close the PKCS#11 session, C_Logout where the token
 *  permits -- WITHOUT CLAIMING THE CARD HAS FORGOTTEN, because some tokens and
 *  middleware cache authentication at a level nothing here controls -- cancel any
 *  in-flight operation, and free every handle.
 *
 *  Sketch only; nothing here is implemented.
 */

typedef struct CertificateImplSession CertificateImplSession;

/** Export a Session object at the path the frontend chose, bound to @app_id. */
CertificateImplSession* certificate_impl_session_new(const char* session_handle, const char* app_id,
                                                 GError** error);

/** Look up the session an impl call names. A call naming a session this backend does not
 *  have is a frontend bug or an impostor; either way it is refused and logged. */
CertificateImplSession* certificate_impl_session_lookup(const char* session_handle,
                                                    const char* app_id, GError** error);

/** Close(): tear the device state down, as described above. Idempotent. */
void certificate_impl_session_close(CertificateImplSession* session);

/** The hardware went away underneath a session. Emits SessionInvalidated with
 *  "token_removed" | "device_error" | "backend_shutdown" and closes the session. The
 *  frontend turns that into GrantInvalidated (with reason token_removed, or its own
 *  released/expired/owner_gone/policy/service_shutdown/backend_gone/error) and closes the
 *  Session; the backend does not decide that a grant is over for any reason that is not
 *  physical. */
void certificate_impl_session_invalidate(CertificateImplSession* session, const char* reason);

#endif /* CERTIFICATE_IMPL_SESSION_H */
