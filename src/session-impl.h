/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * The export/unexport shape mirrors xdg-desktop-portal-gtk's src/session.c,
 * LGPL-2.1-or-later, Copyright (C) 2016 Red Hat, Inc.
 */
#ifndef CERTIFICATE_IMPL_SESSION_H
#define CERTIFICATE_IMPL_SESSION_H

#include <gio/gio.h>
#include <glib.h>

#include "certificate.h"
#include "broker/device.h"
#include "tokens/discovery.h"
#include "xdp-impl-dbus.h"

/** @file
 *  org.freedesktop.impl.portal.Session -- the backend side of one grant.
 *
 *  xdg-desktop-portal chooses the object path; this backend exports a Session
 *  there and hangs the DEVICE STATE off it.
 *
 *  WHAT THE BACKEND'S SESSION HOLDS -- and this is the whole of the ownership
 *  split in one list:
 *
 *    the PKCS#11 session and its login state
 *    the selected token, identified by every stable attribute available
 *    the underlying object handles for the certificate and the private key
 *    the mechanism allow-list as the KEY supports it
 *
 *  WHAT IT DOES NOT HOLD: the grant's identity, its owner, its operation
 *  budget, or which application it belongs to beyond the app id string it was
 *  told. Those are the frontend's. The backend cannot renew a grant and is
 *  never asked to. It DOES keep its own copy of the expiry, because a backend
 *  that holds a logged-in card session for longer than the grant it was told
 *  about is holding a capability nobody authorised -- see
 *  docs/IMPL-INTERFACE.md, "The backend enforces the lifetime too".
 *
 *  Close() from the portal: close the PKCS#11 session, C_Logout where the token
 *  permits -- WITHOUT CLAIMING THE CARD HAS FORGOTTEN, because some tokens and
 *  middleware cache authentication at a level nothing here controls -- cancel
 *  any in-flight operation, and free every handle.
 */

#define CERTIFICATE_TYPE_IMPL_SESSION (certificate_impl_session_get_type())
G_DECLARE_FINAL_TYPE(CertificateImplSession, certificate_impl_session, CERTIFICATE, IMPL_SESSION,
                     XdpImplSessionSkeleton)

struct _CertificateImplSession
{
	XdpImplSessionSkeleton parent_instance;

	gboolean exported;
	gboolean closed;
	char* id;     /**< the object path the frontend chose */
	char* app_id; /**< as the FRONTEND established it */
	char* owner;  /**< the unique name that owned the frontend name at CreateSession */

	/* The identity level this session has been used at. It may fall -- the
	 * frontend can legitimately know less about a caller later -- and it may
	 * NEVER RISE: a session created for an unidentified caller does not become
	 * a session for a verified one because a later call said so. */
	CertificateIdentityLevel identity_level;
	gboolean identity_seen;

	/* The grant, once AcquireCredential has filled it in. */
	gboolean granted;
	CertificateCandidate* candidate;
	CertificatePurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;
	guint32 lifetime;
	gint64 expires_at;
	guint expiry_source;

	/* Device state. Touched from worker threads, so it has its own lock; the
	 * GObject itself is only ever created and destroyed on the main thread. */
	GMutex device_lock;
	CertificateDevice device;

	/* ONE PIN PROMPT PER SESSION AT A TIME, under device_lock. Two Sign calls
	 * on a logged-out grant used to produce two windows for the same token;
	 * the second and later ones now wait here for the first one's answer.
	 * broker/operations.c owns the contents. */
	gboolean login_in_progress;
	GPtrArray* login_waiters;
};

CertificateImplSession* certificate_impl_session_new(const char* session_handle,
                                                     const char* app_id);

void certificate_impl_session_export(CertificateImplSession* session,
                                     GDBusConnection* connection);
void certificate_impl_session_unexport(CertificateImplSession* session);

/** Record the grant this session now carries. Starts the lifetime timer. */
void certificate_impl_session_grant(CertificateImplSession* session,
                                    CertificateCandidate* candidate, CertificatePurpose purpose,
                                    gboolean may_sign, gboolean may_decrypt, guint32 lifetime);

/** Close the PKCS#11 session, logging out where the token permits. Idempotent,
 *  and safe to call from any thread. Does NOT emit anything: closing is what
 *  the caller asked for. */
void certificate_impl_session_release_device(CertificateImplSession* session);

/** Tear the device state down and mark the session closed. Idempotent, and it
 *  leaves the skeleton EXPORTED so that a Close() arriving afterwards is
 *  answered rather than returning UnknownObject. */
void certificate_impl_session_close(CertificateImplSession* session);

/** The hardware went away, or the lifetime ran out. Emits the "invalidated"
 *  signal with @reason and closes the session; certificate-impl.c turns that
 *  into org.freedesktop.impl.portal.experimental.Certificate.SessionInvalidated,
 *  which the frontend turns into GrantInvalidated. The backend does not decide
 *  that a grant is over for any reason that is not physical or temporal. */
void certificate_impl_session_invalidate(CertificateImplSession* session, const char* reason);

gboolean certificate_impl_session_is_expired(CertificateImplSession* session);

#endif /* CERTIFICATE_IMPL_SESSION_H */
