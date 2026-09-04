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

	/* Decryptions this grant has been charged for. See
	 * CERTIFICATE_MAX_DECRYPTS_PER_GRANT and the comment in
	 * broker/operations.c that explains the number. */
	guint decrypt_count;
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
	 * broker/operations.c owns the contents.
	 *
	 * THE PROMPT BELONGS TO THE SESSION, NOT TO THE OPERATION THAT OPENED IT.
	 * login_cancellable is the window's, and it is cancelled only when the last
	 * live waiter has gone: an operation that is closed while it waits takes
	 * itself out of the list and is answered on its own, and the window stays up
	 * for the ones that are still asking. Cancelling the FIRST caller used to
	 * close the shared window and report "the user cancelled" to every other
	 * caller behind it. */
	gboolean login_in_progress;
	GPtrArray* login_waiters;
	GCancellable* login_cancellable;
};

CertificateImplSession* certificate_impl_session_new(const char* session_handle,
                                                     const char* app_id);

/** Put the Session on the bus at the path the frontend chose. Returns FALSE and
 *  sets @error when the path cannot be exported -- a collision, or a path this
 *  connection may not own -- and the CALLER MUST THEN ABORT: a session that is
 *  not on the bus is one the frontend can never close. */
gboolean certificate_impl_session_export(CertificateImplSession* session,
                                         GDBusConnection* connection, GError** error);

/** Take it off the bus. Idempotent. NOT called by invalidation: the frontend
 *  answers SessionInvalidated with Session.Close(), and a Session that has
 *  already left the bus turns that into a D-Bus error the application sees. */
void certificate_impl_session_unexport(CertificateImplSession* session);

/** Record the grant this session now carries. Starts the lifetime timer. */
void certificate_impl_session_grant(CertificateImplSession* session,
                                    CertificateCandidate* candidate, CertificatePurpose purpose,
                                    gboolean may_sign, gboolean may_decrypt, guint32 lifetime);

/** Close the PKCS#11 session, logging out where the token permits. Idempotent,
 *  and safe to call from any thread. Does NOT emit anything: closing is what
 *  the caller asked for.
 *
 *  IT BLOCKS, TWICE OVER: on device_lock, which a worker holds for the whole of
 *  a C_Login or a C_Sign, and then on C_Logout and C_CloseSession themselves.
 *  CALL IT ON A WORKER THREAD. Everything on the main thread wants
 *  certificate_impl_session_release_device_async(). */
void certificate_impl_session_release_device(CertificateImplSession* session);

/** The same close, moved off the main thread. The session is referenced for as
 *  long as the worker needs it, so the caller may drop its own reference (and
 *  the sessions table may drop the last one) the moment this returns.
 *
 *  WHY THIS EXISTS: Close(), lifetime expiry, token removal and the frontend
 *  going away all arrive on the main thread, and all of them used to close the
 *  card there -- which meant the main loop stalled for the duration of whatever
 *  a worker was holding device_lock for. A PIN window that stops redrawing
 *  while the card is being logged out from under it is the visible half; the
 *  D-Bus connection not being serviced is the other. */
void certificate_impl_session_release_device_async(CertificateImplSession* session);

/** Wait for the workers started by certificate_impl_session_release_device_async()
 *  to finish, for at most @timeout_ms. SHUTDOWN ONLY, and the one place this
 *  backend blocks its main thread on the card on purpose: a process that exits
 *  before C_Logout has been issued leaves the token's login state to the
 *  module's own teardown. The wait is BOUNDED because a wedged reader must not
 *  turn "quit" into "hang" -- when it runs out, the message says so. */
void certificate_impl_session_drain_releases(guint timeout_ms);

/** Tear the device state down and mark the session closed. Idempotent, and it
 *  leaves the skeleton EXPORTED so that a Close() arriving afterwards is
 *  answered rather than returning UnknownObject. */
void certificate_impl_session_close(CertificateImplSession* session);

/** The hardware went away, the lifetime ran out, or the frontend that owned the
 *  grant is gone. Emits the "invalidated" signal with @reason and closes the
 *  session; certificate-impl.c turns that into
 *  org.freedesktop.impl.portal.experimental.Certificate.SessionInvalidated,
 *  which the frontend turns into GrantInvalidated. The backend does not decide
 *  that a grant is over for any reason that is not physical or temporal.
 *
 *  @reason MUST BE ONE OF THE INTERFACE'S EIGHT: released, expired,
 *  token_removed, owner_gone, policy, service_shutdown, backend_gone, error.
 *  The frontend forwards it verbatim to applications, so an invented value is
 *  a word nobody can act on delivered as though it were part of the contract.
 *  Anything else is g_critical()ed and sent as "error". */
void certificate_impl_session_invalidate(CertificateImplSession* session, const char* reason);

/** How many Decrypt calls one grant may make. A raw private-key operation on
 *  caller-chosen bytes is the input to every practical attack on RSA
 *  decryption -- padding oracles, fault injection, timing -- and all of them
 *  need thousands to millions of queries against one key. Real use is
 *  unwrapping: one C_Decrypt, occasionally a handful. Nothing else on either
 *  side of the boundary counts them. */
#define CERTIFICATE_MAX_DECRYPTS_PER_GRANT 32

gboolean certificate_impl_session_is_expired(CertificateImplSession* session);

#endif /* CERTIFICATE_IMPL_SESSION_H */
