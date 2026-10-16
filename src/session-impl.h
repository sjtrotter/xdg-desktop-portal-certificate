/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
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

/** Backend session ownership and teardown rules are documented in docs/IMPL-INTERFACE.md. */

/** Delay fallback teardown so the frontend can announce expiry and close the session first. */
#define CERTIFICATE_EXPIRY_GRACE_SECONDS 30

#define CERTIFICATE_TYPE_IMPL_SESSION (certificate_impl_session_get_type())
G_DECLARE_FINAL_TYPE(CertificateImplSession, certificate_impl_session, CERTIFICATE, IMPL_SESSION,
                     XdpImplSessionSkeleton)

struct _CertificateImplSession
{
	XdpImplSessionSkeleton parent_instance;

	gboolean exported;
	gboolean closed;
	char* id;     /**< Object path chosen by the frontend. */
	char* app_id; /**< App ID established by the frontend. */
	char* owner;  /**< Frontend connection owner at CreateSession. */

	/* Identity assurance may fall but must never rise within a session. */
	CertificateIdentityLevel identity_level;
	gboolean identity_seen;

	gboolean granted;
	CertificateCandidate* candidate;
	CertificatePurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;

	guint decrypt_count;
	guint32 lifetime;
	gint64 expires_at;
	guint expiry_source;

	/* Workers hold device_lock; GObject creation and destruction stay on the main thread. */
	GMutex device_lock;
	CertificateDevice device;

	/* The session owns one shared PIN prompt; cancel it only after the last login waiter leaves. */
	gboolean login_in_progress;
	GPtrArray* login_waiters;
	GCancellable* login_cancellable;
};

CertificateImplSession* certificate_impl_session_new(const char* session_handle,
                                                     const char* app_id);

/** Abort creation if export fails, since the frontend must be able to close the session. */
gboolean certificate_impl_session_export(CertificateImplSession* session,
                                         GDBusConnection* connection, GError** error);

/** Unexport the session; repeated calls have no effect. */
void certificate_impl_session_unexport(CertificateImplSession* session);

void certificate_impl_session_grant(CertificateImplSession* session,
                                    CertificateCandidate* candidate, CertificatePurpose purpose,
                                    gboolean may_sign, gboolean may_decrypt, guint32 lifetime);

/** Blocks on device_lock and token calls; main-thread callers must use the async form. */
void certificate_impl_session_release_device(CertificateImplSession* session);

/** The worker holds a session reference until release completes. */
void certificate_impl_session_release_device_async(CertificateImplSession* session);

/** Shutdown only: wait at most @timeout_ms for pending device releases. */
void certificate_impl_session_drain_releases(guint timeout_ms);

/** Close device state but retain the exported skeleton to answer frontend Close(). */
void certificate_impl_session_close(CertificateImplSession* session);

/** Emit expired, token_removed, backend_gone or error while keeping the session exported for frontend Close(); policy is accepted but never emitted here. */
void certificate_impl_session_invalidate(CertificateImplSession* session, const char* reason);

/** Bound decryption queries per grant; see docs/SECURITY.md. */
#define CERTIFICATE_MAX_DECRYPTS_PER_GRANT 32

gboolean certificate_impl_session_is_expired(CertificateImplSession* session);

#endif
