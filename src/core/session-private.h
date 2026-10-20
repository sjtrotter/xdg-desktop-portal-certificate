/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#ifndef XCC_SESSION_PRIVATE_H
#define XCC_SESSION_PRIVATE_H

#include "session.h"
#include <stdint.h>
#include "../broker/device.h"

G_BEGIN_DECLS

typedef struct XccContext XccContext;

/* Coordinator state; workers use the existing device/operation locks. */
struct _XccSession
{
	GObject parent_instance;
	XccContext* context;
	uint64_t owner_generation;
	char* app_id;
	CertificateIdentityLevel identity_level;
	gboolean identity_seen;
	char* id; /* Redacted logging context; no path interpretation. */
	gboolean closed;
	gboolean invalidating;
	XccSessionInvalidated invalidated;
	gpointer invalidated_data;

	gboolean granted;
	/* Atomic: desktop delivery makes a new grant available to operations. */
	gint grant_pending;
	CertificateCandidate* candidate;
	CertificatePurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;

	guint decrypt_count;
	guint32 lifetime;
	gint64 expires_at;
	guint expiry_source;

	/* Workers hold device_lock while using the device. */
	GMutex device_lock;
	/* Operation initialization survives PIN retries while device_lock is released. */
	GMutex operation_lock;
	CertificateDevice device;

	/* The session owns one shared PIN prompt; cancel it only after the last login waiter leaves. */
	gboolean login_in_progress;
	guint64 login_generation;
	GPtrArray* login_waiters;
	GCancellable* login_cancellable;
};

G_END_DECLS

#endif
