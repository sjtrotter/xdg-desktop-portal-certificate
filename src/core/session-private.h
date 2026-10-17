/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#ifndef XCC_SESSION_PRIVATE_H
#define XCC_SESSION_PRIVATE_H

#include "session.h"
#include "../broker/device.h"

/* Shared by the session and broker; frontend identity belongs to the adapter. */
struct _XccSession
{
	GObject parent_instance;
	char* id; /* Redacted logging context; no path interpretation. */
	gboolean closed;
	gboolean invalidating;
	XccSessionInvalidated invalidated;
	gpointer invalidated_data;

	gboolean granted;
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
	GPtrArray* login_waiters;
	GCancellable* login_cancellable;
};

#endif
