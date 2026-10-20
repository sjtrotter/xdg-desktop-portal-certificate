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
#include "core/session.h"
#include "core/core.h"
#include "xdp-impl-dbus.h"

/** Backend session ownership and teardown rules are documented in docs/IMPL-INTERFACE.md. */

#define CERTIFICATE_TYPE_IMPL_SESSION (certificate_impl_session_get_type())
G_DECLARE_FINAL_TYPE(CertificateImplSession, certificate_impl_session, CERTIFICATE, IMPL_SESSION,
                     XdpImplSessionSkeleton)

struct _CertificateImplSession
{
	XdpImplSessionSkeleton parent_instance;

	gboolean exported;
	gboolean invalidated;
	char* id;     /**< Object path chosen by the frontend. */
	char* app_id; /**< App ID established by the frontend. */
	char* owner;  /**< Frontend connection owner at CreateSession. */


	XccSession* core;
};

CertificateImplSession* certificate_impl_session_new(const char* session_handle,
                                                     const char* app_id);

CertificateImplSession* certificate_impl_session_new_for_context(XccContext*, uint64_t, const char*,
																 const char*);

/** Abort creation if export fails, since the frontend must be able to close the session. */
gboolean certificate_impl_session_export(CertificateImplSession* session,
                                         GDBusConnection* connection, GError** error);

/** Unexport the session; repeated calls have no effect. */
void certificate_impl_session_unexport(CertificateImplSession* session);

/** Close core device state but retain the export for frontend Close(). */
void certificate_impl_session_close(CertificateImplSession* session);

#endif
