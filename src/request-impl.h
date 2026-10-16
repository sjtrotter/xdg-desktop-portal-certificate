/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * The shape of this file -- a GObject deriving from the generated
 * XdpImplRequestSkeleton, exported at the handle path, with a default
 * handle_close that unexports and completes -- is xdg-desktop-portal-gtk's
 * src/request.h, Copyright (C) 2016 Red Hat, Inc, by Alexander Larsson and
 * Matthias Clasen; see docs/decisions/0004-license.md.
 */
#ifndef CERTIFICATE_IMPL_REQUEST_H
#define CERTIFICATE_IMPL_REQUEST_H

#include <gio/gio.h>
#include <glib.h>

#include "xdp-impl-dbus.h"

/** Impl requests return results in the method reply; frontend requests emit Response. See docs/IMPL-INTERFACE.md. */

#define CERTIFICATE_TYPE_IMPL_REQUEST (certificate_impl_request_get_type())
G_DECLARE_FINAL_TYPE(CertificateImplRequest, certificate_impl_request, CERTIFICATE, IMPL_REQUEST,
                     XdpImplRequestSkeleton)

CertificateImplRequest* certificate_impl_request_new(const char* sender, const char* app_id,
                                                     const char* handle);

/** Export holds a reference until unexport; export failure must abort the interaction. */
gboolean certificate_impl_request_export(CertificateImplRequest* request,
                                         GDBusConnection* connection, GError** error);

void certificate_impl_request_unexport(CertificateImplRequest* request);

/** The transaction's shared cancellable ends windows and workers on Close() or shutdown. */
GCancellable* certificate_impl_request_get_cancellable(CertificateImplRequest* request);

const char* certificate_impl_request_get_app_id(CertificateImplRequest* request);
gboolean certificate_impl_request_is_exported(CertificateImplRequest* request);

#endif
