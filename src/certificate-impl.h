/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_IMPL_CERTIFICATE_H
#define CERTIFICATE_IMPL_CERTIFICATE_H

#include <gio/gio.h>
#include <glib.h>

#include "certificate.h"
#include "session-impl.h"
#include "tokens/discovery.h"

/** Backend trust and ownership boundaries are documented in docs/IMPL-INTERFACE.md. */

typedef struct CertificateImpl CertificateImpl;

CertificateImpl* certificate_impl_new(GDBusConnection* connection, CertificateTokens* tokens,
                                      GError** error);

/** Every method requires the current frontend owner; refusals expose only AccessDenied. */
gboolean certificate_impl_sender_is_frontend(CertificateImpl* impl, const char* sender);

/** Request and Session handlers use the process's single backend instance. */
gboolean certificate_impl_sender_is_frontend_default(const char* sender);

/** Only Session.Close() forgets the exported session; other termination paths keep it available for that call. */
void certificate_impl_session_forget(CertificateImplSession* session);

GVariant* certificate_impl_acquire_results(CertificateCandidate* candidate, gboolean may_sign);

/** Emit backend_gone for each session before releasing token sessions. */
void certificate_impl_shutdown(CertificateImpl* impl);

void certificate_impl_free(CertificateImpl* impl);

#endif
