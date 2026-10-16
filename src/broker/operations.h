/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_BROKER_OPERATIONS_H
#define CERTIFICATE_BROKER_OPERATIONS_H

#include <gio/gio.h>
#include <glib.h>

#include "../certificate.h"
#include "../session-impl.h"
#include "../tokens/discovery.h"
#include "mechanism.h"

/** Purpose constrains selection and consent text; it cannot attest later signature use. See docs/IMPL-INTERFACE.md. */

typedef void (*CertificateBrokerDone)(GBytes* result, const GError* error, gpointer user_data);

void certificate_broker_perform(CertificateTokens* tokens, CertificateImplSession* session,
                                gboolean decrypt, const char* operation_id,
                                const char* mechanism_name,
                                GVariant* parameters, GBytes* data, const char* parent_window,
                                const char* caller_display, GCancellable* cancellable,
                                CertificateBrokerDone done, gpointer user_data);

/** The test gate runs on a worker under device_lock to hold a card operation during cancellation. */
typedef void (*CertificateBrokerGate)(gpointer user_data);
void certificate_broker_set_gate(CertificateBrokerGate gate, gpointer user_data);

/** The test open gate runs once on a worker after the device opens, without locks held. */
void certificate_broker_set_open_gate(CertificateBrokerGate gate, gpointer user_data);

#endif
