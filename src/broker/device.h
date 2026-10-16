/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_BROKER_DEVICE_H
#define CERTIFICATE_BROKER_DEVICE_H

#include <glib.h>

#include "../tokens/discovery.h"
#include "mechanism.h"

/** Blocking token operations run on workers; PIN ownership stays with ui/pin.c. */

typedef struct
{
	CK_FUNCTION_LIST* module;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE private_key;
	gboolean logged_in;

	/* The device owns a candidate reference so re-granting cannot change its key binding. */
	CertificateCandidate* candidate;
} CertificateDevice;

/** Re-resolve the token by identity and reopen on credential changes; private keys may appear only after login. */
gboolean certificate_device_open(CertificateDevice* device, CertificateTokens* tokens,
                                 const CertificateCandidate* candidate, GError** error);

/** A NULL PIN selects protected authentication; login may reveal the private key. */
gboolean certificate_device_login(CertificateDevice* device,
                                  const CertificateCandidate* candidate, const char* pin,
                                  GError** error);

/** Payloads come from certificate_mechanism_prepare(); returned signatures retain the module's encoding. */
GBytes* certificate_device_perform(CertificateDevice* device, gboolean decrypt,
                                   CertificateMechanism* mechanism, GBytes* payload,
                                   GError** error);

/** Middleware may retain authentication after logout and session close. */
void certificate_device_close(CertificateDevice* device);

#endif
