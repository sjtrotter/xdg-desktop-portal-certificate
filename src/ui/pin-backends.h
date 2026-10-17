/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_UI_PIN_BACKENDS_H
#define CERTIFICATE_UI_PIN_BACKENDS_H

#include "config.h"
#include "pin-provider.h"

const CertificatePinProvider* certificate_pin_provider_gtk(void);
#if HAVE_GCR
const CertificatePinProvider* certificate_pin_provider_system(void);
/* Availability includes owned or activatable prompters and never activates one. */
gboolean certificate_pin_provider_system_available(void);
#endif

/* Resolve auto on the session bus and inject the selected provider at startup. */
gboolean certificate_pin_set_prompt_kind(const char* name, GError** error);
const char* certificate_pin_prompt_name(void);

#endif
