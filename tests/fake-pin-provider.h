/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#ifndef CERTIFICATE_TEST_FAKE_PIN_PROVIDER_H
#define CERTIFICATE_TEST_FAKE_PIN_PROVIDER_H

#include "ui/pin-provider.h"

typedef struct
{
	CertificatePinProvider provider;
	PinPrompt* prompt;
	guint shows;
	guint retries;
	guint warnings;
	guint hides;
	guint closes;
	guint busy_updates;
	gboolean busy;
	gboolean protected_path;
	gboolean count_low;
	gboolean final_try;
	const char* status;
} FakePinProvider;

void fake_pin_provider_init(FakePinProvider* fake);
void fake_pin_provider_submit(FakePinProvider* fake, const char* pin);
void fake_pin_provider_confirm(FakePinProvider* fake, gboolean accepted);
void fake_pin_provider_cancel(FakePinProvider* fake);

#endif
