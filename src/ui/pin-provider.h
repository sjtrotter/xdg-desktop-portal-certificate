/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_UI_PIN_PROVIDER_H
#define CERTIFICATE_UI_PIN_PROVIDER_H

#include "pin.h"

typedef struct _PinPrompt PinPrompt;

/* Internal precursor to XccUiV1's PIN callbacks; prompt handles become UI IDs later. */
/* Callbacks run on the main thread; close runs once, including for unshown queued prompts. */
typedef struct
{
	const char* name;
	gboolean needs_display;
	gpointer user_data;
	void (*pin_show)(gpointer user_data, PinPrompt* prompt);
	/* NULL status updates busy state; non-NULL status requests fresh input. */
	void (*pin_update)(gpointer user_data, PinPrompt* prompt, const char* status);
	void (*warning)(gpointer user_data, PinPrompt* prompt, const char* message);
	void (*hide)(gpointer user_data, PinPrompt* prompt);
	void (*close)(gpointer user_data, PinPrompt* prompt);
} CertificatePinProvider;

/* Main thread only; copied per login; user_data must outlive all retained prompt handles. */
void certificate_pin_set_provider(const CertificatePinProvider* provider);

/* Copies only into the existing locked buffer; clear the source after submission. */
gboolean certificate_pin_prompt_hold(PinPrompt* prompt, const char* pin);
/* Submit held input or protected-path NULL; policy requests a warning before a final attempt. */
void certificate_pin_prompt_submit(PinPrompt* prompt);
void certificate_pin_prompt_warning_reply(PinPrompt* prompt, gboolean accepted);
void certificate_pin_prompt_answer(PinPrompt* prompt, CertificatePinOutcome outcome);

/* Asynchronous provider callbacks retain the handle until they return. */
PinPrompt* certificate_pin_prompt_ref(PinPrompt* prompt);
void certificate_pin_prompt_unref(PinPrompt* prompt);

#endif
