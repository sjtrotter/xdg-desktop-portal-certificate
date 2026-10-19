/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_UI_PIN_PROVIDER_H
#define CERTIFICATE_UI_PIN_PROVIDER_H

#include "../core/ui.h"
#include "../core/pin.h"
#include "../core/secret.h"

G_BEGIN_DECLS

typedef struct _PinPrompt PinPrompt;

/* Internal precursor to XccUiV1's PIN callbacks; prompt handles become UI IDs later. */
/* Callbacks run on the main thread; close runs once, including for unshown queued prompts. */
typedef struct
{
	const char* name;
	gboolean needs_display;
	gpointer user_data;
	/* Typed PIN warnings are presented upfront, without a warning reply. */
	void (*pin_show)(gpointer user_data, PinPrompt* prompt, const XccPinView* view);
	void (*pin_update)(gpointer user_data, PinPrompt* prompt, const XccPinView* view);
	/* Only protected-path FINAL_TRY requires an explicit Continue/Cancel reply. */
	void (*warning)(gpointer user_data, PinPrompt* prompt, const char* message);
	void (*hide)(gpointer user_data, PinPrompt* prompt);
	void (*close)(gpointer user_data, PinPrompt* prompt);
} CertificatePinProvider;

/* Main thread only; copied per login; user_data must outlive all retained prompt handles. */
void certificate_pin_set_provider(const CertificatePinProvider* provider);
const CertificatePinProvider* certificate_pin_get_provider(void);

/* Consumes provider-filled storage and validates length before transfer to the worker. */
gboolean certificate_pin_prompt_hold(PinPrompt* prompt, XccSecret* secret, size_t length);
/* Signal readiness after presentation/open; starts protected-path confirmation or login. */
void certificate_pin_prompt_ready(PinPrompt* prompt);
/* Submit held input or protected-path NULL; only protected-path final attempts require Continue. */
void certificate_pin_prompt_submit(PinPrompt* prompt);
void certificate_pin_prompt_warning_reply(PinPrompt* prompt, gboolean accepted);
void certificate_pin_prompt_answer(PinPrompt* prompt, CertificatePinOutcome outcome);

/* Asynchronous provider callbacks retain the handle until they return. */
PinPrompt* certificate_pin_prompt_ref(PinPrompt* prompt);
void certificate_pin_prompt_unref(PinPrompt* prompt);

G_END_DECLS

#endif
