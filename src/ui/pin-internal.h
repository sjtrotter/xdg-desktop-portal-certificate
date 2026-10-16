/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_UI_PIN_INTERNAL_H
#define CERTIFICATE_UI_PIN_INTERNAL_H

#include <glib.h>

#include "config.h"
#include "pin.h"

/** PIN implementations collect input; core policy and ownership rules are documented in docs/SECURITY.md. */

typedef struct _PinPrompt PinPrompt;

/** Main-thread entry points must settle through submit or answer; core calls close exactly once. */
typedef struct
{
	const char* name;

	gboolean needs_display;

	/** Protected-path prompts have no PIN field and submit through the core. */
	void (*start)(PinPrompt* prompt);

	void (*busy)(PinPrompt* prompt, gboolean busy);

	/** Retries require fresh user input; implementations must not spend attempts automatically. */
	void (*retry)(PinPrompt* prompt, const char* status);

	/** Hide immediately during an in-flight login; settlement waits for the worker. */
	void (*hide)(PinPrompt* prompt);

	/** Core calls close once after settlement and after readers finish. */
	void (*close)(PinPrompt* prompt);
} PinPromptImpl;

/** Only ui/pin.c writes outcome policy state. */
struct _PinPrompt
{
	/* Cancellation, worker and timeout references may be released on different threads. */
	gint refs;

	CertificateToken* token;
	char* session_id;
	char* parent_window;
	char* caller_display;
	char* purpose_display;

	CertificatePinLoginFunc login;
	CertificatePinRefreshFunc refresh;
	CertificatePinAbandonFunc abandon;
	gpointer login_data;
	/* Release login_data only after done and abandon callbacks; NULL leaves ownership with the caller. */
	GDestroyNotify login_data_free;
	GCancellable* cancellable;
	gulong cancel_id;
	CertificatePinDone done;
	gpointer user_data;

	const PinPromptImpl* impl;
	gpointer impl_data;
	GDestroyNotify impl_data_free;

	/** Protected authentication uses NULL PIN, has no field and cannot retry through this UI. */
	gboolean protected_path;

	gboolean finished;
	gboolean busy;

	/* Cancellation hides the prompt immediately; buffers and callbacks wait for the login worker. */
	gboolean login_in_flight;
	gboolean cancel_deferred;
	CertificatePinOutcome deferred_outcome;

	/* A successful login discarded by the caller must be undone. */
	gboolean login_succeeded;

	/** Only ui/pin.c may read the locked page. */
	gpointer buffer_opaque;

	guint cancel_idle;
	guint login_timeout_id;
	guint attempts;
	gboolean final_try_confirmed;
};

/** Copies PIN into locked storage without submission; clear the source on return. Empty or oversized PINs trigger retry. */
gboolean certificate_pin_prompt_hold(PinPrompt* prompt, const char* pin);

/** Submit the held PIN or protected-path NULL; busy, finished and in-flight prompts cannot spend another attempt. */
void certificate_pin_prompt_submit(PinPrompt* prompt);

/** Each asynchronous implementation callback must hold a reference until it returns. */
PinPrompt* certificate_pin_prompt_ref(PinPrompt* prompt);
void certificate_pin_prompt_unref(PinPrompt* prompt);

/** Settlement during login hides immediately and defers the answer until the worker returns. */
void certificate_pin_prompt_answer(PinPrompt* prompt, CertificatePinOutcome outcome);

/** Reports standard PIN state flags without inventing a remaining-attempt count. */
const char* certificate_pin_prompt_retry_hint(const PinPrompt* prompt);

/** Calling records final-attempt confirmation; TRUE requires warning before a second submission. */
gboolean certificate_pin_prompt_needs_final_confirm(PinPrompt* prompt);

const char* certificate_pin_prompt_final_try_warning(void);

const char* certificate_pin_prompt_heading(const PinPrompt* prompt);
const char* certificate_pin_prompt_protected_note(void);

const PinPromptImpl* certificate_pin_impl_gtk(void);

#if HAVE_GCR
const PinPromptImpl* certificate_pin_impl_system(void);
/** Availability includes owned or activatable prompters and never activates one. */
gboolean certificate_pin_impl_system_available(void);
#endif

#endif
