/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_CORE_PIN_INTERNAL_H
#define CERTIFICATE_CORE_PIN_INTERNAL_H

#include <glib.h>

#include "../ui/pin-provider.h"

/** PIN implementations collect input; core policy and ownership rules are documented in docs/SECURITY.md. */

/** Only core/pin.c writes outcome policy state. */
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

	CertificatePinProvider provider;
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

	/* Held until submission, then transferred to the worker. */
	XccSecret* secret;

	guint cancel_idle;
	guint login_timeout_id;
	guint attempts;
	gboolean protected_path_confirmed;
	gboolean warning_pending;
};

/** Reports standard PIN state flags without inventing a remaining-attempt count. */
const char* certificate_pin_prompt_retry_hint(const XccPinView* view);

const char* certificate_pin_prompt_final_try_warning(void);

const char* certificate_pin_prompt_heading(const PinPrompt* prompt);
const char* certificate_pin_prompt_protected_note(void);

#endif
