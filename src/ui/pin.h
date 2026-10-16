/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_UI_PIN_H
#define CERTIFICATE_UI_PIN_H

#include <gio/gio.h>
#include <glib.h>

#include "../tokens/discovery.h"

/** PIN trust, buffer and interaction guarantees are documented in docs/SECURITY.md. */

typedef enum
{
	CERTIFICATE_PIN_OK,
	CERTIFICATE_PIN_INCORRECT,
	CERTIFICATE_PIN_LOCKED,
	CERTIFICATE_PIN_CANCELLED,
	CERTIFICATE_PIN_DEVICE_ERROR,
	CERTIFICATE_PIN_TOKEN_REMOVED,
	CERTIFICATE_PIN_NO_DISPLAY,
	/** A timed-out C_Login may still spend an attempt or succeed; late success is abandoned. */
	CERTIFICATE_PIN_TIMED_OUT
} CertificatePinOutcome;

/** Worker-only login borrows the PIN or protected-path NULL; cancellation cannot withdraw the submitted attempt. */
typedef gboolean (*CertificatePinLoginFunc)(const char* pin, gpointer user_data, GError** error);

/** Refresh token flags on the login worker after refusal; NULL disables refresh. */
typedef void (*CertificatePinRefreshFunc)(CertificateToken* token, gpointer user_data);

/** After done(), the main-thread abandon callback must undo a successful discarded login; NULL leaves it authenticated. */
typedef void (*CertificatePinAbandonFunc)(gpointer user_data);

typedef void (*CertificatePinDone)(CertificatePinOutcome outcome, gpointer user_data);

/** PIN text stays outside accessibility; failures are announced. */
void certificate_pin_login(CertificateToken* token, const char* parent_window,
                           const char* caller_display, const char* purpose_display,
                           CertificatePinLoginFunc login, CertificatePinRefreshFunc refresh,
                           CertificatePinAbandonFunc abandon, gpointer login_data,
                           GCancellable* cancellable, CertificatePinDone done,
                           gpointer user_data);

/** Prompt owns login_data and frees it exactly once after done and any subsequent abandon callback. */
void certificate_pin_login_full(CertificateToken* token, const char* parent_window,
                                const char* caller_display, const char* purpose_display,
                                CertificatePinLoginFunc login, CertificatePinRefreshFunc refresh,
                                CertificatePinAbandonFunc abandon, gpointer login_data,
                                GDestroyNotify login_data_free, GCancellable* cancellable,
                                CertificatePinDone done, gpointer user_data);

/** The module defaults to GTK; auto selects an owned or activatable system prompter. */
typedef enum
{
	CERTIFICATE_PIN_PROMPT_AUTO,
	CERTIFICATE_PIN_PROMPT_GTK,
	CERTIFICATE_PIN_PROMPT_SYSTEM
} CertificatePinPromptKind;

gboolean certificate_pin_set_prompt_kind(const char* name, GError** error);

/** Resolving auto may query the bus. */
const char* certificate_pin_prompt_name(void);

/** Default 60 seconds; 0 disables. On timeout the prompt closes with
 *  CERTIFICATE_PIN_TIMED_OUT and a login that returns later is abandoned. The
 *  module call is not interrupted, so the caller is answered when it returns. */
void certificate_pin_set_login_timeout(guint seconds);
guint certificate_pin_login_timeout(void);

void certificate_ui_set_has_display(gboolean has_display);
gboolean certificate_ui_has_display(void);

#endif
