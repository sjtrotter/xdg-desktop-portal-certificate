/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_UI_PIN_H
#define CERTIFICATE_UI_PIN_H

#include <gio/gio.h>
#include <glib.h>

#include "../tokens/discovery.h"

/** @file
 *  The PIN prompt. The only place in the system where a PIN is typed for a
 *  transaction.
 *
 *  A PIN PROMPT IS NOT CONSENT. Consent is ui/chooser.h. This window unlocks a
 *  token that consent has already authorised the use of.
 *
 *  WHEN IT APPEARS: at FIRST PRIVATE-KEY USE, not at grant time. Logging in
 *  early spends the user's presence before it is needed.
 *
 *  THE PIN NEVER LEAVES THIS PROCESS -- "this process" being the BACKEND, which
 *  is the only side that ever had a reason to hold one. xdg-desktop-portal
 *  cannot see a PIN because it has no window and no token session; that is not
 *  a rule it must obey, it is a thing it cannot do. Neither the public nor the
 *  impl interface has a field a PIN could travel in.
 *
 *  THERE IS NO "GET THE PIN" ENTRY POINT, on purpose. The caller hands this
 *  module a login function and receives the OUTCOME of a login this module
 *  performed. The PIN is never returned, never copied into a GVariant, a GError
 *  or a log line, and never reaches the caller.
 *
 *  THE BUFFER is allocated page-aligned and mlock()ed where the platform
 *  allows, and is wiped with explicit_bzero() on EVERY exit path: success,
 *  failure, cancel, window destroyed, backend shutdown.
 *
 *  NOTHING PERSISTS A PIN. There is no "remember PIN", no keyring entry, no
 *  option, and no configuration key. Storing a PIN converts a two-factor
 *  credential into a one-factor one.
 *
 *  PROTECTED AUTHENTICATION PATH: when the token sets
 *  CKF_PROTECTED_AUTHENTICATION_PATH -- PIN pad readers, biometric tokens --
 *  the login is made with a NULL PIN and the token or reader collects the
 *  secret itself. This module shows an INSTRUCTIONAL WINDOW WITH NO EDITABLE
 *  PIN FIELD and never receives the PIN.
 *
 *  RETRIES: displayed only when the token reports them RELIABLY through
 *  CKF_USER_PIN_COUNT_LOW / CKF_USER_PIN_FINAL_TRY / CKF_USER_PIN_LOCKED, and
 *  NEVER INVENTED -- a wrong count is worse than none, and PKCS#11 has no
 *  portable way to ask for the number itself. Retries are USER-INITIATED ONLY.
 *  Prompts are SERIALISED process-wide, so two grants cannot race two windows
 *  at the user.
 *
 *  HEADLESS: NEVER READ A PIN FROM STDIN. With no display the caller gets
 *  CERTIFICATE_PIN_NO_DISPLAY.
 *
 *  WE CANNOT FORCE FORGETTING. Some tokens and middleware cache authentication
 *  internally, for a duration this service does not control. C_Logout is issued
 *  at grant end; nothing here may claim the card has forgotten.
 */

/** Distinguished deliberately. Collapsing these is how a user blocks a card
 *  while being told "authentication failed". */
typedef enum
{
	CERTIFICATE_PIN_OK,
	CERTIFICATE_PIN_INCORRECT,
	CERTIFICATE_PIN_LOCKED,
	CERTIFICATE_PIN_CANCELLED,
	CERTIFICATE_PIN_DEVICE_ERROR,
	CERTIFICATE_PIN_TOKEN_REMOVED,
	CERTIFICATE_PIN_NO_DISPLAY
} CertificatePinOutcome;

/** Perform the login. Called ON A WORKER THREAD with the PIN this module
 *  collected, or with NULL for a protected authentication path. The
 *  implementation must not copy the PIN anywhere. */
typedef gboolean (*CertificatePinLoginFunc)(const char* pin, gpointer user_data, GError** error);

typedef void (*CertificatePinDone)(CertificatePinOutcome outcome, gpointer user_data);

/** Prompt and log in. The window restates the verified caller and the purpose
 *  from the chooser, and names the token being unlocked.
 *
 *  The PIN field is never echoed and its contents never enter the accessibility
 *  tree, while the "incorrect PIN" state IS announced. */
void certificate_pin_login(CertificateToken* token, const char* parent_window,
                           const char* caller_display, const char* purpose_display,
                           CertificatePinLoginFunc login, gpointer login_data,
                           GCancellable* cancellable, CertificatePinDone done, gpointer user_data);

/** Whether a display was available when the process started. With none, every
 *  window-drawing path answers CERTIFICATE_PIN_NO_DISPLAY instead of hanging. */
void certificate_ui_set_has_display(gboolean has_display);
gboolean certificate_ui_has_display(void);

#endif /* CERTIFICATE_UI_PIN_H */
