/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_UI_PIN_H
#define CERTIFICATE_UI_PIN_H

#include <glib.h>

#include "../tokens/discovery.h"

/** @file
 *  The PIN prompt. The only place in the system where a PIN is typed for a transaction.
 *
 *  A PIN PROMPT IS NOT CONSENT. Consent is ui/chooser.h. This window unlocks a
 *  token that consent has already authorised the use of.
 *
 *  WHEN IT APPEARS: at FIRST PRIVATE-KEY USE, not at grant time. Logging in early spends
 *  the user's presence before it is needed, and across a PKCS#11 forwarding boundary it
 *  buys nothing at all, because login state is per application and does not transfer.
 *  See docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md failure mode 3.
 *
 *  THE PIN NEVER LEAVES THIS PROCESS -- and after the frontend/backend split "this
 *  process" is the BACKEND, which is the only side that ever had a reason to hold one.
 *  The frontend cannot see a PIN because the frontend has no window and no token
 *  session; that is not a rule it must obey, it is a thing it cannot do.
 *
 *  It never crosses D-Bus in either direction, never
 *  enters a GVariant, a GError message, a PKCS#11 URI, or a log line. NO pin-value and
 *  NO pin-source ever appears in a URI this service emits.
 *
 *  THE BUFFER is allocated in locked, non-swappable memory where the platform allows,
 *  and is wiped on EVERY exit path: success, failure, cancel, timeout, window destroyed,
 *  crash handler. Core dumps are disabled for the process where practical.
 *
 *  NOTHING PERSISTS A PIN. There is no "remember PIN", no keyring entry, no option, and
 *  no configuration key. Storing a PIN converts a two-factor credential into a
 *  one-factor one.
 *
 *  PROTECTED AUTHENTICATION PATH: when the token sets CKF_PROTECTED_AUTHENTICATION_PATH
 *  -- PIN pad readers, biometric tokens -- the login is made with a NULL PIN and the
 *  token or reader collects the secret itself. This module shows an INSTRUCTIONAL DIALOG
 *  WITH NO EDITABLE PIN FIELD and never receives the PIN. Emulating a PIN field for such
 *  a token would be a lie about where the secret goes.
 *
 *  RETRIES: displayed only when the token reports them RELIABLY, and NEVER INVENTED --
 *  a wrong count is worse than none. Warn before the final known attempt. Retries are
 *  USER-INITIATED ONLY; this service never retries on its own, and never after an
 *  ambiguous transport failure. Prompts for the SAME TOKEN ARE SERIALISED, so two grants
 *  cannot race two windows at the user.
 *
 *  HEADLESS: NEVER READ A PIN FROM STDIN. With no display, or with interaction_mode
 *  "forbidden", the caller gets NoDisplay or InteractionRequired. A trusted agent
 *  protocol for headless use would be a separate, separately configured, separately
 *  reviewed mechanism.
 *
 *  WE CANNOT FORCE FORGETTING. Some tokens and middleware cache authentication
 *  internally, for a duration this service does not control. C_Logout is issued at grant
 *  end; nothing here may claim the card has forgotten.
 *
 *  Sketch only; nothing here is implemented.
 */

/** Distinguished deliberately. Collapsing these is how a user blocks a card while being
 *  told "authentication failed". */
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

typedef void (*CertificatePinDone)(CertificatePinOutcome outcome, gpointer user_data);

/** Prompt and log in. There is no "get the PIN" entry point on purpose: the caller never
 *  receives the PIN, only the outcome of a login this module performed. The window
 *  restates the verified caller, purpose and operation class from the chooser, and names
 *  the token being unlocked.
 *
 *  The PIN field is never echoed and its contents never enter the accessibility tree,
 *  while the "incorrect PIN, N attempts remaining" state IS announced. */
void certificate_pin_login(const char* parent_window, const CertificateToken* token,
                         const char* caller_display, const char* purpose_display,
                         GCancellable* cancellable, CertificatePinDone done, gpointer user_data);

/** Show the instruction window for a token with a protected authentication path, while
 *  the underlying null-PIN login runs. No editable field. */
void certificate_pin_protected_path(const char* parent_window, const CertificateToken* token,
                                  GCancellable* cancellable, CertificatePinDone done,
                                  gpointer user_data);

#endif /* CERTIFICATE_UI_PIN_H */
