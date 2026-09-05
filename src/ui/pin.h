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

/** @file
 *  The PIN prompt. The only place in the system where a PIN is typed for a
 *  transaction.
 *
 *  A PIN PROMPT IS NOT CONSENT. Consent is ui/chooser.h, and it is always drawn
 *  by THIS process. This prompt unlocks a token that consent has already
 *  authorised the use of.
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
 *  WHERE THE PIN IS TYPED IS A CHOICE, AND IT IS RECORDED. There are two
 *  implementations of everything below (src/ui/pin-internal.h):
 *
 *    gtk     this backend draws the window and the field. The PIN exists only
 *            in this process.
 *    system  the desktop shell's own system prompter draws it
 *            (org.gnome.keyring.SystemPrompter, over GcrSystemPrompt). The
 *            field and its buffer live in the SHELL; the PIN reaches this
 *            process over gcr's secret exchange and lands in the same locked
 *            page. Only available when the build found gcr-4.
 *
 *  Neither choice changes any rule below except where the entry widget lives.
 *  docs/SECURITY.md says what moves and what does not.
 *
 *  THE BUFFER is allocated page-aligned, mlock()ed where the platform allows,
 *  marked MADV_DONTDUMP, and wiped with explicit_bzero() on EVERY exit path:
 *  success, failure, cancel, window destroyed, backend shutdown. The login
 *  worker is handed a PRIVATE COPY that it owns and wipes itself, so that
 *  cancelling the window cannot pull the buffer out from under a C_Login.
 *
 *  WHAT THIS MODULE DOES NOT CLAIM: that the PIN exists in exactly one place.
 *  On the gtk path it is typed into a GtkPasswordEntry, which GTK backs with a
 *  GtkPasswordEntryBuffer from its secure-memory pool -- zeroed when freed, and
 *  in non-pageable memory "if the underlying platform allows it" -- but GTK
 *  guarantees nothing about the copies a text widget, an input method or a
 *  Pango layout may have made. On the system path the same question is the
 *  SHELL's, and the PIN reaches this process through gcr's secret exchange and
 *  gcr's secure memory. Either way the entry is cleared the moment this module
 *  has its own copy, and that copy is in one locked, non-dumpable, wiped page.
 *  That is the whole of the claim.
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
 *  portable way to ask for the number itself. The flags are RE-READ after every
 *  refusal, because FINAL_TRY is normally set by the attempt that just failed.
 *  Once FINAL_TRY is set, the prompt requires a SECOND, EXPLICIT confirmation
 *  before the attempt is spent -- a second Unlock in the window, a confirmation
 *  round on the same open system prompt. Retries are USER-INITIATED ONLY and one
 *  prompt offers at most three of them. Prompts are SERIALISED process-wide, so
 *  two grants cannot race two prompts at the user.
 *
 *  CANCELLING WHILE THE CARD IS BUSY hides the prompt at once and answers the
 *  caller when the worker returns: nothing the login is reading is freed while
 *  it is reading it, and the caller is answered exactly once. If the login the
 *  user cancelled SUCCEEDED anyway -- the card was simply slower than the
 *  Escape key -- the abandon callback is invoked afterwards so that the token
 *  is not left authenticated for an operation nobody consented to.
 *
 *  HEADLESS: NEVER READ A PIN FROM STDIN. With no display the gtk prompt
 *  answers CERTIFICATE_PIN_NO_DISPLAY. The system prompt does NOT need a display
 *  in this process -- the window is the shell's -- and that is not a headless
 *  mode either: a session with a shell in it is a graphical session, and in any
 *  case nothing reaches this module without ui/chooser.h having drawn consent
 *  first, which does need one.
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
	CERTIFICATE_PIN_NO_DISPLAY,
	/** A submitted C_Login did not return within the login timeout. NOT the
	 *  same as a failure: the attempt may still be spent and may still succeed,
	 *  in which case it is abandoned. See certificate_pin_set_login_timeout(). */
	CERTIFICATE_PIN_TIMED_OUT
} CertificatePinOutcome;

/** Perform the login. Called ON A WORKER THREAD with the PIN this module
 *  collected, or with NULL for a protected authentication path. The
 *  implementation must not copy the PIN anywhere.
 *
 *  IT CANNOT BE CANCELLED. PKCS#11 has no way to withdraw a C_Login, so an
 *  attempt that has been submitted is spent whatever the user does with the
 *  window. Cancelling hides the window and defers the answer until this
 *  function has returned; it never frees anything under it. */
typedef gboolean (*CertificatePinLoginFunc)(const char* pin, gpointer user_data, GError** error);

/** Re-read @token's CKF_USER_PIN_COUNT_LOW / FINAL_TRY / LOCKED flags in place.
 *  Called ON THE SAME WORKER THREAD immediately after a refused PIN, because
 *  FINAL_TRY is normally set BY the attempt that just failed: a window still
 *  showing the flags captured at discovery would never warn anybody before the
 *  last attempt. Optional; NULL means the flags are never refreshed. */
typedef void (*CertificatePinRefreshFunc)(CertificateToken* token, gpointer user_data);

/** Called ON THE MAIN THREAD when a login SUCCEEDED but its outcome is being
 *  thrown away -- the one case being a cancel that arrived while C_Login was in
 *  flight and lost the race. PKCS#11 cannot withdraw a login, so the token is
 *  authenticated and nobody asked for it to be: the implementation is expected
 *  to log the session out again, and this is the only place that knows the
 *  difference. Called after the outcome has been delivered, so the caller's
 *  own bookkeeping has already run. Optional; NULL means a discarded login is
 *  left in place. */
typedef void (*CertificatePinAbandonFunc)(gpointer user_data);

typedef void (*CertificatePinDone)(CertificatePinOutcome outcome, gpointer user_data);

/** Prompt and log in. The window restates the verified caller and the purpose
 *  from the chooser, and names the token being unlocked.
 *
 *  The PIN field is never echoed and its contents never enter the accessibility
 *  tree, while the "incorrect PIN" state IS announced. */
void certificate_pin_login(CertificateToken* token, const char* parent_window,
                           const char* caller_display, const char* purpose_display,
                           CertificatePinLoginFunc login, CertificatePinRefreshFunc refresh,
                           CertificatePinAbandonFunc abandon, gpointer login_data,
                           GCancellable* cancellable, CertificatePinDone done,
                           gpointer user_data);

/** Which implementation asks for the PIN.
 *
 *  AUTO means the system prompter when org.gnome.keyring.SystemPrompter has an
 *  owner on the session bus or is activatable, and the in-process window
 *  otherwise. THE MODULE DEFAULT IS GTK, not AUTO: linking this code must never
 *  be enough to start putting prompts on a shell that was never asked. main()
 *  is the only caller that opts in to AUTO. */
typedef enum
{
	CERTIFICATE_PIN_PROMPT_AUTO,
	CERTIFICATE_PIN_PROMPT_GTK,
	CERTIFICATE_PIN_PROMPT_SYSTEM
} CertificatePinPromptKind;

/** Set it from a --pin-prompt argument: "auto", "gtk" or "system". Fails on
 *  anything else rather than falling back to a default, for the same reason a
 *  mistyped mechanism parameter is an error. */
gboolean certificate_pin_set_prompt_kind(const char* name, GError** error);

/** The name of the implementation that will be used, resolving AUTO if it has
 *  not been resolved yet. Resolving asks the bus, so it is not free. */
const char* certificate_pin_prompt_name(void);

/** HOW LONG A SUBMITTED C_Login MAY GO UNANSWERED, in seconds; 0 disables it.
 *  Default 60.
 *
 *  IT DOES NOT INTERRUPT THE MODULE, because PKCS#11 offers no way to: the
 *  attempt is spent whatever happens, and the caller is still answered only
 *  when the module returns. What it does is take the prompt down at a known
 *  moment, fail the interaction with CERTIFICATE_PIN_TIMED_OUT rather than
 *  leaving a spinner up forever, and make a login that lands afterwards get
 *  ABANDONED instead of being handed to whoever is still waiting. */
void certificate_pin_set_login_timeout(guint seconds);
guint certificate_pin_login_timeout(void);

/** Whether a display was available when the process started. With none, every
 *  window-drawing path answers CERTIFICATE_PIN_NO_DISPLAY instead of hanging. */
void certificate_ui_set_has_display(gboolean has_display);
gboolean certificate_ui_has_display(void);

#endif /* CERTIFICATE_UI_PIN_H */
