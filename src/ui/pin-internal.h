/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_UI_PIN_INTERNAL_H
#define CERTIFICATE_UI_PIN_INTERNAL_H

#include <glib.h>

#include "config.h"
#include "pin.h"

/** @file
 *  THE PART OF ui/pin.h THAT IS SHARED BETWEEN PROMPT IMPLEMENTATIONS, and
 *  nothing outside src/ui/ may include it.
 *
 *  There are two implementations of the same contract:
 *
 *    ui/pin-gtk.c     this backend draws the window itself. The PIN is typed
 *                     into a GtkPasswordEntry in THIS process.
 *    ui/pin-system.c  the PIN is typed into the desktop shell's own system
 *                     prompter (org.gnome.keyring.SystemPrompter) over
 *                     GcrSystemPrompt, and reaches this process through gcr's
 *                     secret exchange. Optional: it exists only when the build
 *                     found gcr-4.
 *
 *  EVERYTHING THAT DECIDES ANYTHING IS IN ui/pin.c, not in either
 *  implementation: the locked buffer, the login worker, the attempt cap, the
 *  FINAL_TRY rule, the flag re-read, the serialisation queue, the deferred
 *  cancel and the login timeout. An implementation collects characters and
 *  draws warnings; it never decides whether an attempt is spent, and it never
 *  sees the login function.
 *
 *  A PIN NEVER PASSES THROUGH THIS HEADER as anything but the argument to
 *  certificate_pin_prompt_hold(), which copies it into the locked page and
 *  returns. The implementation is expected to have wiped or released whatever
 *  it was holding by the time that call returns.
 */

typedef struct _PinPrompt PinPrompt;

/** One prompt implementation. Every entry point is called ON THE MAIN THREAD.
 *
 *  THE CONTRACT IN ONE LINE: after @start, exactly one of
 *  certificate_pin_prompt_submit() or certificate_pin_prompt_answer() is
 *  reached for every state the interaction can end in, and @close is called
 *  exactly once by the core when the answer is settled. */
typedef struct
{
	/** For the journal and --pin-prompt. */
	const char* name;

	/** Whether this implementation needs a display in THIS process.
	 *  The system prompter does not: the window is the shell's. */
	gboolean needs_display;

	/** Put the interaction up. For a protected-authentication-path token the
	 *  implementation shows a passive notice with no field and calls
	 *  certificate_pin_prompt_submit(prompt) itself. */
	void (*start)(PinPrompt* prompt);

	/** The card is thinking. Optional. */
	void (*busy)(PinPrompt* prompt, gboolean busy);

	/** The token refused the PIN and the core has decided another attempt may
	 *  be offered. @status is this backend's wording for the refusal and
	 *  certificate_pin_prompt_retry_hint() is the token's, or NULL.
	 *  The implementation must ask again -- and must not spend an attempt of
	 *  its own accord. */
	void (*retry)(PinPrompt* prompt, const char* status);

	/** Take the interaction off the screen NOW, without settling anything: a
	 *  cancel or a timeout arrived while C_Login was in flight and the answer
	 *  has to wait for the worker. Optional. */
	void (*hide)(PinPrompt* prompt);

	/** Tear the interaction down. Called exactly once, from the core, with the
	 *  answer already decided and nothing else reading the prompt. */
	void (*close)(PinPrompt* prompt);
} PinPromptImpl;

/** The state every implementation shares. Implementations read it; only
 *  ui/pin.c writes anything that decides an outcome. */
struct _PinPrompt
{
	/* ATOMIC. Cancellation handlers run on whatever thread called
	 * g_cancellable_cancel(), the login task drops its reference from a worker
	 * thread's completion, and the timeout runs on the main context. A plain
	 * int here would have to be defended with a comment about which of those
	 * are the main thread today; g_atomic_int_* costs nothing measurable and
	 * removes the argument. */
	gint refs;

	CertificateToken* token;
	char* parent_window;
	char* caller_display;
	char* purpose_display;

	CertificatePinLoginFunc login;
	CertificatePinRefreshFunc refresh;
	CertificatePinAbandonFunc abandon;
	gpointer login_data;
	GCancellable* cancellable;
	gulong cancel_id;
	CertificatePinDone done;
	gpointer user_data;

	const PinPromptImpl* impl;
	gpointer impl_data;
	GDestroyNotify impl_data_free;

	/** CKF_PROTECTED_AUTHENTICATION_PATH: no field is drawn anywhere, the login
	 *  is made with a NULL PIN, and a refusal cannot be retried from here
	 *  because the reader owns the interaction. */
	gboolean protected_path;

	gboolean finished;
	gboolean busy;

	/* THE CANCEL-WHILE-BUSY STATE. login_in_flight is true from the moment the
	 * worker is started until its completion callback runs on the main thread.
	 * A cancel or a timeout arriving in that window takes the interaction off
	 * the screen immediately and records what to answer, and nothing at all is
	 * freed until the worker has returned. */
	gboolean login_in_flight;
	gboolean cancel_deferred;
	CertificatePinOutcome deferred_outcome;

	/* A login that went through. It matters after the fact only when the answer
	 * given is NOT "unlocked": that is a login the caller never asked for and
	 * has to be able to undo. */
	gboolean login_succeeded;

	/** The locked page. Opaque here: ui/pin.c owns it outright and no
	 *  implementation may read it, which is the point of handing the PIN to
	 *  certificate_pin_prompt_hold() rather than exposing a buffer. */
	gpointer buffer_opaque;

	guint cancel_idle;
	guint login_timeout_id;
	guint attempts;
	gboolean final_try_confirmed;
};

/** COPY @pin INTO THE LOCKED PAGE. Nothing else happens: no attempt is spent
 *  and no worker starts, so an implementation can hold a typed PIN across a
 *  confirmation round without ever owning a second copy of it. The caller's
 *  storage is not referenced after this returns and the implementation is
 *  expected to drop or clear its own copy immediately.
 *
 *  Returns FALSE, having said so through @impl->retry, when the PIN is EMPTY --
 *  which is never an attempt, in either implementation, because a token that
 *  counts a zero-length PIN as a failure would spend a retry on a stray Return
 *  -- or when it is longer than this backend will send to a token. Never called
 *  for a protected authentication path. */
gboolean certificate_pin_prompt_hold(PinPrompt* prompt, const char* pin);

/** Spend an attempt: hand the worker a private copy of what
 *  certificate_pin_prompt_hold() put in the locked page -- or a NULL PIN for a
 *  protected authentication path -- and start the login.
 *
 *  Returns quietly when the prompt is busy, finished, or a login is already in
 *  flight, so a late answer from a prompter cannot spend a second attempt. */
void certificate_pin_prompt_submit(PinPrompt* prompt);

/** REFERENCE COUNTING, for an implementation whose asynchronous calls outlive
 *  the interaction. The core drops its own reference the moment the answer is
 *  settled, so a callback that is still queued -- a gcr password round the
 *  prompter has not answered, say -- must hold one of its own or it will run on
 *  freed memory. Take one before every asynchronous call and drop it in the
 *  callback, whatever the callback then decides. */
PinPrompt* certificate_pin_prompt_ref(PinPrompt* prompt);
void certificate_pin_prompt_unref(PinPrompt* prompt);

/** Settle the interaction with @outcome. Safe to call more than once and safe
 *  to call while a login is in flight, in which case the interaction is hidden
 *  now and the answer is delivered when the worker returns. */
void certificate_pin_prompt_answer(PinPrompt* prompt, CertificatePinOutcome outcome);

/** The token's own retry state in words, or NULL when it reports none. Only
 *  ever CKF_USER_PIN_COUNT_LOW / FINAL_TRY / LOCKED; never a number. */
const char* certificate_pin_prompt_retry_hint(const PinPrompt* prompt);

/** TRUE when this submission must be confirmed a second time before it is
 *  spent, because the token says CKF_USER_PIN_FINAL_TRY. Calling it RECORDS the
 *  confirmation, so an implementation asks once per attempt, immediately before
 *  it would submit, and shows certificate_pin_prompt_final_try_warning() when
 *  the answer is TRUE. */
gboolean certificate_pin_prompt_needs_final_confirm(PinPrompt* prompt);

/** The wording for that second confirmation. One string, shared, so that the
 *  window and the shell's prompter say the same thing. */
const char* certificate_pin_prompt_final_try_warning(void);

/** The heading and the passive protected-path notice, shared for the same
 *  reason. */
const char* certificate_pin_prompt_heading(const PinPrompt* prompt);
const char* certificate_pin_prompt_protected_note(void);

/** The GTK implementation. Always present. */
const PinPromptImpl* certificate_pin_impl_gtk(void);

#if HAVE_GCR
/** The system-prompter implementation, and whether a prompter is reachable.
 *  certificate_pin_impl_system_available() asks the bus whether
 *  org.gnome.keyring.SystemPrompter has an owner OR is activatable; it never
 *  starts one. */
const PinPromptImpl* certificate_pin_impl_system(void);
gboolean certificate_pin_impl_system_available(void);
#endif

#endif /* CERTIFICATE_UI_PIN_INTERNAL_H */
