/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * THE PIN PROMPT, MINUS THE WINDOW. Everything that decides anything is here:
 * the locked buffer, the login worker, the attempt cap, the FINAL_TRY rule, the
 * flag re-read, the serialisation queue, the deferred cancel and the login
 * timeout. The two implementations that actually ask a human -- ui/pin-gtk.c
 * and ui/pin-system.c -- collect characters and draw warnings, and decide
 * nothing.
 */

/* explicit_bzero(), posix_memalign(), mlock(), madvise(): the PIN buffer needs
 * all four. */
#define _GNU_SOURCE 1

#include "pin.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../certificate.h"
#include "../redact.h"
#include "config.h"
#include "pin-internal.h"

static gboolean ui_has_display = FALSE;

void certificate_ui_set_has_display(gboolean has_display)
{
	ui_has_display = has_display;
}

gboolean certificate_ui_has_display(void)
{
	return ui_has_display;
}

/* ------------------------------------------------------- choosing a prompt */

/* THE MODULE DEFAULT IS THE IN-PROCESS WINDOW, and that is a safety property
 * rather than a preference: a test, or anything else that links this code
 * without asking, must not start putting prompts on the operator's real
 * session shell because a name happened to be on the bus. main() is the only
 * caller that opts in to AUTO. */
static CertificatePinPromptKind pin_prompt_kind = CERTIFICATE_PIN_PROMPT_GTK;
static const PinPromptImpl* pin_prompt_resolved = NULL;

gboolean certificate_pin_set_prompt_kind(const char* name, GError** error)
{
	if (name == NULL || g_ascii_strcasecmp(name, "auto") == 0)
		pin_prompt_kind = CERTIFICATE_PIN_PROMPT_AUTO;
	else if (g_ascii_strcasecmp(name, "gtk") == 0)
		pin_prompt_kind = CERTIFICATE_PIN_PROMPT_GTK;
	else if (g_ascii_strcasecmp(name, "system") == 0)
		pin_prompt_kind = CERTIFICATE_PIN_PROMPT_SYSTEM;
	else
	{
		g_set_error(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
		            "Unknown PIN prompt '%s'; expected auto, gtk or system", name);
		return FALSE;
	}

	pin_prompt_resolved = NULL;
	return TRUE;
}

/* RESOLVED ONCE, AND THE ANSWER IS LOGGED. Which process drew the window the
 * user typed a PIN into is exactly the sort of thing that must not be a
 * mystery afterwards. */
static const PinPromptImpl* pin_impl(void)
{
	if (pin_prompt_resolved != NULL)
		return pin_prompt_resolved;

	switch (pin_prompt_kind)
	{
		case CERTIFICATE_PIN_PROMPT_SYSTEM:
#if HAVE_GCR
			pin_prompt_resolved = certificate_pin_impl_system();
			break;
#else
			/* --pin-prompt=system does not exist in a build without gcr, so
			 * this is unreachable from the command line; it stays as the
			 * answer for anything that sets the kind programmatically. */
			pin_prompt_resolved = certificate_pin_impl_gtk();
			break;
#endif

		case CERTIFICATE_PIN_PROMPT_AUTO:
#if HAVE_GCR
			if (certificate_pin_impl_system_available())
			{
				pin_prompt_resolved = certificate_pin_impl_system();
				break;
			}
#endif
			pin_prompt_resolved = certificate_pin_impl_gtk();
			break;

		case CERTIFICATE_PIN_PROMPT_GTK:
		default:
			pin_prompt_resolved = certificate_pin_impl_gtk();
			break;
	}

	g_message("pin-prompt-selected detail=%s", pin_prompt_resolved->name);
	return pin_prompt_resolved;
}

const char* certificate_pin_prompt_name(void)
{
	return pin_impl()->name;
}

/* ------------------------------------------------------------- PIN buffer */

/* Page-aligned, mlock()ed where the kernel and the rlimit allow, marked
 * MADV_DONTDUMP so that it is left out of a core dump even if one is somehow
 * produced, and wiped with explicit_bzero() on every exit path.
 *
 * MLOCK FAILURE POLICY, stated because it is a real one: mlock() failing is NOT
 * fatal and does not refuse the login. The default RLIMIT_MEMLOCK is small and a
 * desktop session may have spent it, and refusing to unlock a card because the
 * kernel would not pin one page would be a denial of service with no security
 * gain -- the page is still wiped, and the process still has core dumps and
 * ptrace attach disabled (see main.c). It is warned about ONCE per process, at
 * message level, so that the difference between "not written to swap" and
 * "probably not written to swap" is in the journal rather than assumed.
 * docs/SECURITY.md says the same thing in the same words. */
typedef struct
{
	char* data;
	gsize capacity;
	gboolean locked;
} PinBuffer;

/* The longest PIN this backend will send to a token. It is the ENFORCED
 * maximum, not a hint: pin_buffer_set() refuses anything longer. */
#define PIN_BUFFER_CAPACITY 512

/* Attempts one prompt may spend before it gives up and hands the outcome back
 * to the caller. A PIN prompt that offers unbounded retries is a prompt in
 * which a card can be walked all the way to locked. */
#define PIN_MAX_ATTEMPTS 3

static gboolean pin_mlock_warned = FALSE;

static PinBuffer* pin_buffer_new(void)
{
	PinBuffer* buffer = g_new0(PinBuffer, 1);
	long page = sysconf(_SC_PAGESIZE);
	gsize size = page > 0 ? (gsize) page : 4096;

	if (posix_memalign((void**) &buffer->data, size, size) != 0)
	{
		g_free(buffer);
		return NULL;
	}

	buffer->capacity = size;
	memset(buffer->data, 0, buffer->capacity);
	buffer->locked = mlock(buffer->data, buffer->capacity) == 0;

	if (!buffer->locked && !pin_mlock_warned)
	{
		pin_mlock_warned = TRUE;
		g_message("pin-buffer-unlocked detail=mlock-failed: the PIN page could not be "
		          "pinned in memory; it is still wiped and excluded from core dumps");
	}

	/* Best effort and unchecked on purpose: an older kernel that does not know
	 * the advice simply keeps the page dumpable, which main.c has already made
	 * moot by disabling dumps outright. */
#ifdef MADV_DONTDUMP
	(void) madvise(buffer->data, buffer->capacity, MADV_DONTDUMP);
#endif

	return buffer;
}

static void pin_buffer_wipe(PinBuffer* buffer)
{
	if (buffer == NULL || buffer->data == NULL)
		return;

	explicit_bzero(buffer->data, buffer->capacity);
}

static void pin_buffer_free(PinBuffer* buffer)
{
	if (buffer == NULL)
		return;

	pin_buffer_wipe(buffer);

	if (buffer->locked)
		munlock(buffer->data, buffer->capacity);

	free(buffer->data);
	g_free(buffer);
}

static gsize pin_buffer_limit(const PinBuffer* buffer)
{
	return MIN(buffer->capacity, (gsize) PIN_BUFFER_CAPACITY);
}

static gboolean pin_buffer_set(PinBuffer* buffer, const char* text)
{
	gsize length = text != NULL ? strlen(text) : 0;

	pin_buffer_wipe(buffer);

	if (length + 1 > pin_buffer_limit(buffer))
		return FALSE;

	memcpy(buffer->data, text, length);
	buffer->data[length] = '\0';
	return TRUE;
}

/* A PRIVATE COPY FOR THE WORKER. The login task owns this one and wipes and
 * frees it itself, so that cancelling the prompt cannot pull the buffer out
 * from under a C_Login that is already in flight -- which would hand the card a
 * truncated PIN and spend an attempt on it. */
static PinBuffer* pin_buffer_dup(const PinBuffer* source)
{
	PinBuffer* copy = pin_buffer_new();

	if (copy == NULL)
		return NULL;

	if (!pin_buffer_set(copy, source->data))
	{
		pin_buffer_free(copy);
		return NULL;
	}

	return copy;
}

/* --------------------------------------------------------- the login timeout */

/* HOW LONG A SUBMITTED C_Login MAY GO UNANSWERED before the interaction is
 * given up on. Zero disables it. A wedged middleware daemon is a normal
 * Tuesday, and before this the prompt simply stayed on the screen forever with
 * a spinner in it.
 *
 * WHAT IT DOES NOT DO, and docs/SECURITY.md says the same: it does not
 * interrupt the module. PKCS#11 has no way to withdraw a C_Login, so the
 * attempt is spent whatever happens here, and the CALLER IS STILL ANSWERED ONLY
 * WHEN THE MODULE RETURNS -- answering earlier would mean freeing, on the main
 * thread, the interaction a worker thread is still reading through. What the
 * timeout buys is that the prompt comes down at a known moment, the failure has
 * a reason of its own, and a login that lands afterwards is ABANDONED rather
 * than being handed to whoever is still waiting. */
#define PIN_LOGIN_TIMEOUT_DEFAULT_SECONDS 60

static guint pin_login_timeout_seconds = PIN_LOGIN_TIMEOUT_DEFAULT_SECONDS;

void certificate_pin_set_login_timeout(guint seconds)
{
	pin_login_timeout_seconds = seconds;
}

guint certificate_pin_login_timeout(void)
{
	return pin_login_timeout_seconds;
}

/* -------------------------------------------------------------- the prompt */

/* PROMPTS ARE SERIALISED PROCESS-WIDE. Two grants must not race two PIN
 * prompts at the user: whichever arrives second waits, and a user who is asked
 * for one PIN is never looking at two prompts wondering which is real. */
static GQueue pin_queue = G_QUEUE_INIT;
static PinPrompt* pin_active = NULL;

static void pin_prompt_start(PinPrompt* prompt);

static void pin_prompt_free(PinPrompt* prompt)
{
	if (prompt->impl_data != NULL && prompt->impl_data_free != NULL)
		prompt->impl_data_free(prompt->impl_data);
	prompt->impl_data = NULL;

	pin_buffer_free(prompt->buffer_opaque);
	prompt->buffer_opaque = NULL;
	g_clear_pointer(&prompt->token, certificate_token_unref);
	g_free(prompt->parent_window);
	g_free(prompt->caller_display);
	g_free(prompt->purpose_display);
	g_clear_object(&prompt->cancellable);
	g_free(prompt);
}

static PinPrompt* pin_prompt_ref(PinPrompt* prompt)
{
	g_atomic_int_inc(&prompt->refs);
	return prompt;
}

static void pin_prompt_unref(gpointer data)
{
	PinPrompt* prompt = data;

	if (prompt == NULL)
		return;

	if (!g_atomic_int_dec_and_test(&prompt->refs))
		return;

	pin_prompt_free(prompt);
}

PinPrompt* certificate_pin_prompt_ref(PinPrompt* prompt)
{
	return pin_prompt_ref(prompt);
}

void certificate_pin_prompt_unref(PinPrompt* prompt)
{
	pin_prompt_unref(prompt);
}

/* Everything that has to happen on the main thread once the answer is known,
 * and NOT ONE STEP OF IT while a worker is still reading this object. */
void certificate_pin_prompt_answer(PinPrompt* prompt, CertificatePinOutcome outcome)
{
	CertificatePinDone done = NULL;
	gpointer user_data = NULL;
	CertificatePinAbandonFunc abandon = NULL;
	gpointer login_data = NULL;

	if (prompt->finished)
		return;

	/* A CANCEL OR A TIMEOUT WHILE C_LOGIN IS IN FLIGHT. The prompt goes away,
	 * because that is what was asked for, but the callback, the buffer free and
	 * the object free all wait for the worker: the alternative is a
	 * use-after-free across two threads on a page the token is reading a PIN
	 * out of.
	 *
	 * The card operation itself is NOT cancellable. PKCS#11 has no way to
	 * withdraw a C_Login, so the attempt that was submitted is spent whatever
	 * the user does with the prompt. */
	if (prompt->login_in_flight)
	{
		if (!prompt->cancel_deferred)
		{
			prompt->cancel_deferred = TRUE;
			prompt->deferred_outcome = outcome;

			if (prompt->impl->hide != NULL)
				prompt->impl->hide(prompt);

			certificate_log_grant(outcome == CERTIFICATE_PIN_TIMED_OUT
			                          ? CERTIFICATE_REASON_PIN_TIMEOUT
			                          : CERTIFICATE_REASON_CHOOSER_CANCELLED,
			                      NULL, "deferred-login-in-flight");
		}

		return;
	}

	prompt->finished = TRUE;
	done = prompt->done;
	user_data = prompt->user_data;
	abandon = prompt->login_succeeded && outcome != CERTIFICATE_PIN_OK ? prompt->abandon : NULL;
	login_data = prompt->login_data;

	/* THE ORDER MATTERS: disconnect first, so that no new idle can be queued
	 * behind the removal below. g_cancellable_disconnect() blocks until a
	 * handler already running on another thread has returned. */
	if (prompt->cancel_id != 0)
	{
		g_cancellable_disconnect(prompt->cancellable, prompt->cancel_id);
		prompt->cancel_id = 0;
	}

	if (prompt->cancel_idle != 0)
	{
		g_source_remove(prompt->cancel_idle);
		prompt->cancel_idle = 0;
	}

	if (prompt->login_timeout_id != 0)
	{
		g_source_remove(prompt->login_timeout_id);
		prompt->login_timeout_id = 0;
	}

	/* The buffer is wiped before anything else can run, including the caller's
	 * callback. */
	pin_buffer_wipe(prompt->buffer_opaque);

	prompt->impl->close(prompt);

	if (pin_active == prompt)
	{
		pin_active = NULL;

		if (!g_queue_is_empty(&pin_queue))
			pin_prompt_start(g_queue_pop_head(&pin_queue));
	}
	else
	{
		g_queue_remove(&pin_queue, prompt);
	}

	done(outcome, user_data);

	/* A LOGIN NOBODY IS GOING TO USE IS A LOGIN THAT HAS TO BE UNDONE. The card
	 * is slower than the Escape key: an attempt submitted before the cancel can
	 * succeed after it, and PKCS#11 has no way to withdraw one. The prompt said
	 * the request was cancelled, so the token must not be left authenticated
	 * for the rest of the grant -- the next Sign would otherwise go through
	 * with no prompt and no consent. Called AFTER done(), so that the caller
	 * has already answered its waiters and this sees the settled state. */
	if (abandon != NULL)
	{
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL, "abandoning-cancelled-login");
		abandon(login_data);
	}

	/* The creation reference. Any worker or queued idle still holding one keeps
	 * the object alive until it drops it. */
	pin_prompt_unref(prompt);
}

typedef struct
{
	PinPrompt* prompt; /* a reference the task owns */
	PinBuffer* buffer; /* a PRIVATE COPY the task owns and wipes */
	gboolean protected_path;
} LoginTask;

static void login_task_free(gpointer data)
{
	LoginTask* task = data;

	g_clear_pointer(&task->buffer, pin_buffer_free);
	g_clear_pointer(&task->prompt, pin_prompt_unref);
	g_free(task);
}

static void login_thread(GTask* task, gpointer source, gpointer task_data,
                         GCancellable* cancellable)
{
	LoginTask* data = task_data;
	g_autoptr(GError) error = NULL;
	const char* pin = data->protected_path || data->buffer == NULL ? NULL : data->buffer->data;

	/* C_Login on a card takes hundreds of milliseconds and can block for as
	 * long as the middleware wants. It never runs on the main thread. */
	if (data->prompt->login(pin, data->prompt->login_data, &error))
	{
		g_task_return_boolean(task, TRUE);
		return;
	}

	/* THE FLAGS ARE RE-READ HERE, on this thread, while the failure is fresh:
	 * CKF_USER_PIN_FINAL_TRY is normally set BY the attempt that just failed,
	 * and a prompt that keeps showing the flags captured at discovery will
	 * never warn anybody. */
	if (data->prompt->refresh != NULL &&
	    g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
		data->prompt->refresh(data->prompt->token, data->prompt->login_data);

	g_task_return_error(task, g_steal_pointer(&error));
}

static void set_busy(PinPrompt* prompt, gboolean busy)
{
	prompt->busy = busy;

	if (prompt->impl->busy != NULL)
		prompt->impl->busy(prompt, busy);
}

/* The remaining-attempts hint, and NOTHING ELSE. PKCS#11 has no portable way to
 * ask a token how many tries are left, so this reports only the three flags the
 * standard defines, and never a number. A wrong count is worse than none. */
const char* certificate_pin_prompt_retry_hint(const PinPrompt* prompt)
{
	if (prompt->token->pin_locked)
		return "This token is locked. It cannot be unlocked here.";
	if (prompt->token->pin_final_try)
		return "This is the last attempt before the token locks.";
	if (prompt->token->pin_count_low)
		return "There have been recent failed attempts on this token.";

	return NULL;
}

const char* certificate_pin_prompt_final_try_warning(void)
{
	return "This is the LAST attempt before the token locks. Confirm to use it, or Cancel.";
}

const char* certificate_pin_prompt_heading(const PinPrompt* prompt)
{
	return prompt->protected_path ? "Enter your PIN on the reader"
	                              : "Enter your PIN to unlock this token";
}

const char* certificate_pin_prompt_protected_note(void)
{
	return "This reader collects the PIN itself. Follow the instructions on the reader; "
	       "nothing typed on screen is sent to the token.";
}

gboolean certificate_pin_prompt_needs_final_confirm(PinPrompt* prompt)
{
	/* THE LAST ATTEMPT IS NOT SPENT ON A SINGLE PRESS. When the token says
	 * CKF_USER_PIN_FINAL_TRY, the next refusal locks the card, so the prompt
	 * says so and requires the user to ask a second time. */
	if (!prompt->token->pin_final_try || prompt->final_try_confirmed)
		return FALSE;

	prompt->final_try_confirmed = TRUE;
	return TRUE;
}

static void on_login_done(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	g_autoptr(GError) error = NULL;
	gboolean ok = g_task_propagate_boolean(G_TASK(result), &error);

	prompt->login_in_flight = FALSE;

	if (prompt->login_timeout_id != 0)
	{
		g_source_remove(prompt->login_timeout_id);
		prompt->login_timeout_id = 0;
	}

	if (ok)
		prompt->login_succeeded = TRUE;

	/* The prompt was closed, Escape was pressed, Close() arrived, or the login
	 * timeout ran out while the card was busy. The answer that was asked for is
	 * given now that nothing is reading the buffer any more. */
	if (prompt->cancel_deferred)
	{
		prompt->cancel_deferred = FALSE;

		if (ok)
			certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL,
			                      prompt->deferred_outcome == CERTIFICATE_PIN_TIMED_OUT
			                          ? "login-landed-after-timeout"
			                          : "cancelled-after-login");

		certificate_pin_prompt_answer(prompt, prompt->deferred_outcome);
		return;
	}

	if (prompt->finished)
		return;

	if (ok)
	{
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL, "pin-accepted");
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_OK);
		return;
	}

	set_busy(prompt, FALSE);

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, NULL, "retry-offered");

		/* The flags were re-read on the worker thread after the refusal, so the
		 * warning the implementation is about to draw is about the state the
		 * token is in NOW. */
		prompt->final_try_confirmed = FALSE;

		if (prompt->token->pin_locked)
		{
			certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, NULL, "terminal");
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_LOCKED);
			return;
		}

		if (prompt->protected_path)
		{
			/* A protected authentication path cannot be retried from here: the
			 * reader owns the interaction. */
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		/* THE PROMPT DOES NOT OFFER UNBOUNDED RETRIES. Three refused attempts
		 * is where it stops asking; the caller can ask again, which makes a new
		 * decision rather than a habit. */
		if (prompt->attempts >= PIN_MAX_ATTEMPTS)
		{
			certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, NULL, "attempt-cap");
			certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		/* RETRIES ARE USER-INITIATED. The implementation asks again with the
		 * field cleared; nothing here spends another attempt on its own. */
		pin_buffer_wipe(prompt->buffer_opaque);
		prompt->impl->retry(prompt, "That PIN was not accepted. Try again.");
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_LOCKED))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, NULL, "terminal");
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_LOCKED);
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
	{
		certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_TOKEN_REMOVED);
		return;
	}

	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
}

static gboolean on_login_timeout(gpointer user_data)
{
	PinPrompt* prompt = user_data;

	prompt->login_timeout_id = 0;

	if (!prompt->login_in_flight)
		return G_SOURCE_REMOVE;

	certificate_log_grant(CERTIFICATE_REASON_PIN_TIMEOUT, NULL, "login-did-not-return");
	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_TIMED_OUT);
	return G_SOURCE_REMOVE;
}

gboolean certificate_pin_prompt_hold(PinPrompt* prompt, const char* pin)
{
	if (prompt->finished || prompt->login_in_flight)
		return FALSE;

	if (!pin_buffer_set(prompt->buffer_opaque, pin))
	{
		prompt->impl->retry(prompt, "That is longer than any PIN this backend will send.");
		return FALSE;
	}

	return TRUE;
}

void certificate_pin_prompt_submit(PinPrompt* prompt)
{
	g_autoptr(GTask) task = NULL;
	LoginTask* data = NULL;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	data = g_new0(LoginTask, 1);
	data->prompt = pin_prompt_ref(prompt);
	data->protected_path = prompt->protected_path;

	if (!prompt->protected_path)
	{
		data->buffer = pin_buffer_dup(prompt->buffer_opaque);

		if (data->buffer == NULL)
		{
			login_task_free(data);
			prompt->impl->retry(prompt, "The PIN could not be held in locked memory.");
			return;
		}
	}

	/* From here the PIN is in the task's own page and nowhere else this module
	 * owns. */
	pin_buffer_wipe(prompt->buffer_opaque);

	prompt->attempts++;
	prompt->login_in_flight = TRUE;
	set_busy(prompt, TRUE);

	if (pin_login_timeout_seconds > 0)
		prompt->login_timeout_id =
		    g_timeout_add_seconds(pin_login_timeout_seconds, on_login_timeout, prompt);

	task = g_task_new(NULL, NULL, on_login_done, prompt);
	g_task_set_task_data(task, data, login_task_free);
	g_task_run_in_thread(task, login_thread);
}

static gboolean on_cancelled_idle(gpointer user_data)
{
	PinPrompt* prompt = user_data;

	prompt->cancel_idle = 0;
	certificate_pin_prompt_answer(prompt, CERTIFICATE_PIN_CANCELLED);
	return G_SOURCE_REMOVE;
}

static void on_cancelled(GCancellable* cancellable, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	/* A cancellation is delivered on whatever thread called
	 * g_cancellable_cancel(). Today that is always the main thread -- no
	 * skeleton in this backend sets
	 * G_DBUS_INTERFACE_SKELETON_FLAGS_HANDLE_METHOD_INVOCATIONS_IN_THREAD, so
	 * every Close() handler runs on the main context -- and this function is
	 * written not to depend on that: it touches no widget and queues an idle.
	 * g_cancellable_disconnect() in certificate_pin_prompt_answer() blocks
	 * until this returns, so the prompt is alive here, and the idle takes its
	 * own reference because the object may be finished and freed before the
	 * idle is dispatched. */
	if (prompt->cancel_idle != 0)
		return;

	prompt->cancel_idle = g_idle_add_full(G_PRIORITY_DEFAULT, on_cancelled_idle,
	                                      pin_prompt_ref(prompt), pin_prompt_unref);
}

static void pin_prompt_start(PinPrompt* prompt)
{
	pin_active = prompt;

	certificate_log_grant(CERTIFICATE_REASON_PIN_PROMPTED, NULL,
	                      prompt->protected_path ? "protected-path" : "on-screen");

	prompt->impl->start(prompt);
}

void certificate_pin_login(CertificateToken* token, const char* parent_window,
                           const char* caller_display, const char* purpose_display,
                           CertificatePinLoginFunc login, CertificatePinRefreshFunc refresh,
                           CertificatePinAbandonFunc abandon, gpointer login_data,
                           GCancellable* cancellable, CertificatePinDone done,
                           gpointer user_data)
{
	PinPrompt* prompt = NULL;
	const PinPromptImpl* impl = pin_impl();

	/* NEVER READ A PIN FROM STDIN. With no display there is no way for THIS
	 * process to ask, and inventing one would be a trusted prompt nobody can
	 * see. The system prompter is the exception that proves the rule: the
	 * window is the shell's, so this process needs no display of its own -- and
	 * the shell is still a graphical session, which is why the answer is
	 * "no_display" rather than "headless works now". */
	if (impl->needs_display && !certificate_ui_has_display())
	{
		done(CERTIFICATE_PIN_NO_DISPLAY, user_data);
		return;
	}

	if (token->pin_locked)
	{
		done(CERTIFICATE_PIN_LOCKED, user_data);
		return;
	}

	prompt = g_new0(PinPrompt, 1);
	prompt->refs = 1;
	prompt->impl = impl;
	prompt->token = certificate_token_ref(token);
	prompt->protected_path = token->protected_authentication_path;
	prompt->parent_window = g_strdup(parent_window);
	prompt->caller_display = g_strdup(caller_display);
	prompt->purpose_display = g_strdup(purpose_display);
	prompt->login = login;
	prompt->refresh = refresh;
	prompt->abandon = abandon;
	prompt->login_data = login_data;
	prompt->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;
	prompt->done = done;
	prompt->user_data = user_data;
	prompt->buffer_opaque = pin_buffer_new();

	if (prompt->buffer_opaque == NULL)
	{
		pin_prompt_unref(prompt);
		done(CERTIFICATE_PIN_DEVICE_ERROR, user_data);
		return;
	}

	if (prompt->cancellable != NULL)
		prompt->cancel_id =
		    g_cancellable_connect(prompt->cancellable, G_CALLBACK(on_cancelled), prompt, NULL);

	if (pin_active != NULL)
	{
		g_queue_push_tail(&pin_queue, prompt);
		return;
	}

	pin_prompt_start(prompt);
}
