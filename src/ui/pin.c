/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

/* explicit_bzero(), posix_memalign(), mlock(), madvise(): the PIN buffer needs
 * all four. */
#define _GNU_SOURCE 1

#include "pin.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <adwaita.h>
#include <gtk/gtk.h>

#include "../certificate.h"
#include "../redact.h"
#include "external-window.h"

static gboolean ui_has_display = FALSE;

void certificate_ui_set_has_display(gboolean has_display)
{
	ui_has_display = has_display;
}

gboolean certificate_ui_has_display(void)
{
	return ui_has_display;
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

/* Attempts one window may spend before it gives up and hands the outcome back
 * to the caller. A PIN prompt that offers unbounded retries is a window in
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
 * frees it itself, so that cancelling the window cannot pull the buffer out
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

/* -------------------------------------------------------------- the prompt */

typedef struct
{
	int refs;

	CertificateToken* token;
	char* parent_window;
	char* caller_display;
	char* purpose_display;

	CertificatePinLoginFunc login;
	CertificatePinRefreshFunc refresh;
	gpointer login_data;
	GCancellable* cancellable;
	gulong cancel_id;
	CertificatePinDone done;
	gpointer user_data;

	GtkWindow* window;
	GtkWidget* entry;
	GtkWidget* unlock_button;
	GtkWidget* status;
	GtkWidget* hint;
	GtkWidget* spinner;

	PinBuffer* buffer;
	gboolean finished;
	gboolean busy;

	/* THE CANCEL-WHILE-BUSY STATE. login_in_flight is true from the moment the
	 * worker is started until its completion callback runs on the main thread.
	 * A cancel arriving in that window hides the window immediately and records
	 * what to answer, and nothing at all is freed until the worker has
	 * returned. */
	gboolean login_in_flight;
	gboolean cancel_deferred;
	CertificatePinOutcome deferred_outcome;

	guint cancel_idle;
	guint attempts;
	gboolean final_try_confirmed;
} PinPrompt;

/* PROMPTS ARE SERIALISED PROCESS-WIDE. Two grants must not race two PIN windows
 * at the user: whichever arrives second waits, and a user who is asked for one
 * PIN is never looking at two windows wondering which is real. */
static GQueue pin_queue = G_QUEUE_INIT;
static PinPrompt* pin_active = NULL;

static void pin_prompt_start(PinPrompt* prompt);

static void pin_prompt_free(PinPrompt* prompt)
{
	g_clear_pointer(&prompt->buffer, pin_buffer_free);
	g_clear_pointer(&prompt->token, certificate_token_unref);
	g_free(prompt->parent_window);
	g_free(prompt->caller_display);
	g_free(prompt->purpose_display);
	g_clear_object(&prompt->cancellable);
	g_free(prompt);
}

static PinPrompt* pin_prompt_ref(PinPrompt* prompt)
{
	prompt->refs++;
	return prompt;
}

static void pin_prompt_unref(gpointer data)
{
	PinPrompt* prompt = data;

	if (prompt == NULL)
		return;

	if (--prompt->refs > 0)
		return;

	pin_prompt_free(prompt);
}

/* Everything that has to happen on the main thread once the answer is known,
 * and NOT ONE STEP OF IT while a worker is still reading this object. */
static void pin_prompt_finish(PinPrompt* prompt, CertificatePinOutcome outcome)
{
	CertificatePinDone done = NULL;
	gpointer user_data = NULL;

	if (prompt->finished)
		return;

	/* A CANCEL WHILE C_LOGIN IS IN FLIGHT. The window goes away, because that
	 * is what the user asked for, but the callback, the buffer free and the
	 * object free all wait for the worker: the alternative is a use-after-free
	 * across two threads on a page the token is reading a PIN out of.
	 *
	 * The card operation itself is NOT cancellable. PKCS#11 has no way to
	 * withdraw a C_Login, so the attempt that was submitted is spent whatever
	 * the user does with the window. */
	if (prompt->login_in_flight)
	{
		if (!prompt->cancel_deferred)
		{
			prompt->cancel_deferred = TRUE;
			prompt->deferred_outcome = outcome;

			if (prompt->window != NULL)
				gtk_widget_set_visible(GTK_WIDGET(prompt->window), FALSE);

			certificate_log_grant(CERTIFICATE_REASON_CHOOSER_CANCELLED, NULL,
			                      "cancel-deferred-login-in-flight");
		}

		return;
	}

	prompt->finished = TRUE;
	done = prompt->done;
	user_data = prompt->user_data;

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

	/* The buffer is wiped before anything else can run, including the caller's
	 * callback. */
	if (prompt->buffer != NULL)
		pin_buffer_wipe(prompt->buffer);

	/* Disconnected before the destroy, for the same reason the chooser does it:
	 * tearing a window down emits signals at a point where the widgets those
	 * handlers touch have already been disposed. */
	if (prompt->entry != NULL)
		g_signal_handlers_disconnect_by_data(prompt->entry, prompt);
	if (prompt->window != NULL)
		g_signal_handlers_disconnect_by_data(prompt->window, prompt);

	if (prompt->window != NULL)
	{
		gtk_window_destroy(prompt->window);
		prompt->window = NULL;
	}

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
	 * and a window that keeps showing the flags captured at discovery will
	 * never warn anybody. */
	if (data->prompt->refresh != NULL &&
	    g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
		data->prompt->refresh(data->prompt->token, data->prompt->login_data);

	g_task_return_error(task, g_steal_pointer(&error));
}

static void set_status(PinPrompt* prompt, const char* text, gboolean is_error)
{
	if (prompt->status == NULL)
		return;

	gtk_label_set_text(GTK_LABEL(prompt->status), text != NULL ? text : "");
	gtk_widget_set_visible(prompt->status, text != NULL && *text != '\0');

	if (is_error)
	{
		gtk_widget_add_css_class(prompt->status, "error");
		/* The failure state IS announced: a screen-reader user must learn that
		 * an attempt was spent. The PIN itself never enters this tree. */
		if (prompt->window != NULL)
			gtk_accessible_announce(GTK_ACCESSIBLE(prompt->window), text,
			                        GTK_ACCESSIBLE_ANNOUNCEMENT_PRIORITY_HIGH);
	}
	else
	{
		gtk_widget_remove_css_class(prompt->status, "error");
	}
}

static void set_busy(PinPrompt* prompt, gboolean busy)
{
	prompt->busy = busy;

	if (prompt->entry != NULL)
		gtk_widget_set_sensitive(prompt->entry, !busy);
	if (prompt->unlock_button != NULL)
		gtk_widget_set_sensitive(prompt->unlock_button, !busy);
	if (prompt->spinner != NULL)
		gtk_widget_set_visible(prompt->spinner, busy);
}

/* The remaining-attempts hint, and NOTHING ELSE. PKCS#11 has no portable way to
 * ask a token how many tries are left, so this reports only the three flags the
 * standard defines, and never a number. A wrong count is worse than none. */
static const char* retry_hint(const CertificateToken* token)
{
	if (token->pin_locked)
		return "This token is locked. It cannot be unlocked here.";
	if (token->pin_final_try)
		return "This is the last attempt before the token locks.";
	if (token->pin_count_low)
		return "There have been recent failed attempts on this token.";

	return NULL;
}

static void update_retry_hint(PinPrompt* prompt)
{
	const char* hint = retry_hint(prompt->token);

	if (prompt->hint == NULL)
		return;

	gtk_label_set_text(GTK_LABEL(prompt->hint), hint != NULL ? hint : "");
	gtk_widget_set_visible(prompt->hint, hint != NULL);
}

static void on_login_done(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	g_autoptr(GError) error = NULL;
	gboolean ok = g_task_propagate_boolean(G_TASK(result), &error);

	prompt->login_in_flight = FALSE;

	/* The window was closed, Escape was pressed, or Close() arrived while the
	 * card was busy. The answer the user asked for is given now that nothing is
	 * reading the buffer any more. */
	if (prompt->cancel_deferred)
	{
		prompt->cancel_deferred = FALSE;

		if (ok)
			certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL, "cancelled-after-login");

		pin_prompt_finish(prompt, prompt->deferred_outcome);
		return;
	}

	if (prompt->finished)
		return;

	if (ok)
	{
		certificate_log_grant(CERTIFICATE_REASON_LOGIN_OK, NULL, "pin-accepted");
		pin_prompt_finish(prompt, CERTIFICATE_PIN_OK);
		return;
	}

	set_busy(prompt, FALSE);

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, NULL, "retry-offered");

		/* The flags were re-read on the worker thread after the refusal, so the
		 * warning below is about the state the token is in NOW. */
		update_retry_hint(prompt);
		prompt->final_try_confirmed = FALSE;

		if (prompt->token->pin_locked)
		{
			certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, NULL, "terminal");
			pin_prompt_finish(prompt, CERTIFICATE_PIN_LOCKED);
			return;
		}

		if (prompt->entry == NULL)
		{
			/* A protected authentication path cannot be retried from here: the
			 * reader owns the interaction. */
			pin_prompt_finish(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		/* THE PROMPT DOES NOT OFFER UNBOUNDED RETRIES. Three refused attempts
		 * is where this window stops asking; the caller can ask again, which
		 * makes a new decision rather than a habit. */
		if (prompt->attempts >= PIN_MAX_ATTEMPTS)
		{
			certificate_log_grant(CERTIFICATE_REASON_PIN_INCORRECT, NULL, "attempt-cap");
			pin_prompt_finish(prompt, CERTIFICATE_PIN_INCORRECT);
			return;
		}

		/* RETRIES ARE USER-INITIATED. The window stays up with the field
		 * cleared; nothing here spends another attempt on its own. */
		pin_buffer_wipe(prompt->buffer);
		gtk_editable_set_text(GTK_EDITABLE(prompt->entry), "");
		set_status(prompt, "That PIN was not accepted. Try again.", TRUE);
		gtk_widget_grab_focus(prompt->entry);
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_LOCKED))
	{
		certificate_log_grant(CERTIFICATE_REASON_PIN_LOCKED, NULL, "terminal");
		pin_prompt_finish(prompt, CERTIFICATE_PIN_LOCKED);
		return;
	}

	if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
	{
		pin_prompt_finish(prompt, CERTIFICATE_PIN_TOKEN_REMOVED);
		return;
	}

	pin_prompt_finish(prompt, CERTIFICATE_PIN_DEVICE_ERROR);
}

static void run_login(PinPrompt* prompt, gboolean protected_path)
{
	g_autoptr(GTask) task = NULL;
	LoginTask* data = g_new0(LoginTask, 1);

	data->prompt = pin_prompt_ref(prompt);
	data->protected_path = protected_path;

	if (!protected_path)
	{
		data->buffer = pin_buffer_dup(prompt->buffer);

		if (data->buffer == NULL)
		{
			login_task_free(data);
			set_status(prompt, "The PIN could not be held in locked memory.", TRUE);
			return;
		}

		/* From here the PIN is in the task's own page and nowhere else this
		 * module owns. GTK's GtkPasswordEntry keeps its own copy in the
		 * secure-memory buffer it allocates; see the comment in on_unlock(). */
		pin_buffer_wipe(prompt->buffer);
	}

	prompt->attempts++;
	prompt->login_in_flight = TRUE;
	set_busy(prompt, TRUE);

	task = g_task_new(NULL, NULL, on_login_done, prompt);
	g_task_set_task_data(task, data, login_task_free);
	g_task_run_in_thread(task, login_thread);
}

static void on_unlock(GtkWidget* widget, gpointer user_data)
{
	PinPrompt* prompt = user_data;
	const char* text = NULL;

	if (prompt->busy || prompt->finished || prompt->login_in_flight)
		return;

	text = gtk_editable_get_text(GTK_EDITABLE(prompt->entry));
	if (text == NULL || *text == '\0')
	{
		set_status(prompt, "Enter the PIN for this token.", FALSE);
		return;
	}

	/* THE LAST ATTEMPT IS NOT SPENT ON A SINGLE CLICK. When the token says
	 * CKF_USER_PIN_FINAL_TRY, the next refusal locks the card, so the window
	 * says so and requires the user to ask a second time. */
	if (prompt->token->pin_final_try && !prompt->final_try_confirmed)
	{
		prompt->final_try_confirmed = TRUE;
		set_status(prompt,
		           "This is the LAST attempt before the token locks. Press Unlock again to "
		           "use it, or Cancel.",
		           TRUE);
		return;
	}

	if (!pin_buffer_set(prompt->buffer, text))
	{
		set_status(prompt, "That is longer than any PIN this backend will send.", TRUE);
		return;
	}

	/* The entry is cleared the moment the value is in the locked buffer. GTK's
	 * own storage is a GtkPasswordEntryBuffer, which GTK allocates from its
	 * secure-memory pool and zeroes when it frees it -- but GTK guarantees
	 * nothing about the intermediate copies a text widget, an input method or a
	 * Pango layout may have made, so this backend does not claim the PIN
	 * existed in exactly one place. It claims what is true: THIS module holds
	 * it in one wiped, locked, non-dumpable page. */
	gtk_editable_set_text(GTK_EDITABLE(prompt->entry), "");
	set_status(prompt, NULL, FALSE);

	run_login(prompt, FALSE);
}

static void on_cancel(GtkWidget* widget, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
}

static gboolean on_close_request(GtkWindow* window, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
	return TRUE;
}

static gboolean on_key_pressed(GtkEventControllerKey* controller, guint keyval, guint keycode,
                               GdkModifierType state, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	if (keyval == GDK_KEY_Escape)
	{
		pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
		return GDK_EVENT_STOP;
	}

	return GDK_EVENT_PROPAGATE;
}

static gboolean on_cancelled_idle(gpointer user_data)
{
	PinPrompt* prompt = user_data;

	prompt->cancel_idle = 0;
	pin_prompt_finish(prompt, CERTIFICATE_PIN_CANCELLED);
	return G_SOURCE_REMOVE;
}

static void on_cancelled(GCancellable* cancellable, gpointer user_data)
{
	PinPrompt* prompt = user_data;

	/* Close() can arrive on any thread GDBus feels like; the window is only
	 * ever touched from the main context. g_cancellable_disconnect() in
	 * pin_prompt_finish() blocks until this returns, so the prompt is alive
	 * here -- and the idle takes its own reference, because the object may be
	 * finished and freed before the idle is dispatched. */
	if (prompt->cancel_idle != 0)
		return;

	prompt->cancel_idle = g_idle_add_full(G_PRIORITY_DEFAULT, on_cancelled_idle,
	                                      pin_prompt_ref(prompt), pin_prompt_unref);
}

static GtkWidget* label_row(const char* title, const char* value)
{
	GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget* name = gtk_label_new(title);
	GtkWidget* text = gtk_label_new(value);

	gtk_widget_add_css_class(name, "dim-label");
	gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
	gtk_label_set_xalign(GTK_LABEL(text), 0.0f);
	gtk_label_set_wrap(GTK_LABEL(text), TRUE);
	gtk_label_set_selectable(GTK_LABEL(text), FALSE);
	gtk_widget_set_hexpand(text, TRUE);
	gtk_widget_set_size_request(name, 110, -1);

	gtk_box_append(GTK_BOX(box), name);
	gtk_box_append(GTK_BOX(box), text);

	return box;
}

static void pin_prompt_start(PinPrompt* prompt)
{
	GtkWidget* window = NULL;
	GtkWidget* toolbar = NULL;
	GtkWidget* header = NULL;
	GtkWidget* content = NULL;
	GtkWidget* buttons = NULL;
	GtkWidget* cancel = NULL;
	GtkEventController* keys = NULL;
	gboolean protected_path = prompt->token->protected_authentication_path;

	pin_active = prompt;

	window = adw_window_new();
	prompt->window = GTK_WINDOW(window);
	gtk_window_set_title(GTK_WINDOW(window), "Unlock Security Token");
	gtk_window_set_modal(GTK_WINDOW(window), TRUE);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_window_set_default_size(GTK_WINDOW(window), 440, -1);

	header = adw_header_bar_new();
	adw_header_bar_set_show_end_title_buttons(ADW_HEADER_BAR(header), FALSE);

	content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
	gtk_widget_set_margin_top(content, 18);
	gtk_widget_set_margin_bottom(content, 18);
	gtk_widget_set_margin_start(content, 18);
	gtk_widget_set_margin_end(content, 18);

	{
		GtkWidget* heading = gtk_label_new(protected_path
		                                       ? "Enter your PIN on the reader"
		                                       : "Enter your PIN to unlock this token");

		gtk_label_set_wrap(GTK_LABEL(heading), TRUE);
		gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
		gtk_widget_add_css_class(heading, "title-2");
		gtk_box_append(GTK_BOX(content), heading);
	}

	/* The window restates the verified caller and the purpose from the chooser,
	 * so that a PIN prompt arriving on its own is still attributable. EVERY
	 * VALUE BELOW IS SANITISED AND CAPPED: the caller display comes from a
	 * desktop file and the token label and reader name come off the card, and
	 * none of the three may draw chrome of its own inside this window. */
	{
		g_autofree char* caller = certificate_display_text(prompt->caller_display,
		                                                   CERTIFICATE_DISPLAY_MAX_APP_NAME, NULL);
		g_autofree char* purpose = certificate_display_text(prompt->purpose_display,
		                                                    CERTIFICATE_DISPLAY_MAX_PURPOSE, NULL);
		g_autofree char* label = certificate_display_text(
		    prompt->token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "Unnamed token");
		g_autofree char* reader = certificate_display_text(prompt->token->reader_name,
		                                                   CERTIFICATE_DISPLAY_MAX_READER, NULL);

		if (caller != NULL)
			gtk_box_append(GTK_BOX(content), label_row("Application", caller));
		if (purpose != NULL)
			gtk_box_append(GTK_BOX(content), label_row("In order to", purpose));
		gtk_box_append(GTK_BOX(content), label_row("Token", label));
		if (reader != NULL)
			gtk_box_append(GTK_BOX(content), label_row("Reader", reader));
	}

	if (!protected_path)
	{
		prompt->entry = gtk_password_entry_new();
		gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(prompt->entry), FALSE);
		gtk_widget_set_hexpand(prompt->entry, TRUE);
		gtk_accessible_update_property(GTK_ACCESSIBLE(prompt->entry),
		                               GTK_ACCESSIBLE_PROPERTY_LABEL, "Token PIN", -1);
		g_signal_connect(prompt->entry, "activate", G_CALLBACK(on_unlock), prompt);
		gtk_box_append(GTK_BOX(content), prompt->entry);
	}
	else
	{
		GtkWidget* note = gtk_label_new(
		    "This reader collects the PIN itself. Follow the instructions on the reader; "
		    "nothing you type here is sent to the token.");

		gtk_label_set_wrap(GTK_LABEL(note), TRUE);
		gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
		gtk_widget_add_css_class(note, "dim-label");
		gtk_box_append(GTK_BOX(content), note);
	}

	prompt->status = gtk_label_new(NULL);
	gtk_label_set_wrap(GTK_LABEL(prompt->status), TRUE);
	gtk_label_set_xalign(GTK_LABEL(prompt->status), 0.0f);
	gtk_widget_set_visible(prompt->status, FALSE);
	gtk_box_append(GTK_BOX(content), prompt->status);

	/* Created whether or not there is a hint to show right now: the flags are
	 * re-read after every refusal, and a warning that only exists if it was
	 * needed at window-open time is a warning that arrives too late. */
	prompt->hint = gtk_label_new(NULL);
	gtk_label_set_wrap(GTK_LABEL(prompt->hint), TRUE);
	gtk_label_set_xalign(GTK_LABEL(prompt->hint), 0.0f);
	gtk_widget_add_css_class(prompt->hint, "warning");
	gtk_box_append(GTK_BOX(content), prompt->hint);
	update_retry_hint(prompt);

	prompt->spinner = gtk_spinner_new();
	gtk_spinner_set_spinning(GTK_SPINNER(prompt->spinner), TRUE);
	gtk_widget_set_visible(prompt->spinner, FALSE);
	gtk_widget_set_halign(prompt->spinner, GTK_ALIGN_CENTER);
	gtk_box_append(GTK_BOX(content), prompt->spinner);

	buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign(buttons, GTK_ALIGN_END);

	cancel = gtk_button_new_with_mnemonic("_Cancel");
	g_signal_connect(cancel, "clicked", G_CALLBACK(on_cancel), prompt);
	gtk_box_append(GTK_BOX(buttons), cancel);

	if (!protected_path)
	{
		prompt->unlock_button = gtk_button_new_with_mnemonic("_Unlock");
		gtk_widget_add_css_class(prompt->unlock_button, "suggested-action");
		g_signal_connect(prompt->unlock_button, "clicked", G_CALLBACK(on_unlock), prompt);
		gtk_box_append(GTK_BOX(buttons), prompt->unlock_button);
	}

	gtk_box_append(GTK_BOX(content), buttons);

	toolbar = adw_toolbar_view_new();
	adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
	adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), content);
	adw_window_set_content(ADW_WINDOW(window), toolbar);

	keys = gtk_event_controller_key_new();
	g_signal_connect(keys, "key-pressed", G_CALLBACK(on_key_pressed), prompt);
	gtk_widget_add_controller(window, keys);

	g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), prompt);

	certificate_log_grant(CERTIFICATE_REASON_PIN_PROMPTED, NULL,
	                      protected_path ? "protected-path" : "on-screen");

	certificate_external_window_present(GTK_WINDOW(window), prompt->parent_window, NULL);

	if (prompt->entry != NULL)
		gtk_widget_grab_focus(prompt->entry);
	else
		run_login(prompt, TRUE);
}

void certificate_pin_login(CertificateToken* token, const char* parent_window,
                           const char* caller_display, const char* purpose_display,
                           CertificatePinLoginFunc login, CertificatePinRefreshFunc refresh,
                           gpointer login_data, GCancellable* cancellable, CertificatePinDone done,
                           gpointer user_data)
{
	PinPrompt* prompt = NULL;

	if (!certificate_ui_has_display())
	{
		/* NEVER READ A PIN FROM STDIN. With no display there is no way to ask,
		 * and inventing one would be a trusted prompt nobody can see. */
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
	prompt->token = certificate_token_ref(token);
	prompt->parent_window = g_strdup(parent_window);
	prompt->caller_display = g_strdup(caller_display);
	prompt->purpose_display = g_strdup(purpose_display);
	prompt->login = login;
	prompt->refresh = refresh;
	prompt->login_data = login_data;
	prompt->cancellable = cancellable != NULL ? g_object_ref(cancellable) : NULL;
	prompt->done = done;
	prompt->user_data = user_data;
	prompt->buffer = pin_buffer_new();

	if (prompt->buffer == NULL)
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
