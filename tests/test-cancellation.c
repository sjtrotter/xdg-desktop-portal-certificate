/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * CANCELLING WHILE THE CARD IS BUSY. This is the regression test for the worst
 * bug the 2026 review found: cancelling the PIN window while C_Login was in
 * flight wiped and freed the buffer the worker was passing to the token, freed
 * the prompt the worker was reading its callbacks out of, and freed the
 * operation the login was being performed for -- across two threads, on a page
 * that had just been munlock()ed.
 *
 * The consequence was not only a crash. A torn buffer means the card is handed
 * a truncated PIN, which SPENDS AN ATTEMPT, and the callback that would have
 * said so ran on freed memory. On a PIV card that is one of three.
 *
 * RUN IT UNDER ASAN. `meson setup build-asan -Db_sanitize=address,undefined`
 * and `meson test -C build-asan`: without a sanitizer these tests pass on a
 * lucky allocator. docs/TESTING.md has the invocation.
 *
 * The login half needs a display (it opens the real window); the sign half
 * needs a SoftHSM fixture. Each skips itself when it cannot run.
 */

#include <glib.h>
#include <gtk/gtk.h>

#include "broker/device.h"
#include "broker/operations.h"
#include "session-impl.h"
#include "ui/pin.h"

#define FIXTURE_PIN "123456"

/* ------------------------------------------------------- cancel during login */

typedef struct
{
	GMutex lock;
	GCond cond;
	gboolean login_entered;
	gboolean login_may_return;

	guint done_calls;
	CertificatePinOutcome outcome;
	gboolean login_returned_before_done;
	gboolean login_finished;

	CertificateToken* token;
} LoginProbe;

/* Stands in for C_Login: blocks until the test lets it go, exactly as a card
 * does for the hundreds of milliseconds that matter. */
static gboolean probe_login(const char* pin, gpointer user_data, GError** error)
{
	LoginProbe* probe = user_data;

	g_mutex_lock(&probe->lock);
	probe->login_entered = TRUE;
	g_cond_broadcast(&probe->cond);

	while (!probe->login_may_return)
		g_cond_wait(&probe->cond, &probe->lock);

	/* THE BUFFER MUST STILL BE THERE. Reading it after the window was
	 * cancelled is precisely what used to be a use-after-free, and what handed
	 * the card a zero-length PIN. */
	g_assert_nonnull(pin);
	g_assert_cmpstr(pin, ==, "1234");

	probe->login_finished = TRUE;
	g_mutex_unlock(&probe->lock);

	g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT,
	                    "not accepted");
	return FALSE;
}

static void probe_done(CertificatePinOutcome outcome, gpointer user_data)
{
	LoginProbe* probe = user_data;

	g_mutex_lock(&probe->lock);
	probe->done_calls++;
	probe->outcome = outcome;
	probe->login_returned_before_done = probe->login_finished;
	g_mutex_unlock(&probe->lock);
}

static CertificateToken* make_token(void)
{
	/* CertificateToken has no public constructor: it is only ever produced from
	 * a slot, which is why the struct is in the header and why building one by
	 * hand is legitimate here and nowhere else. */
	CertificateToken* token = g_new0(CertificateToken, 1);

	g_atomic_ref_count_init(&token->ref_count);
	token->label = g_strdup("Cancellation Test Token");
	token->manufacturer = g_strdup("Test");
	token->model = g_strdup("Test");
	token->serial = g_strdup("0123456789abcdef");
	token->reader_name = g_strdup("Test reader");
	token->login_required = TRUE;

	return token;
}

static gboolean quit_loop(gpointer user_data)
{
	g_main_loop_quit(user_data);
	return G_SOURCE_REMOVE;
}

static GtkWidget* find_pin_entry(void);
static gboolean pin_window_is_up(void);

static void iterate_for(guint milliseconds)
{
	g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);

	g_timeout_add(milliseconds, quit_loop, loop);
	g_main_loop_run(loop);
}

static void test_cancel_during_login(void)
{
	LoginProbe probe = { 0 };
	g_autoptr(GCancellable) cancellable = g_cancellable_new();
	gint64 deadline;

	if (!gtk_init_check())
	{
		g_test_skip("no display: the PIN window cannot be opened");
		return;
	}

	certificate_ui_set_has_display(TRUE);

	g_mutex_init(&probe.lock);
	g_cond_init(&probe.cond);
	probe.token = make_token();

	certificate_pin_login(probe.token, NULL, "Test application", "prove who you are", probe_login,
	                      NULL, NULL, &probe, cancellable, probe_done, &probe);

	/* Type a PIN and press Unlock, the way ui-smoke.sh does with xdotool but
	 * without needing one. */
	{
		GtkWidget* entry = find_pin_entry();

		g_assert_nonnull(entry);
		gtk_editable_set_text(GTK_EDITABLE(entry), "1234");
		g_signal_emit_by_name(entry, "activate");
	}

	/* Wait for the worker to be inside the login. */
	g_mutex_lock(&probe.lock);
	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (!probe.login_entered)
	{
		if (!g_cond_wait_until(&probe.cond, &probe.lock, deadline))
			g_error("the login worker never started");
	}
	g_mutex_unlock(&probe.lock);

	/* CANCEL, exactly as Request.Close() does, while the card is busy. */
	g_cancellable_cancel(cancellable);
	iterate_for(200);

	/* NOTHING MAY HAVE BEEN ANSWERED YET: the worker is still reading the
	 * prompt and the buffer. */
	g_mutex_lock(&probe.lock);
	g_assert_cmpuint(probe.done_calls, ==, 0);
	probe.login_may_return = TRUE;
	g_cond_broadcast(&probe.cond);
	g_mutex_unlock(&probe.lock);

	/* Now the answer arrives, exactly once, and only after the worker returned. */
	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (probe.done_calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	iterate_for(200);

	g_assert_cmpuint(probe.done_calls, ==, 1);
	g_assert_cmpint(probe.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_true(probe.login_returned_before_done);

	certificate_token_unref(probe.token);
	g_mutex_clear(&probe.lock);
	g_cond_clear(&probe.cond);
}

/* A cancellation delivered before the window is even up must answer once and
 * free nothing twice. */
static void test_cancel_before_prompt(void)
{
	LoginProbe probe = { 0 };
	g_autoptr(GCancellable) cancellable = g_cancellable_new();

	if (!gtk_init_check())
	{
		g_test_skip("no display: the PIN window cannot be opened");
		return;
	}

	certificate_ui_set_has_display(TRUE);
	g_mutex_init(&probe.lock);
	g_cond_init(&probe.cond);
	probe.token = make_token();

	g_cancellable_cancel(cancellable);
	certificate_pin_login(probe.token, NULL, "Test application", "prove who you are", probe_login,
	                      NULL, NULL, &probe, cancellable, probe_done, &probe);

	iterate_for(200);

	g_assert_cmpuint(probe.done_calls, ==, 1);
	g_assert_cmpint(probe.outcome, ==, CERTIFICATE_PIN_CANCELLED);

	certificate_token_unref(probe.token);
	g_mutex_clear(&probe.lock);
	g_cond_clear(&probe.cond);
}

/* ------------------------------- a cancelled login that succeeded regardless */

typedef struct
{
	GMutex lock;
	GCond cond;
	gboolean login_entered;
	gboolean login_may_return;

	guint done_calls;
	guint abandon_calls;
	CertificatePinOutcome outcome;
	gboolean abandoned_after_done;

	CertificateToken* token;
} AbandonProbe;

/* Blocks like a card, and then SUCCEEDS. That is the case nothing used to
 * handle: the attempt was already submitted when the user pressed Escape, and
 * PKCS#11 cannot withdraw one. */
static gboolean abandon_probe_login(const char* pin, gpointer user_data, GError** error)
{
	AbandonProbe* probe = user_data;

	g_mutex_lock(&probe->lock);
	probe->login_entered = TRUE;
	g_cond_broadcast(&probe->cond);

	while (!probe->login_may_return)
		g_cond_wait(&probe->cond, &probe->lock);

	g_mutex_unlock(&probe->lock);

	return TRUE;
}

static void abandon_probe_done(CertificatePinOutcome outcome, gpointer user_data)
{
	AbandonProbe* probe = user_data;

	probe->done_calls++;
	probe->outcome = outcome;
}

static void abandon_probe_abandon(gpointer user_data)
{
	AbandonProbe* probe = user_data;

	probe->abandon_calls++;
	/* THE ORDER IS PART OF THE CONTRACT. The caller has to have answered its
	 * own waiters before it is told to undo the login, or it would be deciding
	 * whether anybody still wants it from a list it has not emptied yet. */
	probe->abandoned_after_done = probe->done_calls > 0;
}

static GtkWidget* find_pin_entry(void)
{
	GQueue queue = G_QUEUE_INIT;
	GListModel* windows = gtk_window_get_toplevels();
	g_autoptr(GtkWindow) window = NULL;
	GtkWidget* entry = NULL;

	for (guint i = 0; i < g_list_model_get_n_items(windows); i++)
	{
		GtkWindow* candidate = g_list_model_get_item(windows, i);

		if (g_strcmp0(gtk_window_get_title(candidate), "Unlock Security Token") == 0)
			window = candidate;
		else
			g_object_unref(candidate);
	}

	if (window == NULL)
		return NULL;

	g_queue_push_tail(&queue, GTK_WIDGET(window));

	while (!g_queue_is_empty(&queue))
	{
		GtkWidget* widget = g_queue_pop_head(&queue);

		if (GTK_IS_PASSWORD_ENTRY(widget))
		{
			entry = widget;
			break;
		}

		for (GtkWidget* child = gtk_widget_get_first_child(widget); child != NULL;
		     child = gtk_widget_get_next_sibling(child))
			g_queue_push_tail(&queue, child);
	}

	g_queue_clear(&queue);
	return entry;
}

static gboolean pin_window_is_up(void)
{
	GListModel* windows = gtk_window_get_toplevels();
	gboolean found = FALSE;

	for (guint i = 0; i < g_list_model_get_n_items(windows); i++)
	{
		GtkWindow* candidate = g_list_model_get_item(windows, i);

		if (g_strcmp0(gtk_window_get_title(candidate), "Unlock Security Token") == 0)
			found = TRUE;

		g_object_unref(candidate);
	}

	return found;
}

/* THE CARD IS LOGGED IN AND NOBODY ASKED FOR IT. The user cancelled while
 * C_Login was in flight and the login succeeded anyway; the outcome the caller
 * is given is "cancelled", and the token must not be left authenticated for the
 * rest of the grant -- the next Sign would otherwise go through with no window.
 * broker/operations.c answers this callback by closing the token session. */
static void test_cancelled_login_is_abandoned(void)
{
	AbandonProbe probe = { 0 };
	g_autoptr(GCancellable) cancellable = g_cancellable_new();
	GtkWidget* entry = NULL;
	gint64 deadline;

	if (!gtk_init_check())
	{
		g_test_skip("no display: the PIN window cannot be opened");
		return;
	}

	certificate_ui_set_has_display(TRUE);
	g_mutex_init(&probe.lock);
	g_cond_init(&probe.cond);
	probe.token = make_token();

	certificate_pin_login(probe.token, NULL, "Test application", "prove who you are",
	                      abandon_probe_login, NULL, abandon_probe_abandon, &probe, cancellable,
	                      abandon_probe_done, &probe);

	entry = find_pin_entry();
	g_assert_nonnull(entry);
	gtk_editable_set_text(GTK_EDITABLE(entry), "1234");
	g_signal_emit_by_name(entry, "activate");

	g_mutex_lock(&probe.lock);
	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (!probe.login_entered)
	{
		if (!g_cond_wait_until(&probe.cond, &probe.lock, deadline))
			g_error("the login worker never started");
	}
	g_mutex_unlock(&probe.lock);

	g_cancellable_cancel(cancellable);
	iterate_for(200);

	g_assert_cmpuint(probe.done_calls, ==, 0);
	g_assert_cmpuint(probe.abandon_calls, ==, 0);

	/* And now the card says yes, too late. */
	g_mutex_lock(&probe.lock);
	probe.login_may_return = TRUE;
	g_cond_broadcast(&probe.cond);
	g_mutex_unlock(&probe.lock);

	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (probe.done_calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	iterate_for(200);

	g_assert_cmpuint(probe.done_calls, ==, 1);
	g_assert_cmpint(probe.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(probe.abandon_calls, ==, 1);
	g_assert_true(probe.abandoned_after_done);

	certificate_token_unref(probe.token);
	g_mutex_clear(&probe.lock);
	g_cond_clear(&probe.cond);
}

/* A login that is NOT cancelled must not be abandoned: the callback exists to
 * undo an unwanted login, and undoing a wanted one would make every grant ask
 * for the PIN twice. */
static void test_successful_login_is_not_abandoned(void)
{
	AbandonProbe probe = { 0 };
	GtkWidget* entry = NULL;
	gint64 deadline;

	if (!gtk_init_check())
	{
		g_test_skip("no display: the PIN window cannot be opened");
		return;
	}

	certificate_ui_set_has_display(TRUE);
	g_mutex_init(&probe.lock);
	g_cond_init(&probe.cond);
	probe.token = make_token();
	probe.login_may_return = TRUE;

	certificate_pin_login(probe.token, NULL, "Test application", "prove who you are",
	                      abandon_probe_login, NULL, abandon_probe_abandon, &probe, NULL,
	                      abandon_probe_done, &probe);

	entry = find_pin_entry();
	g_assert_nonnull(entry);
	gtk_editable_set_text(GTK_EDITABLE(entry), "1234");
	g_signal_emit_by_name(entry, "activate");

	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (probe.done_calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	iterate_for(200);

	g_assert_cmpuint(probe.done_calls, ==, 1);
	g_assert_cmpint(probe.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(probe.abandon_calls, ==, 0);

	certificate_token_unref(probe.token);
	g_mutex_clear(&probe.lock);
	g_cond_clear(&probe.cond);
}

/* -------------------------------------------------------- cancel during sign */

typedef struct
{
	guint calls;
	guint32 response;
	gboolean cancelled;
} SignProbe;

static void on_operation_done(GBytes* result, const GError* error, gpointer user_data)
{
	SignProbe* probe = user_data;

	probe->calls++;

	if (result != NULL)
		return;

	probe->cancelled =
	    g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_CANCELLED) ||
	    g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
}

static char* fixture_directory(void)
{
	const char* directory = g_getenv("SOFTHSM_FIXTURE_DIR");
	g_autofree char* fallback = NULL;

	if (directory != NULL)
		return g_strdup(directory);

	fallback = g_build_filename(g_get_tmp_dir(), "xdp-certificate-softhsm", NULL);
	if (g_file_test(fallback, G_FILE_TEST_IS_DIR))
		return g_steal_pointer(&fallback);

	return NULL;
}

/* THE WORKER IS HELD WHERE A CARD WOULD BE. SoftHSM answers a C_Sign in
 * microseconds, so a cancel issued after certificate_broker_perform() returns
 * always lands before the operation has started -- which is
 * test_cancel_before_prompt again, not this. The gate blocks the worker inside
 * sign_thread, with the device lock held, at exactly the point a real card
 * spends its time. */
typedef struct
{
	GMutex lock;
	GCond cond;
	gboolean entered;
	gboolean may_return;
} SignGate;

static SignGate sign_gate;

static void sign_gate_hold(gpointer user_data)
{
	g_mutex_lock(&sign_gate.lock);
	sign_gate.entered = TRUE;
	g_cond_broadcast(&sign_gate.cond);

	while (!sign_gate.may_return)
		g_cond_wait(&sign_gate.cond, &sign_gate.lock);

	g_mutex_unlock(&sign_gate.lock);
}

/* The signature path, cancelled WHILE THE DEVICE CALL IS IN PROGRESS. The
 * session is logged in first, so no window is needed and the test is headless:
 * what is under test is the operation's own lifetime, not the prompt's. */
static void test_cancel_during_sign(void)
{
	g_autofree char* directory = fixture_directory();
	g_autofree char* module = NULL;
	g_autoptr(CertificateTokens) tokens = NULL;
	g_autoptr(GPtrArray) candidates = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GCancellable) cancellable = g_cancellable_new();
	g_autoptr(GVariant) parameters = NULL;
	g_autoptr(GBytes) data = NULL;
	CertificateImplSession* session = NULL;
	CertificateCandidate* candidate = NULL;
	SignProbe probe = { 0 };
	const char* modules[2] = { NULL, NULL };
	guint8 digest[32];
	gint64 deadline;

	if (directory == NULL)
	{
		g_test_skip("no SoftHSM fixture; run tools/softhsm-fixture.sh");
		return;
	}

	{
		g_autofree char* module_path = g_build_filename(directory, "module-path", NULL);
		g_autofree char* config = g_build_filename(directory, "softhsm2.conf", NULL);

		if (!g_file_get_contents(module_path, &module, NULL, NULL))
		{
			g_test_skip("the SoftHSM fixture has no module-path; rebuild it");
			return;
		}

		g_setenv("SOFTHSM2_CONF", config, TRUE);
	}

	modules[0] = module;
	tokens = certificate_tokens_new(modules, &error);
	g_assert_no_error(error);

	candidates = certificate_tokens_enumerate(tokens, NULL, &error);
	g_assert_no_error(error);

	for (guint i = 0; i < candidates->len; i++)
	{
		CertificateCandidate* item = g_ptr_array_index(candidates, i);

		if (g_strcmp0(item->key_type, "RSA") == 0)
			candidate = item;
	}

	if (candidate == NULL)
	{
		g_test_skip("the fixture has no RSA key");
		return;
	}

	session = certificate_impl_session_new("/org/freedesktop/portal/desktop/session/t/1",
	                                       "org.example.App");
	certificate_impl_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE,
	                               FALSE, 300);

	/* Logged in up front: the point of this test is the operation, and a PIN
	 * window would need a display. */
	g_assert_true(certificate_device_open(&session->device, tokens, candidate, &error));
	g_assert_true(certificate_device_login(&session->device, candidate, FIXTURE_PIN, &error));
	g_assert_no_error(error);

	memset(digest, 0x5a, sizeof(digest));
	data = g_bytes_new(digest, sizeof(digest));
	/* g_variant_parse() already returns a FULL reference. */
	parameters = g_variant_parse(G_VARIANT_TYPE_VARDICT, "{'hash': <'SHA256'>}", NULL, NULL,
	                             NULL);

	g_mutex_init(&sign_gate.lock);
	g_cond_init(&sign_gate.cond);
	certificate_broker_set_gate(sign_gate_hold, NULL);

	certificate_broker_perform(tokens, session, FALSE, "RSA_PKCS1_V1_5", parameters, data, NULL,
	                           "Test application", cancellable, on_operation_done, &probe);

	/* Wait until the worker is inside the operation, holding the device lock,
	 * about to hand the payload to the module. THE MAIN LOOP HAS TO KEEP
	 * TURNING: open_thread's completion callback is what starts the signing
	 * worker, and it is dispatched here. */
	deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	for (;;)
	{
		gboolean entered;

		g_mutex_lock(&sign_gate.lock);
		entered = sign_gate.entered;
		g_mutex_unlock(&sign_gate.lock);

		if (entered)
			break;

		if (g_get_monotonic_time() >= deadline)
			g_error("the signing worker never reached the device call");

		g_main_context_iteration(NULL, FALSE);
	}

	/* NOTHING MAY HAVE BEEN ANSWERED: the operation is in flight. */
	g_assert_cmpuint(probe.calls, ==, 0);

	/* CANCEL, exactly as Request.Close() does, mid-operation. */
	g_cancellable_cancel(cancellable);
	iterate_for(200);

	g_mutex_lock(&sign_gate.lock);
	sign_gate.may_return = TRUE;
	g_cond_broadcast(&sign_gate.cond);
	g_mutex_unlock(&sign_gate.lock);

	deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while (probe.calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	iterate_for(300);

	/* EXACTLY ONE ANSWER, whether the card won the race or the cancel did.
	 * Which one it is depends on the module: the operation was submitted, so a
	 * signature may well have come back, and the GTask carries the cancellable
	 * so GIO reports it as cancelled anyway. What must never happen is two
	 * answers, no answer, or a device failure. */
	g_assert_cmpuint(probe.calls, ==, 1);
	g_assert_true(probe.cancelled);

	certificate_broker_set_gate(NULL, NULL);
	g_mutex_clear(&sign_gate.lock);
	g_cond_clear(&sign_gate.cond);

	certificate_impl_session_close(session);
	/* The close runs on a worker now, and the module below must not be
	 * finalised under it. */
	certificate_impl_session_drain_releases(2000);
	g_object_unref(session);
}

/* ------------------------------------------- one waiter, cancelled on its own */

/* TWO Sign CALLS ON A LOGGED-OUT GRANT SHARE ONE WINDOW, and until now they
 * also shared one cancellation: closing the request that opened the prompt
 * closed the window and told every other caller behind it that the USER had
 * cancelled -- which they had not. Cancelling a waiter, conversely, did nothing
 * at all until the prompt in front of it finished.
 *
 * The window belongs to the SESSION now. A cancelled operation leaves the queue
 * and is answered on its own; the window comes down only when the last live
 * waiter has gone. */
static void test_one_waiter_cancels_alone(void)
{
	g_autofree char* directory = fixture_directory();
	g_autofree char* module = NULL;
	g_autoptr(CertificateTokens) tokens = NULL;
	g_autoptr(GPtrArray) candidates = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GCancellable) first_cancellable = g_cancellable_new();
	g_autoptr(GCancellable) second_cancellable = g_cancellable_new();
	g_autoptr(GVariant) parameters = NULL;
	g_autoptr(GBytes) data = NULL;
	CertificateImplSession* session = NULL;
	CertificateCandidate* candidate = NULL;
	SignProbe first = { 0 };
	SignProbe second = { 0 };
	const char* modules[2] = { NULL, NULL };
	guint8 digest[32];
	gint64 deadline;

	if (!gtk_init_check())
	{
		g_test_skip("no display: the PIN window cannot be opened");
		return;
	}

	certificate_ui_set_has_display(TRUE);

	if (directory == NULL)
	{
		g_test_skip("no SoftHSM fixture; run tools/softhsm-fixture.sh");
		return;
	}

	{
		g_autofree char* module_path = g_build_filename(directory, "module-path", NULL);
		g_autofree char* config = g_build_filename(directory, "softhsm2.conf", NULL);

		if (!g_file_get_contents(module_path, &module, NULL, NULL))
		{
			g_test_skip("the SoftHSM fixture has no module-path; rebuild it");
			return;
		}

		g_setenv("SOFTHSM2_CONF", config, TRUE);
	}

	modules[0] = module;
	tokens = certificate_tokens_new(modules, &error);
	g_assert_no_error(error);

	candidates = certificate_tokens_enumerate(tokens, NULL, &error);
	g_assert_no_error(error);

	for (guint i = 0; i < candidates->len; i++)
	{
		CertificateCandidate* item = g_ptr_array_index(candidates, i);

		if (g_strcmp0(item->key_type, "RSA") == 0)
			candidate = item;
	}

	if (candidate == NULL)
	{
		g_test_skip("the fixture has no RSA key");
		return;
	}

	session = certificate_impl_session_new("/org/freedesktop/portal/desktop/session/t/waiters",
	                                       "org.example.App");
	certificate_impl_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE,
	                               FALSE, 300);

	memset(digest, 0x5a, sizeof(digest));
	data = g_bytes_new(digest, sizeof(digest));
	/* g_variant_parse() already returns a FULL reference. */
	parameters = g_variant_parse(G_VARIANT_TYPE_VARDICT, "{'hash': <'SHA256'>}", NULL, NULL,
	                             NULL);

	/* NOT logged in: the first operation opens the one PIN window. */
	certificate_broker_perform(tokens, session, FALSE, "RSA_PKCS1_V1_5", parameters, data, NULL,
	                           "First application", first_cancellable, on_operation_done, &first);

	deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while (!pin_window_is_up() && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	g_assert_true(pin_window_is_up());

	/* The second arrives while the window is up, so it joins the queue rather
	 * than opening a second window at the user. */
	certificate_broker_perform(tokens, session, FALSE, "RSA_PKCS1_V1_5", parameters, data, NULL,
	                           "Second application", second_cancellable, on_operation_done,
	                           &second);

	iterate_for(400);
	g_assert_cmpuint(first.calls, ==, 0);
	g_assert_cmpuint(second.calls, ==, 0);
	g_assert_true(pin_window_is_up());

	/* CANCEL THE ONE THAT OPENED THE WINDOW. It is answered, on its own, now. */
	g_cancellable_cancel(first_cancellable);
	iterate_for(300);

	g_assert_cmpuint(first.calls, ==, 1);
	g_assert_true(first.cancelled);

	/* AND THE OTHER ONE IS STILL WAITING, in front of a window that is still
	 * up, for a request nobody cancelled. */
	g_assert_cmpuint(second.calls, ==, 0);
	g_assert_true(pin_window_is_up());

	/* The last live waiter going takes the window with it. */
	g_cancellable_cancel(second_cancellable);
	iterate_for(300);

	g_assert_cmpuint(second.calls, ==, 1);
	g_assert_true(second.cancelled);
	g_assert_false(pin_window_is_up());

	certificate_impl_session_close(session);
	certificate_impl_session_drain_releases(2000);
	g_object_unref(session);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/cancel/during-login", test_cancel_during_login);
	g_test_add_func("/cancel/before-prompt", test_cancel_before_prompt);
	g_test_add_func("/cancel/during-sign", test_cancel_during_sign);
	g_test_add_func("/cancel/cancelled-login-is-abandoned", test_cancelled_login_is_abandoned);
	g_test_add_func("/cancel/successful-login-is-not-abandoned",
	                test_successful_login_is_not_abandoned);
	g_test_add_func("/cancel/one-waiter-cancels-alone", test_one_waiter_cancels_alone);

	return g_test_run();
}
