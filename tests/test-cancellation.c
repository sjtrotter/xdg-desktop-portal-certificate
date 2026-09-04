/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
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
	                      NULL, &probe, cancellable, probe_done, &probe);

	/* Type a PIN and press Unlock, the way ui-smoke.sh does with xdotool but
	 * without needing one: find this process's prompt window and its
	 * GtkPasswordEntry, and activate it. */
	{
		GtkWidget* entry = NULL;
		GQueue queue = G_QUEUE_INIT;
		GListModel* windows = gtk_window_get_toplevels();
		g_autoptr(GtkWindow) window = NULL;

		for (guint i = 0; i < g_list_model_get_n_items(windows); i++)
		{
			GtkWindow* candidate = g_list_model_get_item(windows, i);

			if (g_strcmp0(gtk_window_get_title(candidate), "Unlock Security Token") == 0)
				window = candidate;
			else
				g_object_unref(candidate);
		}

		g_assert_nonnull(window);
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
	                      NULL, &probe, cancellable, probe_done, &probe);

	iterate_for(200);

	g_assert_cmpuint(probe.done_calls, ==, 1);
	g_assert_cmpint(probe.outcome, ==, CERTIFICATE_PIN_CANCELLED);

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

/* The signature path, cancelled while it is in flight. The session is logged in
 * first, so no window is needed and the test is headless: what is under test is
 * the operation's own lifetime, not the prompt's. */
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
	parameters = g_variant_ref_sink(
	    g_variant_parse(G_VARIANT_TYPE_VARDICT, "{'hash': <'SHA256'>}", NULL, NULL, NULL));

	certificate_broker_perform(tokens, session, FALSE, "RSA_PKCS1_V1_5", parameters, data, NULL,
	                           "Test application", cancellable, on_operation_done, &probe);

	/* Cancelled immediately: whether the card finished first is a race, and
	 * BOTH outcomes must be answered exactly once and never as a device
	 * failure. */
	g_cancellable_cancel(cancellable);

	deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while (probe.calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);

	iterate_for(300);

	g_assert_cmpuint(probe.calls, ==, 1);
	g_assert_true(probe.cancelled);

	certificate_impl_session_close(session);
	g_object_unref(session);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/cancel/during-login", test_cancel_during_login);
	g_test_add_func("/cancel/before-prompt", test_cancel_before_prompt);
	g_test_add_func("/cancel/during-sign", test_cancel_during_sign);

	return g_test_run();
}
