/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <glib.h>
#include <gnutls/abstract.h>

#include "pin-prompter.h"
#include "broker/operations.h"
#include "core/session-private.h"
#include "fixture-util.h"
#include "tokens/discovery.h"
#include "core/pin.h"
#include "ui/pin-backends.h"

#define GOOD_PIN "1234"

typedef struct
{
	GTestDBus* bus;
	GDBusConnection* connection;
	CertificateTestPrompter* prompter;
} Fixture;

typedef struct
{
	CertificateToken* token;

	const char** answers;
	guint attempts;
	guint block_ms;

	gboolean done_called;
	CertificatePinOutcome outcome;
	guint abandons;
	char* last_pin;
} LoginScript;

static CertificateToken* make_token(void)
{
	CertificateToken* token = g_new0(CertificateToken, 1);

	g_atomic_ref_count_init(&token->ref_count);
	token->label = g_strdup("System Prompt Test Token");
	token->manufacturer = g_strdup("Test");
	token->model = g_strdup("Test");
	token->serial = g_strdup("0123456789abcdef");
	token->reader_name = g_strdup("Test reader");
	token->login_required = TRUE;

	return token;
}

static gboolean script_login(const char* pin, gpointer user_data, GError** error)
{
	LoginScript* script = user_data;
	const char* answer = script->answers[script->attempts];

	script->attempts++;
	g_free(script->last_pin);
	script->last_pin = g_strdup(pin);

	if (script->block_ms > 0)
		g_usleep((gulong) script->block_ms * 1000);

	if (g_strcmp0(answer, "ok") == 0)
		return TRUE;

	if (g_strcmp0(answer, "locked") == 0)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_LOCKED,
		                    "locked");
		return FALSE;
	}

	g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT,
	                    "not accepted");
	return FALSE;
}

static void script_done(CertificatePinOutcome outcome, gpointer user_data)
{
	LoginScript* script = user_data;

	script->done_called = TRUE;
	script->outcome = outcome;
}

static void script_abandon(gpointer user_data)
{
	LoginScript* script = user_data;

	script->abandons++;
}

static gboolean quit_loop(gpointer user_data)
{
	g_main_loop_quit(user_data);
	return G_SOURCE_REMOVE;
}

static void run_until_done(LoginScript* script, guint timeout_ms)
{
	g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);
	gint64 deadline = g_get_monotonic_time() + (gint64) timeout_ms * 1000;

	while (!script->done_called && g_get_monotonic_time() < deadline)
	{
		g_timeout_add(20, quit_loop, loop);
		g_main_loop_run(loop);
	}

	g_assert_true(script->done_called);
}

/* The caller's answer can precede the asynchronous close; dispatch it before reading counters. */
static void settle(guint milliseconds)
{
	g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);

	g_timeout_add(milliseconds, quit_loop, loop);
	g_main_loop_run(loop);
}

static void wait_for_password_round(guint rounds, guint timeout_ms)
{
	gint64 deadline = g_get_monotonic_time() + (gint64) timeout_ms * 1000;

	while (certificate_test_prompter_password_rounds() < rounds &&
	       g_get_monotonic_time() < deadline)
		settle(20);

	g_assert_cmpuint(certificate_test_prompter_password_rounds(), >=, rounds);
}

static void wait_for_confirm_round(guint rounds, guint timeout_ms)
{
	gint64 deadline = g_get_monotonic_time() + (gint64) timeout_ms * 1000;

	while (certificate_test_prompter_confirm_rounds() < rounds &&
	       g_get_monotonic_time() < deadline)
		settle(20);

	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), >=, rounds);
}

static void script_clear(LoginScript* script)
{
	g_clear_pointer(&script->token, certificate_token_unref);
	g_clear_pointer(&script->last_pin, g_free);
}

static void fixture_set_up(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;

	fixture->bus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_up(fixture->bus);

	fixture->connection = g_dbus_connection_new_for_address_sync(
	    g_test_dbus_get_bus_address(fixture->bus),
	    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
	    NULL, NULL, &error);
	g_assert_no_error(error);

	certificate_test_prompter_reset();
	fixture->prompter =
	    certificate_test_prompter_start(fixture->connection, "org.gnome.keyring.SystemPrompter");

	/* Resolve auto on the fixture's private bus to exercise prompter selection. */
	g_assert_true(certificate_pin_set_prompt_kind("auto", NULL));

	certificate_ui_set_has_display(FALSE);
	certificate_pin_set_login_timeout(60);
}

static void fixture_tear_down(Fixture* fixture, gconstpointer user_data)
{
	certificate_test_prompter_stop(fixture->prompter);
	certificate_test_prompter_reset();
	certificate_test_prompter_set_default_password(NULL);

	g_clear_object(&fixture->connection);
	g_test_dbus_down(fixture->bus);
	g_clear_object(&fixture->bus);

	g_assert_true(certificate_pin_set_prompt_kind("gtk", NULL));
	certificate_pin_set_login_timeout(60);
}

static void test_auto_picks_the_prompter(Fixture* fixture, gconstpointer user_data)
{
	g_assert_cmpstr(certificate_pin_prompt_name(), ==, "system");
}

static void test_happy_path(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* title = NULL;
	g_autofree char* description = NULL;
	g_autofree char* choice = NULL;

	script.token = make_token();
	script.answers = answers;

	certificate_test_prompter_expect_password(GOOD_PIN);

	g_assert_cmpstr(certificate_pin_prompt_name(), ==, "system");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "pin-prompted session=/org/freedesktop/portal/desktop/session/t/logging "
	                      "detail=on-screen");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "login-ok session=/org/freedesktop/portal/desktop/session/t/logging "
	                      "detail=pin-accepted");
	certificate_pin_login_full(script.token,
	                           "/org/freedesktop/portal/desktop/session/t/logging",
	                           "wayland:handle-123", "Test application", "prove who you are",
	                           script_login, NULL, script_abandon, &script, NULL, NULL,
	                           script_done, &script);

	run_until_done(&script, 10000);
	g_test_assert_expected_messages();

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpstr(script.last_pin, ==, GOOD_PIN);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 1);
	g_assert_cmpuint(certificate_test_prompter_prompts_created(), ==, 1);

	title = certificate_test_prompter_last_title();
	description = certificate_test_prompter_last_description();
	g_assert_cmpstr(title, ==, "Unlock Security Token");
	g_assert_nonnull(strstr(description, "Test application"));
	g_assert_nonnull(strstr(description, "System Prompt Test Token"));
	g_assert_nonnull(strstr(description, "Test reader"));

	/* gcr transports NULL choice-label as an empty wire string. */
	choice = certificate_test_prompter_last_choice_label();
	g_assert_true(choice == NULL || *choice == '\0');
	g_assert_false(certificate_test_prompter_last_password_new());

	script_clear(&script);
}

static void test_caller_window_is_passed(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* window = NULL;

	script.token = make_token();
	script.answers = answers;
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, "x11:1a2b3c", "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 10000);

	window = certificate_test_prompter_last_caller_window();
	g_assert_cmpstr(window, ==, "1a2b3c");

	script_clear(&script);
}

static void test_wrong_pin_then_right(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "wrong", "ok" };
	g_autofree char* warning = NULL;

	script.token = make_token();
	script.answers = answers;

	certificate_test_prompter_expect_password("0000");
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, script_abandon, &script, NULL, script_done,
	                      &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 2);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 2);
	g_assert_cmpuint(certificate_test_prompter_prompts_created(), ==, 1);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "not accepted"));

	script_clear(&script);
}

static void test_attempt_cap(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "wrong", "wrong", "wrong", "wrong" };

	script.token = make_token();
	script.answers = answers;

	for (guint i = 0; i < 4; i++)
		certificate_test_prompter_expect_password("0000");

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 15000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_INCORRECT);
	g_assert_cmpuint(script.attempts, ==, 3);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 3);

	script_clear(&script);
}

static void test_cancel_in_the_prompter(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.answers = answers;

	/* gcr represents user cancellation as NULL. */
	certificate_test_prompter_expect_password(NULL);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, script_abandon, &script, NULL, script_done,
	                      &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);
	g_assert_cmpuint(script.abandons, ==, 0);

	script_clear(&script);
}

static void test_cancellable_closes_the_prompt(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autoptr(GCancellable) cancellable = g_cancellable_new();

	script.token = make_token();
	script.answers = answers;
	certificate_test_prompter_set_delay(2000);

	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, cancellable, script_done, &script);

	settle(300);
	g_cancellable_cancel(cancellable);

	run_until_done(&script, 10000);
	settle(300);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);
	g_assert_cmpuint(certificate_test_prompter_closes(), >=, 1);

	certificate_test_prompter_set_delay(40);
	script_clear(&script);
}

static void test_final_try_warns_before_input(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* warning = NULL;
	g_autofree char* action = NULL;

	script.token = make_token();
	script.token->pin_final_try = TRUE;
	script.answers = answers;

	certificate_test_prompter_set_delay(300);
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	wait_for_password_round(1, 10000);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "last attempt"));
	action = certificate_test_prompter_last_continue_label();
	g_assert_cmpstr(action, ==, "Unlock");
	g_assert_cmpuint(script.attempts, ==, 0);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 0);

	run_until_done(&script, 10000);
	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 1);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 0);

	certificate_test_prompter_set_delay(40);
	script_clear(&script);
}

static void test_final_try_cancelled_spends_nothing(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.token->pin_final_try = TRUE;
	script.answers = answers;

	certificate_test_prompter_expect_password(NULL);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 0);

	script_clear(&script);
}

static void refresh_final_try(CertificateToken* token, gpointer user_data)
{
	token->pin_count_low = TRUE;
	token->pin_final_try = TRUE;
}

static void test_refreshed_final_try_warns_before_input(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "wrong", "ok" };
	g_autofree char* warning = NULL;

	script.token = make_token();
	script.answers = answers;
	certificate_test_prompter_set_delay(300);
	certificate_test_prompter_expect_password("0000");
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, refresh_final_try, NULL, &script, NULL, script_done,
	                      &script);
	wait_for_password_round(2, 10000);
	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "not accepted"));
	g_assert_nonnull(strstr(warning, "last attempt"));
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 0);

	run_until_done(&script, 10000);
	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 2);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 2);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 0);
	g_assert_cmpuint(certificate_test_prompter_prompts_created(), ==, 1);

	certificate_test_prompter_set_delay(40);
	script_clear(&script);
}

static void test_warning_carries_the_token_flags(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* warning = NULL;

	script.token = make_token();
	script.token->pin_count_low = TRUE;
	script.answers = answers;

	certificate_test_prompter_set_delay(300);
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	wait_for_password_round(1, 10000);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "recent failed attempts"));
	g_assert_null(strstr(warning, "2 attempts"));

	g_assert_cmpuint(script.attempts, ==, 0);
	run_until_done(&script, 10000);
	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 0);
	certificate_test_prompter_set_delay(40);
	script_clear(&script);
}

static void test_login_timeout(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.answers = answers;
	script.block_ms = 2500;

	certificate_pin_set_login_timeout(1);
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, script_abandon, &script, NULL, script_done,
	                      &script);
	run_until_done(&script, 20000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_TIMED_OUT);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpuint(script.abandons, ==, 1);

	script_clear(&script);
}

static void test_protected_path_asks_for_nothing(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* description = NULL;

	script.token = make_token();
	script.token->protected_authentication_path = TRUE;
	script.answers = answers;

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_null(script.last_pin);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 0);

	description = certificate_test_prompter_last_description();
	g_assert_nonnull(strstr(description, "reader collects the PIN itself"));

	script_clear(&script);
}

static void test_empty_answer_never_reaches_the_card(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* warning = NULL;

	script.token = make_token();
	script.answers = answers;

	certificate_test_prompter_expect_password("");
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, script_abandon, &script, NULL, script_done,
	                      &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpstr(script.last_pin, ==, GOOD_PIN);

	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 2);
	g_assert_cmpuint(certificate_test_prompter_prompts_created(), ==, 1);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "Enter the PIN"));

	script_clear(&script);
}

static void test_protected_path_final_try_refused(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* warning = NULL;

	script.token = make_token();
	script.token->protected_authentication_path = TRUE;
	script.token->pin_final_try = TRUE;
	script.answers = answers;

	certificate_test_prompter_expect_confirm(FALSE);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, script_abandon, &script, NULL, script_done,
	                      &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);
	g_assert_cmpuint(script.abandons, ==, 0);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 1);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 0);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "last attempt"));

	script_clear(&script);
}

static void test_protected_path_final_try_confirmed(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* action = NULL;
	g_autofree char* warning = NULL;

	script.token = make_token();
	script.token->protected_authentication_path = TRUE;
	script.token->pin_final_try = TRUE;
	script.answers = answers;

	certificate_test_prompter_set_delay(300);
	certificate_test_prompter_expect_confirm(TRUE);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	wait_for_confirm_round(1, 10000);
	g_assert_cmpuint(script.attempts, ==, 0);
	action = certificate_test_prompter_last_continue_label();
	g_assert_cmpstr(action, ==, "Continue");
	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "last attempt"));
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_null(script.last_pin);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 1);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 0);

	certificate_test_prompter_set_delay(40);
	script_clear(&script);
}

static void test_shell_cancel_after_the_pin_was_submitted(Fixture* fixture,
                                                          gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.answers = answers;
	/* Delay login completion so shell dismissal lands while C_Login is running. */
	script.block_ms = 1500;

	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, script_abandon, &script, NULL, script_done,
	                      &script);

	wait_for_password_round(1, 5000);
	settle(400);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_false(script.done_called);

	certificate_test_prompter_dismiss();

	run_until_done(&script, 20000);
	settle(300);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpuint(script.abandons, ==, 1);

	script_clear(&script);
}

static void test_prompter_vanishes_during_password(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	LoginScript second = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.answers = answers;
	second.token = make_token();
	second.answers = answers;

	certificate_test_prompter_set_delay(5000);
	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);

	wait_for_password_round(1, 5000);
	settle(200);
	certificate_test_prompter_vanish(fixture->prompter);

	run_until_done(&script, 15000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_DEVICE_ERROR);
	g_assert_cmpuint(script.attempts, ==, 0);

	certificate_pin_login(second.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &second, NULL, script_done, &second);
	run_until_done(&second, 15000);
	g_assert_cmpuint(second.attempts, ==, 0);

	certificate_test_prompter_set_delay(40);
	script_clear(&script);
	script_clear(&second);
}

static void test_prompter_vanishes_during_confirm(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.token->pin_final_try = TRUE;
	script.token->protected_authentication_path = TRUE;
	script.answers = answers;

	/* Delay each round so prompter loss can occur during final-attempt confirmation. */
	certificate_test_prompter_set_delay(300);
	certificate_test_prompter_expect_confirm(TRUE);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);

	wait_for_confirm_round(1, 10000);
	certificate_test_prompter_vanish(fixture->prompter);

	run_until_done(&script, 15000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_DEVICE_ERROR);
	g_assert_cmpuint(script.attempts, ==, 0);

	certificate_test_prompter_set_delay(40);
	script_clear(&script);
}

typedef struct
{
	GTestDBus* bus;
	GDBusConnection* connection;
	CertificateTestStallingPrompter* prompter;
	gboolean send_ready;
} StallFixture;

static void stall_set_up_common(StallFixture* fixture, gboolean send_ready)
{
	g_autoptr(GError) error = NULL;

	fixture->bus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_up(fixture->bus);

	fixture->connection = g_dbus_connection_new_for_address_sync(
	    g_test_dbus_get_bus_address(fixture->bus),
	    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
	    NULL, NULL, &error);
	g_assert_no_error(error);

	fixture->prompter = certificate_test_stalling_prompter_start(
	    fixture->connection, "org.gnome.keyring.SystemPrompter", send_ready);

	g_assert_true(certificate_pin_set_prompt_kind("system", NULL));
	certificate_ui_set_has_display(FALSE);
	certificate_pin_set_login_timeout(60);
}

static void stall_set_up(StallFixture* fixture, gconstpointer user_data)
{
	stall_set_up_common(fixture, TRUE);
}

static void stall_set_up_no_ready(StallFixture* fixture, gconstpointer user_data)
{
	stall_set_up_common(fixture, FALSE);
}

static void stall_tear_down(StallFixture* fixture, gconstpointer user_data)
{
	certificate_test_stalling_prompter_stop(fixture->prompter);
	g_clear_object(&fixture->connection);
	g_test_dbus_down(fixture->bus);
	g_clear_object(&fixture->bus);

	g_assert_true(certificate_pin_set_prompt_kind("gtk", NULL));
	certificate_pin_set_login_timeout(60);
}

/* Hold PerformPrompt across close, then fail it to trigger gcr's duplicate completion. */
static void test_close_racing_a_transport_error(StallFixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autoptr(GCancellable) cancellable = g_cancellable_new();

	script.token = make_token();
	script.answers = answers;

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, cancellable, script_done, &script);

	for (guint i = 0; i < 100 && !certificate_test_stalling_prompter_is_performing(
	                                 fixture->prompter);
	     i++)
		settle(20);
	g_assert_true(certificate_test_stalling_prompter_is_performing(fixture->prompter));

	g_cancellable_cancel(cancellable);
	run_until_done(&script, 10000);
	settle(300);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);

	/* Expect the duplicate-completion diagnostic to verify the guard without requiring a sanitizer. */
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "pin-prompt-round-completed-twice*");
	certificate_test_stalling_prompter_fail_perform(fixture->prompter);
	settle(500);
	g_test_assert_expected_messages();

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);

	script_clear(&script);
}

static void test_prompter_vanishes_during_open(StallFixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.answers = answers;

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);

	settle(400);
	g_assert_false(script.done_called);

	certificate_test_stalling_prompter_vanish(fixture->prompter);

	run_until_done(&script, 15000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_NO_DISPLAY);
	g_assert_cmpuint(script.attempts, ==, 0);

	script_clear(&script);
}

static guint context_logins;
static gboolean context_sign_active;
static gboolean context_authenticated;

static CK_RV context_get_attribute(CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE key,
                                    CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
{
	g_assert_cmpuint(count, ==, 1);
	g_assert_cmpuint(attributes[0].type, ==, CKA_ALWAYS_AUTHENTICATE);
	*(CK_BBOOL*) attributes[0].pValue = CK_TRUE;
	attributes[0].ulValueLen = sizeof(CK_BBOOL);
	return CKR_OK;
}

static CK_RV context_sign_init(CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                                CK_OBJECT_HANDLE key)
{
	g_assert_false(context_sign_active);
	context_sign_active = TRUE;
	context_authenticated = FALSE;
	return CKR_OK;
}

static CK_RV context_token_login(CK_SESSION_HANDLE handle, CK_USER_TYPE user,
                                  CK_UTF8CHAR_PTR pin, CK_ULONG length)
{
	g_assert_true(context_sign_active);
	g_assert_cmpuint(user, ==, CKU_CONTEXT_SPECIFIC);
	g_assert_cmpmem(pin, length, GOOD_PIN, strlen(GOOD_PIN));
	context_logins++;
	context_authenticated = TRUE;
	return CKR_OK;
}

static CK_RV context_sign(CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG length,
                           CK_BYTE_PTR signature, CK_ULONG_PTR size)
{
	g_assert_true(context_sign_active);
	g_assert_true(context_authenticated);
	*size = 1;
	if (signature != NULL)
	{
		signature[0] = 42;
		context_sign_active = FALSE;
		context_authenticated = FALSE;
	}
	return CKR_OK;
}

static CK_RV context_close(CK_SESSION_HANDLE handle)
{
	return CKR_OK;
}

static void context_signed(GBytes* result, const GError* error, gpointer user_data)
{
	guint* completions = user_data;

	g_assert_no_error(error);
	g_assert_nonnull(result);
	g_assert_cmpuint(g_bytes_get_size(result), ==, 1);
	(*completions)++;
}

static void test_broker_context_login(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autoptr(XccSession) session = xcc_session_new(
	    "/org/freedesktop/portal/desktop/session/t/context", NULL, NULL);
	g_autoptr(GBytes) digest = g_bytes_new_static("01234567890123456789012345678901", 32);
	g_autoptr(GVariant) parameters =
	    g_variant_parse(G_VARIANT_TYPE_VARDICT, "{'hash': <'SHA256'>}", NULL, NULL, NULL);
	CK_FUNCTION_LIST module = {
		.C_GetAttributeValue = context_get_attribute,
		.C_SignInit = context_sign_init,
		.C_Login = context_token_login,
		.C_Sign = context_sign,
		.C_Logout = context_close,
		.C_CloseSession = context_close,
	};
	guint completions = 0;
	gint64 deadline;

	g_clear_pointer(&candidate->token, certificate_token_unref);
	candidate->token = make_token();
	xcc_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE,
	                  FALSE, 300);
	session->device.module = &module;
	session->device.session = 1;
	session->device.private_key = 1;
	session->device.logged_in = TRUE;
	session->device.candidate = certificate_candidate_ref(candidate);
	context_logins = 0;
	context_sign_active = FALSE;

	certificate_test_prompter_expect_password(GOOD_PIN);
	certificate_test_prompter_expect_password(GOOD_PIN);
	for (guint i = 0; i < 2; i++)
		certificate_broker_perform(NULL, session, FALSE, "sign-context", "RSA_PKCS1_V1_5",
		                           parameters, digest, NULL, "Test application", NULL,
		                           context_signed, &completions);

	deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while (completions < 2 && g_get_monotonic_time() < deadline)
		settle(20);

	g_assert_cmpuint(completions, ==, 2);
	g_assert_cmpuint(context_logins, ==, 2);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 2);
	g_assert_cmpuint(certificate_test_prompter_prompts_created(), ==, 2);
	certificate_device_close(&session->device);
	xcc_session_close(session);
}

typedef struct
{
	guint calls;
	GBytes* signature;
	GError* error;
} ContextResult;

static void context_result(GBytes* result, const GError* error, gpointer user_data)
{
	ContextResult* probe = user_data;

	probe->calls++;
	if (result != NULL)
		probe->signature = g_bytes_ref(result);
	if (error != NULL)
		probe->error = g_error_copy(error);
}

typedef struct
{
	GMutex lock;
	GCond cond;
	gboolean entered;
	gboolean released;
} OpenGate;

static void open_gate_hold(gpointer user_data)
{
	OpenGate* gate = user_data;
	gint64 deadline = g_get_monotonic_time() + 20 * G_TIME_SPAN_SECOND;

	g_mutex_lock(&gate->lock);
	gate->entered = TRUE;
	g_cond_broadcast(&gate->cond);
	while (!gate->released && g_cond_wait_until(&gate->cond, &gate->lock, deadline))
		;
	g_mutex_unlock(&gate->lock);
}

static gboolean open_gate_entered(OpenGate* gate)
{
	gboolean entered;

	g_mutex_lock(&gate->lock);
	entered = gate->entered;
	g_mutex_unlock(&gate->lock);
	return entered;
}

static void open_gate_release(OpenGate* gate)
{
	g_mutex_lock(&gate->lock);
	gate->released = TRUE;
	g_cond_broadcast(&gate->cond);
	g_mutex_unlock(&gate->lock);
}

/* With hold_open, the queued request's open completes before the cancel and its callback runs after. */
static void run_context_cancel_queued(gboolean hold_open)
{
	const char* directory = g_getenv("SOFTHSM_FIXTURE_DIR");
	g_autofree char* fallback = g_build_filename(g_get_tmp_dir(), "xdp-certificate-softhsm", NULL);
	g_autofree char* config = NULL;
	g_autofree char* module = NULL;
	g_autoptr(CertificateTokens) tokens = NULL;
	g_autoptr(GPtrArray) candidates = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(XccSession) session = NULL;
	CertificateCandidate* candidate = NULL;
	CertificateDevice setup = { 0 };
	const char* modules[2] = { NULL, NULL };
	g_autoptr(GBytes) digest = g_bytes_new_static("01234567890123456789012345678901", 32);
	g_autoptr(GVariant) parameters =
	    g_variant_parse(G_VARIANT_TYPE_VARDICT, "{'hash': <'SHA256'>}", NULL, NULL, NULL);
	CK_BBOOL yes = CK_TRUE;
	CK_ULONG bits = 2048;
	CK_BYTE exponent[] = { 1, 0, 1 };
	CK_BYTE id[] = "queued-context-cancel";
	CK_ATTRIBUTE public_attributes[] = {
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent) },
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_ID, id, sizeof(id) },
	};
	CK_ATTRIBUTE private_attributes[] = {
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_SIGN, &yes, sizeof(yes) },
		{ CKA_ALWAYS_AUTHENTICATE, &yes, sizeof(yes) },
		{ CKA_ID, id, sizeof(id) },
	};
	CK_MECHANISM generation = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
	CK_OBJECT_HANDLE public_key;
	CK_OBJECT_HANDLE private_key;
	g_autoptr(GByteArray) modulus = NULL;
	gnutls_pubkey_t verifier;
	gnutls_datum_t exponent_data = { exponent, sizeof(exponent) };
	ContextResult probes[2] = { 0 };
	OpenGate gate = { 0 };
	gint64 deadline;

	if (directory == NULL)
		directory = fallback;
	config = g_build_filename(directory, "softhsm2.conf", NULL);
	{
		g_autofree char* path = g_build_filename(directory, "module-path", NULL);

		if (!g_file_get_contents(path, &module, NULL, NULL))
		{
			g_test_skip("no SoftHSM fixture; run tools/softhsm-fixture.sh");
			return;
		}
	}
	g_setenv("SOFTHSM2_CONF", config, TRUE);
	modules[0] = module;
	tokens = certificate_tokens_new(modules, &error);
	g_assert_no_error(error);
	candidates = certificate_tokens_enumerate(tokens, NULL, &error);
	g_assert_no_error(error);
	for (guint i = 0; i < candidates->len; i++)
	{
		CertificateCandidate* item = g_ptr_array_index(candidates, i);

		if (g_strcmp0(item->key_type, "RSA") == 0)
		{
			candidate = item;
			break;
		}
	}
	g_assert_nonnull(candidate);
	g_assert_true(certificate_device_open(&setup, tokens, candidate, &error));
	g_assert_cmpuint(setup.module->C_CloseSession(setup.session), ==, CKR_OK);
	g_assert_cmpuint(setup.module->C_OpenSession(candidate->token->slot,
	                                            CKF_SERIAL_SESSION | CKF_RW_SESSION,
	                                            NULL, NULL, &setup.session), ==, CKR_OK);
	g_assert_true(certificate_device_login(&setup, candidate, "123456", &error));
	g_assert_no_error(error);
	/* Remove keys left by an earlier aborted run so the broker finds only this pair. */
	{
		CK_ATTRIBUTE stale_id = { CKA_ID, id, sizeof(id) };
		g_autoptr(GArray) stale = certificate_pkcs11_find_objects(setup.module, setup.session,
		                                                        &stale_id, 1, &error);
		g_assert_no_error(error);
		for (guint i = 0; stale != NULL && i < stale->len; i++)
			setup.module->C_DestroyObject(setup.session,
			                              g_array_index(stale, CK_OBJECT_HANDLE, i));
	}
	g_assert_cmpuint(setup.module->C_GenerateKeyPair(
	                    setup.session, &generation, public_attributes,
	                    G_N_ELEMENTS(public_attributes), private_attributes,
	                    G_N_ELEMENTS(private_attributes), &public_key, &private_key), ==, CKR_OK);
	modulus = certificate_pkcs11_get_attribute(setup.module, setup.session, public_key, CKA_MODULUS);
	g_assert_nonnull(modulus);
	gnutls_datum_t modulus_data = { modulus->data, modulus->len };
	g_assert_cmpint(gnutls_pubkey_init(&verifier), ==, GNUTLS_E_SUCCESS);
	g_assert_cmpint(gnutls_pubkey_import_rsa_raw(verifier, &modulus_data, &exponent_data), ==,
	                GNUTLS_E_SUCCESS);
	g_byte_array_set_size(candidate->cka_id, 0);
	g_byte_array_append(candidate->cka_id, id, sizeof(id));

	session = xcc_session_new("/org/freedesktop/portal/desktop/session/t/queued", NULL, NULL);
	xcc_session_grant(session, candidate, CERTIFICATE_PURPOSE_CLIENT_AUTH, TRUE,
	                  FALSE, 300);
	g_assert_true(certificate_device_open(&session->device, tokens, candidate, &error));
	g_assert_true(certificate_device_login(&session->device, candidate, "123456", &error));
	g_assert_no_error(error);

	certificate_test_prompter_set_delay(5000);
	certificate_test_prompter_expect_password(NULL);
	certificate_test_prompter_expect_password("123456");
	certificate_test_prompter_expect_password("123456");
	certificate_broker_perform(tokens, session, FALSE, "cancel-context", "RSA_PKCS1_V1_5",
	                           parameters, digest, NULL, "Test application", NULL,
	                           context_result, &probes[0]);
	wait_for_password_round(1, 5000);
	if (hold_open)
	{
		g_mutex_init(&gate.lock);
		g_cond_init(&gate.cond);
		certificate_broker_set_open_gate(open_gate_hold, &gate);
	}
	certificate_broker_perform(tokens, session, FALSE, "queued-context", "RSA_PKCS1_V1_5",
	                           parameters, digest, NULL, "Test application", NULL,
	                           context_result, &probes[1]);
	/* Let the second request queue behind the first operation's PIN interaction. */
	settle(300);
	g_assert_cmpuint(probes[0].calls, ==, 0);
	g_assert_cmpuint(probes[1].calls, ==, 0);
	/* The scripted NULL answer is gcr's user cancellation; it arrives after the 5 s delay. */
	certificate_test_prompter_set_delay(40);

	if (hold_open)
	{
		/* A's scripted cancellation arrives 5 s after its prompt opened. */
		deadline = g_get_monotonic_time() + 4 * G_TIME_SPAN_SECOND;
		while (!open_gate_entered(&gate) && g_get_monotonic_time() < deadline)
			settle(20);
		g_assert_true(open_gate_entered(&gate));
		g_assert_cmpuint(probes[0].calls, ==, 0);
		deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
		while (probes[0].calls == 0 && g_get_monotonic_time() < deadline)
			settle(20);
		g_assert_cmpuint(probes[0].calls, ==, 1);
		g_mutex_lock(&session->device_lock);
		g_assert_null(session->device.module);
		g_mutex_unlock(&session->device_lock);
		open_gate_release(&gate);
	}

	deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while ((probes[0].calls == 0 || probes[1].calls == 0) && g_get_monotonic_time() < deadline)
		settle(20);
	g_assert_cmpuint(probes[0].calls, ==, 1);
	g_assert_null(probes[0].signature);
	g_assert_error(probes[0].error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_CANCELLED);
	g_assert_cmpuint(probes[1].calls, ==, 1);
	g_assert_no_error(probes[1].error);
	g_assert_nonnull(probes[1].signature);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 3);
	g_assert_cmpuint(certificate_test_prompter_prompts_created(), ==, 3);
	gnutls_datum_t digest_data = { (unsigned char*) g_bytes_get_data(digest, NULL), 32 };
	gnutls_datum_t signature_data = {
		(unsigned char*) g_bytes_get_data(probes[1].signature, NULL),
		g_bytes_get_size(probes[1].signature)
	};
	g_assert_cmpint(gnutls_pubkey_verify_hash2(verifier, GNUTLS_SIGN_RSA_SHA256, 0,
	                                         &digest_data, &signature_data), >=, 0);

	g_clear_error(&probes[0].error);
	g_bytes_unref(probes[1].signature);
	if (hold_open)
	{
		certificate_broker_set_open_gate(NULL, NULL);
		g_cond_clear(&gate.cond);
		g_mutex_clear(&gate.lock);
	}
	gnutls_pubkey_deinit(verifier);
	certificate_device_close(&session->device);
	xcc_session_close(session);
	g_assert_true(certificate_device_login(&setup, candidate, "123456", &error));
	g_assert_no_error(error);
	/* Logout invalidates private object handles, so resolve both keys again for cleanup. */
	CK_ATTRIBUTE key_id = { CKA_ID, id, sizeof(id) };
	g_autoptr(GArray) keys = certificate_pkcs11_find_objects(setup.module, setup.session,
	                                                       &key_id, 1, &error);
	g_assert_no_error(error);
	g_assert_nonnull(keys);
	g_assert_cmpuint(keys->len, ==, 2);
	for (guint i = 0; i < keys->len; i++)
		g_assert_cmpuint(setup.module->C_DestroyObject(
		                    setup.session, g_array_index(keys, CK_OBJECT_HANDLE, i)), ==, CKR_OK);
	certificate_device_close(&setup);
}

static void test_broker_context_cancel_queued(Fixture* fixture, gconstpointer user_data)
{
	run_context_cancel_queued(FALSE);
}

static void test_broker_context_cancel_before_opened(Fixture* fixture, gconstpointer user_data)
{
	run_context_cancel_queued(TRUE);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

#define ADD(path, function) \
	g_test_add(path, Fixture, NULL, fixture_set_up, function, fixture_tear_down)

	ADD("/pin-system/broker-context-login", test_broker_context_login);
	ADD("/pin-system/broker-context-cancel-queued", test_broker_context_cancel_queued);
	ADD("/pin-system/broker-context-cancel-before-opened",
	    test_broker_context_cancel_before_opened);
	ADD("/pin-system/auto-picks-the-prompter", test_auto_picks_the_prompter);
	ADD("/pin-system/happy-path", test_happy_path);
	ADD("/pin-system/caller-window-is-passed", test_caller_window_is_passed);
	ADD("/pin-system/wrong-pin-then-right", test_wrong_pin_then_right);
	ADD("/pin-system/attempt-cap", test_attempt_cap);
	ADD("/pin-system/cancel-in-the-prompter", test_cancel_in_the_prompter);
	ADD("/pin-system/cancellable-closes-the-prompt", test_cancellable_closes_the_prompt);
	ADD("/pin-system/final-try-warns-before-input", test_final_try_warns_before_input);
	ADD("/pin-system/final-try-cancelled-spends-nothing", test_final_try_cancelled_spends_nothing);
	ADD("/pin-system/refreshed-final-try-warns-before-input", test_refreshed_final_try_warns_before_input);
	ADD("/pin-system/warning-carries-the-token-flags", test_warning_carries_the_token_flags);
	ADD("/pin-system/login-timeout", test_login_timeout);
	ADD("/pin-system/protected-path-asks-for-nothing", test_protected_path_asks_for_nothing);
	ADD("/pin-system/empty-answer-never-reaches-the-card", test_empty_answer_never_reaches_the_card);
	ADD("/pin-system/protected-path-final-try-refused", test_protected_path_final_try_refused);
	ADD("/pin-system/protected-path-final-try-confirmed", test_protected_path_final_try_confirmed);
	ADD("/pin-system/shell-cancel-after-the-pin-was-submitted",
	    test_shell_cancel_after_the_pin_was_submitted);
	ADD("/pin-system/prompter-vanishes-during-password", test_prompter_vanishes_during_password);
	ADD("/pin-system/prompter-vanishes-during-confirm", test_prompter_vanishes_during_confirm);

#undef ADD

#define ADD_STALL(path, setup, function) \
	g_test_add(path, StallFixture, NULL, setup, function, stall_tear_down)

	ADD_STALL("/pin-system/close-racing-a-transport-error", stall_set_up,
	          test_close_racing_a_transport_error);
	ADD_STALL("/pin-system/prompter-vanishes-during-open", stall_set_up_no_ready,
	          test_prompter_vanishes_during_open);

#undef ADD_STALL

	return g_test_run();
}
