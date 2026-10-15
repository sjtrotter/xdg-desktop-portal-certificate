/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <glib.h>

#include "pin-prompter.h"
#include "tokens/discovery.h"
#include "ui/pin.h"

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

	certificate_pin_login(script.token, "wayland:handle-123", "Test application",
	                      "prove who you are", script_login, NULL, script_abandon, &script, NULL,
	                      script_done, &script);

	run_until_done(&script, 10000);

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

static void test_final_try_needs_a_second_answer(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autofree char* warning = NULL;

	script.token = make_token();
	script.token->pin_final_try = TRUE;
	script.answers = answers;

	certificate_test_prompter_expect_password(GOOD_PIN);
	certificate_test_prompter_expect_confirm(TRUE);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 1);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "last attempt"));

	script_clear(&script);
}

static void test_final_try_refused_spends_nothing(Fixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.token->pin_final_try = TRUE;
	script.answers = answers;

	certificate_test_prompter_expect_password(GOOD_PIN);
	certificate_test_prompter_expect_confirm(FALSE);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);

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

	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 10000);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "recent failed attempts"));
	g_assert_null(strstr(warning, "2 attempts"));

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

	script.token = make_token();
	script.token->protected_authentication_path = TRUE;
	script.token->pin_final_try = TRUE;
	script.answers = answers;

	certificate_test_prompter_expect_confirm(TRUE);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);
	run_until_done(&script, 10000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_OK);
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_null(script.last_pin);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 0);

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
	script.answers = answers;

	/* Delay each round so prompter loss can occur during final-attempt confirmation. */
	certificate_test_prompter_set_delay(300);
	certificate_test_prompter_expect_password(GOOD_PIN);
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

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

#define ADD(path, function) \
	g_test_add(path, Fixture, NULL, fixture_set_up, function, fixture_tear_down)

	ADD("/pin-system/auto-picks-the-prompter", test_auto_picks_the_prompter);
	ADD("/pin-system/happy-path", test_happy_path);
	ADD("/pin-system/caller-window-is-passed", test_caller_window_is_passed);
	ADD("/pin-system/wrong-pin-then-right", test_wrong_pin_then_right);
	ADD("/pin-system/attempt-cap", test_attempt_cap);
	ADD("/pin-system/cancel-in-the-prompter", test_cancel_in_the_prompter);
	ADD("/pin-system/cancellable-closes-the-prompt", test_cancellable_closes_the_prompt);
	ADD("/pin-system/final-try-needs-a-second-answer", test_final_try_needs_a_second_answer);
	ADD("/pin-system/final-try-refused-spends-nothing", test_final_try_refused_spends_nothing);
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
