/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * THE PIN PROMPT THE DESKTOP SHELL DRAWS, driven end to end without a shell and
 * without a display.
 *
 * On a real session the PIN field belongs to gnome-shell, which cannot be
 * driven from a test and MUST NOT BE: the operator's own shell is not a
 * fixture, and a test that put a prompt on it would be a test that spends a PIN
 * attempt on a card in a reader. gcr ships the server half of the protocol, so
 * tests/pin-prompter.c stands one up on a private GTestDBus bus, owns
 * org.gnome.keyring.SystemPrompter there, and answers from a script.
 *
 * WHAT THAT BUYS BEYOND "IT WORKS": the retry, warning, final-try and
 * attempt-cap logic is finally testable at all. In the GTK path those rules can
 * only be checked by typing into a window; here "wrong PIN, then the right one,
 * on ONE prompt" is three lines and an assertion on the round counter.
 *
 * THE LOGIN IS SYNTHETIC, as in tests/test-cancellation.c: a function that says
 * PIN_INCORRECT or succeeds on command. The point of this suite is the prompt
 * state machine, and a real C_Login only makes the answers less deterministic.
 * The card path is tests/test-broker-device.c and docs/TESTING.md tier 3.
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

	/* The script the synthetic C_Login follows: one entry per attempt. */
	const char** answers; /* "ok", "wrong", "locked", "removed" */
	guint attempts;
	guint block_ms;

	gboolean done_called;
	CertificatePinOutcome outcome;
	guint abandons;
	char* last_pin;
} LoginScript;

static CertificateToken* make_token(void)
{
	/* CertificateToken has no public constructor: it is only ever produced from
	 * a slot, which is why the struct is in the header and why building one by
	 * hand is legitimate here and nowhere else. */
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

/* Run the main loop until the prompt has answered, or fail. Everything here is
 * a private bus and a scripted prompter, so a generous ceiling costs nothing
 * and a hang is still a failure rather than a stuck suite. */
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

/* Give the prompter's own close round trip a chance to land before the counters
 * are read: the answer reaches the caller before the close does. */
static void settle(guint milliseconds)
{
	g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);

	g_timeout_add(milliseconds, quit_loop, loop);
	g_main_loop_run(loop);
}

/* Poll the main loop until @rounds password rounds have STARTED. The counter is
 * incremented on the way in, before the prompter's answer delay, so this says
 * "a round is outstanding" rather than "a round finished". */
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

	/* AUTO, not "system": the point of resolving here is that a bus which has
	 * the prompter name on it is what MAKES the choice. tests/ never touches
	 * the real session bus, and the module default is gtk, so no other suite
	 * can reach a prompter by accident. */
	g_assert_true(certificate_pin_set_prompt_kind("auto", NULL));

	/* There is no display in this suite and there must not need to be. */
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

	/* Back to the safe default for whatever runs next in this process. */
	g_assert_true(certificate_pin_set_prompt_kind("gtk", NULL));
	certificate_pin_set_login_timeout(60);
}

/* THE SELECTION ITSELF. "auto" on a bus that has the name resolves to the
 * system prompter -- and resolving it is what every test below depends on. */
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

	/* WHAT THE SHELL WAS ASKED TO SHOW. The application, the purpose and the
	 * token are in the prompt, so a request that arrives on its own is still
	 * attributable -- the same rule the GTK window follows. */
	title = certificate_test_prompter_last_title();
	description = certificate_test_prompter_last_description();
	g_assert_cmpstr(title, ==, "Unlock Security Token");
	g_assert_nonnull(strstr(description, "Test application"));
	g_assert_nonnull(strstr(description, "System Prompt Test Token"));
	g_assert_nonnull(strstr(description, "Test reader"));

	/* NEVER "REMEMBER". A NULL choice-label is what makes a prompter draw no
	 * checkbox, and there is no code path in this repository that sets one. */
	/* An EMPTY choice-label, which is what a NULL one becomes on the wire: gcr
	 * transports properties as a vardict and a GVariant "s" cannot be NULL, so
	 * the prompter sees "". Empty is what makes a prompter draw no checkbox;
	 * what matters, and what is asserted, is that no label ever has text in it. */
	choice = certificate_test_prompter_last_choice_label();
	g_assert_true(choice == NULL || *choice == '\0');
	g_assert_false(certificate_test_prompter_last_password_new());

	script_clear(&script);
}

/* THE PARENT WINDOW HANDLE reaches the prompter with the portal's scheme
 * stripped, which is the form GcrPrompt:caller-window documents. What a
 * prompter does with it is its own business, and gnome-shell's does nothing. */
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

/* ONE PROMPT, TWO ATTEMPTS. The refusal has to come back as a WARNING on the
 * prompt that is already up, not as a second prompt: a user who is asked twice
 * without being told why is a user learning to type a PIN whenever asked. */
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

/* THREE ATTEMPTS AND NO MORE. The cap is a bound on one prompt: the caller may
 * ask again, which is a new decision rather than a habit. */
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

	/* NULL is gcr's "the user pressed Cancel". */
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

/* Request.Close(), or the frontend vanishing: our own GCancellable takes the
 * prompt off the shell. */
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

/* THE LAST ATTEMPT IS NOT SPENT ON A SINGLE ANSWER. With
 * CKF_USER_PIN_FINAL_TRY set, the prompt must ask a second time before the
 * login goes out -- the same rule as the GTK window's second Unlock. */
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
	g_assert_nonnull(strstr(warning, "LAST attempt"));

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
	/* THE POINT OF THE WHOLE MECHANISM: the card was never asked. */
	g_assert_cmpuint(script.attempts, ==, 0);

	script_clear(&script);
}

/* THE TOKEN'S OWN RETRY STATE, and never a count. */
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
	/* Not a number. PKCS#11 cannot tell us one, so nothing may print one. */
	g_assert_null(strstr(warning, "2 attempts"));

	script_clear(&script);
}

/* A C_LOGIN THAT NEVER COMES BACK. The prompt comes down, the interaction
 * fails with its own outcome, and the caller is answered when the module
 * finally returns -- which is the honest bound, because PKCS#11 cannot
 * withdraw a submitted login. */
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
	/* The login landed after the prompt was given up on, so it is undone. */
	g_assert_cmpuint(script.abandons, ==, 1);

	script_clear(&script);
}

/* A PROTECTED AUTHENTICATION PATH HAS NO FIELD ANYWHERE, the shell's included:
 * the reader collects the secret and the login goes out with a NULL PIN. */
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

/* AN EMPTY ANSWER IS NOT AN ATTEMPT. A stray Return in the shell's field used
 * to arrive here as "", be copied into the locked page, and be handed to
 * C_Login -- spending one of the three the card has on a string PKCS#11 says
 * nothing about. The rule lives in ui/pin.c so that BOTH implementations obey
 * it; what the prompter sees is the same prompt, asked again. */
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
	/* THE POINT OF THE WHOLE THING: one login, not two. */
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_cmpstr(script.last_pin, ==, GOOD_PIN);

	/* And it was re-asked on the prompt that was already up, with a warning. */
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 2);
	g_assert_cmpuint(certificate_test_prompter_prompts_created(), ==, 1);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "Enter the PIN"));

	script_clear(&script);
}

/* A PROTECTED AUTHENTICATION PATH ON ITS LAST ATTEMPT IS STILL ON ITS LAST
 * ATTEMPT. The reader collects the digits, so there is no field to type into --
 * but the NULL-PIN login still spends the try that locks the card, and it used
 * to go out the instant the prompt appeared, with the confirmation running
 * beside it rather than in front of it. */
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
	/* THE CARD WAS NEVER ASKED. */
	g_assert_cmpuint(script.attempts, ==, 0);
	g_assert_cmpuint(script.abandons, ==, 0);
	g_assert_cmpuint(certificate_test_prompter_confirm_rounds(), ==, 1);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 0);

	warning = certificate_test_prompter_last_warning();
	g_assert_nonnull(warning);
	g_assert_nonnull(strstr(warning, "LAST attempt"));

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
	/* The reader collected it: nothing on screen was sent to the token. */
	g_assert_null(script.last_pin);
	g_assert_cmpuint(certificate_test_prompter_password_rounds(), ==, 0);

	script_clear(&script);
}

/* CANCEL IN THE SHELL AFTER THE PIN HAS GONE TO THE CARD. No round is
 * outstanding by then, so nothing this backend was waiting on ever comes back
 * -- gnome-shell simply stops prompting and gcr's prompt emits prompt-close.
 * Before that signal was connected the interaction carried on to PIN_OK and the
 * grant would sign, for a request the user had just refused.
 *
 * What must happen instead is ui/pin.c's round-2 path: the answer is CANCELLED,
 * the login that nonetheless succeeded is logged, and it is ABANDONED so the
 * token is not left authenticated. */
static void test_shell_cancel_after_the_pin_was_submitted(Fixture* fixture,
                                                          gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };

	script.token = make_token();
	script.answers = answers;
	/* Long enough that the dismissal lands while C_Login is still running. */
	script.block_ms = 1500;

	certificate_test_prompter_expect_password(GOOD_PIN);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, script_abandon, &script, NULL, script_done,
	                      &script);

	wait_for_password_round(1, 5000);
	settle(400); /* the answer, the submit, and the worker started */
	g_assert_cmpuint(script.attempts, ==, 1);
	g_assert_false(script.done_called);

	certificate_test_prompter_dismiss();

	run_until_done(&script, 20000);
	settle(300);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 1);
	/* The login landed after the cancel, so it is undone. */
	g_assert_cmpuint(script.abandons, ==, 1);

	script_clear(&script);
}

/* THE PROMPTER DISAPPEARING IS NOT A REASON TO WAIT FOR EVER. gcr makes a
 * cancellation of its own when the prompter's bus name vanishes
 * (gcr/gcr-system-prompt.c, on_prompter_vanished), and G_IO_ERROR_CANCELLED
 * used to be swallowed on every one of these paths -- which left the caller
 * unanswered and ui/pin.c's single prompt slot occupied for the life of the
 * process, so no later request could ever put a prompt up either. */
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

	/* AND THE SLOT IS FREE. A second request must still be able to try; before
	 * the fix it was queued behind a prompt that would never be answered. */
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

	/* The password round is answered after this long; the confirmation round it
	 * arms is then left outstanding for the same again, which is the window the
	 * prompter is made to vanish in. */
	certificate_test_prompter_set_delay(300);
	certificate_test_prompter_expect_password(GOOD_PIN);
	certificate_test_prompter_expect_confirm(TRUE);

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, NULL, script_done, &script);

	wait_for_confirm_round(1, 10000);
	certificate_test_prompter_vanish(fixture->prompter);

	run_until_done(&script, 15000);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_DEVICE_ERROR);
	/* The confirmation never came back, so the last attempt was not spent. */
	g_assert_cmpuint(script.attempts, ==, 0);

	certificate_test_prompter_set_delay(40);
	script_clear(&script);
}

/* ------------------------------------------- against a prompter that answers nothing */

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

/* THE ROUND THAT COMES BACK TWICE, which is the whole reason every gcr callback
 * in src/ui/pin-system.c claims its result before it touches anything.
 *
 * gcr 4.4, gcr/gcr-system-prompt.c:
 *
 *   perform_prompt_async() puts the PerformPrompt result in ->pending.
 *   perform_close() -- which gcr_prompt_close() reaches -- takes ->pending and
 *   completes it from an idle. That is completion one, and it is the one that
 *   drops the reference the round held; here it is the LAST reference, so the
 *   PinPrompt and its SystemPinPrompt are freed inside it.
 *   on_perform_prompt_complete() then lands with the transport error and calls
 *   g_simple_async_result_complete() on the same result. That is completion
 *   two, on freed memory.
 *
 * Passing no GCancellable does not help: nothing here cancelled anything. The
 * prompter simply failed a call that was still on the wire when the prompt was
 * closed. Under -Db_sanitize=address this test is a heap-use-after-free without
 * the guard, and a pair of quiet returns with it. */
static void test_close_racing_a_transport_error(StallFixture* fixture, gconstpointer user_data)
{
	LoginScript script = { 0 };
	const char* answers[] = { "ok" };
	g_autoptr(GCancellable) cancellable = g_cancellable_new();

	script.token = make_token();
	script.answers = answers;

	certificate_pin_login(script.token, NULL, "Test application", "prove who you are",
	                      script_login, NULL, NULL, &script, cancellable, script_done, &script);

	/* The open has completed and the password round is on the wire, unanswered. */
	for (guint i = 0; i < 100 && !certificate_test_stalling_prompter_is_performing(
	                                 fixture->prompter);
	     i++)
		settle(20);
	g_assert_true(certificate_test_stalling_prompter_is_performing(fixture->prompter));

	/* Request.Close(): the prompt is closed, gcr completes the round in flight
	 * as a dismissal, and this backend answers and lets go of everything. */
	g_cancellable_cancel(cancellable);
	run_until_done(&script, 10000);
	settle(300);

	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);

	/* And NOW the call that was left on the wire fails, which is gcr's second
	 * completion of the round this backend has already finished with.
	 *
	 * THE MESSAGE IS THE ASSERTION. What the second run would do without the
	 * guard is read freed memory, and a read of freed memory is not observable
	 * from a test unless the test is running under a sanitizer -- so the guard
	 * says so in the journal, and this insists on hearing it. Remove
	 * round_claim()'s check and g_test_assert_expected_messages() fails here. */
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "pin-prompt-round-completed-twice*");
	certificate_test_stalling_prompter_fail_perform(fixture->prompter);
	settle(500);
	g_test_assert_expected_messages();

	/* Nothing more happened: the second completion was ignored, not acted on. */
	g_assert_cmpint(script.outcome, ==, CERTIFICATE_PIN_CANCELLED);
	g_assert_cmpuint(script.attempts, ==, 0);

	script_clear(&script);
}

/* THE PROMPTER VANISHING WHILE THE OPEN IS STILL WAITING. gcr answers the open
 * with G_IO_ERROR_CANCELLED, which this file used to return quietly on -- and
 * before any login has been submitted the login timeout cannot rescue it, so
 * the caller waited for ever and so did everything queued behind it. */
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
