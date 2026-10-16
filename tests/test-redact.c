/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <glib.h>
#include <string.h>

#include "certificate.h"
#include "redact.h"

static void test_error_text_is_truncated_before_a_uri(void)
{
	struct
	{
		const char* input;
		const char* expected;
	} cases[] = {
		{ "Failed to open pkcs11:token=Foo;pin-value=1234", "Failed to open (redacted)" },
		{ "pkcs11:token=Foo;pin-value=1234", "(redacted)" },
		{ "the module said pin-value=1234", "the module said (redacted)" },
		{ "reading pin-source=/tmp/x failed", "reading (redacted)" },
		{ "pin-value=1234 while opening pkcs11:token=Foo", "(redacted)" },
		{ "loading pin-value=1234 from pkcs11:token=Foo", "loading (redacted)" },
		{ "at pin-source=/tmp/x for pkcs11:token=Foo", "at (redacted)" },
		{ "CKR_PIN_INCORRECT", "CKR_PIN_INCORRECT" },
		{ NULL, "(no message)" },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		g_autofree char* out = certificate_redact_error_text(cases[i].input);

		g_assert_cmpstr(out, ==, cases[i].expected);
	}
}

static void test_no_pin_attribute_survives(void)
{
	static const char* const inputs[] = {
		"module error: pkcs11:object=x;pin-value=secret;type=private",
		"p11-kit: pin-value=hunter2",
		"gnutls: could not load pkcs11:pin-value=0000",
		NULL,
	};

	for (gsize i = 0; inputs[i] != NULL; i++)
	{
		g_autofree char* out = certificate_redact_error_text(inputs[i]);

		g_assert_null(strstr(out, "pin-value"));
		g_assert_null(strstr(out, "secret"));
		g_assert_null(strstr(out, "hunter2"));
		g_assert_null(strstr(out, "0000"));
	}
}

static void test_serials_are_reduced_to_four_characters(void)
{
	g_autofree char* long_serial = certificate_redact_serial("0123456789abcdef");
	g_autofree char* short_serial = certificate_redact_serial("abc");
	g_autofree char* empty = certificate_redact_serial("");
	g_autofree char* none = certificate_redact_serial(NULL);

	g_assert_cmpstr(long_serial, ==, "****cdef");
	g_assert_null(strstr(long_serial, "0123"));
	g_assert_cmpstr(short_serial, ==, "****");
	g_assert_cmpstr(empty, ==, "(none)");
	g_assert_cmpstr(none, ==, "(none)");
}

static void test_untrusted_text_is_flattened(void)
{
	g_autofree char* multiline =
	    certificate_sanitize_untrusted_text("Sign in\n\nMicrosoft Login\nVerified", 160);
	g_autofree char* controls =
	    certificate_sanitize_untrusted_text("a\x01\x02\x7f b", 160);
	g_autofree char* bidi =
	    certificate_sanitize_untrusted_text("safe\xe2\x80\xaegnp.exe", 160);
	g_autofree char* tabs = certificate_sanitize_untrusted_text("a\tb\r\nc", 160);

	g_assert_nonnull(multiline);
	g_assert_null(strchr(multiline, '\n'));
	g_assert_cmpstr(multiline, ==, "Sign in Microsoft Login Verified");

	g_assert_cmpstr(controls, ==, "a b");
	g_assert_cmpstr(tabs, ==, "a b c");

	g_assert_nonnull(bidi);
	g_assert_null(strstr(bidi, "\xe2\x80\xae"));
}

static void test_untrusted_text_is_capped(void)
{
	g_autofree char* long_input = g_strnfill(1000, 'x');
	g_autofree char* capped = certificate_sanitize_untrusted_text(long_input, 20);

	g_assert_nonnull(capped);
	g_assert_cmpint(g_utf8_strlen(capped, -1), ==, 21);
}

static void test_untrusted_text_that_is_only_whitespace(void)
{
	g_assert_null(certificate_sanitize_untrusted_text("   \n\t  ", 160));
	g_assert_null(certificate_sanitize_untrusted_text("", 160));
	g_assert_null(certificate_sanitize_untrusted_text(NULL, 160));
}

static void test_invalid_utf8_does_not_escape(void)
{
	g_autofree char* out = certificate_sanitize_untrusted_text("ok\xff\xfe", 160);

	g_assert_nonnull(out);
	g_assert_true(g_utf8_validate(out, -1, NULL));
}

static void test_logging_entry_points_are_structural(void)
{
	certificate_log_decision("test", "org.example.App", "derived_host", "client_auth", TRUE);
	certificate_log_grant("test", "/org/freedesktop/portal/desktop/session/1_1/s", "detail");
	certificate_log_operation("test", NULL, "op-1", "ECDSA");
	certificate_log_counts("test", 1, 2);
	certificate_log_debug("test", "detail");
	g_assert_true(TRUE);
}

static void test_logged_fields_are_escaped(void)
{
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "*app_id=org.example.App\\x0aMESSAGE:*");
	certificate_log_decision("test", "org.example.App\nMESSAGE: forged", NULL, NULL, TRUE);
	g_test_assert_expected_messages();
}

static void test_verbose_log_domains(gconstpointer user_data)
{
	const char* requested = user_data;
	g_auto(GStrv) env = NULL;

	if (g_test_subprocess())
	{
		gboolean all = g_strcmp0(requested, "all") == 0;

		g_log_set_debug_enabled(FALSE);
		for (int verbose = FALSE; verbose <= TRUE; verbose++)
		{
			certificate_log_set_verbose(verbose);
			g_assert_cmpint(g_log_writer_default_would_drop(G_LOG_LEVEL_DEBUG, "Gcr"),
			                ==, requested == NULL);
			g_assert_cmpint(g_log_writer_default_would_drop(G_LOG_LEVEL_DEBUG, "Gdk"),
			                ==, requested == NULL);
			g_assert_cmpint(g_log_writer_default_would_drop(G_LOG_LEVEL_DEBUG, "Vulkan"),
			                ==, !all);
			g_assert_cmpint(g_log_writer_default_would_drop(G_LOG_LEVEL_DEBUG, "GLib-GIO"),
			                ==, !all);
			g_assert_cmpint(g_log_writer_default_would_drop(G_LOG_LEVEL_DEBUG, G_LOG_DOMAIN),
			                ==, !(verbose || all));
			g_assert_cmpint(g_log_writer_default_would_drop(G_LOG_LEVEL_DEBUG,
			                                              "pkcs11-portal-certificate"),
			                ==, !(verbose || all));
		}
		return;
	}

	env = g_get_environ();
	env = g_environ_unsetenv(env, "DEBUG_INVOCATION");
	if (requested != NULL)
		env = g_environ_setenv(env, "G_MESSAGES_DEBUG", requested, TRUE);
	else
		env = g_environ_unsetenv(env, "G_MESSAGES_DEBUG");

	g_test_trap_subprocess_with_envp(NULL, (const char* const*) env, 0, 0);
	g_test_trap_assert_passed();
}

static void test_combining_mark_runs_are_capped(void)
{
	g_autofree char* accented = certificate_sanitize_untrusted_text("e\xcc\x81t\xc3\xa9", 80);
	g_autoptr(GString) attack = g_string_new("x");
	g_autofree char* capped = NULL;

	g_assert_nonnull(accented);
	g_assert_cmpstr(accented, ==, "e\xcc\x81t\xc3\xa9");

	for (int i = 0; i < 60; i++)
		g_string_append(attack, "\xcc\x81");

	capped = certificate_sanitize_untrusted_text(attack->str, 200);
	g_assert_nonnull(capped);
	g_assert_cmpuint(g_utf8_strlen(capped, -1), <=, 5);
}

static void test_display_text_falls_back(void)
{
	g_autofree char* empty = certificate_display_text("   \n\t ", 40, "unnamed token");
	g_autofree char* nothing = certificate_display_text(NULL, 40, NULL);
	g_autofree char* kept = certificate_display_text("Portal Test Token", 40, "unnamed token");
	g_autofree char* flattened =
	    certificate_display_text("Thing\n\nSandboxed application, identity verified", 40, NULL);

	g_assert_cmpstr(empty, ==, "unnamed token");
	g_assert_null(nothing);
	g_assert_cmpstr(kept, ==, "Portal Test Token");
	g_assert_null(strchr(flattened, '\n'));
}

static void test_error_text_is_capped_and_escaped(void)
{
	g_autofree char* forged = certificate_redact_error_text("module said\nMESSAGE: forged");
	g_autofree char* long_input = g_strnfill(1000, 'x');
	g_autofree char* capped = certificate_redact_error_text(long_input);
	g_autofree char* both = NULL;
	g_autofree char* prefix = g_strnfill(1000, 'y');
	g_autofree char* with_uri = g_strconcat(prefix, " pkcs11:token=Foo;pin-value=1234", NULL);

	g_assert_null(strchr(forged, '\n'));
	g_assert_nonnull(strstr(forged, "\\x0a"));

	g_assert_cmpuint(strlen(capped), <=, 131);

	both = certificate_redact_error_text(with_uri);
	g_assert_cmpuint(strlen(both), <=, 141);
	g_assert_null(strstr(both, "pin-value"));
	g_assert_nonnull(strstr(both, "(redacted)"));
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/redact/error-text-truncated", test_error_text_is_truncated_before_a_uri);
	g_test_add_func("/redact/no-pin-attribute-survives", test_no_pin_attribute_survives);
	g_test_add_func("/redact/error-text-capped", test_error_text_is_capped_and_escaped);
	g_test_add_func("/redact/serials", test_serials_are_reduced_to_four_characters);
	g_test_add_func("/redact/untrusted-text-flattened", test_untrusted_text_is_flattened);
	g_test_add_func("/redact/untrusted-text-capped", test_untrusted_text_is_capped);
	g_test_add_func("/redact/untrusted-text-whitespace",
	                test_untrusted_text_that_is_only_whitespace);
	g_test_add_func("/redact/untrusted-text-invalid-utf8", test_invalid_utf8_does_not_escape);
	g_test_add_func("/redact/logging-is-structural", test_logging_entry_points_are_structural);
	g_test_add_func("/redact/logged-fields-escaped", test_logged_fields_are_escaped);
	g_test_add_data_func("/redact/verbose-log-domains", NULL, test_verbose_log_domains);
	g_test_add_data_func("/redact/user-debug-domains", "Gcr Gdk", test_verbose_log_domains);
	g_test_add_data_func("/redact/user-all-domains", "all", test_verbose_log_domains);
	g_test_add_func("/redact/combining-mark-runs", test_combining_mark_runs_are_capped);
	g_test_add_func("/redact/display-text-fallback", test_display_text_falls_back);

	return g_test_run();
}
