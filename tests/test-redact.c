/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * The redaction rules. The important tests here are the NEGATIVE ones: a
 * library error string carrying a PKCS#11 URI with a pin-value attribute must
 * be truncated before the URI, and caller-supplied text must not be able to
 * draw chrome of its own.
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
		{ "CKR_PIN_INCORRECT", "CKR_PIN_INCORRECT" },
		{ NULL, "(no message)" },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		g_autofree char* out = certificate_redact_error_text(cases[i].input);

		g_assert_cmpstr(out, ==, cases[i].expected);
	}
}

/* Whatever else changes, the string "pin-value" must never survive the
 * redactor, because that is the attribute a PIN travels in. */
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

/* NOTHING CALLER-SUPPLIED MAY DRAW ITS OWN CHROME. A reason that contains
 * newlines, control characters or bidi overrides must come out as one plain
 * line. */
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

	/* U+202E RIGHT-TO-LEFT OVERRIDE is a format character and does not
	 * survive. */
	g_assert_nonnull(bidi);
	g_assert_null(strstr(bidi, "\xe2\x80\xae"));
}

static void test_untrusted_text_is_capped(void)
{
	g_autofree char* long_input = g_strnfill(1000, 'x');
	g_autofree char* capped = certificate_sanitize_untrusted_text(long_input, 20);

	g_assert_nonnull(capped);
	/* Twenty characters plus a one-character ellipsis. */
	g_assert_cmpint(g_utf8_strlen(capped, -1), ==, 21);
}

/* Text that is empty once cleaned yields NULL, so that a caller cannot reserve
 * a labelled, framed area of the window with whitespace. */
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

/* THE LOGGING ENTRY POINTS TAKE NO FORMAT STRING. This test does not assert on
 * output; it exists so that the compiler checks the signatures stay as they
 * are, and so that a future certificate_log_printf() has to delete a test that
 * says why it must not exist. */
static void test_logging_entry_points_are_structural(void)
{
	certificate_log_decision("test", "org.example.App", "derived_host", "client_auth", TRUE);
	certificate_log_grant("test", "/org/freedesktop/portal/desktop/session/1_1/s", "detail");
	certificate_log_operation("test", NULL, "op-1", "ECDSA");
	certificate_log_counts("test", 1, 2);
	certificate_log_debug("test", "detail");
	g_assert_true(TRUE);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/redact/error-text-truncated", test_error_text_is_truncated_before_a_uri);
	g_test_add_func("/redact/no-pin-attribute-survives", test_no_pin_attribute_survives);
	g_test_add_func("/redact/serials", test_serials_are_reduced_to_four_characters);
	g_test_add_func("/redact/untrusted-text-flattened", test_untrusted_text_is_flattened);
	g_test_add_func("/redact/untrusted-text-capped", test_untrusted_text_is_capped);
	g_test_add_func("/redact/untrusted-text-whitespace",
	                test_untrusted_text_that_is_only_whitespace);
	g_test_add_func("/redact/untrusted-text-invalid-utf8", test_invalid_utf8_does_not_escape);
	g_test_add_func("/redact/logging-is-structural", test_logging_entry_points_are_structural);

	return g_test_run();
}
