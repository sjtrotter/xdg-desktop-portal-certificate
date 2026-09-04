/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * THE STRINGS THE CONSENT WINDOW PUTS IN FRONT OF THE USER.
 *
 * src/ui/chooser.c had no automated coverage at all: the impl suite turns the
 * display off, so every path there answers no_display before a chooser is
 * built. The window itself needs a display and a person, and neither is
 * available to `meson test` -- but the text it renders is where a hostile card
 * label or a hostile desktop file would do its work, and that text comes out of
 * pure functions.
 *
 * WHAT IS BEING ASSERTED IS THE SECURITY PROPERTY, not the wording: nothing
 * that came off a card or out of ~/.local/share/applications may add a line, an
 * escape sequence, a direction override, or unbounded length to a window that
 * carries a security decision.
 */

#include <glib.h>
#include <string.h>

#include "fixture-util.h"
#include "ui/chooser.h"

/* One line, no controls, no ANSI, and no bidi overrides. Applied to every
 * string these helpers produce, whatever it was made of. */
static void assert_is_safe_display_text(const char* text)
{
	g_assert_nonnull(text);
	g_assert_true(g_utf8_validate(text, -1, NULL));
	g_assert_null(strchr(text, '\n'));
	g_assert_null(strchr(text, '\r'));
	g_assert_null(strchr(text, '\t'));
	g_assert_null(strchr(text, '\033'));
	/* U+202E RIGHT-TO-LEFT OVERRIDE and U+200B ZERO WIDTH SPACE, the two that
	 * make a label read as something it is not. */
	g_assert_null(strstr(text, "\xe2\x80\xae"));
	g_assert_null(strstr(text, "\xe2\x80\x8b"));
}

static void test_lifetime_wording(void)
{
	static const struct
	{
		guint32 seconds;
		const char* expected;
	} cases[] = {
		{ 1, "1 seconds" },   { 119, "119 seconds" }, { 120, "2 minutes" },
		{ 300, "5 minutes" }, { 301, "6 minutes" },   { 7199, "120 minutes" },
		{ 7200, "2 hours" },  { 3600, "60 minutes" }, { 10800, "3 hours" },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		g_autofree char* text = certificate_chooser_format_lifetime(cases[i].seconds);

		g_assert_cmpstr(text, ==, cases[i].expected);
	}
}

/* THE TRUSTED IDENTITY POSITION. The desktop file's Name= is writable by any
 * unsandboxed process and by any Flatpak with home access, and GKeyFile
 * unescapes \n in it: a name of "Bank\nVerified by the system" would otherwise
 * put a second line of chrome under the heading. */
static void test_display_name_cannot_draw_chrome(void)
{
	{
		CertificateCallerIdentity caller = { CERTIFICATE_IDENTITY_DERIVED_HOST,
			                                 (char*) "org.example.App",
			                                 (char*) "Bank\nVerified by the system" };
		g_autofree char* text = certificate_chooser_display_name(&caller);

		assert_is_safe_display_text(text);
		g_assert_null(strstr(text, "\nVerified"));
	}

	/* Capped, so that a very long name cannot push the level statement off the
	 * window. */
	{
		g_autofree char* long_name = g_strnfill(4000, 'A');
		CertificateCallerIdentity caller = { CERTIFICATE_IDENTITY_DERIVED_HOST,
			                                 (char*) "org.example.App", long_name };
		g_autofree char* text = certificate_chooser_display_name(&caller);

		assert_is_safe_display_text(text);
		/* The cap plus the one ellipsis that says it was cut. */
		g_assert_cmpuint(g_utf8_strlen(text, -1), <=, CERTIFICATE_DISPLAY_MAX_APP_NAME + 1);
	}

	/* No name: the app id. No app id either: a fixed phrase, never an empty
	 * heading a caller could have reserved with whitespace. */
	{
		CertificateCallerIdentity with_id = { CERTIFICATE_IDENTITY_DERIVED_HOST,
			                                  (char*) "org.example.App", NULL };
		CertificateCallerIdentity with_nothing = { CERTIFICATE_IDENTITY_UNKNOWN, (char*) "",
			                                       (char*) "   " };
		g_autofree char* from_id = certificate_chooser_display_name(&with_id);
		g_autofree char* from_nothing = certificate_chooser_display_name(&with_nothing);

		g_assert_cmpstr(from_id, ==, "org.example.App");
		g_assert_cmpstr(from_nothing, ==, "An unidentified application");
	}
}

/* EXPIRY IS A WORD, NOT A COLOUR: it has to survive a monochrome screen and a
 * screen reader, so the fact is in the string. */
static void test_expiry_is_a_word(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);

	{
		/* One second after the certificate stopped being valid. */
		g_autofree char* text =
		    certificate_chooser_format_expiry(candidate, candidate->not_after + 1);

		assert_is_safe_display_text(text);
		g_assert_nonnull(strstr(text, "EXPIRED"));
	}

	{
		g_autofree char* text =
		    certificate_chooser_format_expiry(candidate, candidate->not_before - 1);

		assert_is_safe_display_text(text);
		g_assert_cmpstr(text, ==, "NOT YET VALID");
	}

	{
		g_autofree char* text =
		    certificate_chooser_format_expiry(candidate, candidate->not_before + 1);

		assert_is_safe_display_text(text);
		g_assert_nonnull(strstr(text, "Valid until"));
	}
}

/* THE TOKEN LABEL AND THE READER NAME COME OFF A CARD, and a card can be handed
 * to a user by somebody who is not a friend. */
static void test_detail_line_sanitises_the_card(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autofree char* hostile = g_strdup("Bank\n\033[2KVerified\xe2\x80\xae by the system");
	g_autofree char* detail = NULL;

	certificate_test_attach_token(candidate, hostile, NULL);
	g_clear_pointer(&candidate->token->reader_name, g_free);
	candidate->token->reader_name = g_strnfill(4000, 'R');

	detail = certificate_chooser_format_detail(candidate, candidate->not_before + 1);

	assert_is_safe_display_text(detail);
	g_assert_nonnull(strstr(detail, "Valid until"));
	g_assert_nonnull(strstr(detail, "RSA"));

	/* Both card strings are capped, so the row cannot be made to fill the
	 * window and push the rest of the list out of view. */
	g_assert_cmpuint(g_utf8_strlen(detail, -1), <,
	                 CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL + CERTIFICATE_DISPLAY_MAX_READER + 120);
}

/* An empty token label is not an empty gap in the row: the fallback wording is
 * used, so the user is told there is a token and that it has no name. */
static void test_detail_line_has_a_fallback(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autofree char* detail = NULL;

	certificate_test_attach_token(candidate, "   ", NULL);
	g_clear_pointer(&candidate->token->reader_name, g_free);

	detail = certificate_chooser_format_detail(candidate, candidate->not_before + 1);

	assert_is_safe_display_text(detail);
	g_assert_nonnull(strstr(detail, "unnamed token"));
	/* No reader, so no " in " clause rather than a dangling one. */
	g_assert_null(strstr(detail, " in "));
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/chooser/lifetime-wording", test_lifetime_wording);
	g_test_add_func("/chooser/display-name-cannot-draw-chrome",
	                test_display_name_cannot_draw_chrome);
	g_test_add_func("/chooser/expiry-is-a-word", test_expiry_is_a_word);
	g_test_add_func("/chooser/detail-line-sanitises-the-card",
	                test_detail_line_sanitises_the_card);
	g_test_add_func("/chooser/detail-line-has-a-fallback", test_detail_line_has_a_fallback);

	return g_test_run();
}
