/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <adwaita.h>
#include <glib.h>
#include <string.h>

#include "fixture-util.h"
#include "ui/chooser.h"
#include "ui/pin.h"

static void assert_is_safe_display_text(const char* text)
{
	g_assert_nonnull(text);
	g_assert_true(g_utf8_validate(text, -1, NULL));
	g_assert_null(strchr(text, '\n'));
	g_assert_null(strchr(text, '\r'));
	g_assert_null(strchr(text, '\t'));
	g_assert_null(strchr(text, '\033'));
	/* U+202E and U+200B exercise bidi and format-character filtering. */
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

/* GKeyFile expands escaped newlines in desktop-file Name values. */
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

	{
		g_autofree char* long_name = g_strnfill(4000, 'A');
		CertificateCallerIdentity caller = { CERTIFICATE_IDENTITY_DERIVED_HOST,
			                                 (char*) "org.example.App", long_name };
		g_autofree char* text = certificate_chooser_display_name(&caller);

		assert_is_safe_display_text(text);
		g_assert_cmpuint(g_utf8_strlen(text, -1), <=, CERTIFICATE_DISPLAY_MAX_APP_NAME + 1);
	}

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

static void test_expiry_is_a_word(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);

	{
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

	g_assert_cmpuint(g_utf8_strlen(detail, -1), <,
	                 CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL + CERTIFICATE_DISPLAY_MAX_READER + 120);
}

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
	g_assert_null(strstr(detail, " in "));
}

static GtkWidget* find_list(GtkWidget* widget)
{
	if (GTK_IS_LIST_BOX(widget))
		return widget;

	for (GtkWidget* child = gtk_widget_get_first_child(widget); child != NULL;
	     child = gtk_widget_get_next_sibling(child))
	{
		GtkWidget* list = find_list(child);

		if (list != NULL)
			return list;
	}

	return NULL;
}

static void on_chooser_done(const CertificateChooserResult* result, gpointer user_data)
{
	CertificateChooserResult* received = user_data;

	received->chosen = result->chosen;
}

static void test_completion_log_fields(gconstpointer data)
{
	static int has_display = -1;
	gboolean granted = GPOINTER_TO_INT(data);
	g_autoptr(GPtrArray) candidates =
	    g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);
	CertificateCallerIdentity caller = { CERTIFICATE_IDENTITY_DERIVED_HOST,
	                                     g_strdup("org.example.App"), NULL };
	CertificateChooserRequest request = { .caller = &caller,
	                                      .purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                      .may_sign = TRUE,
	                                      .lifetime_seconds = 300 };
	CertificateChooserResult received = { NULL };
	g_autoptr(GtkWindow) window = NULL;
	g_autofree char* expected = NULL;

	if (has_display < 0)
		has_display = gtk_init_check();

	if (!has_display)
	{
		g_free(caller.app_id);
		g_test_skip("no display: the chooser window cannot be opened");
		return;
	}

	adw_init();
	certificate_ui_set_has_display(TRUE);
	g_ptr_array_add(candidates, certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE));

	g_test_expect_message(NULL, G_LOG_LEVEL_MESSAGE,
	                      "chooser-shown app_id=org.example.App identity=host "
	                      "purpose=client_auth granted=no");
	certificate_chooser_show(NULL, NULL, candidates, &request, NULL, on_chooser_done, &received);
	g_test_assert_expected_messages();
	g_clear_pointer(&caller.app_id, g_free);

	g_assert_cmpuint(g_list_model_get_n_items(gtk_window_get_toplevels()), ==, 1);
	window = g_list_model_get_item(gtk_window_get_toplevels(), 0);
	expected = g_strdup_printf("%s app_id=org.example.App identity=host "
	                           "purpose=client_auth granted=%s",
	                           granted ? "consent-granted" : "chooser-cancelled",
	                           granted ? "yes" : "no");
	g_test_expect_message(NULL, G_LOG_LEVEL_MESSAGE, expected);
	if (granted)
	{
		GtkWidget* list = find_list(GTK_WIDGET(window));
		GtkListBoxRow* row = NULL;

		g_assert_nonnull(list);
		row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0);
		gtk_list_box_select_row(GTK_LIST_BOX(list), row);
		g_signal_emit_by_name(list, "row-activated", row);
	}
	else
	{
		gboolean handled = FALSE;

		g_signal_emit_by_name(window, "close-request", &handled);
		g_assert_true(handled);
	}
	g_test_assert_expected_messages();
	g_assert_true(received.chosen == (granted ? g_ptr_array_index(candidates, 0) : NULL));
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
	g_test_add_data_func("/chooser/consent-log-fields", GINT_TO_POINTER(TRUE),
	                     test_completion_log_fields);
	g_test_add_data_func("/chooser/cancel-log-fields", GINT_TO_POINTER(FALSE),
	                     test_completion_log_fields);

	return g_test_run();
}
