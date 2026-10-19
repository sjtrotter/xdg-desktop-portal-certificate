/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <adwaita.h>
#include <glib.h>
#include <string.h>

#include "fixture-util.h"
#include "core/chooser.h"
#include "core/pin.h"
#include "ui/pin-backends.h"
#include "ui/chooser.h"

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

static void test_purpose_wording(void)
{
	static const struct
	{
		CertificatePurpose purpose;
		const char* expected;
	} cases[] = {
		{ CERTIFICATE_PURPOSE_CLIENT_AUTH, "prove who you are to a server" },
		{ CERTIFICATE_PURPOSE_SIGNING, "sign a document or a piece of data" },
		{ CERTIFICATE_PURPOSE_EMAIL, "sign or read secure email" },
		{ CERTIFICATE_PURPOSE_SSH, "authenticate an SSH connection" },
	};
	static const struct
	{
		const char* handle;
		gboolean module;
	} handles[] = {
		{ NULL, FALSE },
		{ "/org/freedesktop/portal/desktop/request/1_42/native", FALSE },
		{ "/org/freedesktop/portal/desktop/request/pkcs11a/native", FALSE },
		{ "/org/freedesktop/portal/desktop/request/1_42/pkcs11a123_2", TRUE },
		{ "/org/freedesktop/portal/desktop/request/1_42/pkcs11a123_2/456", TRUE },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		for (gsize j = 0; j < G_N_ELEMENTS(handles); j++)
		{
			CertificateChooserRequest request = { 0 };
			g_autofree char* text = NULL;
			g_autofree char* expected = NULL;

			request.purpose = cases[i].purpose;
			request.request_handle = handles[j].handle;
			request.reason = "Application-provided explanation";
			text = certificate_chooser_format_purpose(&request);
			g_assert_cmpint(certificate_chooser_is_generic_purpose(&request), ==, handles[j].module);

			if (handles[j].module)
			{
				g_assert_cmpstr(text, ==,
				                "is asking to use a certificate on your security token.");
				g_assert_cmpstr(certificate_chooser_purpose_detail(&request), ==,
				                "The application will be able to use this key until the "
				                "grant expires. It cannot read the private key.");
			}
			else
			{
				expected = g_strdup_printf("wants to use a certificate on your security "
				                           "token to %s.", cases[i].expected);
				g_assert_cmpstr(text, ==, expected);
				g_assert_cmpstr(certificate_chooser_purpose_detail(&request), ==,
				                certificate_purpose_detail(cases[i].purpose));
			}
		}
	}
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

	g_test_expect_message("xdg-desktop-portal-certificate", G_LOG_LEVEL_MESSAGE,
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
	g_test_expect_message("xdg-desktop-portal-certificate", G_LOG_LEVEL_MESSAGE, expected);
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

static GtkWidget* find_text(GtkWidget* widget, const char* text)
{
	if ((GTK_IS_LABEL(widget) &&
	     g_strcmp0(gtk_label_get_text(GTK_LABEL(widget)), text) == 0) ||
	    (GTK_IS_BUTTON(widget) &&
	     g_strcmp0(gtk_button_get_label(GTK_BUTTON(widget)), text) == 0))
		return widget;

	for (GtkWidget* child = gtk_widget_get_first_child(widget); child != NULL;
	     child = gtk_widget_get_next_sibling(child))
	{
		GtkWidget* found = find_text(child, text);

		if (found != NULL)
			return found;
	}
	return NULL;
}

typedef struct
{
	guint calls;
	gboolean cancelled;
} EmptyResult;

static void on_empty_done(const CertificateChooserResult* result, gpointer user_data)
{
	EmptyResult* received = user_data;

	received->calls++;
	received->cancelled = result->chosen == NULL;
}

typedef struct
{
	guint calls;
	char* text;
} Announcement;

static void on_announcement(const char* text, gpointer user_data)
{
	Announcement* announcement = user_data;
	g_autoptr(GtkWindow) window = g_list_model_get_item(gtk_window_get_toplevels(), 0);

	g_assert_nonnull(window);
	g_assert_true(gtk_widget_get_realized(GTK_WIDGET(window)));
	g_assert_true(gtk_widget_get_mapped(GTK_WIDGET(window)));
	announcement->calls++;
	g_free(announcement->text);
	announcement->text = g_strdup(text);
}

static void assert_focus_in_list(GtkWindow* window, GtkWidget* list)
{
	GtkWidget* focus = gtk_root_get_focus(GTK_ROOT(window));

	g_assert_nonnull(focus);
	g_assert_true(focus == list || gtk_widget_is_ancestor(focus, list));
}

static void test_empty_and_updates(gconstpointer data)
{
	gboolean tokens_present = GPOINTER_TO_INT(data);
	g_autoptr(GPtrArray) empty = g_ptr_array_new();
	g_autoptr(GPtrArray) candidates =
	    g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);
	CertificateCallerIdentity caller = { CERTIFICATE_IDENTITY_DERIVED_HOST,
	                                     (char*) "org.example.App", NULL };
	CertificateChooserRequest request = { .caller = &caller,
	                                      .purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                      .may_sign = TRUE,
	                                      .lifetime_seconds = 300,
	                                      .tokens_present = tokens_present };
	EmptyResult received = { 0 };
	Announcement announcement = { 0 };
	gint64 deadline;
	CertificateChooser* chooser;
	g_autoptr(GtkWindow) window = NULL;
	GtkWidget* list;
	GtkWidget* use;
	GtkWidget* cancel;
	GtkWidget* neutral;
	GtkWidget* detail;
	CertificateCandidate* candidate;

	if (!gtk_init_check())
	{
		g_test_skip("no display: the chooser window cannot be opened");
		return;
	}
	adw_init();
	certificate_ui_set_has_display(TRUE);
	certificate_chooser_set_announce_hook(on_announcement, &announcement);
	g_test_expect_message("xdg-desktop-portal-certificate", G_LOG_LEVEL_MESSAGE,
	                      "chooser-shown app_id=org.example.App identity=host "
	                      "purpose=client_auth granted=no");
	chooser = certificate_chooser_show(NULL, NULL, empty, &request, NULL,
	                                   on_empty_done, &received);
	g_test_assert_expected_messages();
	g_assert_nonnull(chooser);
	g_assert_cmpuint(g_list_model_get_n_items(gtk_window_get_toplevels()), ==, 1);
	window = g_list_model_get_item(gtk_window_get_toplevels(), 0);
	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (announcement.calls == 0 && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);
	g_assert_cmpuint(announcement.calls, ==, 1);
	g_assert_cmpstr(announcement.text, ==, tokens_present
	    ? "Insert your security token. No certificate on the inserted token can be used for this request"
	    : "Insert your security token");
	list = find_list(GTK_WIDGET(window));
	use = find_text(GTK_WIDGET(window), "_Use Certificate");
	cancel = find_text(GTK_WIDGET(window), "_Cancel");
	neutral = find_text(GTK_WIDGET(window), "Insert your security token");
	detail = find_text(GTK_WIDGET(window),
	                   "No certificate on the inserted token can be used for this request");
	g_assert_nonnull(list);
	g_assert_nonnull(use);
	g_assert_nonnull(cancel);
	g_assert_nonnull(neutral);
	g_assert_nonnull(detail);
	g_assert_true(gtk_widget_get_visible(neutral));
	g_assert_cmpint(gtk_widget_get_visible(detail), ==, tokens_present);
	g_assert_false(gtk_widget_get_sensitive(use));
	g_assert_true(gtk_widget_get_focusable(cancel));
	g_assert_true(gtk_root_get_focus(GTK_ROOT(window)) == cancel);
	g_assert_null(gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));
	g_assert_cmpuint(received.calls, ==, 0);

	candidate = certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	candidate->cka_id = g_byte_array_new();
	g_byte_array_append(candidate->cka_id, (const guint8*) "one", 3);
	g_ptr_array_add(candidates, candidate);
	certificate_chooser_update(chooser, candidates, TRUE);
	g_assert_false(gtk_widget_get_visible(neutral));
	g_assert_false(gtk_widget_get_visible(detail));
	g_assert_nonnull(gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));
	g_assert_false(gtk_widget_get_sensitive(use));
	gtk_list_box_select_row(GTK_LIST_BOX(list),
	                        gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));
	g_assert_true(gtk_widget_grab_focus(GTK_WIDGET(
	    gtk_list_box_get_selected_row(GTK_LIST_BOX(list)))));
	assert_focus_in_list(window, list);
	g_assert_true(gtk_widget_get_sensitive(use));
	certificate_chooser_update(chooser, candidates, TRUE);
	g_assert_nonnull(gtk_list_box_get_selected_row(GTK_LIST_BOX(list)));
	g_assert_true(gtk_widget_get_sensitive(use));
	g_assert_true(gtk_root_get_focus(GTK_ROOT(window)) ==
	              GTK_WIDGET(gtk_list_box_get_selected_row(GTK_LIST_BOX(list))));

	gtk_list_box_unselect_all(GTK_LIST_BOX(list));
	certificate_chooser_update(chooser, candidates, TRUE);
	assert_focus_in_list(window, list);
	g_assert_false(gtk_widget_get_sensitive(use));
	gtk_list_box_select_row(GTK_LIST_BOX(list),
	                        gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));
	/* A surviving row without the selected key keeps focus in the list. */
	{
		g_autoptr(GPtrArray) replacement =
		    g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);
		CertificateCandidate* other = certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);

		other->cka_id = g_byte_array_new();
		g_byte_array_append(other->cka_id, (const guint8*) "two", 3);
		g_ptr_array_add(replacement, other);
		certificate_chooser_update(chooser, replacement, TRUE);
		g_assert_null(gtk_list_box_get_selected_row(GTK_LIST_BOX(list)));
		assert_focus_in_list(window, list);
	}

	certificate_chooser_update(chooser, empty, FALSE);
	g_assert_null(gtk_list_box_get_selected_row(GTK_LIST_BOX(list)));
	g_assert_false(gtk_widget_get_sensitive(use));
	g_assert_true(gtk_widget_get_visible(neutral));
	g_assert_false(gtk_widget_get_visible(detail));
	g_assert_true(gtk_root_get_focus(GTK_ROOT(window)) == cancel);
	g_assert_cmpuint(announcement.calls, ==, 2);
	g_assert_cmpstr(announcement.text, ==, "Insert your security token");
	g_test_expect_message("xdg-desktop-portal-certificate", G_LOG_LEVEL_MESSAGE,
	                      "chooser-cancelled app_id=org.example.App identity=host "
	                      "purpose=client_auth granted=no");
	g_signal_emit_by_name(cancel, "clicked");
	g_test_assert_expected_messages();
	g_assert_cmpuint(received.calls, ==, 1);
	g_assert_true(received.cancelled);
	certificate_chooser_set_announce_hook(NULL, NULL);
	g_free(announcement.text);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	certificate_pin_set_provider(certificate_pin_provider_gtk());
	certificate_chooser_set_provider(certificate_chooser_provider_gtk());

	g_test_add_func("/chooser/purpose-wording", test_purpose_wording);
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

	g_test_add_data_func("/chooser/empty-no-token", GINT_TO_POINTER(FALSE),
	                     test_empty_and_updates);
	g_test_add_data_func("/chooser/empty-no-match", GINT_TO_POINTER(TRUE),
	                     test_empty_and_updates);

	return g_test_run();
}
