/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "chooser.h"

#include <string.h>

static gboolean is_module_request(const CertificateChooserRequest* request)
{
	static const char prefix[] = "/org/freedesktop/portal/desktop/request/";
	const char* token = NULL;

	if (request->request_handle == NULL || !g_str_has_prefix(request->request_handle, prefix))
		return FALSE;

	token = strchr(request->request_handle + strlen(prefix), '/');

	/* The module's request-token prefix selects wording only, not permissions or identity. */
	return token != NULL && g_str_has_prefix(token + 1, "pkcs11a");
}

char* certificate_chooser_format_purpose(const CertificateChooserRequest* request)
{
	if (is_module_request(request))
		return g_strdup("is asking to use a certificate on your security token.");

	return g_strdup_printf("wants to use a certificate on your security token to %s.",
	                       certificate_purpose_display(request->purpose));
}

const char* certificate_chooser_purpose_detail(const CertificateChooserRequest* request)
{
	if (is_module_request(request))
		return "The application will be able to use this key until the "
		       "grant expires. It cannot read the private key.";

	return certificate_purpose_detail(request->purpose);
}

char* certificate_chooser_format_lifetime(guint32 seconds)
{
	if (seconds < 120)
		return g_strdup_printf("%u seconds", seconds);

	if (seconds < 7200)
		return g_strdup_printf("%u minutes", (seconds + 59) / 60);

	return g_strdup_printf("%u hours", (seconds + 3599) / 3600);
}

char* certificate_chooser_display_name(const CertificateCallerIdentity* caller)
{
	/* Desktop-file Name values are writable external input and may contain escaped newlines. */
	g_autofree char* app_name =
	    certificate_display_text(caller->app_display_name, CERTIFICATE_DISPLAY_MAX_APP_NAME, NULL);
	g_autofree char* app_id =
	    certificate_display_text(caller->app_id, CERTIFICATE_DISPLAY_MAX_APP_ID, NULL);

	if (app_name != NULL)
		return g_steal_pointer(&app_name);

	if (app_id != NULL)
		return g_steal_pointer(&app_id);

	return g_strdup("An unidentified application");
}

char* certificate_chooser_format_expiry(const CertificateCandidate* candidate, gint64 now)
{
	g_autoptr(GDateTime) expiry = g_date_time_new_from_unix_local(candidate->not_after);
	g_autofree char* date =
	    expiry != NULL ? g_date_time_format(expiry, "%x") : g_strdup("an unknown date");

	if (date == NULL)
		date = g_strdup("an unknown date");

	/* Expiry must be stated in words for screen readers and monochrome displays. */
	if (certificate_candidate_is_expired(candidate, now))
		return g_strdup_printf("EXPIRED on %s", date);

	if (certificate_candidate_is_not_yet_valid(candidate, now))
		return g_strdup("NOT YET VALID");

	return g_strdup_printf("Valid until %s", date);
}

char* certificate_chooser_format_detail(const CertificateCandidate* candidate, gint64 now)
{
	g_autofree char* expiry_text = certificate_chooser_format_expiry(candidate, now);
	/* Token labels and reader names are external input and require display sanitization. */
	g_autofree char* token_text = certificate_display_text(
	    candidate->token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "unnamed token");
	g_autofree char* reader_text = certificate_display_text(
	    candidate->token->reader_name, CERTIFICATE_DISPLAY_MAX_READER, NULL);

	return g_strdup_printf("%s  ·  %s %u-bit  ·  %s%s%s", expiry_text,
	                       candidate->key_type != NULL ? candidate->key_type : "unknown",
	                       candidate->key_size, token_text, reader_text != NULL ? " in " : "",
	                       reader_text != NULL ? reader_text : "");
}

