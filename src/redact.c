/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "redact.h"

#include <string.h>

static gboolean certificate_verbose = FALSE;

/* The longest any externally sourced field may be in a log line. */
#define CERTIFICATE_LOG_FIELD_MAX 128

/* EVERY EXTERNAL STRING THAT REACHES A LOG LINE GOES THROUGH THIS. Structural
 * redaction stops a secret being formatted into a message; it does not by
 * itself stop a newline in an app id from forging a second journal entry, or a
 * kilobyte of text from filling the journal. Control characters become \xNN,
 * the result is capped, and NULL becomes "(none)" so that no call site has to
 * remember to. */
static char* field(const char* text)
{
	GString* out = NULL;
	gsize count = 0;

	if (text == NULL || *text == '\0')
		return g_strdup("(none)");

	out = g_string_new(NULL);

	for (const unsigned char* p = (const unsigned char*) text; *p != '\0'; p++)
	{
		if (count >= CERTIFICATE_LOG_FIELD_MAX)
		{
			g_string_append(out, "...");
			break;
		}

		if (*p < 0x20 || *p == 0x7f)
			g_string_append_printf(out, "\\x%02x", *p);
		else
			g_string_append_c(out, (char) *p);

		count++;
	}

	return g_string_free(out, FALSE);
}

void certificate_log_set_verbose(gboolean verbose)
{
	certificate_verbose = verbose;
}

gboolean certificate_log_get_verbose(void)
{
	return certificate_verbose;
}

void certificate_log_decision(const char* reason_code, const char* app_id, const char* level,
                              const char* purpose, gboolean granted)
{
	g_autofree char* safe_app_id = field(app_id);
	g_autofree char* safe_level = field(level);
	g_autofree char* safe_purpose = field(purpose);

	g_message("%s app_id=%s identity=%s purpose=%s granted=%s", reason_code, safe_app_id,
	          safe_level, safe_purpose, granted ? "yes" : "no");
}

void certificate_log_grant(const char* reason_code, const char* grant_id, const char* detail_code)
{
	g_autofree char* safe_grant = field(grant_id);
	g_autofree char* safe_detail = field(detail_code);

	g_message("%s session=%s detail=%s", reason_code, safe_grant, safe_detail);
}

void certificate_log_operation(const char* reason_code, const char* grant_id,
                               const char* operation_id, const char* mechanism)
{
	g_autofree char* safe_grant = field(grant_id);
	g_autofree char* safe_operation = field(operation_id);
	g_autofree char* safe_mechanism = field(mechanism);

	g_message("%s session=%s operation=%s mechanism=%s", reason_code, safe_grant, safe_operation,
	          safe_mechanism);
}

void certificate_log_counts(const char* reason_code, guint tokens, guint candidates)
{
	g_message("%s tokens=%u candidates=%u", reason_code, tokens, candidates);
}

void certificate_log_debug(const char* reason_code, const char* detail_code)
{
	g_autofree char* safe_detail = NULL;

	if (!certificate_verbose)
		return;

	safe_detail = field(detail_code);
	g_debug("%s detail=%s", reason_code, safe_detail);
}

char* certificate_redact_error_text(const char* text)
{
	const char* uri = NULL;

	if (text == NULL)
		return g_strdup("(no message)");

	/* p11-kit, OpenSC and GnuTLS all put PKCS#11 URIs into error strings, and a
	 * URI may carry a pin-value attribute. Truncating at the first "pkcs11:" is
	 * cheap and correct; passing library error text through unmodified is how a
	 * PIN reaches a journal. Both cases are covered: the scheme in a URI, and
	 * the bare attribute name in case some library prints it on its own. */
	uri = strstr(text, "pkcs11:");
	if (uri == NULL)
		uri = strstr(text, "pin-value");
	if (uri == NULL)
		uri = strstr(text, "pin-source");

	if (uri == NULL)
		return g_strdup(text);

	if (uri == text)
		return g_strdup("(redacted)");

	return g_strdup_printf("%.*s(redacted)", (int) (uri - text), text);
}

char* certificate_redact_serial(const char* serial)
{
	gsize length;

	if (serial == NULL || *serial == '\0')
		return g_strdup("(none)");

	/* A card serial is a stable hardware identifier. The last four characters
	 * are enough for a human to tell two cards apart in a log and are not
	 * enough to identify the card anywhere else. */
	length = strlen(serial);
	if (length <= 4)
		return g_strdup("****");

	return g_strdup_printf("****%s", serial + length - 4);
}
