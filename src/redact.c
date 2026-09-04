/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "redact.h"

#include <string.h>

static gboolean certificate_verbose = FALSE;

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
	g_message("%s app_id=%s identity=%s purpose=%s granted=%s", reason_code,
	          app_id != NULL && *app_id != '\0' ? app_id : "(none)",
	          level != NULL ? level : "(none)", purpose != NULL ? purpose : "(none)",
	          granted ? "yes" : "no");
}

void certificate_log_grant(const char* reason_code, const char* grant_id, const char* detail_code)
{
	g_message("%s session=%s detail=%s", reason_code, grant_id != NULL ? grant_id : "(none)",
	          detail_code != NULL ? detail_code : "(none)");
}

void certificate_log_operation(const char* reason_code, const char* grant_id,
                               const char* operation_id, const char* mechanism)
{
	g_message("%s session=%s operation=%s mechanism=%s", reason_code,
	          grant_id != NULL ? grant_id : "(none)",
	          operation_id != NULL ? operation_id : "(none)",
	          mechanism != NULL ? mechanism : "(none)");
}

void certificate_log_counts(const char* reason_code, guint tokens, guint candidates)
{
	g_message("%s tokens=%u candidates=%u", reason_code, tokens, candidates);
}

void certificate_log_debug(const char* reason_code, const char* detail_code)
{
	if (!certificate_verbose)
		return;

	g_debug("%s detail=%s", reason_code, detail_code != NULL ? detail_code : "(none)");
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
