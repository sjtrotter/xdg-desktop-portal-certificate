/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "certificate.h"

#include <gio/gdesktopappinfo.h>

#include <string.h>

gboolean certificate_purpose_parse(const char* text, CertificatePurpose* out)
{
	static const struct
	{
		const char* name;
		CertificatePurpose purpose;
	} table[] = {
		{ "client_auth", CERTIFICATE_PURPOSE_CLIENT_AUTH },
		{ "signing", CERTIFICATE_PURPOSE_SIGNING },
		{ "email", CERTIFICATE_PURPOSE_EMAIL },
		{ "ssh", CERTIFICATE_PURPOSE_SSH },
	};

	if (text == NULL)
		return FALSE;

	for (gsize i = 0; i < G_N_ELEMENTS(table); i++)
	{
		if (g_strcmp0(text, table[i].name) == 0)
		{
			if (out != NULL)
				*out = table[i].purpose;
			return TRUE;
		}
	}

	return FALSE;
}

const char* certificate_purpose_to_string(CertificatePurpose purpose)
{
	switch (purpose)
	{
		case CERTIFICATE_PURPOSE_CLIENT_AUTH:
			return "client_auth";
		case CERTIFICATE_PURPOSE_SIGNING:
			return "signing";
		case CERTIFICATE_PURPOSE_EMAIL:
			return "email";
		case CERTIFICATE_PURPOSE_SSH:
			return "ssh";
		default:
			return "unknown";
	}
}

const char* certificate_purpose_display(CertificatePurpose purpose)
{
	/* THIS BACKEND'S OWN WORDS. Never the caller's, never the frontend's. */
	switch (purpose)
	{
		case CERTIFICATE_PURPOSE_CLIENT_AUTH:
			return "prove who you are to a server";
		case CERTIFICATE_PURPOSE_SIGNING:
			return "sign a document or a piece of data";
		case CERTIFICATE_PURPOSE_EMAIL:
			return "sign or read secure email";
		case CERTIFICATE_PURPOSE_SSH:
			return "authenticate an SSH connection";
		default:
			return "use a certificate";
	}
}

const char* certificate_purpose_detail(CertificatePurpose purpose)
{
	switch (purpose)
	{
		case CERTIFICATE_PURPOSE_CLIENT_AUTH:
			return "The application will be able to authenticate as you until the "
			       "grant expires. It cannot read the private key.";
		case CERTIFICATE_PURPOSE_SIGNING:
			return "The application will be able to have data signed with this key "
			       "until the grant expires. It cannot read the private key.";
		case CERTIFICATE_PURPOSE_EMAIL:
			return "The application will be able to sign, and where permitted "
			       "decrypt, mail until the grant expires. It cannot read the "
			       "private key.";
		case CERTIFICATE_PURPOSE_SSH:
			return "The application will be able to authenticate SSH connections as "
			       "you until the grant expires. It cannot read the private key.";
		default:
			return "The application cannot read the private key.";
	}
}

CertificateIdentityLevel certificate_identity_level_parse(const char* level)
{
	if (g_strcmp0(level, CERTIFICATE_IDENTITY_LEVEL_VERIFIED) == 0)
		return CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED;
	if (g_strcmp0(level, CERTIFICATE_IDENTITY_LEVEL_DERIVED) == 0)
		return CERTIFICATE_IDENTITY_DERIVED_HOST;

	/* Anything else, including a missing option and a value invented by a
	 * caller that reached this bus name directly, is the strongest warning.
	 * Failing safe here means failing loud. */
	return CERTIFICATE_IDENTITY_UNKNOWN;
}

const char* certificate_identity_level_to_string(CertificateIdentityLevel level)
{
	switch (level)
	{
		case CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED:
			return CERTIFICATE_IDENTITY_LEVEL_VERIFIED;
		case CERTIFICATE_IDENTITY_DERIVED_HOST:
			return CERTIFICATE_IDENTITY_LEVEL_DERIVED;
		default:
			return CERTIFICATE_IDENTITY_LEVEL_UNKNOWN;
	}
}

void certificate_caller_identity_clear(CertificateCallerIdentity* caller)
{
	if (caller == NULL)
		return;

	g_clear_pointer(&caller->app_id, g_free);
	g_clear_pointer(&caller->app_display_name, g_free);
}

char* certificate_app_display_name(const char* app_id)
{
	g_autofree char* desktop_id = NULL;
	g_autoptr(GDesktopAppInfo) info = NULL;
	const char* name = NULL;

	if (app_id == NULL || *app_id == '\0')
		return NULL;

	/* An app id is not a path and must not be treated as one. */
	if (strchr(app_id, '/') != NULL)
		return NULL;

	desktop_id = g_strconcat(app_id, ".desktop", NULL);
	info = g_desktop_app_info_new(desktop_id);
	if (info == NULL)
		return NULL;

	name = g_app_info_get_display_name(G_APP_INFO(info));
	if (name == NULL || *name == '\0')
		return NULL;

	return g_strdup(name);
}

/* Combining marks in a row before the rest of the run is dropped. Four is
 * enough for anything a human language does to one base character. */
#define CERTIFICATE_SANITIZE_MAX_MARK_RUN 4

char* certificate_sanitize_untrusted_text(const char* text, gsize max_chars)
{
	g_autofree char* valid = NULL;
	g_autoptr(GString) out = NULL;
	const char* p = NULL;
	gboolean pending_space = FALSE;
	gsize count = 0;

	gsize marks = 0;

	if (text == NULL || *text == '\0')
		return NULL;

	/* Anything off the wire may be invalid UTF-8, and a GVariant string is not
	 * checked for anything but a terminating NUL. */
	valid = g_utf8_make_valid(text, -1);
	out = g_string_new(NULL);

	for (p = valid; *p != '\0'; p = g_utf8_next_char(p))
	{
		gunichar c = g_utf8_get_char(p);

		/* Control characters, line separators and format characters are how a
		 * single-line label is turned into several, and how right-to-left
		 * overrides are used to make text read as something else. None of them
		 * survive. */
		if (g_unichar_iscntrl(c) || g_unichar_type(c) == G_UNICODE_FORMAT ||
		    g_unichar_type(c) == G_UNICODE_LINE_SEPARATOR ||
		    g_unichar_type(c) == G_UNICODE_PARAGRAPH_SEPARATOR)
		{
			pending_space = out->len > 0;
			continue;
		}

		if (g_unichar_isspace(c))
		{
			pending_space = out->len > 0;
			continue;
		}

		/* A LONG RUN OF COMBINING MARKS is how one "character" is made to
		 * cover the line above it. They are legitimate in small numbers -- an
		 * accented name is exactly this -- so the run is capped rather than the
		 * category refused. */
		switch (g_unichar_type(c))
		{
			case G_UNICODE_NON_SPACING_MARK:
			case G_UNICODE_SPACING_MARK:
			case G_UNICODE_ENCLOSING_MARK:
				if (marks >= CERTIFICATE_SANITIZE_MAX_MARK_RUN)
					continue;
				marks++;
				break;
			default:
				marks = 0;
				break;
		}

		if (pending_space)
		{
			g_string_append_c(out, ' ');
			pending_space = FALSE;
			count++;
		}

		g_string_append_unichar(out, c);
		count++;

		if (count >= max_chars)
		{
			g_string_append(out, "\xe2\x80\xa6");
			break;
		}
	}

	if (out->len == 0)
		return NULL;

	return g_strdup(out->str);
}

char* certificate_display_text(const char* text, gsize max_chars, const char* fallback)
{
	char* clean = certificate_sanitize_untrusted_text(text, max_chars);

	if (clean != NULL)
		return clean;

	return fallback != NULL ? g_strdup(fallback) : NULL;
}
