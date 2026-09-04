/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <glib.h>

/** @file
 *  Types shared by every part of the backend.
 *
 *  The interface this backend implements is defined by the xdg-desktop-portal
 *  branch experimental/certificate-webauthentication; the copy of the XML in
 *  data/ tracks that branch verbatim. See docs/IMPL-INTERFACE.md.
 */

#define CERTIFICATE_IMPL_BUS_NAME "org.freedesktop.impl.portal.desktop.certificate"
#define CERTIFICATE_IMPL_OBJECT_PATH "/org/freedesktop/portal/desktop"
#define CERTIFICATE_IMPL_INTERFACE "org.freedesktop.impl.portal.experimental.Certificate"
#define CERTIFICATE_IMPL_INTERFACE_VERSION 1u

/** The only bus name whose owner may call this backend. */
#define CERTIFICATE_FRONTEND_BUS_NAME "org.freedesktop.portal.Desktop"

/* Process exit codes. They have nothing to do with the D-Bus response codes. */
#define CERTIFICATE_EXIT_SUCCESS 0
#define CERTIFICATE_EXIT_UNAVAILABLE 40 /* no session bus, no p11-kit, no reader, no display */
#define CERTIFICATE_EXIT_USAGE 64
#define CERTIFICATE_EXIT_INTERNAL 70

/* The three response codes an impl method may return, as
 * shared/xdp-types.h names them upstream. */
#define CERTIFICATE_RESPONSE_SUCCESS 0u
#define CERTIFICATE_RESPONSE_CANCELLED 1u
#define CERTIFICATE_RESPONSE_OTHER 2u

/** How well the frontend knows the caller, as it arrives on the wire. The
 *  backend does not compute this and cannot improve it; it DISPLAYS it. */
#define CERTIFICATE_IDENTITY_LEVEL_VERIFIED "verified_sandboxed"
#define CERTIFICATE_IDENTITY_LEVEL_DERIVED "derived_host"
#define CERTIFICATE_IDENTITY_LEVEL_UNKNOWN "unidentified"

/** The four purposes, parsed from the string the frontend sent. The frontend
 *  has already validated it -- an unknown purpose never reaches a backend --
 *  and the backend parses it again, because a backend that trusted a string
 *  because "the frontend checked" is a backend that will one day be called by
 *  something else. There is no "any". */
typedef enum
{
	CERTIFICATE_PURPOSE_CLIENT_AUTH,
	CERTIFICATE_PURPOSE_SIGNING,
	CERTIFICATE_PURPOSE_EMAIL,
	CERTIFICATE_PURPOSE_SSH
} CertificatePurpose;

gboolean certificate_purpose_parse(const char* text, CertificatePurpose* out);
const char* certificate_purpose_to_string(CertificatePurpose purpose);

/** The purpose IN THIS BACKEND'S OWN WORDS, for the chooser and the PIN window.
 *  Never the caller's words, and never the frontend's either -- the words
 *  belong to whoever draws the window. */
const char* certificate_purpose_display(CertificatePurpose purpose);

/** A one-line explanation of what a grant for this purpose allows, for the
 *  chooser's "what happens next" line. */
const char* certificate_purpose_detail(CertificatePurpose purpose);

/** How well the FRONTEND knows the caller. The backend cannot compute this,
 *  cannot improve it, and MUST DISPLAY IT: an application name shown without
 *  saying how it was established is a lie by omission. */
typedef enum
{
	CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED,
	CERTIFICATE_IDENTITY_DERIVED_HOST,
	CERTIFICATE_IDENTITY_UNKNOWN
} CertificateIdentityLevel;

CertificateIdentityLevel certificate_identity_level_parse(const char* level);
const char* certificate_identity_level_to_string(CertificateIdentityLevel level);

/** What the frontend told this backend about the caller. Every field arrived
 *  as an argument. NONE of it is caller-supplied text, and none of it may be
 *  replaced by caller-supplied text. */
typedef struct
{
	CertificateIdentityLevel level;
	char* app_id;           /**< as the FRONTEND established it; "" if unidentified */
	char* app_display_name; /**< resolved from the desktop file, or NULL */
} CertificateCallerIdentity;

void certificate_caller_identity_clear(CertificateCallerIdentity* caller);

/** Resolve @app_id to a human readable name through the installed desktop
 *  files. NEVER through anything the caller supplied. Returns NULL when the app
 *  id does not resolve, which the chooser renders as "unverified". */
char* certificate_app_display_name(const char* app_id);

/** Turn caller-supplied text into something that cannot impersonate a window's
 *  own chrome: control characters and line breaks removed, the result collapsed
 *  to a single line and capped in length, long runs of combining marks cut
 *  short, and always valid UTF-8. Returns NULL for text that is empty once
 *  cleaned, so that a caller cannot reserve space in the window with
 *  whitespace. */
char* certificate_sanitize_untrusted_text(const char* text, gsize max_chars);

/** EVERY externally sourced string that reaches a window goes through this.
 *  "Externally sourced" is wider than "caller-supplied": a desktop file's Name=
 *  is writable by any unsandboxed process, and a certificate subject, an issuer,
 *  a token label and a reader name all come off a card that somebody else
 *  issued. None of them may draw a second line, a right-to-left override or a
 *  hundred combining marks inside a window that carries a security decision.
 *
 *  Sanitises @text and caps it at @max_chars; returns a copy of @fallback (which
 *  may be NULL) when nothing survives. The caller owns the result. */
char* certificate_display_text(const char* text, gsize max_chars, const char* fallback);

/* Per-field caps. They are display limits, not validation: a longer value is
 * shown truncated rather than refused, because refusing a certificate because
 * its subject is long would be this backend deciding which credentials exist. */
#define CERTIFICATE_DISPLAY_MAX_APP_NAME 80
#define CERTIFICATE_DISPLAY_MAX_APP_ID 128
#define CERTIFICATE_DISPLAY_MAX_SUBJECT 120
#define CERTIFICATE_DISPLAY_MAX_ISSUER 120
#define CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL 64
#define CERTIFICATE_DISPLAY_MAX_READER 80
#define CERTIFICATE_DISPLAY_MAX_PURPOSE 160

#endif /* CERTIFICATE_H */
