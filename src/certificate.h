/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <glib.h>
#include "core/core.h"

/** The interface tracks the frontend branch; see docs/IMPL-INTERFACE.md. */

#define CERTIFICATE_IMPL_BUS_NAME "org.freedesktop.impl.portal.desktop.certificate"
#define CERTIFICATE_IMPL_OBJECT_PATH "/org/freedesktop/portal/desktop"
#define CERTIFICATE_IMPL_INTERFACE "org.freedesktop.impl.portal.experimental.Certificate1"
#define CERTIFICATE_IMPL_INTERFACE_VERSION 1u

/** Only this bus name's owner may call the backend. */
#define CERTIFICATE_FRONTEND_BUS_NAME "org.freedesktop.portal.Desktop"

#define CERTIFICATE_EXIT_SUCCESS 0
#define CERTIFICATE_EXIT_UNAVAILABLE 40
#define CERTIFICATE_EXIT_USAGE 64
#define CERTIFICATE_EXIT_INTERNAL 70

#define CERTIFICATE_RESPONSE_SUCCESS 0u
#define CERTIFICATE_RESPONSE_CANCELLED 1u
#define CERTIFICATE_RESPONSE_OTHER 2u

/** Identity assurance is supplied by the frontend and must be displayed without promotion. */
#define CERTIFICATE_IDENTITY_LEVEL_VERIFIED "sandboxed"
#define CERTIFICATE_IDENTITY_LEVEL_DERIVED "host"
#define CERTIFICATE_IDENTITY_LEVEL_UNKNOWN "unidentified"

typedef XccPurpose CertificatePurpose;
#define CERTIFICATE_PURPOSE_CLIENT_AUTH XCC_PURPOSE_CLIENT_AUTH
#define CERTIFICATE_PURPOSE_SIGNING XCC_PURPOSE_SIGNING
#define CERTIFICATE_PURPOSE_EMAIL XCC_PURPOSE_EMAIL
#define CERTIFICATE_PURPOSE_SSH XCC_PURPOSE_SSH

gboolean certificate_purpose_parse(const char* text, CertificatePurpose* out);
const char* certificate_purpose_to_string(CertificatePurpose purpose);

/** Purpose text belongs to the backend drawing the window. */
const char* certificate_purpose_display(CertificatePurpose purpose);

const char* certificate_purpose_detail(CertificatePurpose purpose);

typedef XccIdentityLevel CertificateIdentityLevel;
#define CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED XCC_IDENTITY_VERIFIED_SANDBOXED
#define CERTIFICATE_IDENTITY_DERIVED_HOST XCC_IDENTITY_DERIVED_HOST
#define CERTIFICATE_IDENTITY_UNKNOWN XCC_IDENTITY_UNKNOWN

CertificateIdentityLevel certificate_identity_level_parse(const char* level);
const char* certificate_identity_level_to_string(CertificateIdentityLevel level);

/** Frontend identity fields must never be replaced with caller-supplied display text. */
typedef struct
{
	CertificateIdentityLevel level;
	char* app_id;           /**< Frontend-established app ID; empty if unidentified. */
	char* app_display_name; /**< Resolved desktop-file name, or NULL. */
} CertificateCallerIdentity;

void certificate_caller_identity_clear(CertificateCallerIdentity* caller);

/** Resolve through installed desktop files; NULL displays as unverified. */
char* certificate_app_display_name(const char* app_id);

/** Sanitize caller text to a capped single line; return NULL when empty after cleaning. */
char* certificate_sanitize_untrusted_text(const char* text, gsize max_chars);

/** Sanitize all external display text, including desktop and token metadata; the caller owns the result. */
char* certificate_display_text(const char* text, gsize max_chars, const char* fallback);

/* Display caps truncate text without rejecting the credential. */
#define CERTIFICATE_DISPLAY_MAX_APP_NAME 80
#define CERTIFICATE_DISPLAY_MAX_APP_ID 128
#define CERTIFICATE_DISPLAY_MAX_SUBJECT 120
#define CERTIFICATE_DISPLAY_MAX_ISSUER 120
#define CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL 64
#define CERTIFICATE_DISPLAY_MAX_READER 80
#define CERTIFICATE_DISPLAY_MAX_PURPOSE 160

#endif
