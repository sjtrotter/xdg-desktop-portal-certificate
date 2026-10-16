/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_UI_CHOOSER_H
#define CERTIFICATE_UI_CHOOSER_H

#include <gio/gio.h>
#include <glib.h>

#include "../certificate.h"
#include "../tokens/discovery.h"

/** Chooser trust and accessibility requirements are documented in docs/IMPL-INTERFACE.md. */

typedef struct
{
	const CertificateCallerIdentity* caller;
	CertificatePurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;
	guint32 lifetime_seconds;
	const char* reason; /**< Untrusted subordinate text; never logged. */
	const char* request_handle;
} CertificateChooserRequest;

typedef struct
{
	CertificateCandidate* chosen; /**< NULL on user cancellation. */
} CertificateChooserResult;

typedef void (*CertificateChooserDone)(const CertificateChooserResult* result, gpointer user_data);

/** Invalid or expired parent handles fall back to an unparented backend window. */
void certificate_chooser_show(const char* parent_window, const char* activation_token,
                              GPtrArray* candidates, const CertificateChooserRequest* request,
                              GCancellable* cancellable, CertificateChooserDone done,
                              gpointer user_data);

/* Display helpers sanitize and cap external fields. */

char* certificate_chooser_display_name(const CertificateCallerIdentity* caller);

char* certificate_chooser_format_purpose(const CertificateChooserRequest* request);

const char* certificate_chooser_purpose_detail(const CertificateChooserRequest* request);

/** Lifetime is positive before display formatting. */
char* certificate_chooser_format_lifetime(guint32 seconds);

/** Validity is expressed in words for accessibility. */
char* certificate_chooser_format_expiry(const CertificateCandidate* candidate, gint64 now);

char* certificate_chooser_format_detail(const CertificateCandidate* candidate, gint64 now);

#endif
