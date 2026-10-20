/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_CORE_CHOOSER_H
#define CERTIFICATE_CORE_CHOOSER_H

#include <gio/gio.h>
#include <glib.h>

#include "../certificate.h"
#include "../tokens/discovery.h"

G_BEGIN_DECLS

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
	gboolean tokens_present;
	gboolean generic_purpose;
} CertificateChooserRequest;

typedef struct
{
	CertificateCandidate* chosen; /**< NULL on user cancellation. */
	int error;					  /* Typed UI failure; zero for normal consent/cancellation. */
} CertificateChooserResult;

typedef void (*CertificateChooserDone)(const CertificateChooserResult* result, gpointer user_data);

typedef struct CertificateChooser CertificateChooser;

/* Core interaction; providers receive only display views and IDs. */
CertificateChooser* certificate_chooser_show(const char* parent_window,
                                             const char* activation_token,
                                             GPtrArray* candidates,
                                             const CertificateChooserRequest* request,
                                             GCancellable* cancellable,
                                             CertificateChooserDone done, gpointer user_data);

/* Main-thread replacement; the handle is valid until done is called. */
void certificate_chooser_update(CertificateChooser* chooser, GPtrArray* candidates,
                                gboolean tokens_present);

/* Reading changes advance the revision and preserve the current candidates. */
void certificate_chooser_set_tokens_reading(CertificateChooser* chooser, gboolean reading);

gboolean certificate_chooser_available(void);

/* Display helpers sanitize and cap external fields. */

char* certificate_chooser_display_name(const CertificateCallerIdentity* caller);

char* certificate_chooser_format_purpose(const CertificateChooserRequest* request);

gboolean certificate_chooser_is_generic_purpose(const CertificateChooserRequest* request);

const char* certificate_chooser_purpose_detail(const CertificateChooserRequest* request);

/** Lifetime is positive before display formatting. */
char* certificate_chooser_format_lifetime(guint32 seconds);

/** Validity is expressed in words for accessibility. */
char* certificate_chooser_format_expiry(const CertificateCandidate* candidate, gint64 now);

char* certificate_chooser_format_detail(const CertificateCandidate* candidate, gint64 now);

G_END_DECLS

#endif
