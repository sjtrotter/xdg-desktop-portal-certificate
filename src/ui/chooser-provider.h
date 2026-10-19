/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#ifndef CERTIFICATE_UI_CHOOSER_PROVIDER_H
#define CERTIFICATE_UI_CHOOSER_PROVIDER_H

#include "../core/ui.h"
#include "../certificate.h"

G_BEGIN_DECLS

/* Internal precursor to XccUiV1's chooser callbacks; close runs once per shown ID. */
/* Callbacks run on the main thread; inline replies are deferred until they return. */
typedef struct
{
	const char* name;
	gboolean needs_display;
	gpointer user_data;
	void (*chooser_show)(gpointer user_data, XccUiId id, const XccChooserView* view);
	void (*chooser_update)(gpointer user_data, XccUiId id, const XccChooserView* view);
	void (*close)(gpointer user_data, XccUiId id);
} CertificateChooserProvider;

/* Main thread only; copied per interaction; user_data must outlive active interactions. */
void certificate_chooser_set_provider(const CertificateChooserProvider* provider);
const CertificateChooserProvider* certificate_chooser_get_provider(void);

/* Main-thread replies; closed IDs, stale revisions and unknown candidate IDs are ignored. */
void certificate_chooser_choose(XccUiId id, guint64 revision, guint64 candidate_id);
void certificate_chooser_cancel(XccUiId id);
void certificate_chooser_fail(XccUiId id, int error);

G_END_DECLS

#endif
