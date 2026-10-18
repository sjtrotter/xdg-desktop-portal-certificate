/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#ifndef CERTIFICATE_UI_CHOOSER_PROVIDER_H
#define CERTIFICATE_UI_CHOOSER_PROVIDER_H

#include "../core/abi.h"
#include "../certificate.h"

G_BEGIN_DECLS

typedef guint64 XccUiId;

typedef struct
{
	uint32_t struct_size, abi_version;
	guint64 id;
	const char* subject;
	const char* issuer;
	const char* token;
	const char* reader;
	const char* expiry;
	const char* detail;
	const char* fingerprint;
	gboolean invalid;
} XccChooserCandidateView;

/* Immutable and borrowed during callbacks; external display fields are sanitized in core. */
typedef struct
{
	uint32_t struct_size, abi_version;
	guint64 revision;
	const XccChooserCandidateView* candidates;
	gsize n_candidates;
	const char* caller_name;
	const char* app_id;
	CertificateIdentityLevel identity_level;
	const char* identity_detail;
	CertificatePurpose purpose;
	const char* purpose_text;
	const char* purpose_detail;
	gboolean may_sign;
	gboolean may_decrypt;
	const char* operation_scope;
	guint32 lifetime_seconds;
	const char* duration;
	const char* later_prompt;
	const char* reason_label;
	const char* untrusted_reason;
	gboolean tokens_present;
	const char* parent_window;
	const char* activation_token;
} XccChooserView;

/* Rows have a uniform byte stride supplied by the producer, allowing fields to
 * be appended without changing how an older UI walks the candidate array. */
static inline const XccChooserCandidateView* xcc_chooser_view_candidate(const XccChooserView* view,
																	  gsize index)
{
	if (index >= view->n_candidates || view->candidates == NULL)
		return NULL;
	return (const XccChooserCandidateView*)((const char*)view->candidates +
											   index * view->candidates->struct_size);
}

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
