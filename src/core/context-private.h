/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_CONTEXT_PRIVATE_H
#define XCC_CONTEXT_PRIVATE_H
#include "ui.h"
#include "adapter.h"
#include "session-private.h"
#include "chooser.h"
#include "../tokens/filter.h"

G_BEGIN_DECLS
struct XccCandidate
{
	gint refs;
	CertificateCandidate* value;
	XccCandidateInfo info;
};
struct XccContext
{
	gint refs;
	gint posts;
	gint ui_pending, ui_handles;
	GMutex queue_lock;
	CertificateChooserProvider previous_chooser;
	CertificatePinProvider previous_pin;
	XccConfig config;
	XccUiV1 ui;
	XccDispatch dispatch;
	CertificateTokens* tokens;
	gboolean own_tokens, watch_stopped;
	gint stopping, shutdown_started, shutdown_posted;
	uint64_t generation;
	GMainContext* coordinator;
	GMainLoop* loop;
	GThread* thread;
	GPtrArray* requests;
	GPtrArray* sessions;
	GHashTable* interactions;
	uint64_t next_ui_id;
	XccShutdownDone shutdown_done;
	void* shutdown_data;
};
struct XccRequest
{
	gint refs;
	XccContext* context;
	XccSession* session;
	GCancellable* cancellable;
	XccDone done;
	void* user;
	gboolean answered, detached;
	gint cancel_intent;
	XccErrorCode cancelled_code;
	XccResult result;
	XccCandidate* candidate;
	GBytes* signature;
	GStrv mechanisms;
	CertificateCallerIdentity caller;
	CertificatePurpose purpose;
	CertificateFilter filter;
	char* parent_window;
	char* activation_token;
	char* reason;
	guint32 lifetime;
	gboolean may_sign, interaction_forbidden, generic_purpose;
	CertificateChooser* chooser;
	gboolean enumerating, enumerate_again, chooser_completed;
	CertificateCandidate* pending_chosen;
	XccErrorCode pending_error;
	char* mechanism;
	char* operation_id;
	GVariant* parameters;
	GBytes* input;
	XccErrorCode validation_error;
	XccPrincipal principal;
};
gboolean xcc_context_post(XccContext*, XccFunction, void*);
void xcc_request_schedule(XccRequest*, XccFunction);
void xcc_context_check_shutdown(XccContext*);
GPtrArray* xcc_context_sessions_snapshot(XccContext*);
void xcc_request_complete(XccRequest*, XccErrorCode);
XccRequest* xcc_request_new(XccContext*, XccSession*, XccResultKind, XccDone, void*);
XccErrorCode xcc_request_validate(XccRequest*);
XccCandidate* xcc_candidate_snapshot(CertificateCandidate*);
void xcc_acquire_start(void*);
void xcc_sign_start(void*);
void xcc_acquire_token_event(XccContext*, CertificateToken*, gboolean);
void xcc_ui_legacy_init(XccContext*);
void xcc_ui_legacy_restore(XccContext*);
gboolean xcc_legacy_choose(XccUiId, guint64, guint64);
void xcc_ui_install(XccContext*);
void xcc_ui_uninstall(XccContext*);
void xcc_session_close_internal(XccSession*);
void xcc_session_invalidate_internal(XccSession*, const char*);
void xcc_session_dispatch_invalidated(XccSession*, const char*);
/* Worker/cancellation sources return to the coordinator, or default context for legacy tests. */
guint xcc_idle_add(GMainContext*, GSourceFunc, void*, GDestroyNotify);
guint xcc_timeout_add(guint, GSourceFunc, void*);
void xcc_source_remove(guint);
G_END_DECLS

#endif
