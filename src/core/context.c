/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "context-private.h"
#include "dispatch-glib.h"
#include "../redact.h"
#include "../broker/operations.h"
#include <string.h>

static gint context_live;
XccContext* xcc_context_ref(XccContext* c)
{
	g_atomic_int_inc(&c->refs);
	return c;
}
void xcc_context_unref(XccContext* c)
{
	if (c == NULL || !g_atomic_int_dec_and_test(&c->refs))
		return;
	g_assert(c->requests->len == 0);
	g_assert(c->sessions->len == 0);
	g_assert(g_atomic_int_get(&c->ui_pending) == 0);
	g_assert(g_atomic_int_get(&c->ui_handles) == 0);
	if (c->own_tokens)
		certificate_tokens_free(c->tokens);
	g_ptr_array_unref(c->requests);
	g_ptr_array_unref(c->sessions);
	g_hash_table_unref(c->interactions);
	g_main_loop_unref(c->loop);
	g_main_context_unref(c->coordinator);
	g_mutex_clear(&c->queue_lock);
	g_free(c);
}
typedef struct
{
	XccContext* c;
	XccFunction function;
	void* data;
} CoordinatorPost;
static void coordinator_post(void* data)
{
	CoordinatorPost* p = data;
	XccContext* c = p->c;
	p->function(p->data);
	g_atomic_int_add(&c->posts, -1);
	xcc_context_check_shutdown(c);
	xcc_context_unref(c);
	g_free(p);
}
gboolean xcc_context_post(XccContext* c, XccFunction f, void* data)
{
	g_mutex_lock(&c->queue_lock);
	if (c->shutdown_posted)
	{
		g_mutex_unlock(&c->queue_lock);
		return FALSE;
	}
	CoordinatorPost* p = g_new(CoordinatorPost, 1);
	*p = (CoordinatorPost){xcc_context_ref(c), f, data};
	g_atomic_int_inc(&c->posts);
	XccDispatch d = xcc_dispatch_glib(c->coordinator);
	d.post(d.user, coordinator_post, p);
	g_mutex_unlock(&c->queue_lock);
	return TRUE;
}
void xcc_request_schedule(XccRequest* r, XccFunction start)
{
	if (!xcc_context_post(r->context, start, r))
	{
		r->detached = TRUE;
		xcc_request_complete(r, XCC_ERROR_BACKEND_GONE);
	}
}
GPtrArray* xcc_context_sessions_snapshot(XccContext* c)
{
	GPtrArray* copy = g_ptr_array_new_with_free_func(g_object_unref);
	for (guint i = 0; i < c->sessions->len; i++)
		g_ptr_array_add(copy, g_object_ref(g_ptr_array_index(c->sessions, i)));
	return copy;
}
static void token_event(CertificateToken* token, gboolean added, gpointer user)
{
	XccContext* c = user;
	certificate_log_counts(
		added ? CERTIFICATE_REASON_DISCOVERY_RESULT : CERTIFICATE_REASON_TOKEN_REMOVED, 1, 0);
	xcc_acquire_token_event(c, token, added);
	if (added)
		return;
	g_autoptr(GPtrArray) sessions = xcc_context_sessions_snapshot(c);
	for (guint i = 0; i < sessions->len; i++)
	{
		XccSession* s = g_ptr_array_index(sessions, i);
		if (xcc_session_uses_token(s, token))
			xcc_session_invalidate_internal(s, "token_removed");
	}
}
typedef struct
{
	XccContext* c;
	GMutex mutex;
	GCond cond;
	gboolean ready;
	GError* error;
} Startup;
static gpointer load_modules(void* data)
{
	Startup* startup = data;
	XccContext* c = startup->c;
	c->tokens = certificate_tokens_new(c->config.module_paths, &startup->error);
	c->own_tokens = TRUE;
	if (c->tokens != NULL)
		certificate_tokens_set_allow_software(c->tokens, c->config.allow_software);
	return NULL;
}
static gpointer unload_modules(void* data)
{
	certificate_tokens_free(data);
	return NULL;
}
static gpointer coordinator(void* data)
{
	Startup* startup = data;
	XccContext* c = startup->c;
	g_main_context_push_thread_default(c->coordinator);
	if (c->tokens == NULL)
		g_thread_join(g_thread_new("certificate-load", load_modules, startup));
	if (c->tokens != NULL)
	{
		xcc_ui_install(c);
		certificate_tokens_watch(c->tokens, token_event, c);
	}
	g_mutex_lock(&startup->mutex);
	startup->ready = TRUE;
	g_cond_signal(&startup->cond);
	g_mutex_unlock(&startup->mutex);
	if (c->tokens != NULL)
		g_main_loop_run(c->loop);
	g_main_context_pop_thread_default(c->coordinator);
	xcc_context_unref(c);
	return NULL;
}
/* UI compatibility is captured on the desktop thread before installing coordinator proxies. */
XccContext* xcc_context_new(const XccConfig* config, const XccUiV1* ui, const XccDispatch* dispatch,
							XccError* error)
{
	return xcc_context_new_for_tokens(config, ui, dispatch, error, NULL);
}
XccContext* xcc_context_new_for_tokens(const XccConfig* config, const XccUiV1* ui,
									   const XccDispatch* dispatch, XccError* error,
									   CertificateTokens* tokens)
{
	if (error != NULL)
		*error = (XccError){sizeof(XccError), XCC_ABI_VERSION, XCC_OK};
	if (config == NULL || config->struct_size < sizeof(*config) ||
		config->abi_version != XCC_ABI_VERSION || dispatch == NULL ||
		dispatch->struct_size < sizeof(*dispatch) || dispatch->abi_version != XCC_ABI_VERSION ||
		dispatch->post == NULL ||
		(ui != NULL && (ui->struct_size < sizeof(*ui) || ui->abi_version != XCC_ABI_VERSION ||
						ui->chooser_show == NULL || ui->chooser_update == NULL ||
						ui->pin_show == NULL || ui->pin_update == NULL || ui->warning == NULL ||
						ui->hide == NULL || ui->close == NULL)) ||
		!g_atomic_int_compare_and_exchange(&context_live, 0, 1))
	{
		if (error != NULL)
			error->code = XCC_ERROR_INVALID_REQUEST;
		return NULL;
	}
	XccContext* c = g_new0(XccContext, 1);
	c->refs = 1;
	g_mutex_init(&c->queue_lock);
	c->config = *config;
	c->dispatch = *dispatch;
	c->tokens = tokens;
	c->coordinator = g_main_context_new();
	c->loop = g_main_loop_new(c->coordinator, FALSE);
	c->requests = g_ptr_array_new();
	c->sessions = g_ptr_array_new_with_free_func(g_object_unref);
	c->interactions = g_hash_table_new(g_int64_hash, g_int64_equal);
	c->previous_chooser = *certificate_chooser_get_provider();
	c->previous_pin = *certificate_pin_get_provider();
	if (ui != NULL)
		c->ui = *ui;
	else
		xcc_ui_legacy_init(c);
	Startup startup = {.c = c};
	g_mutex_init(&startup.mutex);
	g_cond_init(&startup.cond);
	g_mutex_lock(&startup.mutex);
	xcc_context_ref(c);
	c->thread = g_thread_new("certificate-core", coordinator, &startup);
	while (!startup.ready)
		g_cond_wait(&startup.cond, &startup.mutex);
	g_mutex_unlock(&startup.mutex);
	g_mutex_clear(&startup.mutex);
	g_cond_clear(&startup.cond);
	if (startup.error != NULL)
	{
		g_clear_error(&startup.error);
		if (error != NULL)
			error->code = XCC_ERROR_DEVICE;
		g_thread_join(c->thread);
		c->thread = NULL;
		xcc_ui_legacy_restore(c);
		g_atomic_int_set(&context_live, 0);
		xcc_context_unref(c);
		return NULL;
	}
	return c;
}
XccRequest* xcc_request_ref(XccRequest* r)
{
	g_atomic_int_inc(&r->refs);
	return r;
}
void xcc_request_unref(XccRequest* r)
{
	if (r == NULL || !g_atomic_int_dec_and_test(&r->refs))
		return;
	xcc_context_unref(r->context);
	g_clear_object(&r->session);
	g_object_unref(r->cancellable);
	certificate_caller_identity_clear(&r->caller);
	certificate_filter_clear(&r->filter);
	g_clear_pointer(&r->pending_chosen, certificate_candidate_unref);
	xcc_candidate_unref(r->candidate);
	g_clear_pointer(&r->signature, g_bytes_unref);
	g_strfreev(r->mechanisms);
	g_free(r->parent_window);
	g_free(r->activation_token);
	g_free(r->reason);
	g_free(r->mechanism);
	g_free(r->operation_id);
	g_clear_pointer(&r->parameters, g_variant_unref);
	g_clear_pointer(&r->input, g_bytes_unref);
	g_free(r);
}
XccRequest* xcc_request_new(XccContext* c, XccSession* s, XccResultKind kind, XccDone done,
							void* user)
{
	XccRequest* r = g_new0(XccRequest, 1);
	r->refs = 2; /* caller and pending completion */
	r->context = xcc_context_ref(c);
	r->session = s != NULL ? g_object_ref(s) : NULL;
	r->cancellable = g_cancellable_new();
	r->done = done;
	r->user = user;
	r->result.struct_size = sizeof(r->result);
	r->result.abi_version = XCC_ABI_VERSION;
	r->result.kind = kind;
	r->result.signature = (XccBytes){sizeof(XccBytes), XCC_ABI_VERSION, NULL, 0};
	return r;
}
static void completion_ack(void* data)
{
	XccRequest* r = data;
	XccContext* c = r->context;
	g_ptr_array_remove(c->requests, r);
	xcc_context_check_shutdown(c);
	xcc_request_unref(r);
}
static void completion(void* data)
{
	XccRequest* r = data;
	gint intent = g_atomic_int_get(&r->cancel_intent);
	if (intent != 0)
	{
		static const XccErrorCode codes[] = {XCC_ERROR_CANCELLED,		XCC_ERROR_OWNER_GONE,
											 XCC_ERROR_NO_SUCH_SESSION, XCC_ERROR_BACKEND_GONE,
											 XCC_ERROR_TOKEN_REMOVED,	XCC_ERROR_DEVICE};
		r->result.error = codes[intent - 1];
		r->result.candidate_present = r->result.signature_present = r->result.mechanisms_present =
			false;
		r->result.candidate = NULL;
		r->result.signature =
			(XccBytes){.struct_size = sizeof(XccBytes), .abi_version = XCC_ABI_VERSION};
	}
	if (r->done != NULL)
		r->done(r, &r->result, r->user);
	if (r->detached)
		xcc_request_unref(r);
	else
		xcc_context_post(r->context, completion_ack, r);
}
void xcc_request_complete(XccRequest* r, XccErrorCode error)
{
	if (r->answered)
		return;
	r->answered = TRUE;
	if (r->cancelled_code != XCC_OK)
		error = r->cancelled_code;
	else if (g_cancellable_is_cancelled(r->cancellable))
		error = XCC_ERROR_CANCELLED;
	if (r->result.kind == XCC_RESULT_CAPABILITIES && r->mechanisms == NULL)
	{
		gboolean protected_path = FALSE;
		/* Static backend support preserves the dictionary-only wire reply during teardown. */
		certificate_tokens_capabilities(r->context->tokens, &r->mechanisms, &protected_path);
		r->result.protected_path = protected_path;
		r->result.has_display = r->context->config.has_display;
	}
	r->result.error = error;
	r->result.candidate_present = error == XCC_OK && r->candidate != NULL;
	r->result.signature_present = error == XCC_OK && r->signature != NULL;
	r->result.mechanisms_present = error == XCC_OK && r->result.kind == XCC_RESULT_CAPABILITIES;
	r->result.candidate = error == XCC_OK ? r->candidate : NULL;
	if (error == XCC_OK && r->signature != NULL)
		r->result.signature.data = g_bytes_get_data(r->signature, &r->result.signature.size);
	r->result.mechanisms = (const char* const*)r->mechanisms;
	r->context->dispatch.post(r->context->dispatch.user, completion, r);
}
XccErrorCode xcc_request_validate(XccRequest* r)
{
	XccContext* c = r->context;
	XccSession* s = r->session;
	g_ptr_array_add(c->requests, r);
	if (c->stopping)
		return XCC_ERROR_BACKEND_GONE;
	if (g_atomic_int_get(&r->cancel_intent) != 0)
		return XCC_ERROR_CANCELLED;
	if (r->cancelled_code != XCC_OK)
		return r->cancelled_code;
	if (g_cancellable_is_cancelled(r->cancellable))
		return XCC_ERROR_CANCELLED;
	if (r->validation_error != XCC_OK)
		return r->validation_error;
	if (r->principal.app_id == NULL && s != NULL)
		return XCC_ERROR_INVALID_REQUEST;
	if (s == NULL)
	{
		r->principal.owner_generation = c->generation;
		return XCC_OK;
	}
	return xcc_session_check_principal(s, &r->principal);
}
typedef struct
{
	XccRequest* r;
	XccCancelReason reason;
} Cancel;
static void cancel(void* data)
{
	Cancel* cancel = data;
	XccRequest* r = cancel->r;
	static const XccErrorCode codes[] = {XCC_ERROR_CANCELLED,		XCC_ERROR_OWNER_GONE,
										 XCC_ERROR_NO_SUCH_SESSION, XCC_ERROR_BACKEND_GONE,
										 XCC_ERROR_TOKEN_REMOVED,	XCC_ERROR_DEVICE};
	if (!r->answered)
	{
		if (r->cancelled_code == XCC_OK)
			r->cancelled_code = codes[cancel->reason];
		g_cancellable_cancel(r->cancellable);
	}
	xcc_request_unref(r);
	g_free(cancel);
}
void xcc_request_cancel(XccRequest* r, XccCancelReason reason)
{
	if (r == NULL || (unsigned)reason > XCC_CANCEL_DEVICE ||
		g_atomic_int_get(&r->context->stopping))
		return;
	g_atomic_int_compare_and_exchange(&r->cancel_intent, 0, (gint)reason + 1);
	Cancel* c = g_new(Cancel, 1);
	*c = (Cancel){xcc_request_ref(r), reason};
	if (!xcc_context_post(r->context, cancel, c))
	{
		xcc_request_unref(c->r);
		g_free(c);
	}
}
typedef struct
{
	XccContext* c;
	uint64_t generation;
} Generation;
static void generation(void* data)
{
	Generation* g = data;
	XccContext* c = g->c;
	c->generation = g->generation;
	for (guint i = 0; i < c->requests->len; i++)
	{
		XccRequest* r = g_ptr_array_index(c->requests, i);
		if ((r->session != NULL ? r->session->owner_generation : r->principal.owner_generation) !=
			c->generation)
		{
			g_atomic_int_set(&r->cancel_intent, XCC_CANCEL_OWNER_GONE + 1);
			if (!r->answered)
			{
				r->cancelled_code = XCC_ERROR_OWNER_GONE;
				g_cancellable_cancel(r->cancellable);
			}
		}
	}
	g_autoptr(GPtrArray) sessions = xcc_context_sessions_snapshot(c);
	for (guint i = 0; i < sessions->len; i++)
	{
		XccSession* s = g_ptr_array_index(sessions, i);
		if (s->owner_generation != c->generation)
			xcc_session_close_internal(s);
	}
	xcc_context_unref(c);
	g_free(g);
}
void xcc_context_set_owner_generation(XccContext* c, uint64_t value)
{
	Generation* g = g_new(Generation, 1);
	*g = (Generation){xcc_context_ref(c), value};
	if (!xcc_context_post(c, generation, g))
	{
		xcc_context_unref(g->c);
		g_free(g);
	}
}
static void shutdown_delivered(void* data)
{
	XccContext* c = data;
	g_thread_join(c->thread);
	c->thread = NULL;
	g_atomic_int_set(&context_live, 0);
	if (c->shutdown_done != NULL)
		c->shutdown_done(c, c->shutdown_data);
	xcc_context_unref(c);
}
/* Session releases have settled before this is posted; receiver outlives this callback. */
void xcc_context_check_shutdown(XccContext* c)
{
	g_mutex_lock(&c->queue_lock);
	if (!c->stopping || !c->watch_stopped || c->shutdown_posted || c->requests->len != 0 ||
		g_atomic_int_get(&c->posts) != 0 || g_hash_table_size(c->interactions) != 0 ||
		g_atomic_int_get(&c->ui_pending) != 0 || g_atomic_int_get(&c->ui_handles) != 0 ||
		xcc_session_releases_pending() != 0)
	{
		g_mutex_unlock(&c->queue_lock);
		return;
	}
	c->shutdown_posted = TRUE;
	g_mutex_unlock(&c->queue_lock);
	xcc_ui_uninstall(c);
	certificate_tokens_clear_watch(c->tokens);
	g_ptr_array_set_size(c->sessions, 0);
	if (c->own_tokens)
	{
		g_thread_join(g_thread_new("certificate-unload", unload_modules, c->tokens));
		c->tokens = NULL;
		c->own_tokens = FALSE;
	}
	c->dispatch.post(c->dispatch.user, shutdown_delivered, xcc_context_ref(c));
	g_main_loop_quit(c->loop);
}
static gboolean shutdown_poll(void* data)
{
	XccContext* c = data;
	xcc_context_check_shutdown(c);
	return g_main_loop_is_running(c->loop) ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}
static void stop_watch_worker(GTask* task, gpointer source, gpointer data,
							  GCancellable* cancellable)
{
	certificate_tokens_stop_watch(data);
	g_task_return_boolean(task, TRUE);
}
static void stopped_watch(GObject* source, GAsyncResult* result, gpointer data)
{
	XccContext* c = data;
	c->watch_stopped = TRUE;
	xcc_context_check_shutdown(c);
	xcc_context_unref(c);
}
static void shutdown_start(void* data)
{
	XccContext* c = data;
	g_atomic_int_set(&c->stopping, TRUE);
	for (guint i = 0; i < c->requests->len; i++)
	{
		XccRequest* r = g_ptr_array_index(c->requests, i);
		g_atomic_int_set(&r->cancel_intent, XCC_CANCEL_BACKEND_GONE + 1);
		if (!r->answered)
		{
			r->cancelled_code = XCC_ERROR_BACKEND_GONE;
			g_cancellable_cancel(r->cancellable);
		}
	}
	g_autoptr(GPtrArray) sessions = xcc_context_sessions_snapshot(c);
	for (guint i = 0; i < sessions->len; i++)
		xcc_session_invalidate_internal(g_ptr_array_index(sessions, i), "backend_gone");
	g_autoptr(GTask) watch = g_task_new(NULL, NULL, stopped_watch, xcc_context_ref(c));
	g_task_set_task_data(watch, c->tokens, NULL);
	g_task_run_in_thread(watch, stop_watch_worker);

	GSource* source = g_timeout_source_new(10);
	g_source_set_callback(source, shutdown_poll, c, NULL);
	g_source_attach(source, c->coordinator);
	g_source_unref(source);
	xcc_context_check_shutdown(c);
	xcc_context_unref(c);
}
void xcc_context_shutdown_async(XccContext* c, XccShutdownDone done, void* user)
{
	if (!g_atomic_int_compare_and_exchange(&c->shutdown_started, 0, 1))
		return;
	c->shutdown_done = done;
	c->shutdown_data = user;
	xcc_context_post(c, shutdown_start, xcc_context_ref(c));
}
static const char* const error_names[] = {NULL,
										  "cancelled",
										  "owner_gone",
										  "backend_gone",
										  "no_such_session",
										  "invalid_request",
										  "invalid_purpose",
										  "invalid_filter",
										  "device_error",
										  "interaction_required",
										  "no_display",
										  "pin_locked",
										  "token_removed",
										  "device_error",
										  "device_error",
										  "invalid_request"};
const char* xcc_error_wire_name(XccErrorCode error)
{
	return error < G_N_ELEMENTS(error_names) ? error_names[error] : "device_error";
}
uint32_t xcc_error_wire_response(XccErrorCode error)
{
	return error == XCC_OK ? 0 : error == XCC_ERROR_CANCELLED ? 1 : 2;
}
XccCandidate* xcc_candidate_ref(const XccCandidate* value)
{
	XccCandidate* c = (XccCandidate*)value;
	if (c)
		g_atomic_int_inc(&c->refs);
	return c;
}
void xcc_candidate_unref(XccCandidate* c)
{
	if (c == NULL || !g_atomic_int_dec_and_test(&c->refs))
		return;
	g_free((char*)c->info.subject);
	g_free((char*)c->info.issuer);
	g_free((char*)c->info.token);
	g_free((char*)c->info.reader);
	certificate_candidate_unref(c->value);
	g_free(c);
}
XccBytes xcc_candidate_certificate(const XccCandidate* c)
{
	return (XccBytes){sizeof(XccBytes), XCC_ABI_VERSION, c->value->der->data, c->value->der->len};
}
const CertificateCandidate* xcc_candidate_internal(const XccCandidate* c)
{
	return c->value;
}

XccCandidate* xcc_candidate_snapshot(CertificateCandidate* value)
{
	XccCandidate* c = g_new0(XccCandidate, 1);
	c->refs = 1;
	c->value = certificate_candidate_ref(value);
	c->info = (XccCandidateInfo){
		.struct_size = sizeof(c->info),
		.abi_version = XCC_ABI_VERSION,
		.certificate = {sizeof(XccBytes), XCC_ABI_VERSION, value->der->data, value->der->len},
		.subject = certificate_display_text(value->subject_display, CERTIFICATE_DISPLAY_MAX_SUBJECT,
											"Unnamed certificate"),
		.issuer = certificate_display_text(value->issuer_display, CERTIFICATE_DISPLAY_MAX_ISSUER,
										   "an unnamed issuer"),
		.token = certificate_display_text(value->token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL,
										  "unnamed token"),
		.reader = certificate_display_text(value->token->reader_name,
										   CERTIFICATE_DISPLAY_MAX_READER, NULL),
		.key_curve_present = value->key_curve != NULL,
		.key_type = value->key_type,
		.key_curve = value->key_curve,
		.key_size = value->key_size,
		.mechanisms = (const char* const*)value->supported_mechanisms,
		.not_before = value->not_before,
		.not_after = value->not_after,
		.protected_path = value->token->protected_authentication_path};
	return c;
}
const XccCandidateInfo* xcc_candidate_info(const XccCandidate* c)
{
	return &c->info;
}

void xcc_context_hold_ui(XccContext* c)
{
	xcc_context_ref(c);
	g_atomic_int_inc(&c->ui_handles);
}
void xcc_context_release_ui(XccContext* c)
{
	g_atomic_int_add(&c->ui_handles, -1);
	xcc_context_unref(c);
}
void xcc_adapter_settings(bool verbose, uint32_t login_timeout)
{
	certificate_log_set_verbose(verbose);
	certificate_pin_set_login_timeout(login_timeout);
}
