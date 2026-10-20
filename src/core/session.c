/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "context-private.h"
#include "sources.h"

#include "../redact.h"

G_DEFINE_FINAL_TYPE(XccSession, xcc_session, G_TYPE_OBJECT)

static void xcc_session_finalize(GObject* object)
{
	XccSession* session = XCC_SESSION(object);

	/* Async release holds a reference until completion. */
	xcc_session_release_device(session);
	if (session->expiry_source != 0)
		xcc_source_remove(session->expiry_source);

	g_clear_pointer(&session->login_waiters, g_ptr_array_unref);
	g_clear_object(&session->login_cancellable);
	g_clear_pointer(&session->candidate, certificate_candidate_unref);
	g_free(session->id);
	g_free(session->app_id);
	if (session->context != NULL)
		xcc_context_unref(session->context);
	g_mutex_clear(&session->device_lock);
	g_mutex_clear(&session->operation_lock);

	G_OBJECT_CLASS(xcc_session_parent_class)->finalize(object);
}

static void xcc_session_class_init(XccSessionClass* klass)
{
	G_OBJECT_CLASS(klass)->finalize = xcc_session_finalize;
}

static void xcc_session_init(XccSession* session)
{
	g_mutex_init(&session->device_lock);
	g_mutex_init(&session->operation_lock);
	session->device.session = CK_INVALID_HANDLE;
	session->device.private_key = CK_INVALID_HANDLE;
}

XccSession* xcc_session_new_legacy(const char* log_id, XccSessionInvalidated invalidated,
								   gpointer user_data)
{
	XccSession* session = g_object_new(XCC_TYPE_SESSION, NULL);

	session->id = g_strdup(log_id);
	xcc_session_set_invalidated_callback(session, invalidated, user_data);
	return session;
}

void xcc_session_set_invalidated_callback(XccSession* session, XccSessionInvalidated invalidated,
                                          gpointer user_data)
{
	session->invalidated = invalidated;
	session->invalidated_data = user_data;
}

static gboolean on_lifetime_expired(gpointer user_data)
{
	XccSession* session = XCC_SESSION(user_data);

	session->expiry_source = 0;

	/* This timer releases device state if the frontend misses its expiry deadline. */
	certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id, "lifetime-expired");
	xcc_session_invalidate(session, "expired");

	return G_SOURCE_REMOVE;
}

void xcc_session_grant(XccSession* session, CertificateCandidate* candidate,
                        CertificatePurpose purpose, gboolean may_sign, gboolean may_decrypt,
                        guint32 lifetime)
{
	g_clear_pointer(&session->candidate, certificate_candidate_unref);
	session->candidate = certificate_candidate_ref(candidate);
	session->purpose = purpose;
	session->may_sign = may_sign;
	session->may_decrypt = may_decrypt;

	/* Device rebinding and budget updates share device_lock with operation workers. */
	g_mutex_lock(&session->device_lock);
	session->decrypt_count = 0;
	g_mutex_unlock(&session->device_lock);

	session->lifetime = lifetime;
	/* Monotonic expiry prevents wall-clock adjustments from extending grants. */
	session->expires_at = (g_get_monotonic_time() / G_USEC_PER_SEC) + lifetime;
	session->granted = TRUE;

	if (session->expiry_source != 0)
		xcc_source_remove(session->expiry_source);

	/* Operations expire at expires_at; only device teardown receives the grace period. */
	session->expiry_source =
		xcc_timeout_add(lifetime + CERTIFICATE_EXPIRY_GRACE_SECONDS, on_lifetime_expired, session);
}

gboolean xcc_session_is_expired(XccSession* session)
{
	if (!session->granted)
		return FALSE;

	return session->expires_at <= (g_get_monotonic_time() / G_USEC_PER_SEC);
}

void xcc_session_release_device(XccSession* session)
{
	g_mutex_lock(&session->device_lock);
	certificate_device_close(&session->device);
	g_mutex_unlock(&session->device_lock);
}

/* Atomic count of pending worker releases, drained during shutdown. */
static gint certificate_release_pending = 0;

typedef struct
{
	XccSession* session;
	GDestroyNotify done;
	gpointer user_data;
} DeviceRelease;

static void device_release_free(gpointer data)
{
	DeviceRelease* release = data;

	g_object_unref(release->session);
	g_free(release);
}

static void release_thread(GTask* task, gpointer source, gpointer task_data,
                           GCancellable* cancellable)
{
	DeviceRelease* release = task_data;

	xcc_session_release_device(release->session);
	g_task_return_boolean(task, TRUE);
}

static void on_device_released(GObject* source, GAsyncResult* result, gpointer user_data)
{
	DeviceRelease* release = g_task_get_task_data(G_TASK(result));

	if (release->done != NULL)
		release->done(release->user_data);
	g_atomic_int_add(&certificate_release_pending, -1);
}

void xcc_session_release_device_async_full(XccSession* session, GDestroyNotify done,
                                           gpointer user_data)
{
	g_autoptr(GTask) task = NULL;
	DeviceRelease* release = g_new0(DeviceRelease, 1);

	release->session = g_object_ref(session);
	release->done = done;
	release->user_data = user_data;
	g_atomic_int_add(&certificate_release_pending, 1);
	task = g_task_new(NULL, NULL, on_device_released, NULL);
	g_task_set_task_data(task, release, device_release_free);
	g_task_run_in_thread(task, release_thread);
}

void xcc_session_release_device_async(XccSession* session)
{
	/* Avoid blocking the main thread when a worker holds device_lock. */
	if (g_mutex_trylock(&session->device_lock))
	{
		gboolean idle = session->device.module == NULL;

		g_mutex_unlock(&session->device_lock);

		if (idle)
			return;
	}

	xcc_session_release_device_async_full(session, NULL, NULL);
}

void xcc_session_drain_releases(guint timeout_ms)
{
	gint64 deadline = g_get_monotonic_time() + (gint64) timeout_ms * 1000;

	while (g_atomic_int_get(&certificate_release_pending) > 0)
	{
		if (g_get_monotonic_time() >= deadline)
		{
			/* Remaining logout work is left to module teardown. */
			g_message("device-close-unfinished detail=shutdown-timeout timeout_ms=%u",
			          timeout_ms);
			return;
		}

		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
}

/* Close is idempotent; release may wait for an operation worker. */
void xcc_session_close_internal(XccSession* session)
{
	g_autoptr(XccSession) hold = g_object_ref(session);
	if (session->closed)
		return;

	g_atomic_int_set(&session->closed, TRUE);
	if (session->context != NULL)
	{
		XccContext* c = session->context;
		for (guint i = 0; i < c->requests->len; i++)
		{
			XccRequest* r = g_ptr_array_index(c->requests, i);
			if (r->session == session)
			{
				g_atomic_int_compare_and_exchange(&r->cancel_intent, 0,
												  XCC_CANCEL_SESSION_CLOSED + 1);
				if (!r->answered)
				{
					if (r->cancelled_code == XCC_OK)
						r->cancelled_code = XCC_ERROR_NO_SUCH_SESSION;
					g_cancellable_cancel(r->cancellable);
				}
			}
		}
	}

	if (session->expiry_source != 0)
	{
		xcc_source_remove(session->expiry_source);
		session->expiry_source = 0;
	}

	/* The worker owns a session reference while waiting on device_lock and the token. */
	xcc_session_release_device_async(session);
	if (session->context != NULL)
		g_ptr_array_remove(session->context->sessions, session);
}

/* The wire vocabulary accepts policy, but this backend never emits it; expiry is a delayed fallback. */
static const char* const certificate_session_reasons[] = {
	"expired", "token_removed", "policy", "backend_gone", "error",
};

static const char* checked_reason(const char* reason)
{
	for (gsize i = 0; i < G_N_ELEMENTS(certificate_session_reasons); i++)
	{
		if (g_strcmp0(reason, certificate_session_reasons[i]) == 0)
			return reason;
	}

	/* Invalid internal reason values fall back to the wire value error. */
	g_critical("Invalid SessionInvalidated reason: '%s'",
	           reason != NULL ? reason : "(null)");
	return "error";
}

void xcc_session_invalidate_internal(XccSession* session, const char* reason)
{
	g_autoptr(XccSession) hold = g_object_ref(session);

	if (session->closed || session->invalidating)
		return;

	reason = checked_reason(reason);
	session->invalidating = TRUE;
	if (session->context != NULL)
	{
		XccErrorCode code = g_strcmp0(reason, "token_removed") == 0	 ? XCC_ERROR_TOKEN_REMOVED
							: g_strcmp0(reason, "backend_gone") == 0 ? XCC_ERROR_BACKEND_GONE
																	 : XCC_ERROR_DEVICE;
		XccCancelReason cancel = code == XCC_ERROR_TOKEN_REMOVED  ? XCC_CANCEL_TOKEN_REMOVED
								 : code == XCC_ERROR_BACKEND_GONE ? XCC_CANCEL_BACKEND_GONE
																  : XCC_CANCEL_DEVICE;
		for (guint i = 0; i < session->context->requests->len; i++)
		{
			XccRequest* r = g_ptr_array_index(session->context->requests, i);
			if (r->session != session)
				continue;
			g_atomic_int_compare_and_exchange(&r->cancel_intent, 0, cancel + 1);
			if (!r->answered && r->cancelled_code == XCC_OK)
				r->cancelled_code = code;
		}
	}
	xcc_session_dispatch_invalidated(session, reason);

	xcc_session_close(session);
}

/* Main-context state queries; workers retain the existing device/operation locks. */
gboolean xcc_session_is_closed(XccSession* session)
{
	return g_atomic_int_get(&session->closed);
}

gboolean xcc_session_uses_token(XccSession* session, const CertificateToken* token)
{
	return session->candidate != NULL && certificate_token_same(session->candidate->token, token);
}

guint xcc_session_releases_pending(void)
{
	return g_atomic_int_get(&certificate_release_pending);
}
typedef struct
{
	XccSession* session;
	char* reason;
} SessionCall;
static void session_call(void* data)
{
	SessionCall* call = data;
	if (call->reason != NULL)
		xcc_session_invalidate_internal(call->session, call->reason);
	else
		xcc_session_close_internal(call->session);
	g_object_unref(call->session);
	g_free(call->reason);
	g_free(call);
}
void xcc_session_close(XccSession* session)
{
	if (xcc_session_is_closed(session))
		return;
	if (session->context == NULL || g_main_context_is_owner(session->context->coordinator))
	{
		xcc_session_close_internal(session);
		return;
	}
	SessionCall* call = g_new0(SessionCall, 1);
	call->session = g_object_ref(session);
	if (!xcc_context_post(session->context, session_call, call))
	{
		g_object_unref(call->session);
		g_free(call->reason);
		g_free(call);
	}
}
void xcc_session_invalidate(XccSession* session, const char* reason)
{
	if (xcc_session_is_closed(session))
		return;
	if (session->context == NULL || g_main_context_is_owner(session->context->coordinator))
	{
		xcc_session_invalidate_internal(session, reason);
		return;
	}
	SessionCall* call = g_new0(SessionCall, 1);
	call->session = g_object_ref(session);
	call->reason = g_strdup(reason);
	if (!xcc_context_post(session->context, session_call, call))
	{
		g_object_unref(call->session);
		g_free(call->reason);
		g_free(call);
	}
}
static void invalidated_delivery(void* data)
{
	SessionCall* call = data;
	XccSession* s = call->session;
	/* The adapter may detach its callback before this queued delivery. */
	if (s->invalidated != NULL)
		s->invalidated(s, call->reason, s->invalidated_data);
	else if (s->context->config.session_invalidated != NULL)
		s->context->config.session_invalidated(s, call->reason, s->context->config.user);
	g_object_unref(s);
	g_free(call->reason);
	g_free(call);
}
void xcc_session_dispatch_invalidated(XccSession* s, const char* reason)
{
	if (s->context == NULL)
	{
		if (s->invalidated != NULL)
			s->invalidated(s, reason, s->invalidated_data);
		return;
	}
	SessionCall* call = g_new0(SessionCall, 1);
	call->session = g_object_ref(s);
	call->reason = g_strdup(reason);
	s->context->dispatch.post(s->context->dispatch.user, invalidated_delivery, call);
}
typedef struct
{
	XccSession* session;
	GMutex mutex;
	GCond cond;
	gboolean ready, valid;
} SessionNew;
static void session_new_register(void* data)
{
	SessionNew* call = data;
	XccSession* s = call->session;
	XccContext* c = s->context;
	call->valid = !c->stopping && s->owner_generation == c->generation;
	if (call->valid)
		g_ptr_array_add(c->sessions, g_object_ref(s));
	g_mutex_lock(&call->mutex);
	call->ready = TRUE;
	g_cond_signal(&call->cond);
	g_mutex_unlock(&call->mutex);
}
XccSession* xcc_session_new(XccContext* c, const XccSessionSpec* spec, XccError* error)
{
	if (error != NULL)
		*error = (XccError){sizeof(XccError), XCC_ABI_VERSION, XCC_OK};
	if (c == NULL || spec == NULL || spec->struct_size < sizeof(*spec) ||
		spec->abi_version != XCC_ABI_VERSION || spec->app_id == NULL ||
		(spec->identity_present && spec->identity_level > CERTIFICATE_IDENTITY_UNKNOWN))
	{
		if (error != NULL)
			error->code = XCC_ERROR_INVALID_REQUEST;
		return NULL;
	}
	XccSession* s = xcc_session_new_legacy(spec->log_id, NULL, NULL);
	s->context = xcc_context_ref(c);
	s->owner_generation = spec->owner_generation;
	s->app_id = g_strdup(spec->app_id);
	s->identity_seen = spec->identity_present;
	s->identity_level = spec->identity_level;
	SessionNew call = {.session = s};
	g_mutex_init(&call.mutex);
	g_cond_init(&call.cond);
	if (g_main_context_is_owner(c->coordinator))
		session_new_register(&call);
	else
	{
		g_mutex_lock(&call.mutex);
		if (!xcc_context_post(c, session_new_register, &call))
			call.ready = TRUE;
		while (!call.ready)
			g_cond_wait(&call.cond, &call.mutex);
		g_mutex_unlock(&call.mutex);
	}
	g_mutex_clear(&call.mutex);
	g_cond_clear(&call.cond);
	if (!call.valid)
	{
		if (error != NULL)
			error->code = XCC_ERROR_NO_SUCH_SESSION;
		g_object_unref(s);
		return NULL;
	}
	return s;
}

typedef struct
{
	XccSession* session;
	const XccPrincipal* principal;
	XccErrorCode error;
	GMutex mutex;
	GCond cond;
	gboolean ready;
} PrincipalCheck;
static void principal_check(void* data)
{
	PrincipalCheck* call = data;
	XccSession* s = call->session;
	const XccPrincipal* p = call->principal;
	if (p == NULL || p->struct_size < sizeof(*p) || p->abi_version != XCC_ABI_VERSION)
	{
		call->error = XCC_ERROR_INVALID_REQUEST;
		goto completed;
	}
	if (xcc_session_is_closed(s) || s->owner_generation != s->context->generation ||
		p->owner_generation != s->owner_generation || g_strcmp0(s->app_id, p->app_id) != 0)
		call->error = XCC_ERROR_NO_SUCH_SESSION;
	else if (p->identity_present)
	{
		if ((unsigned)p->identity_level > CERTIFICATE_IDENTITY_UNKNOWN)
			call->error = XCC_ERROR_INVALID_REQUEST;
		else if (s->identity_seen && p->identity_level < s->identity_level)
		{
			certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, p->app_id,
									 certificate_identity_level_to_string(p->identity_level),
									 "identity-level-raised", FALSE);
			call->error = XCC_ERROR_NO_SUCH_SESSION;
		}
		else
		{
			s->identity_level = p->identity_level;
			s->identity_seen = TRUE;
		}
	}
completed:
	g_mutex_lock(&call->mutex);
	call->ready = TRUE;
	g_cond_signal(&call->cond);
	g_mutex_unlock(&call->mutex);
}
XccErrorCode xcc_session_check_principal(XccSession* session, const XccPrincipal* principal)
{
	if (session->context == NULL || principal == NULL)
		return XCC_ERROR_INVALID_REQUEST;
	PrincipalCheck call = {.session = session, .principal = principal};
	g_mutex_init(&call.mutex);
	g_cond_init(&call.cond);
	if (g_main_context_is_owner(session->context->coordinator))
		principal_check(&call);
	else
	{
		g_mutex_lock(&call.mutex);
		if (!xcc_context_post(session->context, principal_check, &call))
		{
			call.error = XCC_ERROR_BACKEND_GONE;
			call.ready = TRUE;
		}
		while (!call.ready)
			g_cond_wait(&call.cond, &call.mutex);
		g_mutex_unlock(&call.mutex);
	}
	g_cond_clear(&call.cond);
	g_mutex_clear(&call.mutex);
	return call.error;
}

XccSession* xcc_session_ref(XccSession* session)
{
	return g_object_ref(session);
}
void xcc_session_unref(XccSession* session)
{
	if (session != NULL)
		g_object_unref(session);
}
