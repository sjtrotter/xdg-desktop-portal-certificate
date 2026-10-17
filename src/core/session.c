/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "session-private.h"

#include "../redact.h"

G_DEFINE_FINAL_TYPE(XccSession, xcc_session, G_TYPE_OBJECT)

static void xcc_session_finalize(GObject* object)
{
	XccSession* session = XCC_SESSION(object);

	/* Async release holds a reference until completion. */
	xcc_session_release_device(session);
	if (session->expiry_source != 0)
		g_source_remove(session->expiry_source);

	g_clear_pointer(&session->login_waiters, g_ptr_array_unref);
	g_clear_object(&session->login_cancellable);
	g_clear_pointer(&session->candidate, certificate_candidate_unref);
	g_free(session->id);
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

XccSession* xcc_session_new(const char* log_id, XccSessionInvalidated invalidated,
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
		g_source_remove(session->expiry_source);

	/* Operations expire at expires_at; only device teardown receives the grace period. */
	session->expiry_source = g_timeout_add_seconds(lifetime + CERTIFICATE_EXPIRY_GRACE_SECONDS,
	                                                   on_lifetime_expired, session);
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

static void release_thread(GTask* task, gpointer source, gpointer task_data,
                           GCancellable* cancellable)
{
	xcc_session_release_device(XCC_SESSION(task_data));
	g_task_return_boolean(task, TRUE);
}

static void on_device_released(GObject* source, GAsyncResult* result, gpointer user_data)
{
	g_atomic_int_add(&certificate_release_pending, -1);
}

void xcc_session_release_device_async(XccSession* session)
{
	g_autoptr(GTask) task = NULL;

	/* Avoid blocking the main thread when a worker holds device_lock. */
	if (g_mutex_trylock(&session->device_lock))
	{
		gboolean idle = session->device.module == NULL;

		g_mutex_unlock(&session->device_lock);

		if (idle)
			return;
	}

	g_atomic_int_add(&certificate_release_pending, 1);

	task = g_task_new(NULL, NULL, on_device_released, NULL);
	g_task_set_task_data(task, g_object_ref(session), g_object_unref);
	g_task_run_in_thread(task, release_thread);
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
void xcc_session_close(XccSession* session)
{
	if (session->closed)
		return;

	session->closed = TRUE;

	if (session->expiry_source != 0)
	{
		g_source_remove(session->expiry_source);
		session->expiry_source = 0;
	}

	/* The worker owns a session reference while waiting on device_lock and the token. */
	xcc_session_release_device_async(session);
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

void xcc_session_invalidate(XccSession* session, const char* reason)
{
	g_autoptr(XccSession) hold = g_object_ref(session);

	if (session->closed || session->invalidating)
		return;

	reason = checked_reason(reason);
	session->invalidating = TRUE;
	if (session->invalidated != NULL)
		session->invalidated(session, reason, session->invalidated_data);

	xcc_session_close(session);
}

/* Main-context state queries; workers retain the existing device/operation locks. */
gboolean xcc_session_is_closed(XccSession* session)
{
	return session->closed;
}

gboolean xcc_session_uses_token(XccSession* session, const CertificateToken* token)
{
	return session->candidate != NULL && certificate_token_same(session->candidate->token, token);
}
