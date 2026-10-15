/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "session-impl.h"

#include "certificate-impl.h"
#include "redact.h"

enum
{
	SIGNAL_INVALIDATED,
	N_SIGNALS
};

static guint signals[N_SIGNALS];

static void certificate_impl_session_iface_init(XdpImplSessionIface* iface);

G_DEFINE_FINAL_TYPE_WITH_CODE(CertificateImplSession, certificate_impl_session,
                              XDP_IMPL_TYPE_SESSION_SKELETON,
                              G_IMPLEMENT_INTERFACE(XDP_IMPL_TYPE_SESSION,
                                                    certificate_impl_session_iface_init))

/* Session paths are guessable, so Close() requires frontend-owner authorization. */
static gboolean handle_close(XdpImplSession* object, GDBusMethodInvocation* invocation)
{
	/* Take a reference before authorization, which may discover owner loss and remove this session. */
	g_autoptr(CertificateImplSession) session = g_object_ref(CERTIFICATE_IMPL_SESSION(object));

	if (!certificate_impl_sender_is_frontend_default(
	        g_dbus_method_invocation_get_sender(invocation)))
	{
		certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL, "session_close",
		                         FALSE);
		g_dbus_method_invocation_return_error_literal(
		    invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
		    "Only xdg-desktop-portal may call this interface");
		return TRUE;
	}

	/* The frontend answers invalidation with Close(), so closing an already-closed session must succeed. */
	certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id, "closed-by-portal");

	/* The local reference keeps the session alive after forget() drops the table's reference. */
	certificate_impl_session_close(session);
	certificate_impl_session_forget(session);
	xdp_impl_session_complete_close(object, invocation);

	return TRUE;
}

static void certificate_impl_session_iface_init(XdpImplSessionIface* iface)
{
	iface->handle_close = handle_close;
}

static void certificate_impl_session_finalize(GObject* object)
{
	CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(object);

	/* Async release holds a reference until completion; finalization also closes devices on early error paths. */
	certificate_impl_session_release_device(session);

	if (session->expiry_source != 0)
		g_source_remove(session->expiry_source);

	certificate_impl_session_unexport(session);

	g_clear_pointer(&session->login_waiters, g_ptr_array_unref);
	g_clear_object(&session->login_cancellable);
	g_clear_pointer(&session->candidate, certificate_candidate_unref);
	g_clear_pointer(&session->id, g_free);
	g_clear_pointer(&session->app_id, g_free);
	g_clear_pointer(&session->owner, g_free);
	g_mutex_clear(&session->device_lock);

	G_OBJECT_CLASS(certificate_impl_session_parent_class)->finalize(object);
}

static void certificate_impl_session_class_init(CertificateImplSessionClass* klass)
{
	GObjectClass* object_class = G_OBJECT_CLASS(klass);

	object_class->finalize = certificate_impl_session_finalize;

	/* The reason passes unchanged to SessionInvalidated; see docs/IMPL-INTERFACE.md. */
	signals[SIGNAL_INVALIDATED] =
	    g_signal_new("invalidated", CERTIFICATE_TYPE_IMPL_SESSION, G_SIGNAL_RUN_LAST, 0, NULL,
	                 NULL, NULL, G_TYPE_NONE, 1, G_TYPE_STRING);
}

static void certificate_impl_session_init(CertificateImplSession* session)
{
	g_mutex_init(&session->device_lock);
	session->device.session = CK_INVALID_HANDLE;
	session->device.private_key = CK_INVALID_HANDLE;
	xdp_impl_session_set_version(XDP_IMPL_SESSION(session), 1);
}

CertificateImplSession* certificate_impl_session_new(const char* session_handle,
                                                     const char* app_id)
{
	CertificateImplSession* session = g_object_new(CERTIFICATE_TYPE_IMPL_SESSION, NULL);

	session->id = g_strdup(session_handle);
	session->app_id = g_strdup(app_id);
	session->identity_level = CERTIFICATE_IDENTITY_UNKNOWN;

	return session;
}

gboolean certificate_impl_session_export(CertificateImplSession* session,
                                         GDBusConnection* connection, GError** error)
{
	if (session->exported)
		return TRUE;

	/* Export failure must abort creation because the frontend needs Session.Close(). */
	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(session), connection,
	                                      session->id, error))
		return FALSE;

	session->exported = TRUE;
	return TRUE;
}

void certificate_impl_session_unexport(CertificateImplSession* session)
{
	if (!session->exported)
		return;

	session->exported = FALSE;
	g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(session));
}

static gboolean on_lifetime_expired(gpointer user_data)
{
	CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(user_data);

	session->expiry_source = 0;

	/* This timer releases device state if the frontend misses its expiry deadline. */
	certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id, "lifetime-expired");
	certificate_impl_session_invalidate(session, "expired");

	return G_SOURCE_REMOVE;
}

void certificate_impl_session_grant(CertificateImplSession* session,
                                    CertificateCandidate* candidate, CertificatePurpose purpose,
                                    gboolean may_sign, gboolean may_decrypt, guint32 lifetime)
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

gboolean certificate_impl_session_is_expired(CertificateImplSession* session)
{
	if (!session->granted)
		return FALSE;

	return session->expires_at <= (g_get_monotonic_time() / G_USEC_PER_SEC);
}

void certificate_impl_session_release_device(CertificateImplSession* session)
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
	certificate_impl_session_release_device(CERTIFICATE_IMPL_SESSION(task_data));
	g_task_return_boolean(task, TRUE);
}

static void on_device_released(GObject* source, GAsyncResult* result, gpointer user_data)
{
	g_atomic_int_add(&certificate_release_pending, -1);
}

void certificate_impl_session_release_device_async(CertificateImplSession* session)
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

void certificate_impl_session_drain_releases(guint timeout_ms)
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

/* Keep the skeleton exported until frontend Close() or finalization. */
void certificate_impl_session_close(CertificateImplSession* session)
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
	certificate_impl_session_release_device_async(session);
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

void certificate_impl_session_invalidate(CertificateImplSession* session, const char* reason)
{
	if (session->closed)
		return;

	reason = checked_reason(reason);

	g_signal_emit(session, signals[SIGNAL_INVALIDATED], 0, reason);

	if (session->exported)
		xdp_impl_session_emit_closed(XDP_IMPL_SESSION(session));

	certificate_impl_session_close(session);
}
