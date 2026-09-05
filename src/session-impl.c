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

/* CLOSE IS AUTHORISED LIKE EVERY OTHER METHOD. The Session skeleton is exported
 * on the same bus name as the Certificate interface, at a path whose shape is
 * guessable, and Close() on it logs the card out and destroys a grant. Object
 * path secrecy is not an access control. */
static gboolean handle_close(XdpImplSession* object, GDBusMethodInvocation* invocation)
{
	/* THE REFERENCE COMES FIRST, before the authorisation check: resolving who
	 * owns the frontend name can discover that it has changed hands, and the
	 * first thing that discovery does is invalidate and drop every session the
	 * previous owner created -- which is this one. */
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

	/* IDEMPOTENT. The frontend answers SessionInvalidated with Close(), so the
	 * second close of a session this backend already tore down is the normal
	 * case and must succeed rather than telling the application the device
	 * failed. */
	certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id, "closed-by-portal");

	/* forget() drops the table's reference, which is the only other one, so the
	 * invocation is completed under the reference taken above. */
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

	/* SYNCHRONOUS, AND THE ONE PLACE THAT IS RIGHT. There is no object left to
	 * hand a worker, and there cannot be one running: the asynchronous close
	 * holds a reference for its whole life, so finalize cannot be reached until
	 * it has finished -- which means that by the time this runs the device is
	 * already closed and this is a mutex acquisition and a NULL check. It is
	 * still called, because a session that was never closed (a test, an early
	 * error path) must not leak a logged-in card session. */
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

	/* Carries the reason string straight through to SessionInvalidated. The
	 * vocabulary is the interface's, not this file's; see
	 * docs/IMPL-INTERFACE.md for why "expired" is among the ones emitted even
	 * though the impl XML's prose lists only three. */
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

	/* A FAILURE HERE ABORTS THE CALL. It used to be a warning, and the session
	 * was inserted anyway: the frontend then held a session handle for an
	 * object that was not on the bus, and could neither close it nor learn
	 * that it could not. */
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

	/* THE BACKEND ENFORCES THE LIFETIME TOO. The frontend refuses an expired
	 * grant before this backend is called at all, so this is not the check that
	 * stops the operation -- it is what stops this process from sitting on a
	 * logged-in card session after the authorisation for it has run out. */
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

	/* THE DEVICE IS NOT TOUCHED HERE, and it is not left alone either: the
	 * candidate this session now carries is a different one, and
	 * certificate_device_open() compares what it was opened for against what it
	 * is asked for and re-opens when they differ. Doing it there rather than
	 * here is what keeps it race-free -- the comparison, the close and the
	 * re-open all happen on the worker under device_lock, so a Sign that
	 * arrives in the same turn as the re-grant cannot slip between them.
	 *
	 * The budget is charged and reset under the same lock the workers read it
	 * under. */
	g_mutex_lock(&session->device_lock);
	session->decrypt_count = 0;
	g_mutex_unlock(&session->device_lock);

	session->lifetime = lifetime;
	session->expires_at = (g_get_real_time() / G_USEC_PER_SEC) + lifetime;
	session->granted = TRUE;

	if (session->expiry_source != 0)
		g_source_remove(session->expiry_source);

	session->expiry_source = g_timeout_add_seconds(lifetime, on_lifetime_expired, session);
}

gboolean certificate_impl_session_is_expired(CertificateImplSession* session)
{
	if (!session->granted)
		return FALSE;

	return session->expires_at <= (g_get_real_time() / G_USEC_PER_SEC);
}

void certificate_impl_session_release_device(CertificateImplSession* session)
{
	g_mutex_lock(&session->device_lock);
	certificate_device_close(&session->device);
	g_mutex_unlock(&session->device_lock);
}

/* Outstanding asynchronous closes, process-wide. Only certificate_impl_shutdown()
 * reads it, and only to know whether there is anything left to wait for. */
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

	/* THE COMMON CASE COSTS NOTHING. Most sessions are closed without ever
	 * having opened a token session, and a thread spent discovering that is a
	 * thread spent for nothing. trylock rather than lock, because the whole
	 * point of this function is that it does not block the main thread: a
	 * contended lock means a worker is busy, which means there is something to
	 * close. */
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
			/* C_Logout is left to the module's own teardown. */
			g_message("device-close-unfinished detail=shutdown-timeout timeout_ms=%u",
			          timeout_ms);
			return;
		}

		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
}

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

	/* OFF THE MAIN THREAD. Every caller of this function -- Close(), lifetime
	 * expiry, token removal, the frontend going away, shutdown -- is on the
	 * main thread, and C_Logout plus C_CloseSession behind a lock a worker may
	 * hold for the length of a C_Login is not something the main loop can wait
	 * for. The session is kept alive by the worker's own reference. */
	certificate_impl_session_release_device_async(session);

	/* THE SKELETON STAYS ON THE BUS. Unexporting here is what made the
	 * frontend's own Close() -- which it sends in answer to
	 * SessionInvalidated -- come back as UnknownObject to the application. It
	 * comes off the bus in handle_close() and at finalize, and nowhere else. */
}

/* THE VOCABULARY IS THE INTERFACE'S, and it is closed. The frontend forwards
 * @reason verbatim into GrantInvalidated, so a value invented here goes
 * straight to applications, which have no way to learn what it means and a
 * documented list that says it cannot happen. The impl XML names these eight.
 *
 * Not all eight are this backend's to emit -- `released` and `policy` are
 * decisions the frontend makes, and `backend_gone` is what the frontend says
 * ABOUT this process -- but the list is the interface's rather than this
 * file's, so it is written down whole and the assertion catches a typo in any
 * of them. */
static const char* const certificate_session_reasons[] = {
	"released", "expired",          "token_removed", "owner_gone",
	"policy",   "service_shutdown", "backend_gone",  "error",
};

static const char* checked_reason(const char* reason)
{
	for (gsize i = 0; i < G_N_ELEMENTS(certificate_session_reasons); i++)
	{
		if (g_strcmp0(reason, certificate_session_reasons[i]) == 0)
			return reason;
	}

	/* A programming error, not a caller's. Say so loudly in a development
	 * build and send the one value that is always honest in a shipped one,
	 * rather than putting a word the interface does not define on the bus. */
	g_critical("SessionInvalidated reason '%s' is not in the interface's vocabulary",
	           reason != NULL ? reason : "(null)");
	return "error";
}

void certificate_impl_session_invalidate(CertificateImplSession* session, const char* reason)
{
	if (session->closed)
		return;

	reason = checked_reason(reason);

	/* Tell the frontend BEFORE the object goes away, so that it can turn this
	 * into GrantInvalidated for a caller that would otherwise only discover the
	 * loss at its next Sign. */
	g_signal_emit(session, signals[SIGNAL_INVALIDATED], 0, reason);

	/* And say so on the Session object itself, which is what upstream's
	 * XdpDbusImplSession::Closed is for. */
	if (session->exported)
		xdp_impl_session_emit_closed(XDP_IMPL_SESSION(session));

	certificate_impl_session_close(session);
}
