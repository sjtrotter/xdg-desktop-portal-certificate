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

	if (session->core != NULL)
		xcc_session_set_invalidated_callback(session->core, NULL, NULL);
	g_clear_object(&session->core);
	certificate_impl_session_unexport(session);
	g_free(session->id);
	g_free(session->app_id);
	g_free(session->owner);

	G_OBJECT_CLASS(certificate_impl_session_parent_class)->finalize(object);
}

static void certificate_impl_session_class_init(CertificateImplSessionClass* klass)
{
	G_OBJECT_CLASS(klass)->finalize = certificate_impl_session_finalize;

	/* The reason passes unchanged to SessionInvalidated. */
	signals[SIGNAL_INVALIDATED] =
	    g_signal_new("invalidated", CERTIFICATE_TYPE_IMPL_SESSION, G_SIGNAL_RUN_LAST, 0, NULL,
	                 NULL, NULL, G_TYPE_NONE, 1, G_TYPE_STRING);
}

static void certificate_impl_session_init(CertificateImplSession* session)
{
	xdp_impl_session_set_version(XDP_IMPL_SESSION(session), 1);
}

static void on_core_invalidated(XccSession* core, const char* reason, gpointer user_data)
{
	g_autoptr(CertificateImplSession) session = g_object_ref(user_data);

	g_signal_emit(session, signals[SIGNAL_INVALIDATED], 0, reason);
	if (session->exported)
		xdp_impl_session_emit_closed(XDP_IMPL_SESSION(session));
}

CertificateImplSession* certificate_impl_session_new(const char* session_handle,
                                                     const char* app_id)
{
	CertificateImplSession* session = g_object_new(CERTIFICATE_TYPE_IMPL_SESSION, NULL);

	session->id = g_strdup(session_handle);
	session->app_id = g_strdup(app_id);
	session->identity_level = CERTIFICATE_IDENTITY_UNKNOWN;
	session->core = xcc_session_new(session_handle, on_core_invalidated, session);

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

/* Keep the skeleton exported until frontend Close() or finalization. */
void certificate_impl_session_close(CertificateImplSession* session)
{
	xcc_session_close(session->core);
}
