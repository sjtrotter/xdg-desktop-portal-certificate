/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "session-impl.h"

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

static gboolean handle_close(XdpImplSession* object, GDBusMethodInvocation* invocation)
{
	CertificateImplSession* session = CERTIFICATE_IMPL_SESSION(object);

	certificate_log_grant(CERTIFICATE_REASON_GRANT_INVALIDATED, session->id, "closed-by-portal");
	certificate_impl_session_close(session);

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

	certificate_impl_session_release_device(session);

	if (session->expiry_source != 0)
		g_source_remove(session->expiry_source);

	g_clear_pointer(&session->candidate, certificate_candidate_unref);
	g_clear_pointer(&session->id, g_free);
	g_clear_pointer(&session->app_id, g_free);
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
	session->pkcs11_session = CK_INVALID_HANDLE;
	session->private_key = CK_INVALID_HANDLE;
	xdp_impl_session_set_version(XDP_IMPL_SESSION(session), 1);
}

CertificateImplSession* certificate_impl_session_new(const char* session_handle,
                                                     const char* app_id)
{
	CertificateImplSession* session = g_object_new(CERTIFICATE_TYPE_IMPL_SESSION, NULL);

	session->id = g_strdup(session_handle);
	session->app_id = g_strdup(app_id);

	return session;
}

void certificate_impl_session_export(CertificateImplSession* session, GDBusConnection* connection)
{
	g_autoptr(GError) error = NULL;

	if (session->exported)
		return;

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(session), connection,
	                                      session->id, &error))
	{
		g_warning("Could not export the session object: %s", error->message);
		return;
	}

	session->exported = TRUE;
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

	if (session->module != NULL && session->pkcs11_session != CK_INVALID_HANDLE)
	{
		/* C_Logout is issued because the token may honour it. NOTHING HERE MAY
		 * CLAIM THE CARD HAS FORGOTTEN: some tokens and middleware cache
		 * authentication at a level this process does not control. */
		if (session->logged_in)
			session->module->C_Logout(session->pkcs11_session);

		session->module->C_CloseSession(session->pkcs11_session);
	}

	session->module = NULL;
	session->pkcs11_session = CK_INVALID_HANDLE;
	session->private_key = CK_INVALID_HANDLE;
	session->logged_in = FALSE;

	g_mutex_unlock(&session->device_lock);
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

	certificate_impl_session_release_device(session);
	certificate_impl_session_unexport(session);
}

void certificate_impl_session_invalidate(CertificateImplSession* session, const char* reason)
{
	if (session->closed)
		return;

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
