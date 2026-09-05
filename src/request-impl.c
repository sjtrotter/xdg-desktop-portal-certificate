/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * Derived from xdg-desktop-portal-gtk's src/request.c, LGPL-2.1-or-later,
 * Copyright (C) 2016 Red Hat, Inc, by Alexander Larsson and Matthias Clasen.
 * See docs/decisions/0004-license.md.
 */

#include "request-impl.h"

#include "certificate-impl.h"
#include "redact.h"

struct _CertificateImplRequest
{
	XdpImplRequestSkeleton parent_instance;

	gboolean exported;
	char* sender;
	char* app_id;
	char* id;
	GCancellable* cancellable;
};

static void certificate_impl_request_iface_init(XdpImplRequestIface* iface);

G_DEFINE_FINAL_TYPE_WITH_CODE(CertificateImplRequest, certificate_impl_request,
                              XDP_IMPL_TYPE_REQUEST_SKELETON,
                              G_IMPLEMENT_INTERFACE(XDP_IMPL_TYPE_REQUEST,
                                                    certificate_impl_request_iface_init))

/* THE DEFAULT Close() HANDLER. Every operation connects its own handler to the
 * "handle-close" signal to finish its pending call with response 2; those
 * handlers return FALSE so that emission continues into this class closure,
 * which is the only place that unexports and answers Close() itself. Splitting
 * it that way is upstream's idiom and it is what keeps "answered exactly once"
 * true on both the response path and the close path. */
static gboolean certificate_impl_request_handle_close(XdpImplRequest* object,
                                                      GDBusMethodInvocation* invocation)
{
	/* THE REFERENCE COMES FIRST, before the authorisation check, for the reason
	 * session-impl.c's handle_close() takes one: resolving who owns the
	 * frontend name can discover that it has changed hands, and the first thing
	 * that discovery does is cancel every transaction the previous owner
	 * created -- which is the one holding the other reference to this Request.
	 * The unexport below drops the export's reference too, and the invocation
	 * is completed after it. */
	g_autoptr(CertificateImplRequest) request = g_object_ref(CERTIFICATE_IMPL_REQUEST(object));

	/* CLOSE IS AUTHORISED LIKE EVERY OTHER METHOD. A request path is
	 * /org/freedesktop/portal/desktop/request/<sender>/<handle_token> and the
	 * token is very often a fixed string, so anything on the bus could have
	 * cancelled consent dialogs and PIN prompts as they appeared. It is only a
	 * denial of service, but it is one against smart-card sign-in. */
	if (!certificate_impl_sender_is_frontend_default(
	        g_dbus_method_invocation_get_sender(invocation)))
	{
		certificate_log_decision(CERTIFICATE_REASON_OPERATION_REFUSED, NULL, NULL, "request_close",
		                         FALSE);
		g_dbus_method_invocation_return_error_literal(
		    invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
		    "Only xdg-desktop-portal may call this interface");
		return TRUE;
	}

	/* Cancelling first: every window and every worker this transaction owns is
	 * tied to this cancellable, so one call tears all of it down. */
	g_cancellable_cancel(request->cancellable);

	if (request->exported)
		certificate_impl_request_unexport(request);

	xdp_impl_request_complete_close(object, invocation);

	return TRUE;
}

static void certificate_impl_request_iface_init(XdpImplRequestIface* iface)
{
	iface->handle_close = certificate_impl_request_handle_close;
}

static void certificate_impl_request_finalize(GObject* object)
{
	CertificateImplRequest* request = CERTIFICATE_IMPL_REQUEST(object);

	g_clear_object(&request->cancellable);
	g_clear_pointer(&request->sender, g_free);
	g_clear_pointer(&request->app_id, g_free);
	g_clear_pointer(&request->id, g_free);

	G_OBJECT_CLASS(certificate_impl_request_parent_class)->finalize(object);
}

static void certificate_impl_request_class_init(CertificateImplRequestClass* klass)
{
	GObjectClass* object_class = G_OBJECT_CLASS(klass);

	object_class->finalize = certificate_impl_request_finalize;
}

static void certificate_impl_request_init(CertificateImplRequest* request)
{
	request->cancellable = g_cancellable_new();
}

CertificateImplRequest* certificate_impl_request_new(const char* sender, const char* app_id,
                                                     const char* handle)
{
	CertificateImplRequest* request = g_object_new(CERTIFICATE_TYPE_IMPL_REQUEST, NULL);

	request->sender = g_strdup(sender);
	request->app_id = g_strdup(app_id);
	request->id = g_strdup(handle);

	return request;
}

gboolean certificate_impl_request_export(CertificateImplRequest* request,
                                         GDBusConnection* connection, GError** error)
{
	if (request->exported)
		return TRUE;

	/* A FAILURE HERE ABORTS THE CALL. It used to be a warning and the
	 * transaction went on without a Request on the bus, which degraded
	 * silently into a prompt the frontend could not cancel. */
	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(request), connection,
	                                      request->id, error))
		return FALSE;

	g_object_ref(request);
	request->exported = TRUE;
	return TRUE;
}

void certificate_impl_request_unexport(CertificateImplRequest* request)
{
	if (!request->exported)
		return;

	request->exported = FALSE;
	g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(request));
	g_object_unref(request);
}

GCancellable* certificate_impl_request_get_cancellable(CertificateImplRequest* request)
{
	return request->cancellable;
}

const char* certificate_impl_request_get_app_id(CertificateImplRequest* request)
{
	return request->app_id;
}

gboolean certificate_impl_request_is_exported(CertificateImplRequest* request)
{
	return request->exported;
}
