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

/* Only the Request class closure answers Close() and unexports; operation handlers return FALSE to reach it. */
static gboolean certificate_impl_request_handle_close(XdpImplRequest* object,
                                                      GDBusMethodInvocation* invocation)
{
	/* Take a reference before authorization, which can discover owner loss and drop the transaction's reference. */
	g_autoptr(CertificateImplRequest) request = g_object_ref(CERTIFICATE_IMPL_REQUEST(object));

	/* Request paths are guessable, so Close() requires frontend-owner authorization. */
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

	/* Abort on export failure because the frontend must be able to cancel the request. */
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
