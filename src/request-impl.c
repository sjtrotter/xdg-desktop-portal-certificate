/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * Derived from xdg-desktop-portal-gtk's src/request.c, LGPL-2.1-or-later,
 * Copyright (C) 2016 Red Hat, Inc, by Alexander Larsson and Matthias Clasen.
 * See docs/decisions/0004-license.md.
 */

#include "request-impl.h"

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
	CertificateImplRequest* request = CERTIFICATE_IMPL_REQUEST(object);

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

void certificate_impl_request_export(CertificateImplRequest* request, GDBusConnection* connection)
{
	g_autoptr(GError) error = NULL;

	if (request->exported)
		return;

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(request), connection,
	                                      request->id, &error))
	{
		g_warning("Could not export the request object: %s", error->message);
		return;
	}

	g_object_ref(request);
	request->exported = TRUE;
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
