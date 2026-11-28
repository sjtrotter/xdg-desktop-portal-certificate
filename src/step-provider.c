/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "step-provider.h"
#include "core/context-private.h"

struct CertificateStepProvider
{
	XccContext* context;
	CertificateHandler* handler;
	XccUiV1 legacy;
};
static void chooser_show(void* data, XccUiId id, const XccChooserView* view)
{
	CertificateStepProvider* provider = data;
	if (provider->context->delivering_handler)
		certificate_handler_chooser(provider->handler, id, view);
	else
		provider->legacy.chooser_show(provider->legacy.user, id, view);
}

static void chooser_update(void* data, XccUiId id, const XccChooserView* view)
{
	CertificateStepProvider* provider = data;
	if (provider->context->delivering_handler)
		certificate_handler_chooser(provider->handler, id, view);
	else
		provider->legacy.chooser_update(provider->legacy.user, id, view);
}

static void pin_show(void* data, XccUiId id, const XccPinView* view)
{
	CertificateStepProvider* provider = data;
	if (provider->context->delivering_handler)
		xcc_ui_failed(provider->context, id, XCC_ERROR_NOT_SUPPORTED);
	else
		provider->legacy.pin_show(provider->legacy.user, id, view);
}

static void pin_update(void* data, XccUiId id, const XccPinView* view)
{
	CertificateStepProvider* provider = data;
	if (!provider->context->delivering_handler)
		provider->legacy.pin_update(provider->legacy.user, id, view);
}

static void warning(void* data, XccUiId id, const XccWarning* view)
{
	CertificateStepProvider* provider = data;
	if (!provider->context->delivering_handler)
		provider->legacy.warning(provider->legacy.user, id, view);
}

static void hide(void* data, XccUiId id)
{
	CertificateStepProvider* provider = data;
	if (provider->context->delivering_handler)
		certificate_handler_ui_closed(provider->handler, id);
	else
		provider->legacy.hide(provider->legacy.user, id);
}

static void close_ui(void* data, XccUiId id)
{
	CertificateStepProvider* provider = data;
	if (provider->context->delivering_handler)
		certificate_handler_ui_closed(provider->handler, id);
	else
		provider->legacy.close(provider->legacy.user, id);
}

CertificateStepProvider* certificate_step_provider_new(XccContext* context,
													   CertificateHandler* handler)
{
	CertificateStepProvider* provider = g_new0(CertificateStepProvider, 1);
	provider->context = context;
	provider->handler = handler;
	XccUiV1 router = {sizeof(router), XCC_ABI_VERSION, 0,		   provider, chooser_show,
					  chooser_update, pin_show,		   pin_update, warning,	 hide,
					  close_ui};
	provider->legacy = context->ui;
	router.capabilities = provider->legacy.capabilities;
	/* Install before requests; the coordinator retains the legacy display policy. */
	context->ui = router;
	return provider;
}

void certificate_step_provider_free(CertificateStepProvider* provider)
{
	g_free(provider);
}
