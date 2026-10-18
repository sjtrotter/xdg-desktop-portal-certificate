/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "context-private.h"
#include "../broker/operations.h"
static void on_operation_done(GBytes* value, const GError* error, gpointer data)
{
	XccRequest* r = data;
	XccErrorCode code = XCC_OK;
	if (value == NULL)
	{
		code = XCC_ERROR_DEVICE;
		if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_CANCELLED) ||
			g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			code = XCC_ERROR_CANCELLED;
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
								 CERTIFICATE_PKCS11_ERROR_PIN_LOCKED))
			code = XCC_ERROR_PIN_LOCKED;
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
								 CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED))
			code = XCC_ERROR_TOKEN_REMOVED;
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
								 CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT))
			code = XCC_ERROR_LOGIN_TIMEOUT;
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
								 CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT))
			code = XCC_ERROR_PIN_INCORRECT;
		else if (g_error_matches(error, CERTIFICATE_PKCS11_ERROR,
								 CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED) ||
				 g_error_matches(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED))
			code = XCC_ERROR_NOT_SUPPORTED;
		else if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT))
			code = XCC_ERROR_INVALID_REQUEST;
	}
	else
		r->signature = g_bytes_ref(value);
	xcc_request_complete(r, code);
}
void xcc_sign_start(void* data)
{
	XccRequest* r = data;
	XccErrorCode error = xcc_request_validate(r);
	if (error != XCC_OK)
	{
		xcc_request_complete(r, error);
		return;
	}
	r->caller.app_display_name = certificate_app_display_name(r->caller.app_id);
	certificate_broker_perform(r->context->tokens, r->session, FALSE, r->operation_id, r->mechanism,
							   r->parameters, r->input, r->parent_window,
							   r->caller.app_display_name != NULL ? r->caller.app_display_name
																  : r->caller.app_id,
							   r->cancellable, on_operation_done, r);
}
XccRequest* xcc_sign_async_parsed(XccSession* s, const XccSignSpec* spec, bool valid_parameters,
								  XccDone done, void* user)
{
	g_return_val_if_fail(s != NULL && s->context != NULL, NULL);
	XccRequest* r = xcc_request_new(s->context, s, XCC_RESULT_SIGN, done, user);
	if (spec == NULL || spec->struct_size < sizeof(*spec) || spec->abi_version != XCC_ABI_VERSION ||
		spec->mechanism == NULL || (spec->hash_present && spec->hash == NULL) ||
		(spec->mgf_present && spec->mgf == NULL) ||
		(spec->encoding_present && spec->signature_encoding == NULL) ||
		(spec->data.size != 0 && spec->data.data == NULL))
		r->validation_error = XCC_ERROR_INVALID_REQUEST;
	else
	{
		r->principal = spec->principal;
		r->caller.app_id = g_strdup(spec->principal.app_id);
		r->principal.app_id = r->caller.app_id;
		r->parent_window = g_strdup(spec->parent_window);
		r->mechanism = g_strdup(spec->mechanism);
		r->operation_id = g_strdup(spec->operation_id);
		r->input = g_bytes_new(spec->data.data, spec->data.size);
		GVariantBuilder b;
		g_variant_builder_init(&b, G_VARIANT_TYPE_VARDICT);
		if (!valid_parameters)
			g_variant_builder_add(&b, "{sv}", "invalid", g_variant_new_boolean(TRUE));
		if (spec->hash_present && spec->hash != NULL)
			g_variant_builder_add(&b, "{sv}", "hash", g_variant_new_string(spec->hash));
		if (spec->mgf_present && spec->mgf != NULL)
			g_variant_builder_add(&b, "{sv}", "mgf", g_variant_new_string(spec->mgf));
		if (spec->salt_length_present)
			g_variant_builder_add(&b, "{sv}", "salt_length",
								  g_variant_new_uint32(spec->salt_length));
		if (spec->encoding_present && spec->signature_encoding != NULL)
			g_variant_builder_add(&b, "{sv}", "signature_encoding",
								  g_variant_new_string(spec->signature_encoding));
		r->parameters = g_variant_ref_sink(g_variant_builder_end(&b));
	}
	xcc_request_schedule(r, xcc_sign_start);
	return r;
}
static void capabilities_thread(GTask* task, gpointer source, gpointer data,
								GCancellable* cancellable)
{
	XccRequest* r = data;
	gboolean protected_path = FALSE;
	certificate_tokens_capabilities(r->context->tokens, &r->mechanisms, &protected_path);
	r->result.protected_path = protected_path;
	g_task_return_boolean(task, TRUE);
}
static void capabilities_done(GObject* source, GAsyncResult* result, gpointer data)
{
	XccRequest* r = data;
	r->result.has_display = r->context->config.has_display;
	xcc_request_complete(r, XCC_OK);
}
static void capabilities_start(void* data)
{
	XccRequest* r = data;
	XccErrorCode error = xcc_request_validate(r);
	if (error != XCC_OK)
	{
		xcc_request_complete(r, error);
		return;
	}
	g_autoptr(GTask) task = g_task_new(NULL, r->cancellable, capabilities_done, r);
	g_task_set_task_data(task, r, NULL);
	g_task_run_in_thread(task, capabilities_thread);
}
XccRequest* xcc_get_capabilities_async(XccContext* c, XccDone done, void* user)
{
	XccRequest* r = xcc_request_new(c, NULL, XCC_RESULT_CAPABILITIES, done, user);
	xcc_request_schedule(r, capabilities_start);
	return r;
}

XccRequest* xcc_sign_async(XccSession* s, const XccSignSpec* spec, XccDone done, void* user)
{
	return xcc_sign_async_parsed(s, spec, true, done, user);
}
