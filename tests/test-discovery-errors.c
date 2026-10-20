/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */

#include <string.h>

#include "core/core.h"
#include "core/dispatch-glib.h"
#include "tokens/discovery.h"

/* Keep in step with CERTIFICATE_PKCS11_OBJECT_MAX in tokens/pkcs11-util.c. */
#define OBJECT_MAX 16384

typedef struct
{
	CK_OBJECT_CLASS limited_class, search_class;
	guint find_calls, searches, finalizations, opens, closes, completions;
	gboolean finding, shutdown;
	XccErrorCode result;
} Fixture;

static Fixture* active;

static CK_RV get_slot_list(CK_BBOOL present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	if (slots != NULL)
	{
		g_assert_cmpuint(*count, >=, 1);
		slots[0] = 1;
	}
	*count = 1;
	return CKR_OK;
}

static CK_RV get_slot_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	memset(info->slotDescription, ' ', sizeof(info->slotDescription));
	info->flags = CKF_HW_SLOT | CKF_TOKEN_PRESENT;
	return CKR_OK;
}

static CK_RV get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	memset(info->label, ' ', sizeof(info->label));
	memcpy(info->label, "Test token", strlen("Test token"));
	memset(info->manufacturerID, ' ', sizeof(info->manufacturerID));
	memset(info->model, ' ', sizeof(info->model));
	memset(info->serialNumber, ' ', sizeof(info->serialNumber));
	info->serialNumber[0] = '1';
	info->flags = CKF_TOKEN_INITIALIZED;
	return CKR_OK;
}

static CK_RV open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application,
                          CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session)
{
	active->opens++;
	*session = 1;
	return CKR_OK;
}

static CK_RV close_session(CK_SESSION_HANDLE session)
{
	g_assert_false(active->finding);
	active->closes++;
	return CKR_OK;
}

static CK_RV find_init(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	g_assert_false(active->finding);
	g_assert_cmpuint(count, >, 0);
	g_assert_cmpuint(templ[0].type, ==, CKA_CLASS);
	active->search_class = *(CK_OBJECT_CLASS*) templ[0].pValue;
	active->finding = TRUE;
	active->find_calls = 0;
	active->searches++;
	return CKR_OK;
}

static CK_RV find_objects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects,
                          CK_ULONG max, CK_ULONG_PTR count)
{
	g_assert_true(active->finding);
	/* Bound the regression itself when the production guard is missing. */
	g_assert_cmpuint(++active->find_calls, <=, OBJECT_MAX + 1);
	if (active->search_class == active->limited_class)
		*count = max;
	else
		*count = active->search_class == CKO_CERTIFICATE && active->find_calls == 1 ? 1 : 0;
	for (CK_ULONG i = 0; i < *count; i++)
		objects[i] = 1;
	return CKR_OK;
}

static CK_RV find_final(CK_SESSION_HANDLE session)
{
	g_assert_true(active->finding);
	active->finding = FALSE;
	active->finalizations++;
	return CKR_OK;
}

static CK_RV get_attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	g_assert_cmpuint(count, ==, 1);
	g_assert_true(templ[0].type == CKA_ID || templ[0].type == CKA_VALUE);
	/* Key searches precede DER parsing. */
	if (templ[0].pValue != NULL)
	{
		g_assert_cmpuint(templ[0].ulValueLen, >=, 1);
		*(guint8*) templ[0].pValue = 1;
	}
	templ[0].ulValueLen = 1;
	return CKR_OK;
}

static CK_FUNCTION_LIST module = {
	.C_GetSlotList = get_slot_list,
	.C_GetSlotInfo = get_slot_info,
	.C_GetTokenInfo = get_token_info,
	.C_OpenSession = open_session,
	.C_CloseSession = close_session,
	.C_FindObjectsInit = find_init,
	.C_FindObjects = find_objects,
	.C_FindObjectsFinal = find_final,
	.C_GetAttributeValue = get_attribute,
};

CK_FUNCTION_LIST** __wrap_p11_kit_modules_load_and_initialize(int flags);
void __wrap_p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** modules);
char* __wrap_p11_kit_module_get_name(CK_FUNCTION_LIST* value);
char* __wrap_p11_kit_module_get_filename(CK_FUNCTION_LIST* value);
void __wrap_certificate_tokens_watch(CertificateTokens* tokens, CertificateTokenEvent event,
                                      gpointer data);
void __wrap_certificate_tokens_stop_watch(CertificateTokens* tokens);

CK_FUNCTION_LIST** __wrap_p11_kit_modules_load_and_initialize(int flags)
{
	CK_FUNCTION_LIST** modules = g_new0(CK_FUNCTION_LIST*, 2);
	modules[0] = &module;
	return modules;
}

void __wrap_p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** modules)
{
	g_free(modules);
}

char* __wrap_p11_kit_module_get_name(CK_FUNCTION_LIST* value)
{
	g_assert_true(value == &module);
	return g_strdup("test-discovery-module");
}

char* __wrap_p11_kit_module_get_filename(CK_FUNCTION_LIST* value)
{
	g_assert_true(value == &module);
	return NULL;
}

/* Keep the real discovery worker; presence polling is covered by token-watch. */
void __wrap_certificate_tokens_watch(CertificateTokens* tokens, CertificateTokenEvent event,
                                      gpointer data)
{
}

void __wrap_certificate_tokens_stop_watch(CertificateTokens* tokens)
{
}

static void done(XccRequest* request, const XccResult* result, void* data)
{
	Fixture* f = data;
	f->result = result->error;
	f->completions++;
	g_assert_cmpuint(f->completions, ==, 1);
	g_assert_false(result->candidate_present);
}

static void shutdown_done(XccContext* context, void* data)
{
	Fixture* f = data;
	f->shutdown = TRUE;
}

static void wait_for(guint* count)
{
	gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (*count == 0 && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_cmpuint(*count, ==, 1);
}

static void test_discovery_limit(gconstpointer data)
{
	Fixture fixture = { .limited_class = GPOINTER_TO_UINT(data) };
	active = &fixture;
	XccConfig config = { .struct_size = sizeof(config), .abi_version = XCC_ABI_VERSION };
	XccDispatch dispatch = xcc_dispatch_glib(NULL);
	XccError error;
	XccContext* context = xcc_context_new(&config, NULL, &dispatch, &error);
	g_assert_nonnull(context);
	g_assert_cmpint(error.code, ==, XCC_OK);
	xcc_context_set_owner_generation(context, 1);
	XccSessionSpec session_spec = {
		.struct_size = sizeof(session_spec), .abi_version = XCC_ABI_VERSION,
		.owner_generation = 1, .app_id = "org.example.Discovery", .log_id = "discovery-error-test",
	};
	XccSession* session = xcc_session_new(context, &session_spec, &error);
	g_assert_nonnull(session);
	XccAcquireSpec spec = {
		.struct_size = sizeof(spec), .abi_version = XCC_ABI_VERSION,
		.principal = { sizeof(XccPrincipal), XCC_ABI_VERSION, 1, "org.example.Discovery",
		               XCC_IDENTITY_VERIFIED_SANDBOXED, TRUE },
		.purpose = XCC_PURPOSE_CLIENT_AUTH,
		.interaction_present = TRUE, .interaction_forbidden = TRUE,
	};
	XccRequest* request = xcc_acquire_async(session, &spec, done, &fixture);
	wait_for(&fixture.completions);
	g_assert_cmpint(fixture.result, ==, XCC_ERROR_DEVICE);
	g_assert_cmpstr(xcc_error_wire_name(fixture.result), ==, "device_error");
	g_assert_cmpuint(fixture.opens, ==, 1);
	g_assert_cmpuint(fixture.closes, ==, fixture.opens);
	g_assert_cmpuint(fixture.searches, ==, fixture.limited_class == CKO_CERTIFICATE ? 1 :
	                                      fixture.limited_class == CKO_PRIVATE_KEY ? 2 : 3);
	g_assert_cmpuint(fixture.finalizations, ==, fixture.searches);
	g_assert_false(fixture.finding);
	xcc_request_unref(request);
	xcc_context_shutdown_async(context, shutdown_done, &fixture);
	gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (!fixture.shutdown && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_true(fixture.shutdown);
	g_object_unref(session);
	xcc_context_unref(context);
	active = NULL;
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_data_func("/discovery-error/certificate-limit", GUINT_TO_POINTER(CKO_CERTIFICATE),
	                     test_discovery_limit);
	g_test_add_data_func("/discovery-error/private-key-limit", GUINT_TO_POINTER(CKO_PRIVATE_KEY),
	                     test_discovery_limit);
	g_test_add_data_func("/discovery-error/public-key-limit", GUINT_TO_POINTER(CKO_PUBLIC_KEY),
	                     test_discovery_limit);
	return g_test_run();
}
