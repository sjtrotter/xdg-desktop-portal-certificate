/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <string.h>

#include "handler-impl.h"
#include "core/context-private.h"
#include "fixture-util.h"

#define FRONTEND "org.freedesktop.portal.Desktop"
#define PATH "/org/freedesktop/portal/desktop"
#define SESSION PATH "/session/test/handler"
#define SESSION2 PATH "/session/test/other"
#define HANDLE PATH "/request/test/handler"
#define HANDLE2 PATH "/request/test/other"
#define APP "org.example.HandlerTest"
#define IMPL "org.freedesktop.impl.portal.experimental.Certificate1"

typedef struct
{
	GVariant* reply;
	GError* error;
	gboolean done;
} Call;
typedef struct
{
	GTestDBus* bus;
	GDBusConnection *service, *frontend, *stranger;
	CertificateTokens* tokens;
	CertificateImpl* impl;
	CertificateHandler* handler;
	GPtrArray *events, *stranger_events;
	guint subscription, stranger_subscription;
	GByteArray* der;
	gboolean softhsm, available;
	gboolean coalesce;
	guint legacy_shows;
	XccUiId ui_id;
	char* core_id;
	GMutex lock;
	GCond cond;
	gint entered, fail_discovery;
	gboolean released;
} Fixture;
static Fixture* active;

typedef struct
{
	CK_OBJECT_CLASS kind;
	gboolean found;
} Search;
static CK_RV slots(CK_BBOOL present, CK_SLOT_ID_PTR values, CK_ULONG_PTR count)
{
	if (values != NULL)
		values[0] = 1;
	*count = 1;
	return CKR_OK;
}

static CK_RV slot_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	memset(info, ' ', sizeof(*info));
	memcpy(info->slotDescription, "Handler reader", 14);
	info->flags = CKF_HW_SLOT | CKF_TOKEN_PRESENT;
	return CKR_OK;
}

static CK_RV token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	memset(info, ' ', sizeof(*info));
	memcpy(info->label, "Handler token", 13);
	memcpy(info->manufacturerID, "Test", 4);
	memcpy(info->model, "Test", 4);
	memcpy(info->serialNumber, "handler-test", 12);
	info->flags = CKF_TOKEN_INITIALIZED;
	return CKR_OK;
}

static CK_RV open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application,
						  CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session)
{
	*session = (CK_SESSION_HANDLE)(guintptr)g_new0(Search, 1);
	return CKR_OK;
}

static CK_RV close_session(CK_SESSION_HANDLE session)
{
	g_free((gpointer)(guintptr)session);
	return CKR_OK;
}

static CK_RV find_init(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
{
	Search* search = (gpointer)(guintptr)session;
	search->kind = *(CK_OBJECT_CLASS*)attributes[0].pValue;
	search->found = FALSE;
	return CKR_OK;
}

static CK_RV find(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects, CK_ULONG max,
				  CK_ULONG_PTR count)
{
	Search* search = (gpointer)(guintptr)session;
	if (g_atomic_int_get(&active->fail_discovery))
	{
		*count = max;
		for (CK_ULONG i = 0; i < max; i++)
			objects[i] = 1;
		return CKR_OK;
	}
	*count = search->found ? 0 : 1;
	if (*count != 0)
		objects[0] = search->kind == CKO_CERTIFICATE ? 1 : 2;
	search->found = TRUE;
	return CKR_OK;
}

static CK_RV find_final(CK_SESSION_HANDLE session)
{
	return CKR_OK;
}

static CK_RV attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
					   CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
{
	for (CK_ULONG i = 0; i < count; i++)
	{
		CK_ATTRIBUTE* attr = &attributes[i];
		guint8 id = 1;
		CK_BBOOL boolean = attr->type == CKA_SIGN ? CK_TRUE : CK_FALSE;
		const void* data;
		gsize size;
		if (attr->type == CKA_VALUE)
		{
			data = active->der->data;
			size = active->der->len;
		}
		else if (attr->type == CKA_ID)
		{
			data = &id;
			size = sizeof(id);
		}
		else if (attr->type == CKA_SIGN || attr->type == CKA_DECRYPT)
		{
			data = &boolean;
			size = sizeof(boolean);
		}
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;
		if (attr->pValue != NULL)
		{
			if (attr->ulValueLen < size)
				return CKR_BUFFER_TOO_SMALL;
			memcpy(attr->pValue, data, size);
		}
		attr->ulValueLen = size;
	}
	return CKR_OK;
}

static CK_RV mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR values, CK_ULONG_PTR count)
{
	if (values != NULL)
		values[0] = CKM_RSA_PKCS;
	*count = 1;
	return CKR_OK;
}

static CK_FUNCTION_LIST module = {
	.C_GetSlotList = slots,
	.C_GetSlotInfo = slot_info,
	.C_GetTokenInfo = token_info,
	.C_OpenSession = open_session,
	.C_CloseSession = close_session,
	.C_FindObjectsInit = find_init,
	.C_FindObjects = find,
	.C_FindObjectsFinal = find_final,
	.C_GetAttributeValue = attribute,
	.C_GetMechanismList = mechanisms,
};
CK_FUNCTION_LIST** __wrap_p11_kit_modules_load_and_initialize(int flags);
void __wrap_p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** modules);
char* __wrap_p11_kit_module_get_name(CK_FUNCTION_LIST* value);
char* __wrap_p11_kit_module_get_filename(CK_FUNCTION_LIST* value);
char* __real_p11_kit_module_get_name(CK_FUNCTION_LIST* value);
char* __real_p11_kit_module_get_filename(CK_FUNCTION_LIST* value);
void __real_p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** modules);
CK_FUNCTION_LIST** __wrap_p11_kit_modules_load_and_initialize(int flags)
{
	CK_FUNCTION_LIST** modules = g_new0(CK_FUNCTION_LIST*, 2);
	modules[0] = &module;
	return modules;
}

void __wrap_p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** modules)
{
	if (modules[0] == &module)
		g_free(modules);
	else
		__real_p11_kit_modules_finalize_and_release(modules);
}

char* __wrap_p11_kit_module_get_name(CK_FUNCTION_LIST* value)
{
	return value == &module ? g_strdup("test-handler-module")
							: __real_p11_kit_module_get_name(value);
}

char* __wrap_p11_kit_module_get_filename(CK_FUNCTION_LIST* value)
{
	return value == &module ? NULL : __real_p11_kit_module_get_filename(value);
}

void __real_certificate_handler_chooser(CertificateHandler*, XccUiId, const XccChooserView*);
void __wrap_certificate_handler_chooser(CertificateHandler*, XccUiId, const XccChooserView*);
void __wrap_certificate_handler_chooser(CertificateHandler* handler, XccUiId id,
										const XccChooserView* view)
{
	active->ui_id = id;
	g_free(active->core_id);
	active->core_id = g_strdup(view->operation_id);
	__real_certificate_handler_chooser(handler, id, view);
	if (active->coalesce)
	{
		XccChooserView newest = *view;
		newest.caller_name = "Coalesced intermediate";
		__real_certificate_handler_chooser(handler, id, &newest);
		newest.caller_name = "Coalesced newest";
		__real_certificate_handler_chooser(handler, id, &newest);
	}
}

static void legacy_chooser(void* data, XccUiId id, const XccChooserView* view)
{
	active->legacy_shows++;
}

static void legacy_close(void* data, XccUiId id)
{
}

static void legacy_pin(void* data, PinPrompt* prompt, const XccPinView* view)
{
	g_error("unexpected legacy PIN window");
}

static void legacy_pin_close(void* data, PinPrompt* prompt)
{
}

static void legacy_warning(void* data, PinPrompt* prompt, const char* warning)
{
	g_error("unexpected legacy warning");
}

static void hold_enumeration(gpointer data)
{
	Fixture* fixture = data;
	g_mutex_lock(&fixture->lock);
	g_atomic_int_set(&fixture->entered, TRUE);
	g_cond_broadcast(&fixture->cond);
	while (!fixture->released)
		g_cond_wait(&fixture->cond, &fixture->lock);
	g_mutex_unlock(&fixture->lock);
}

static void release_enumeration(Fixture* fixture)
{
	g_mutex_lock(&fixture->lock);
	fixture->released = TRUE;
	g_cond_broadcast(&fixture->cond);
	g_mutex_unlock(&fixture->lock);
}

static GDBusConnection* connection(GTestDBus* bus)
{
	g_autoptr(GError) error = NULL;
	GDBusConnection* result =
		g_dbus_connection_new_for_address_sync(g_test_dbus_get_bus_address(bus),
											   G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
												   G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
											   NULL, NULL, &error);
	g_assert_no_error(error);
	return result;
}

static void own_name(GDBusConnection* conn)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = g_dbus_connection_call_sync(
		conn, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
		"RequestName", g_variant_new("(su)", FRONTEND, 1u), NULL, 0, 5000, NULL, &error);
	g_assert_no_error(error);
	guint response;
	g_variant_get(reply, "(u)", &response);
	g_assert_cmpuint(response, ==, 1);
}

static void signal_received(GDBusConnection* conn, const char* sender, const char* path,
							const char* interface, const char* signal, GVariant* parameters,
							gpointer data)
{
	GPtrArray* events = data;
	g_ptr_array_add(events, g_variant_ref_sink(
								g_variant_new("(s@v)", signal, g_variant_new_variant(parameters))));
}

static guint subscribe(GDBusConnection* conn, GPtrArray* events)
{
	return g_dbus_connection_signal_subscribe(conn, NULL, CERTIFICATE_HANDLER_INTERFACE, NULL, PATH,
											  NULL, G_DBUS_SIGNAL_FLAGS_NONE, signal_received,
											  events, NULL);
}

static void setup(Fixture* fixture, gconstpointer data)
{
	active = fixture;
	fixture->softhsm = data != NULL;
	g_mutex_init(&fixture->lock);
	g_cond_init(&fixture->cond);
	fixture->bus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_up(fixture->bus);
	fixture->service = connection(fixture->bus);
	fixture->frontend = connection(fixture->bus);
	fixture->stranger = connection(fixture->bus);
	own_name(fixture->frontend);
	fixture->events = g_ptr_array_new_with_free_func((GDestroyNotify)g_variant_unref);
	fixture->stranger_events = g_ptr_array_new_with_free_func((GDestroyNotify)g_variant_unref);
	fixture->subscription = subscribe(fixture->frontend, fixture->events);
	fixture->stranger_subscription = subscribe(fixture->stranger, fixture->stranger_events);
	g_autoptr(CertificateCandidate) candidate =
		certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	fixture->der = g_byte_array_ref(candidate->der);
	const char* modules[2] = {NULL, NULL};
	g_autofree char* module_path = NULL;
	g_autofree char* directory = NULL;
	if (fixture->softhsm)
	{
		directory = g_strdup(g_getenv("SOFTHSM_FIXTURE_DIR"));
		if (directory == NULL)
			directory = g_build_filename(g_get_tmp_dir(), "xdp-certificate-softhsm", NULL);
		g_autofree char* file = g_build_filename(directory, "module-path", NULL);
		g_autofree char* config = g_build_filename(directory, "softhsm2.conf", NULL);
		fixture->available = g_file_get_contents(file, &module_path, NULL, NULL);
		if (!fixture->available)
			return;
		g_setenv("SOFTHSM2_CONF", config, TRUE);
		modules[0] = g_strstrip(module_path);
	}
	else
		fixture->available = TRUE;
	CertificateChooserProvider chooser = {"test-legacy",  TRUE,			  NULL,
										  legacy_chooser, legacy_chooser, legacy_close};
	CertificatePinProvider pin = {
		"test-legacy",	 TRUE, NULL, legacy_pin, legacy_pin, legacy_warning, legacy_pin_close,
		legacy_pin_close};
	certificate_chooser_set_provider(&chooser);
	certificate_pin_set_provider(&pin);
	certificate_ui_set_has_display(FALSE);
	g_autoptr(GError) error = NULL;
	fixture->tokens = certificate_tokens_new(fixture->softhsm ? modules : NULL, &error);
	g_assert_no_error(error);
	fixture->impl = certificate_impl_new(fixture->service, fixture->tokens, &error);
	g_assert_no_error(error);
	certificate_tokens_stop_watch(fixture->tokens);
	fixture->handler = certificate_handler_new(fixture->impl, fixture->service, &error);
	g_assert_no_error(error);
}

static void teardown(Fixture* fixture, gconstpointer data)
{
	release_enumeration(fixture);
	certificate_handler_free(fixture->handler);
	certificate_impl_free(fixture->impl);
	certificate_tokens_set_enumerate_gate(NULL, NULL);
	if (fixture->tokens != NULL)
		certificate_tokens_free(fixture->tokens);
	certificate_chooser_set_provider(NULL);
	certificate_pin_set_provider(NULL);
	g_dbus_connection_signal_unsubscribe(fixture->frontend, fixture->subscription);
	g_dbus_connection_signal_unsubscribe(fixture->stranger, fixture->stranger_subscription);
	g_dbus_connection_close_sync(fixture->frontend, NULL, NULL);
	g_dbus_connection_close_sync(fixture->stranger, NULL, NULL);
	g_dbus_connection_close_sync(fixture->service, NULL, NULL);
	g_object_unref(fixture->frontend);
	g_object_unref(fixture->stranger);
	g_object_unref(fixture->service);
	g_ptr_array_unref(fixture->events);
	g_ptr_array_unref(fixture->stranger_events);
	g_byte_array_unref(fixture->der);
	g_free(fixture->core_id);
	g_cond_clear(&fixture->cond);
	g_mutex_clear(&fixture->lock);
	g_test_dbus_down(fixture->bus);
	g_object_unref(fixture->bus);
	active = NULL;
}

static void on_call(GObject* source, GAsyncResult* result, gpointer data)
{
	Call* call = data;
	call->reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &call->error);
	call->done = TRUE;
}

static void start_call(GDBusConnection* conn, const char* interface, const char* path,
					   const char* method, GVariant* parameters, Call* call)
{
	g_dbus_connection_call(conn, g_dbus_connection_get_unique_name(active->service), path,
						   interface, method, parameters, NULL, 0, 15000, NULL, on_call, call);
}

static void wait_call(Call* call)
{
	gint64 deadline = g_get_monotonic_time() + 16 * G_USEC_PER_SEC;
	while (!call->done && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_true(call->done);
}

static GVariant* call_interface(GDBusConnection* conn, const char* interface, const char* path,
								const char* method, GVariant* parameters)
{
	Call call = {0};
	start_call(conn, interface, path, method, parameters, &call);
	wait_call(&call);
	g_assert_no_error(call.error);
	return call.reply;
}

static GVariant* call(const char* method, GVariant* parameters)
{
	return call_interface(active->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, method,
						  parameters);
}

static GVariant* empty(void)
{
	return g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0);
}

static GVariant* options(void)
{
	return g_variant_new_parsed("{'purpose': <'client_auth'>, 'app_identity_level': <'host'>}");
}

static GVariant* results(GVariant* reply, guint expected, const char* reason)
{
	guint response;
	GVariant* dict;
	g_variant_get(reply, "(u@a{sv})", &response, &dict);
	g_assert_cmpuint(response, ==, expected);
	guint64 instance;
	g_assert_true(g_variant_lookup(dict, "instance", "t", &instance));
	if (reason != NULL)
	{
		const char* actual;
		g_assert_true(g_variant_lookup(dict, "reason", "&s", &actual));
		g_assert_cmpstr(actual, ==, reason);
	}
	return dict;
}

static void create(const char* path)
{
	g_autoptr(GVariant) reply = call(
		"CreateSession", g_variant_new("(oos@a{sv}@a{sv})", HANDLE, path, APP, empty(), empty()));
	g_autoptr(GVariant) dict = results(reply, 0, NULL);
}

static GVariant* acquire_step(const char* handle, const char* session)
{
	g_autoptr(GVariant) reply =
		call("Acquire", g_variant_new("(oo@a{sv})", handle, session, options()));
	return results(reply, 0, NULL);
}

static guint64 number(GVariant* dict, const char* key)
{
	guint64 result;
	g_assert_true(g_variant_lookup(dict, key, "t", &result));
	return result;
}

static guint64 candidate_id(GVariant* step)
{
	g_autoptr(GVariant) view = g_variant_lookup_value(step, "view", G_VARIANT_TYPE_VARDICT);
	g_autoptr(GVariant) rows = g_variant_lookup_value(view, "candidates", G_VARIANT_TYPE("aa{sv}"));
	g_assert_cmpuint(g_variant_n_children(rows), >, 0);
	g_autoptr(GVariant) row = g_variant_get_child_value(rows, 0);
	return number(row, "id");
}

static GVariant* choose_result(const char* handle, guint64 token, guint64 candidate, guint response,
							   const char* reason)
{
	g_autoptr(GVariant) reply = call("Choose", g_variant_new("(ott)", handle, token, candidate));
	return results(reply, response, reason);
}

static void cancel(const char* handle)
{
	g_autoptr(GVariant) reply = call("Cancel", g_variant_new("(o)", handle));
}

static void close_session_path(const char* path)
{
	g_autoptr(GVariant) reply = call_interface(
		active->frontend, "org.freedesktop.impl.portal.Session", path, "Close", NULL);
}

static guint event_count(GPtrArray* events, const char* signal)
{
	guint count = 0;
	for (guint i = 0; i < events->len; i++)
	{
		const char* name;
		g_variant_get_child(g_ptr_array_index(events, i), 0, "&s", &name);
		count += g_str_equal(name, signal);
	}
	return count;
}

static GVariant* event(GPtrArray* events, const char* signal, guint index)
{
	for (guint i = 0; i < events->len; i++)
	{
		GVariant* item = g_ptr_array_index(events, i);
		const char* name;
		g_variant_get_child(item, 0, "&s", &name);
		if (g_str_equal(name, signal) && index-- == 0)
		{
			g_autoptr(GVariant) value = g_variant_get_child_value(item, 1);
			return g_variant_get_variant(value);
		}
	}
	g_assert_not_reached();
}

static void wait_events(GPtrArray* events, const char* signal, guint count)
{
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while (event_count(events, signal) < count && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_cmpuint(event_count(events, signal), ==, count);
}

static void barrier(void)
{
	/* A round trip on each subscriber drains signals already sent by the service. */
	g_dbus_connection_flush_sync(active->service, NULL, NULL);
	for (guint i = 0; i < 2; i++)
	{
		GDBusConnection* conn = i == 0 ? active->frontend : active->stranger;
		g_autoptr(GVariant) reply =
			call_interface(conn, "org.freedesktop.DBus.Peer", PATH, "Ping", NULL);
	}
	while (g_main_context_iteration(NULL, FALSE))
		;
}

static void test_stranger(Fixture* fixture, gconstpointer data)
{
	static const char* methods[] = {"CreateSession", "Acquire", "Sign",	  "Choose",			"Ready",
									"SubmitPin",	 "Confirm", "Cancel", "GetCapabilities"};
	GVariant* parameters[] = {
		g_variant_new("(oos@a{sv}@a{sv})", HANDLE, SESSION, APP, empty(), empty()),
		g_variant_new("(oo@a{sv})", HANDLE, SESSION, empty()),
		g_variant_new("(oo@a{sv})", HANDLE, SESSION, empty()),
		g_variant_new("(ott)", HANDLE, (guint64)1, (guint64)1),
		g_variant_new("(ot)", HANDLE, (guint64)1),
		g_variant_new("(oth)", HANDLE, (guint64)1, 0),
		g_variant_new("(otb)", HANDLE, (guint64)1, TRUE),
		g_variant_new("(o)", HANDLE),
		g_variant_new("(s@a{sv})", APP, empty()),
	};
	for (guint i = 0; i < G_N_ELEMENTS(methods); i++)
	{
		Call pending = {0};
		start_call(fixture->stranger, CERTIFICATE_HANDLER_INTERFACE, PATH, methods[i],
				   parameters[i], &pending);
		wait_call(&pending);
		g_assert_null(pending.reply);
		g_assert_error(pending.error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
		g_clear_error(&pending.error);
	}
}

static void test_headless_and_isolation(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_assert_cmpuint(number(step, "token"), !=, 0);
	g_assert_cmpuint(number(step, "deadline"), >, g_get_monotonic_time() / G_USEC_PER_SEC);
	g_assert_cmpuint(fixture->legacy_shows, ==, 0);
	g_autoptr(GVariant) duplicate =
		call("Acquire", g_variant_new("(oo@a{sv})", HANDLE, SESSION, options()));
	g_autoptr(GVariant) duplicate_results = results(duplicate, 2, "invalid_request");
	g_assert_cmpuint(number(duplicate_results, "instance"), ==, number(step, "instance"));
	g_autoptr(GVariant) impl_use =
		call_interface(fixture->frontend, IMPL, PATH, "AcquireCredential",
					   g_variant_new("(ooss@a{sv})", HANDLE2, SESSION, APP, "", options()));
	guint response;
	g_autoptr(GVariant) impl_results = NULL;
	g_variant_get(impl_use, "(u@a{sv})", &response, &impl_results);
	g_assert_cmpuint(response, ==, 2);
	const char* reason;
	g_assert_true(g_variant_lookup(impl_results, "reason", "&s", &reason));
	g_assert_cmpstr(reason, ==, "no_such_session");
	g_autoptr(GVariant) conflict =
		call_interface(fixture->frontend, IMPL, PATH, "CreateSession",
					   g_variant_new("(oos@a{sv})", HANDLE2, SESSION, APP, empty()));
	g_clear_pointer(&impl_results, g_variant_unref);
	g_variant_get(conflict, "(u@a{sv})", &response, &impl_results);
	g_assert_cmpuint(response, ==, 2);
	cancel(HANDLE);
	g_autoptr(GVariant) legacy =
		call_interface(fixture->frontend, IMPL, PATH, "CreateSession",
					   g_variant_new("(oos@a{sv})", HANDLE2, SESSION2, APP, empty()));
	g_autoptr(GVariant) handler_use =
		call("Acquire", g_variant_new("(oo@a{sv})", HANDLE2, SESSION2, options()));
	g_autoptr(GVariant) refused = results(handler_use, 2, "no_such_session");
	g_autoptr(GVariant) legacy_acquire =
		call_interface(fixture->frontend, IMPL, PATH, "AcquireCredential",
					   g_variant_new("(ooss@a{sv})", HANDLE2, SESSION2, APP, "", options()));
	g_clear_pointer(&impl_results, g_variant_unref);
	g_variant_get(legacy_acquire, "(u@a{sv})", &response, &impl_results);
	g_assert_cmpuint(response, ==, 2);
	g_assert_true(g_variant_lookup(impl_results, "reason", "&s", &reason));
	g_assert_cmpstr(reason, ==, "no_display");
	g_autoptr(GVariant) handler_conflict =
		call("CreateSession",
			 g_variant_new("(oos@a{sv}@a{sv})", HANDLE2, SESSION2, APP, empty(), empty()));
	g_autoptr(GVariant) conflict_results = results(handler_conflict, 2, "invalid_request");
}

static void forged_done(XccRequest* request, const XccResult* result, void* data)
{
	gboolean* done = data;
	g_assert_cmpint(result->error, ==, XCC_ERROR_CANCELLED);
	*done = TRUE;
}

static void test_forged_operation_id(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_autoptr(GVariant) legacy =
		call_interface(fixture->frontend, IMPL, PATH, "CreateSession",
					   g_variant_new("(oos@a{sv})", HANDLE2, SESSION2, APP, empty()));
	CertificateImplSession* session = certificate_impl_find_session(fixture->impl, SESSION2);
	XccAcquireSpec spec = {.struct_size = sizeof(spec),
						   .abi_version = XCC_ABI_VERSION,
						   .principal = {sizeof(XccPrincipal), XCC_ABI_VERSION,
										 certificate_impl_generation(fixture->impl), APP,
										 XCC_IDENTITY_DERIVED_HOST, TRUE},
						   .purpose = XCC_PURPOSE_CLIENT_AUTH,
						   .operation_id = fixture->core_id};
	/* Simulate a legacy caller copying the handler's entire operation ID. */
	certificate_ui_set_has_display(TRUE);
	gboolean done = FALSE;
	XccRequest* request = xcc_acquire_async(session->core, &spec, forged_done, &done);
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while (fixture->legacy_shows == 0 && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_cmpuint(fixture->legacy_shows, ==, 1);
	xcc_request_cancel(request, XCC_CANCEL_USER);
	while (!done && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_true(done);
	xcc_request_unref(request);
	g_autoptr(GVariant) credential =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 0, NULL);
	barrier();
	g_assert_cmpuint(event_count(fixture->events, "OperationUpdated"), ==, 0);
}

static void test_tokens_and_stubs(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	create(SESSION2);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_autoptr(GVariant) other = acquire_step(HANDLE2, SESSION2);
	guint64 token = number(step, "token"), candidate = candidate_id(step);
	g_autoptr(GVariant) wrong_session = choose_result(HANDLE2, token, candidate, 2, "stale_step");
	g_autoptr(GVariant) unknown = choose_result(HANDLE, 0, candidate, 2, "stale_step");
	g_autoptr(GVariant) wrong_handle =
		choose_result(PATH "/request/test/unknown", token, candidate, 2, "stale_step");
	/* Slice 2b methods reject all inputs as unsupported and cannot spend a chooser token. */
	const char* methods[] = {"Sign", "Ready", "SubmitPin", "Confirm"};
	GVariant* params[] = {
		g_variant_new("(oo@a{sv})", HANDLE, SESSION, empty()),
		g_variant_new("(ot)", HANDLE, token),
		g_variant_new("(oth)", HANDLE, token, 0),
		g_variant_new("(otb)", HANDLE, token, TRUE),
	};
	for (guint i = 0; i < G_N_ELEMENTS(methods); i++)
	{
		g_autoptr(GVariant) reply = call(methods[i], params[i]);
		g_autoptr(GVariant) dict = results(reply, 2, "unsupported");
	}
	g_autoptr(GVariant) credential = choose_result(HANDLE, token, candidate, 0, NULL);
	g_assert_cmpuint(number(credential, "instance"), ==, number(step, "instance"));
	g_autoptr(GVariant) der =
		g_variant_lookup_value(credential, "certificate_der", G_VARIANT_TYPE("ay"));
	g_assert_nonnull(der);
	g_autoptr(GVariant) replay = choose_result(HANDLE, token, candidate, 2, "stale_step");
	g_autoptr(GVariant) other_credential =
		choose_result(HANDLE2, number(other, "token"), candidate_id(other), 0, NULL);
	g_assert_cmpuint(fixture->legacy_shows, ==, 0);
}

static void test_cancel_and_deadline(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	certificate_handler_set_chooser_timeout_for_tests(fixture->handler, 30);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	wait_events(fixture->events, "OperationEnded", 1);
	g_autoptr(GVariant) ended = event(fixture->events, "OperationEnded", 0);
	const char* handle;
	guint64 instance;
	guint response;
	g_autoptr(GVariant) dict = NULL;
	g_variant_get(ended, "(&otu@a{sv})", &handle, &instance, &response, &dict);
	g_assert_cmpuint(instance, ==, number(step, "instance"));
	g_assert_cmpuint(response, ==, 2);
	const char* reason;
	g_assert_true(g_variant_lookup(dict, "reason", "&s", &reason));
	g_assert_cmpstr(reason, ==, "timeout");
	g_autoptr(GVariant) dead =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 2, "stale_step");
	cancel(HANDLE);
	certificate_handler_set_chooser_timeout_for_tests(fixture->handler, 300000);
	g_autoptr(GVariant) next = acquire_step(HANDLE, SESSION);
	g_assert_cmpuint(number(next, "instance"), >, instance);
	cancel(HANDLE);
	cancel(HANDLE);
	wait_events(fixture->events, "OperationEnded", 2);
	barrier();
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 2);
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
}

static void test_cancel_before_step(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	Call pending = {0}, cancelled = {0};
	start_call(fixture->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Acquire",
			   g_variant_new("(oo@a{sv})", HANDLE, SESSION, options()), &pending);
	start_call(fixture->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Cancel",
			   g_variant_new("(o)", HANDLE), &cancelled);
	wait_call(&pending);
	wait_call(&cancelled);
	g_assert_no_error(pending.error);
	g_assert_no_error(cancelled.error);
	g_autoptr(GVariant) dict = results(pending.reply, 1, NULL);
	g_variant_unref(pending.reply);
	g_variant_unref(cancelled.reply);
	barrier();
	g_assert_cmpuint(fixture->events->len, ==, 0);
}

static void test_cancel_discovery(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	certificate_tokens_set_enumerate_gate(hold_enumeration, fixture);
	Call pending = {0};
	start_call(fixture->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Acquire",
			   g_variant_new("(oo@a{sv})", HANDLE, SESSION, options()), &pending);
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while (!g_atomic_int_get(&fixture->entered) && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_true(g_atomic_int_get(&fixture->entered));
	cancel(HANDLE);
	wait_call(&pending);
	g_assert_no_error(pending.error);
	g_autoptr(GVariant) dict = results(pending.reply, 1, NULL);
	g_variant_unref(pending.reply);
	release_enumeration(fixture);
	barrier();
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 0);
}

static CertificateToken* token_for_fixture(Fixture* fixture)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) candidates = certificate_tokens_enumerate(fixture->tokens, NULL, &error);
	g_assert_no_error(error);
	g_assert_cmpuint(candidates->len, >, 0);
	return certificate_token_ref(((CertificateCandidate*)g_ptr_array_index(candidates, 0))->token);
}

static void test_updates_and_stale_revision(Fixture* fixture, gconstpointer data)
{
	fixture->coalesce = TRUE;
	create(SESSION);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_autoptr(GVariant) view = g_variant_lookup_value(step, "view", G_VARIANT_TYPE_VARDICT);
	const char* caller;
	g_assert_true(g_variant_lookup(view, "caller_name", "&s", &caller));
	g_assert_cmpstr(caller, ==, "Coalesced newest");
	g_assert_cmpuint(event_count(fixture->events, "OperationUpdated"), ==, 0);
	fixture->coalesce = FALSE;
	g_autoptr(CertificateToken) token = token_for_fixture(fixture);
	certificate_tokens_set_enumerate_gate(hold_enumeration, fixture);
	certificate_tokens_emit_event(fixture->tokens, token, TRUE);
	wait_events(fixture->events, "OperationUpdated", 1);
	g_autoptr(GVariant) update = event(fixture->events, "OperationUpdated", 0);
	const char* handle;
	guint64 instance, step_token;
	g_autoptr(GVariant) updated_view = NULL;
	g_variant_get(update, "(&ott@a{sv})", &handle, &instance, &step_token, &updated_view);
	g_assert_cmpuint(instance, ==, number(step, "instance"));
	g_assert_cmpuint(step_token, ==, number(step, "token"));
	g_assert_cmpuint(number(updated_view, "revision"), >, number(view, "revision"));
	g_autoptr(GVariant) fresh =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 0, NULL);
	g_assert_cmpuint(number(fresh, "token"), !=, number(step, "token"));
	g_autoptr(GVariant) replay =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 2, "stale_step");
	/* A valid choice can wait for the refresh after closing its chooser. */
	Call chosen = {0};
	start_call(fixture->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Choose",
			   g_variant_new("(ott)", HANDLE, number(fresh, "token"), candidate_id(fresh)),
			   &chosen);
	release_enumeration(fixture);
	wait_call(&chosen);
	g_assert_no_error(chosen.error);
	g_autoptr(GVariant) credential = results(chosen.reply, 0, NULL);
	g_variant_unref(chosen.reply);
	/* An update can race the refreshed choice; finish any resulting fresh step. */
	g_autoptr(GVariant) remaining =
		g_variant_lookup_value(credential, "step", G_VARIANT_TYPE_STRING);
	if (remaining != NULL)
	{
		g_autoptr(GVariant) final =
			choose_result(HANDLE, number(credential, "token"), candidate_id(credential), 0, NULL);
		g_autoptr(GVariant) der =
			g_variant_lookup_value(final, "certificate_der", G_VARIANT_TYPE("ay"));
		g_assert_nonnull(der);
	}
	barrier();
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
}

static void test_discovery_failure_after_step(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_autoptr(CertificateToken) token = token_for_fixture(fixture);
	g_atomic_int_set(&fixture->fail_discovery, TRUE);
	certificate_tokens_emit_event(fixture->tokens, token, TRUE);
	wait_events(fixture->events, "OperationEnded", 1);
	g_autoptr(GVariant) ended = event(fixture->events, "OperationEnded", 0);
	guint response;
	guint64 instance;
	const char* handle;
	g_autoptr(GVariant) dict = NULL;
	g_variant_get(ended, "(&otu@a{sv})", &handle, &instance, &response, &dict);
	g_assert_cmpuint(response, ==, 2);
	g_assert_cmpuint(instance, ==, number(step, "instance"));
	const char* reason;
	g_assert_true(g_variant_lookup(dict, "reason", "&s", &reason));
	g_assert_cmpstr(reason, ==, "device_error");
	g_autoptr(GVariant) stale =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 2, "stale_step");
	barrier();
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
}

static void test_close_reuse_and_late_event(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	g_autoptr(GVariant) old = acquire_step(HANDLE, SESSION);
	g_autofree char* old_id = g_strdup(fixture->core_id);
	XccUiId old_ui = fixture->ui_id;
	close_session_path(SESSION);
	wait_events(fixture->events, "OperationEnded", 1);
	create(SESSION);
	g_autoptr(GVariant) next = acquire_step(HANDLE, SESSION);
	g_assert_cmpuint(number(next, "instance"), >, number(old, "instance"));
	XccChooserView late = {.struct_size = sizeof(late),
						   .abi_version = XCC_ABI_VERSION,
						   .session_id = SESSION,
						   .operation_id = old_id,
						   .revision = 900};
	__real_certificate_handler_chooser(fixture->handler, old_ui, &late);
	certificate_handler_ui_closed(fixture->handler, old_ui);
	g_autoptr(GVariant) replay =
		choose_result(HANDLE, number(old, "token"), candidate_id(old), 2, "stale_step");
	g_autoptr(GVariant) credential =
		choose_result(HANDLE, number(next, "token"), candidate_id(next), 0, NULL);
	g_autoptr(GVariant) ended = event(fixture->events, "OperationEnded", 0);
	guint64 instance;
	g_variant_get_child(ended, 1, "t", &instance);
	g_assert_cmpuint(instance, ==, number(old, "instance"));
	barrier();
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 1);
	g_assert_cmpuint(event_count(fixture->events, "OperationUpdated"), ==, 0);
}

static void test_owner_gone(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_dbus_connection_signal_unsubscribe(fixture->frontend, fixture->subscription);
	fixture->subscription = 0;
	g_dbus_connection_close_sync(fixture->frontend, NULL, NULL);
	g_object_unref(fixture->frontend);
	fixture->frontend = connection(fixture->bus);
	own_name(fixture->frontend);
	fixture->subscription = subscribe(fixture->frontend, fixture->events);
	/* Let the name watcher observe replacement before exercising the new owner. */
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while (!certificate_impl_sender_is_frontend(
			   fixture->impl, g_dbus_connection_get_unique_name(fixture->frontend)) &&
		   g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_autoptr(GVariant) stale =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 2, "stale_step");
	g_autoptr(GVariant) missing =
		call("Acquire", g_variant_new("(oo@a{sv})", HANDLE, SESSION, options()));
	g_autoptr(GVariant) missing_results = results(missing, 2, "no_such_session");
	create(SESSION);
	g_autoptr(GVariant) next = acquire_step(HANDLE, SESSION);
	g_assert_cmpuint(number(next, "instance"), >, number(step, "instance"));
	barrier();
	g_assert_cmpuint(fixture->events->len, ==, 0);
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
}

static void test_owner_replaced(Fixture* fixture, gconstpointer data)
{
	create(SESSION);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) replaced = g_dbus_connection_call_sync(
		fixture->stranger, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
		"RequestName", g_variant_new("(su)", FRONTEND, 2u), NULL, 0, 5000, NULL, &error);
	g_assert_no_error(error);
	guint response;
	g_variant_get(replaced, "(u)", &response);
	g_assert_cmpuint(response, ==, 1);
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while (!certificate_impl_sender_is_frontend(
			   fixture->impl, g_dbus_connection_get_unique_name(fixture->stranger)) &&
		   g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_autoptr(GVariant) reply =
		call_interface(fixture->stranger, CERTIFICATE_HANDLER_INTERFACE, PATH, "Choose",
					   g_variant_new("(ott)", HANDLE, number(step, "token"), candidate_id(step)));
	g_autoptr(GVariant) stale = results(reply, 2, "stale_step");
	Call old_owner = {0};
	start_call(fixture->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Cancel",
			   g_variant_new("(o)", HANDLE), &old_owner);
	wait_call(&old_owner);
	g_assert_error(old_owner.error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	g_clear_error(&old_owner.error);
	barrier();
	g_assert_cmpuint(fixture->events->len, ==, 0);
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
}

static void test_invalidation_and_capabilities(Fixture* fixture, gconstpointer data)
{
	g_autoptr(GVariant) caps_reply =
		call("GetCapabilities", g_variant_new("(s@a{sv})", APP, empty()));
	g_autoptr(GVariant) caps = NULL;
	g_variant_get(caps_reply, "(@a{sv})", &caps);
	g_autoptr(GVariant) display = g_variant_lookup_value(caps, "has_display", NULL);
	g_assert_null(display);
	g_autoptr(GVariant) purposes = g_variant_lookup_value(caps, "purposes", G_VARIANT_TYPE("as"));
	g_assert_nonnull(purposes);
	g_autoptr(GVariant) identity =
		g_variant_parse(G_VARIANT_TYPE_VARDICT, "{'uid': <uint32 42>}", NULL, NULL, NULL);
	g_autoptr(GVariant) invalid =
		call("CreateSession", g_variant_new("(oos@a{sv}@a{sv})", HANDLE, SESSION, APP,
											identity, empty()));
	g_autoptr(GVariant) invalid_results = results(invalid, 2, "invalid_request");
	create(SESSION);
	g_autoptr(GVariant) step = acquire_step(HANDLE, SESSION);
	g_autoptr(GVariant) credential =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 0, NULL);
	g_autoptr(CertificateToken) token = token_for_fixture(fixture);
	certificate_tokens_emit_event(fixture->tokens, token, FALSE);
	wait_events(fixture->events, "SessionInvalidated", 1);
	g_autoptr(GVariant) invalidated = event(fixture->events, "SessionInvalidated", 0);
	const char *session, *reason;
	g_variant_get(invalidated, "(&o&s)", &session, &reason);
	g_assert_cmpstr(session, ==, SESSION);
	g_assert_cmpstr(reason, ==, "token_removed");
	close_session_path(SESSION);
	barrier();
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
}

static void test_softhsm(Fixture* fixture, gconstpointer data)
{
	if (!fixture->available)
	{
		g_test_skip("SoftHSM fixture is unavailable");
		return;
	}
	const char* algorithm = data;
	create(SESSION);
	g_autofree char* text =
		g_strdup_printf("{'purpose': <'client_auth'>, 'app_identity_level': <'host'>, "
						"'certificate_filter': <{'key_algorithms': <['%s']>}>}",
						algorithm);
	g_autoptr(GVariant) constraints = g_variant_parse(G_VARIANT_TYPE_VARDICT, text, NULL, NULL, NULL);
	g_autoptr(GVariant) reply =
		call("Acquire", g_variant_new("(oo@a{sv})", HANDLE, SESSION, constraints));
	g_autoptr(GVariant) step = results(reply, 0, NULL);
	g_autoptr(GVariant) credential =
		choose_result(HANDLE, number(step, "token"), candidate_id(step), 0, NULL);
	const char* actual;
	g_assert_true(g_variant_lookup(credential, "key_type", "&s", &actual));
	g_assert_cmpstr(actual, ==, algorithm);
	g_autoptr(GVariant) der =
		g_variant_lookup_value(credential, "certificate_der", G_VARIANT_TYPE("ay"));
	g_assert_cmpuint(g_variant_n_children(der), >, 0);
	g_assert_cmpuint(fixture->legacy_shows, ==, 0);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
#define ADD(name, function) g_test_add("/handler/" name, Fixture, NULL, setup, function, teardown)
	ADD("stranger", test_stranger);
	ADD("headless-and-isolation", test_headless_and_isolation);
	ADD("tokens-and-stubs", test_tokens_and_stubs);
	ADD("forged-operation-id", test_forged_operation_id);
	ADD("cancel-and-deadline", test_cancel_and_deadline);
	ADD("cancel-discovery", test_cancel_discovery);
	ADD("cancel-before-step", test_cancel_before_step);
	ADD("updates-and-stale-revision", test_updates_and_stale_revision);
	ADD("discovery-failure-after-step", test_discovery_failure_after_step);
	ADD("close-reuse-and-late-event", test_close_reuse_and_late_event);
	ADD("owner-gone", test_owner_gone);
	ADD("owner-replaced", test_owner_replaced);
	ADD("invalidation-and-capabilities", test_invalidation_and_capabilities);
	g_test_add("/handler/softhsm-rsa", Fixture, "RSA", setup, test_softhsm, teardown);
	g_test_add("/handler/softhsm-ec", Fixture, "EC", setup, test_softhsm, teardown);
	return g_test_run();
}
