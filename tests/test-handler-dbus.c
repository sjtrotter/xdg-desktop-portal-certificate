/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE 1
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <gio/gunixfdlist.h>
#include "core/session-private.h"
#include "core/pin.h"
#include "core/secret.h"

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
	CK_FLAGS flags, refusal_flags;
	CK_RV login_failure;
	gint logins, context_logins, incorrect, logged_in, sessions, signatures, stale_submit;
	gboolean always_authenticate, block_login, release_login;
} Fixture;
static Fixture* active;

typedef struct
{
	CK_OBJECT_CLASS kind;
	gboolean found, signing, authenticated;
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
	g_mutex_lock(&active->lock);
	info->flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | active->flags;
	g_mutex_unlock(&active->lock);
	return CKR_OK;
}

static CK_RV open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application,
						  CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session)
{
	g_atomic_int_inc(&active->sessions);
	*session = (CK_SESSION_HANDLE)(guintptr)g_new0(Search, 1);
	return CKR_OK;
}

static CK_RV close_session(CK_SESSION_HANDLE session)
{
	g_free((gpointer)(guintptr)session);
	if (g_atomic_int_dec_and_test(&active->sessions))
		g_atomic_int_set(&active->logged_in, FALSE);
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
		CK_BBOOL boolean = attr->type == CKA_SIGN ||
						   (attr->type == CKA_ALWAYS_AUTHENTICATE && active->always_authenticate);
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
		else if (attr->type == CKA_SIGN || attr->type == CKA_DECRYPT ||
				 attr->type == CKA_ALWAYS_AUTHENTICATE)
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

static CK_RV session_info(CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	info->slotID = 1;
	info->flags = CKF_SERIAL_SESSION;
	info->state =
		g_atomic_int_get(&active->logged_in) ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
	return CKR_OK;
}

static CK_RV module_login(CK_SESSION_HANDLE session, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin,
						  CK_ULONG size)
{
	g_atomic_int_inc(&active->logins);
	g_mutex_lock(&active->lock);
	while (active->block_login && !active->release_login)
		g_cond_wait(&active->cond, &active->lock);
	if (active->flags & CKF_PROTECTED_AUTHENTICATION_PATH)
	{
		g_assert_null(pin);
		g_assert_cmpuint(size, ==, 0);
	}
	else
		g_assert_nonnull(pin);
	CK_RV rv = active->login_failure;
	if (rv == CKR_OK && !(active->flags & CKF_PROTECTED_AUTHENTICATION_PATH) &&
		(size != 4 || memcmp(pin, "1234", 4) != 0))
		rv = CKR_PIN_INCORRECT;
	if (rv == CKR_PIN_INCORRECT)
	{
		g_atomic_int_inc(&active->incorrect);
		active->flags |= active->refusal_flags;
	}
	if (rv == CKR_OK)
	{
		if (user == CKU_CONTEXT_SPECIFIC)
		{
			g_assert_true(((Search*)(guintptr)session)->signing);
			((Search*)(guintptr)session)->authenticated = TRUE;
			g_atomic_int_inc(&active->context_logins);
		}
		else
			g_atomic_int_set(&active->logged_in, TRUE);
	}
	g_mutex_unlock(&active->lock);
	return rv;
}

static CK_RV sign_init(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	Search* search = (gpointer)(guintptr)session;
	search->signing = TRUE;
	search->authenticated = FALSE;
	return g_atomic_int_get(&active->logged_in) ? CKR_OK : CKR_USER_NOT_LOGGED_IN;
}

static CK_RV module_sign(CK_SESSION_HANDLE session, CK_BYTE_PTR input, CK_ULONG size,
						 CK_BYTE_PTR signature, CK_ULONG_PTR length)
{
	Search* search = (gpointer)(guintptr)session;
	g_assert_true(search->signing);
	if (active->always_authenticate)
		g_assert_true(search->authenticated);
	if (signature != NULL)
	{
		memset(signature, 0x42, 256);
		search->signing = FALSE;
		g_atomic_int_inc(&active->signatures);
	}
	*length = 256;
	return CKR_OK;
}

static CK_FUNCTION_LIST module = {
	.C_GetSlotList = slots,
	.C_GetSlotInfo = slot_info,
	.C_GetTokenInfo = token_info,
	.C_OpenSession = open_session,
	.C_GetSessionInfo = session_info,
	.C_Login = module_login,
	.C_SignInit = sign_init,
	.C_Sign = module_sign,
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

XccUiReply __real_xcc_pin_submit(XccContext*, XccUiId, XccSecret*);
XccUiReply __wrap_xcc_pin_submit(XccContext*, XccUiId, XccSecret*);
XccUiReply __wrap_xcc_pin_submit(XccContext* context, XccUiId id, XccSecret* secret)
{
	if (g_atomic_int_compare_and_exchange(&active->stale_submit, TRUE, FALSE))
	{
		xcc_secret_free(secret);
		return XCC_UI_REPLY_STALE;
	}
	return __real_xcc_pin_submit(context, id, secret);
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
	g_mutex_lock(&fixture->lock);
	fixture->release_login = TRUE;
	g_cond_broadcast(&fixture->cond);
	g_mutex_unlock(&fixture->lock);
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

static void test_tokens_and_kinds(Fixture* fixture, gconstpointer data)
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
	/* Wrong-kind replies leave the chooser token usable. */
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
		g_autoptr(GVariant) dict = results(reply, 2, i == 0 ? "invalid_request" : "stale_step");
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
	certificate_handler_ui_closed(fixture->handler, old_ui, FALSE);
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
		call("CreateSession",
			 g_variant_new("(oos@a{sv}@a{sv})", HANDLE, SESSION, APP, identity, empty()));
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

static GVariant* sign_options(const char* mechanism)
{
	static const guint8 digest[32] = {0x31};
	GVariantBuilder builder;
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "mechanism", g_variant_new_string(mechanism));
	g_variant_builder_add(&builder, "{sv}", "parameters",
						  g_variant_new_parsed("{'hash': <'SHA256'>}"));
	g_variant_builder_add(
		&builder, "{sv}", "data",
		g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, digest, sizeof(digest), 1));
	/* Handler provenance comes from its registration, never this option. */
	g_variant_builder_add(&builder, "{sv}", "operation_id", g_variant_new_string("forged"));
	return g_variant_builder_end(&builder);
}

static void grant(const char* handle, const char* session)
{
	create(session);
	g_autoptr(GVariant) step = acquire_step(handle, session);
	g_autoptr(GVariant) credential =
		choose_result(handle, number(step, "token"), candidate_id(step), 0, NULL);
}

static GVariant* sign_step(const char* handle, const char* session)
{
	g_autoptr(GVariant) reply =
		call("Sign", g_variant_new("(oo@a{sv})", handle, session, sign_options("RSA_PKCS1_V1_5")));
	return results(reply, 0, NULL);
}

static void assert_step(GVariant* step, const char* expected)
{
	const char* name;
	g_assert_true(g_variant_lookup(step, "step", "&s", &name));
	g_assert_cmpstr(name, ==, expected);
	g_assert_cmpuint(number(step, "token"), !=, 0);
	g_assert_cmpuint(number(step, "deadline"), >=, g_get_monotonic_time() / G_USEC_PER_SEC);
}

static void assert_pin_flag(GVariant* step, const char* key, gboolean expected)
{
	g_autoptr(GVariant) view = g_variant_lookup_value(step, "view", G_VARIANT_TYPE_VARDICT);
	gboolean value;
	g_assert_true(g_variant_lookup(view, key, "b", &value));
	g_assert_cmpint(value, ==, expected);
}

static void assert_signature(GVariant* dict)
{
	g_autoptr(GVariant) signature = g_variant_lookup_value(dict, "signature", G_VARIANT_TYPE("ay"));
	g_assert_nonnull(signature);
	g_assert_cmpuint(g_variant_n_children(signature), >, 0);
	g_autoptr(GVariant) step = g_variant_lookup_value(dict, "step", NULL);
	g_assert_null(step);
}

static int pin_fd(const void* pin, gsize size, int seals)
{
	int fd = memfd_create("handler-test-pin", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	g_assert_cmpint(fd, >=, 0);
	if (size != 0)
		g_assert_cmpint(write(fd, pin, size), ==, size);
	if (seals != 0)
		g_assert_cmpint(fcntl(fd, F_ADD_SEALS, seals), ==, 0);
	return fd;
}

#define PIN_SEALS (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)

static void on_fd_call(GObject* source, GAsyncResult* result, gpointer data)
{
	Call* call = data;
	call->reply = g_dbus_connection_call_with_unix_fd_list_finish(G_DBUS_CONNECTION(source), NULL,
																  result, &call->error);
	call->done = TRUE;
}

static void start_submit(const char* handle, guint64 token, int index, const int* fds, guint count,
						 Call* pending)
{
	g_autoptr(GUnixFDList) list = g_unix_fd_list_new();
	for (guint i = 0; i < count; i++)
		g_assert_cmpint(g_unix_fd_list_append(list, fds[i], NULL), ==, i);
	g_dbus_connection_call_with_unix_fd_list(
		active->frontend, g_dbus_connection_get_unique_name(active->service), PATH,
		CERTIFICATE_HANDLER_INTERFACE, "SubmitPin", g_variant_new("(oth)", handle, token, index),
		NULL, 0, 15000, list, NULL, on_fd_call, pending);
}

static GVariant* submit_fd(const char* handle, guint64 token, int index, const int* fds,
						   guint count, guint response, const char* reason)
{
	Call pending = {0};
	start_submit(handle, token, index, fds, count, &pending);
	wait_call(&pending);
	g_assert_no_error(pending.error);
	g_autoptr(GVariant) reply = pending.reply;
	return results(reply, response, reason);
}

static GVariant* submit(const char* handle, GVariant* step, const char* pin, guint response,
						const char* reason)
{
	int fd = pin_fd(pin, strlen(pin), PIN_SEALS);
	GVariant* dict = submit_fd(handle, number(step, "token"), 0, &fd, 1, response, reason);
	guint8 wiped[511];
	g_assert_cmpint(pread(fd, wiped, strlen(pin), 0), ==, strlen(pin));
	for (gsize i = 0; i < strlen(pin); i++)
		g_assert_cmpuint(wiped[i], ==, 0);
	close(fd);
	return dict;
}

static GVariant* ready(GVariant* step, guint response, const char* reason)
{
	g_autoptr(GVariant) reply = call("Ready", g_variant_new("(ot)", HANDLE, number(step, "token")));
	return results(reply, response, reason);
}

static void assert_ended(Fixture* fixture, guint index, guint response, const char* reason,
						 GVariant* step)
{
	wait_events(fixture->events, "OperationEnded", index + 1);
	g_autoptr(GVariant) ended = event(fixture->events, "OperationEnded", index);
	guint actual;
	guint64 instance;
	g_autoptr(GVariant) dict = NULL;
	const char* handle;
	g_variant_get(ended, "(&otu@a{sv})", &handle, &instance, &actual, &dict);
	g_assert_cmpuint(actual, ==, response);
	g_assert_cmpuint(instance, ==, number(step, "instance"));
	if (reason != NULL)
	{
		const char* value;
		g_assert_true(g_variant_lookup(dict, "reason", "&s", &value));
		g_assert_cmpstr(value, ==, reason);
	}
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
}

static void test_pin_correct_and_kinds(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	assert_step(step, "pin");
	assert_pin_flag(step, "context_specific", FALSE);
	g_autoptr(GVariant) view = g_variant_lookup_value(step, "view", G_VARIANT_TYPE_VARDICT);
	g_autoptr(GVariant) parent = g_variant_lookup_value(view, "parent_window", NULL);
	g_assert_null(parent);
	const char* operation;
	g_assert_true(g_variant_lookup(view, "operation_id", "&s", &operation));
	g_assert_true(g_str_has_prefix(operation, HANDLE "#"));
	g_autoptr(GVariant) wrong_ready = ready(step, 2, "stale_step");
	g_autoptr(GVariant) confirm =
		call("Confirm", g_variant_new("(otb)", HANDLE, number(step, "token"), TRUE));
	g_autoptr(GVariant) wrong_confirm = results(confirm, 2, "stale_step");
	g_autoptr(GVariant) wrong_choose =
		choose_result(HANDLE, number(step, "token"), 1, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
	g_autoptr(GVariant) signature = submit(HANDLE, step, "1234", 0, NULL);
	assert_signature(signature);
	g_autoptr(GVariant) replay =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_autoptr(GVariant) logged_in = sign_step(HANDLE, SESSION);
	assert_signature(logged_in);
	g_assert_cmpuint(number(logged_in, "instance"), >, number(step, "instance"));
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&fixture->signatures), ==, 2);
}

static void test_pin_retry(Fixture* fixture, gconstpointer data)
{
	fixture->refusal_flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_autoptr(GVariant) retry = submit(HANDLE, step, "0000", 0, NULL);
	assert_step(retry, "pin");
	g_assert_cmpuint(number(retry, "token"), !=, number(step, "token"));
	assert_pin_flag(retry, "count_low", TRUE);
	assert_pin_flag(retry, "final_try", TRUE);
	g_autoptr(GVariant) view = g_variant_lookup_value(retry, "view", G_VARIANT_TYPE_VARDICT);
	guint status;
	g_assert_true(g_variant_lookup(view, "status_code", "u", &status));
	g_assert_cmpuint(status, ==, XCC_PIN_STATUS_INCORRECT);
	g_autoptr(GVariant) replay =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->incorrect), ==, 1);
	g_autoptr(GVariant) signature = submit(HANDLE, retry, "1234", 0, NULL);
	assert_signature(signature);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 2);
}

static void test_pin_cap(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	for (guint i = 0; i < 3; i++)
	{
		g_autoptr(GVariant) next =
			submit(HANDLE, step, "0000", i < 2 ? 0 : 2, i < 2 ? NULL : "device_error");
		g_assert_cmpint(g_atomic_int_get(&fixture->incorrect), ==, i + 1);
		if (i < 2)
		{
			assert_step(next, "pin");
			g_assert_cmpuint(number(next, "token"), !=, number(step, "token"));
			g_clear_pointer(&step, g_variant_unref);
			step = g_variant_ref(next);
		}
	}
}

static void test_core_stale_submit(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_atomic_int_set(&fixture->stale_submit, TRUE);
	g_autoptr(GVariant) stale = submit(HANDLE, step, "1234", 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
	g_autoptr(GVariant) signature = submit(HANDLE, step, "1234", 0, NULL);
	assert_signature(signature);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
}

static void test_pin_final_try(Fixture* fixture, gconstpointer data)
{
	fixture->flags = CKF_USER_PIN_FINAL_TRY;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	assert_pin_flag(step, "final_try", TRUE);
	g_autoptr(GVariant) signature = submit(HANDLE, step, "1234", 0, NULL);
	assert_signature(signature);
}

static void test_pin_locked(Fixture* fixture, gconstpointer data)
{
	fixture->refusal_flags = CKF_USER_PIN_LOCKED;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_autoptr(GVariant) locked = submit(HANDLE, step, "0000", 2, "pin_locked");
	g_assert_cmpint(g_atomic_int_get(&fixture->incorrect), ==, 1);
}

static void test_pin_device_error(Fixture* fixture, gconstpointer data)
{
	fixture->login_failure = CKR_DEVICE_ERROR;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_autoptr(GVariant) failed = submit(HANDLE, step, "1234", 2, "device_error");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&fixture->incorrect), ==, 0);
	g_autoptr(GVariant) stale =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
}

static void test_pin_initially_locked(Fixture* fixture, gconstpointer data)
{
	fixture->flags = CKF_USER_PIN_LOCKED;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) reply =
		call("Sign", g_variant_new("(oo@a{sv})", HANDLE, SESSION, sign_options("RSA_PKCS1_V1_5")));
	g_autoptr(GVariant) locked = results(reply, 2, "pin_locked");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
}

static void test_pin_pad(Fixture* fixture, gconstpointer data)
{
	fixture->flags = CKF_PROTECTED_AUTHENTICATION_PATH;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	assert_step(step, "pin_pad");
	g_autoptr(GVariant) wrong =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
	g_autoptr(GVariant) signature = ready(step, 0, NULL);
	assert_signature(signature);
	g_autoptr(GVariant) replay = ready(step, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
}

static GVariant* pad_confirm(Fixture* fixture)
{
	fixture->flags = CKF_PROTECTED_AUTHENTICATION_PATH | CKF_USER_PIN_FINAL_TRY;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	assert_step(step, "pin_pad");
	assert_pin_flag(step, "final_try", TRUE);
	GVariant* confirm = ready(step, 0, NULL);
	assert_step(confirm, "confirm");
	g_assert_cmpuint(number(confirm, "token"), !=, number(step, "token"));
	g_autoptr(GVariant) view = g_variant_lookup_value(confirm, "view", G_VARIANT_TYPE_VARDICT);
	g_assert_cmpuint(number(view, "warning_id"), >, 0);
	g_autoptr(GVariant) replay = ready(step, 2, "stale_step");
	g_autoptr(GVariant) wrong =
		submit_fd(HANDLE, number(confirm, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
	return confirm;
}

static void test_confirm_accept(Fixture* fixture, gconstpointer data)
{
	g_autoptr(GVariant) step = pad_confirm(fixture);
	g_autoptr(GVariant) reply =
		call("Confirm", g_variant_new("(otb)", HANDLE, number(step, "token"), TRUE));
	g_autoptr(GVariant) signature = results(reply, 0, NULL);
	assert_signature(signature);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
}

static void test_confirm_decline(Fixture* fixture, gconstpointer data)
{
	g_autoptr(GVariant) step = pad_confirm(fixture);
	g_autoptr(GVariant) reply =
		call("Confirm", g_variant_new("(otb)", HANDLE, number(step, "token"), FALSE));
	g_autoptr(GVariant) declined = results(reply, 1, NULL);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
}

static void test_pad_incorrect(Fixture* fixture, gconstpointer data)
{
	fixture->flags = CKF_PROTECTED_AUTHENTICATION_PATH;
	fixture->login_failure = CKR_PIN_INCORRECT;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_autoptr(GVariant) failed = ready(step, 2, "device_error");
	g_assert_cmpint(g_atomic_int_get(&fixture->incorrect), ==, 1);
}

static void test_context_pin(Fixture* fixture, gconstpointer data)
{
	fixture->always_authenticate = TRUE;
	grant(HANDLE, SESSION);
	/* Establish ordinary token login first, so each tested step is CKU_CONTEXT_SPECIFIC. */
	g_atomic_int_set(&fixture->logged_in, TRUE);
	for (guint i = 0; i < 2; i++)
	{
		g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
		assert_step(step, "pin");
		assert_pin_flag(step, "context_specific", TRUE);
		g_autoptr(GVariant) signature = submit(HANDLE, step, "1234", 0, NULL);
		assert_signature(signature);
	}
	g_assert_cmpint(g_atomic_int_get(&fixture->context_logins), ==, 2);
}

static void test_pin_descriptors(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	guint64 token = number(step, "token");
	int valid = pin_fd("1234", 4, PIN_SEALS);
	int two[] = {valid, valid};
	g_autoptr(GVariant) absent = submit_fd(HANDLE, token, 0, NULL, 0, 2, "invalid_pin");
	g_autoptr(GVariant) extra = submit_fd(HANDLE, token, 0, two, 2, 2, "invalid_pin");
	g_autoptr(GVariant) index = submit_fd(HANDLE, token, 1, &valid, 1, 2, "invalid_pin");
	g_autoptr(GVariant) negative = submit_fd(HANDLE, token, -1, &valid, 1, 2, "invalid_pin");
	int pipes[2];
	g_assert_cmpint(pipe(pipes), ==, 0);
	g_autoptr(GVariant) pipe_result = submit_fd(HANDLE, token, 0, pipes, 1, 2, "invalid_pin");
	close(pipes[0]);
	close(pipes[1]);
	int seals[] = {0, F_SEAL_GROW | F_SEAL_SEAL, F_SEAL_SHRINK | F_SEAL_SEAL,
				   F_SEAL_SHRINK | F_SEAL_GROW};
	for (guint i = 0; i < G_N_ELEMENTS(seals); i++)
	{
		int fd = pin_fd("1234", 4, seals[i]);
		g_autoptr(GVariant) rejected = submit_fd(HANDLE, token, 0, &fd, 1, 2, "invalid_pin");
		close(fd);
		g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
	}
	guint8 oversized[512];
	memset(oversized, '1', sizeof(oversized));
	const void* pins[] = {"", oversized, "12\0x"};
	gsize sizes[] = {0, sizeof(oversized), 4};
	for (guint i = 0; i < G_N_ELEMENTS(sizes); i++)
	{
		int fd = pin_fd(pins[i], sizes[i], PIN_SEALS);
		g_autoptr(GVariant) rejected = submit_fd(HANDLE, token, 0, &fd, 1, 2, "invalid_pin");
		close(fd);
		g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
	}
	g_autoptr(GVariant) signature = submit_fd(HANDLE, token, 0, &valid, 1, 0, NULL);
	assert_signature(signature);
	guint8 bytes[4];
	g_assert_cmpint(pread(valid, bytes, sizeof(bytes), 0), ==, sizeof(bytes));
	for (guint i = 0; i < sizeof(bytes); i++)
		g_assert_cmpuint(bytes[i], ==, 0);
	close(valid);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
}

static void test_pin_secretmem(Fixture* fixture, gconstpointer data)
{
#ifdef SYS_memfd_secret
	int fd = syscall(SYS_memfd_secret, 0);
	if (fd < 0)
	{
		g_test_skip("memfd_secret is unavailable");
		return;
	}
	g_assert_cmpint(ftruncate(fd, 4), ==, 0);
	void* mapping = mmap(NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED)
	{
		close(fd);
		g_test_skip("secretmem mapping is unavailable");
		return;
	}
	memcpy(mapping, "1234", 4);
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_autoptr(GVariant) signature = submit_fd(HANDLE, number(step, "token"), 0, &fd, 1, 0, NULL);
	assert_signature(signature);
	for (guint i = 0; i < 4; i++)
		g_assert_cmpuint(((guint8*)mapping)[i], ==, 0);
	munmap(mapping, 4);
	close(fd);
#else
	g_test_skip("memfd_secret syscall is unavailable");
#endif
}

static void wait_counter(gint* counter, gint expected)
{
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while (g_atomic_int_get(counter) != expected && g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_assert_cmpint(g_atomic_int_get(counter), ==, expected);
}

typedef struct
{
	XccSession* session;
	guint count;
	gint done;
} WaiterProbe;

static void probe_waiters(void* data)
{
	WaiterProbe* probe = data;
	probe->count = probe->session->login_waiters != NULL ? probe->session->login_waiters->len : 0;
	g_atomic_int_set(&probe->done, TRUE);
}

static void wait_waiters(Fixture* fixture, const char* session, guint count)
{
	WaiterProbe probe = {.session = certificate_impl_find_session(fixture->impl, session)->core};
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	do
	{
		g_atomic_int_set(&probe.done, FALSE);
		g_assert_true(
			xcc_context_post(certificate_impl_context(fixture->impl), probe_waiters, &probe));
		wait_counter(&probe.done, TRUE);
	} while (probe.count != count && g_get_monotonic_time() < deadline);
	g_assert_cmpuint(probe.count, ==, count);
}

static void start_sign(const char* handle, const char* session, Call* pending)
{
	start_call(active->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Sign",
			   g_variant_new("(oo@a{sv})", handle, session, sign_options("RSA_PKCS1_V1_5")),
			   pending);
}

static GVariant* pending_results(Call* pending, guint response, const char* reason)
{
	wait_call(pending);
	g_assert_no_error(pending->error);
	GVariant* dict = results(pending->reply, response, reason);
	g_clear_pointer(&pending->reply, g_variant_unref);
	return dict;
}

static void timeout_step(Fixture* fixture, gboolean pad, gboolean confirm)
{
	if (pad)
		fixture->flags = CKF_PROTECTED_AUTHENTICATION_PATH;
	if (confirm)
		fixture->flags |= CKF_USER_PIN_FINAL_TRY;
	if (!confirm)
		certificate_handler_set_pin_timeout_for_tests(fixture->handler, 50);
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	if (confirm)
	{
		certificate_handler_set_pin_timeout_for_tests(fixture->handler, 50);
		GVariant* next = ready(step, 0, NULL);
		g_variant_unref(step);
		step = next;
		assert_step(step, "confirm");
	}
	assert_ended(fixture, 0, 2, "timeout", step);
	g_autoptr(GVariant) stale =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
}

static void test_pin_timeout(Fixture* fixture, gconstpointer data)
{
	timeout_step(fixture, FALSE, FALSE);
}

static void test_pad_timeout(Fixture* fixture, gconstpointer data)
{
	timeout_step(fixture, TRUE, FALSE);
}

static void test_confirm_timeout(Fixture* fixture, gconstpointer data)
{
	timeout_step(fixture, TRUE, TRUE);
}

static void login_timeout_submitted(Fixture* fixture, gboolean pad, gboolean confirm)
{
	guint previous_timeout = certificate_pin_login_timeout();
	certificate_pin_set_login_timeout(1);
	fixture->block_login = TRUE;
	if (pad)
		fixture->flags = CKF_PROTECTED_AUTHENTICATION_PATH;
	if (confirm)
		fixture->flags |= CKF_USER_PIN_FINAL_TRY;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	assert_step(step, pad ? "pin_pad" : "pin");
	if (confirm)
	{
		GVariant* next = ready(step, 0, NULL);
		g_variant_unref(step);
		step = next;
		assert_step(step, "confirm");
	}

	/* A second waiter keeps the core's existing deferred timeout outcome. */
	Call other = {0};
	start_sign(HANDLE2, SESSION, &other);
	wait_waiters(fixture, SESSION, 2);
	Call pending = {0};
	if (confirm)
		start_call(fixture->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Confirm",
				   g_variant_new("(otb)", HANDLE, number(step, "token"), TRUE), &pending);
	else if (pad)
		start_call(fixture->frontend, CERTIFICATE_HANDLER_INTERFACE, PATH, "Ready",
				   g_variant_new("(ot)", HANDLE, number(step, "token")), &pending);
	else
	{
		int fd = pin_fd("1234", 4, PIN_SEALS);
		start_submit(HANDLE, number(step, "token"), 0, &fd, 1, &pending);
		close(fd);
	}
	wait_counter(&fixture->logins, 1);
	g_autoptr(GVariant) failed = pending_results(&pending, 2, "device_error");
	g_assert_cmpuint(number(failed, "instance"), ==, number(step, "instance"));
	g_autoptr(GVariant) signature = g_variant_lookup_value(failed, "signature", NULL);
	g_assert_null(signature);
	barrier();
	g_assert_false(fixture->release_login);
	g_assert_false(other.done);
	g_assert_cmpint(g_atomic_int_get(&fixture->sessions), >, 0);
	g_assert_cmpint(g_atomic_int_get(&fixture->signatures), ==, 0);
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 0);

	g_mutex_lock(&fixture->lock);
	fixture->release_login = TRUE;
	g_cond_broadcast(&fixture->cond);
	g_mutex_unlock(&fixture->lock);
	g_autoptr(GVariant) other_failed = pending_results(&other, 2, "device_error");
	wait_waiters(fixture, SESSION, 0);
	wait_counter(&fixture->sessions, 0);
	g_assert_false(g_atomic_int_get(&fixture->logged_in));
	g_assert_cmpint(g_atomic_int_get(&fixture->signatures), ==, 0);
	barrier();
	g_assert_null(pending.reply);
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 0);
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
	certificate_pin_set_login_timeout(previous_timeout);
}

static void test_pin_login_timeout_submitted(Fixture* fixture, gconstpointer data)
{
	login_timeout_submitted(fixture, FALSE, FALSE);
}

static void test_pad_login_timeout_submitted(Fixture* fixture, gconstpointer data)
{
	login_timeout_submitted(fixture, TRUE, FALSE);
}

static void test_confirm_login_timeout_submitted(Fixture* fixture, gconstpointer data)
{
	login_timeout_submitted(fixture, TRUE, TRUE);
}

static void test_login_timeout_after_handover(Fixture* fixture, gconstpointer data)
{
	guint previous_timeout = certificate_pin_login_timeout();
	certificate_pin_set_login_timeout(2);
	fixture->block_login = TRUE;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	Call other = {0};
	start_sign(HANDLE2, SESSION, &other);
	wait_waiters(fixture, SESSION, 2);
	Call pending = {0};
	int fd = pin_fd("1234", 4, PIN_SEALS);
	start_submit(HANDLE, number(step, "token"), 0, &fd, 1, &pending);
	close(fd);
	wait_counter(&fixture->logins, 1);
	cancel(HANDLE);
	g_autoptr(GVariant) cancelled = pending_results(&pending, 1, NULL);
	g_autoptr(GVariant) next = pending_results(&other, 0, NULL);
	assert_step(next, "pin");
	assert_pin_flag(next, "busy", TRUE);
	/* The new prompt owner has a step outstanding, with no submission pending. */
	assert_ended(fixture, 0, 2, "device_error", next);
	g_assert_false(fixture->release_login);
	g_assert_cmpint(g_atomic_int_get(&fixture->sessions), >, 0);
	g_assert_cmpint(g_atomic_int_get(&fixture->signatures), ==, 0);

	g_mutex_lock(&fixture->lock);
	fixture->release_login = TRUE;
	g_cond_broadcast(&fixture->cond);
	g_mutex_unlock(&fixture->lock);
	wait_waiters(fixture, SESSION, 0);
	wait_counter(&fixture->sessions, 0);
	g_assert_false(g_atomic_int_get(&fixture->logged_in));
	g_assert_cmpint(g_atomic_int_get(&fixture->signatures), ==, 0);
	barrier();
	g_assert_null(pending.reply);
	g_assert_null(other.reply);
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 1);
	g_assert_cmpuint(fixture->stranger_events->len, ==, 0);
	certificate_pin_set_login_timeout(previous_timeout);
}

static void test_pin_cancel(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	cancel(HANDLE);
	assert_ended(fixture, 0, 1, NULL, step);
	g_autoptr(GVariant) stale =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
}

static void test_cancel_submitted(Fixture* fixture, gconstpointer data)
{
	fixture->block_login = TRUE;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	int fd = pin_fd("1234", 4, PIN_SEALS);
	Call pending = {0};
	start_submit(HANDLE, number(step, "token"), 0, &fd, 1, &pending);
	close(fd);
	wait_counter(&fixture->logins, 1);
	g_assert_false(pending.done);
	g_autoptr(GVariant) replay =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
	wait_events(fixture->events, "OperationUpdated", 1);
	g_autoptr(GVariant) update = event(fixture->events, "OperationUpdated", 0);
	guint64 token;
	g_variant_get_child(update, 2, "t", &token);
	g_assert_cmpuint(token, ==, number(step, "token"));

	cancel(HANDLE);
	g_autoptr(GVariant) cancelled = pending_results(&pending, 1, NULL);
	g_mutex_lock(&fixture->lock);
	fixture->release_login = TRUE;
	g_cond_broadcast(&fixture->cond);
	g_mutex_unlock(&fixture->lock);
	wait_counter(&fixture->sessions, 0);
	g_assert_false(g_atomic_int_get(&fixture->logged_in));
	g_assert_cmpint(g_atomic_int_get(&fixture->signatures), ==, 0);
	barrier();
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 0);
}

static void test_pin_handover(Fixture* fixture, gconstpointer data)
{
	fixture->refusal_flags = CKF_USER_PIN_COUNT_LOW;
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_autoptr(GVariant) retry = submit(HANDLE, step, "0000", 0, NULL);
	Call other = {0};
	start_sign(HANDLE2, SESSION, &other);
	wait_waiters(fixture, SESSION, 2);
	g_assert_false(other.done);
	cancel(HANDLE);
	assert_ended(fixture, 0, 1, NULL, retry);
	g_autoptr(GVariant) next = pending_results(&other, 0, NULL);
	assert_step(next, "pin");
	assert_pin_flag(next, "count_low", TRUE);
	g_assert_cmpuint(number(next, "token"), !=, number(retry, "token"));
	g_autoptr(GVariant) stale =
		submit_fd(HANDLE, number(retry, "token"), 0, NULL, 0, 2, "stale_step");
	g_autoptr(GVariant) signature = submit(HANDLE2, next, "1234", 0, NULL);
	assert_signature(signature);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 2);
	g_assert_cmpint(g_atomic_int_get(&fixture->incorrect), ==, 1);
}

static void test_timeout_handover(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	certificate_handler_set_pin_timeout_for_tests(fixture->handler, 500);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	certificate_handler_set_pin_timeout_for_tests(fixture->handler, 120000);
	Call other = {0};
	start_sign(HANDLE2, SESSION, &other);
	wait_waiters(fixture, SESSION, 2);
	assert_ended(fixture, 0, 2, "timeout", step);
	g_autoptr(GVariant) next = pending_results(&other, 0, NULL);
	assert_step(next, "pin");
	g_assert_cmpuint(number(next, "token"), !=, number(step, "token"));
	g_autoptr(GVariant) signature = submit(HANDLE2, next, "1234", 0, NULL);
	assert_signature(signature);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
}

static void test_pin_shared_login(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	Call other = {0};
	start_sign(HANDLE2, SESSION, &other);
	wait_waiters(fixture, SESSION, 2);
	g_assert_false(other.done);
	g_autoptr(GVariant) signature = submit(HANDLE, step, "1234", 0, NULL);
	assert_signature(signature);
	g_autoptr(GVariant) second = pending_results(&other, 0, NULL);
	assert_signature(second);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&fixture->signatures), ==, 2);
}

static void test_pin_queue_cancel(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	grant(HANDLE2, SESSION2);
	g_autoptr(GVariant) first = sign_step(HANDLE, SESSION);
	Call queued = {0};
	start_sign(HANDLE2, SESSION2, &queued);
	wait_waiters(fixture, SESSION2, 1);
	barrier();
	g_assert_false(queued.done);
	cancel(HANDLE2);
	g_autoptr(GVariant) cancelled = pending_results(&queued, 1, NULL);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
	g_autoptr(GVariant) signature = submit(HANDLE, first, "1234", 0, NULL);
	assert_signature(signature);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
}

static void test_pin_queue_turn(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	grant(HANDLE2, SESSION2);
	g_autoptr(GVariant) first = sign_step(HANDLE, SESSION);
	Call queued = {0};
	start_sign(HANDLE2, SESSION2, &queued);
	wait_waiters(fixture, SESSION2, 1);
	barrier();
	g_assert_false(queued.done);
	cancel(HANDLE);
	assert_ended(fixture, 0, 1, NULL, first);
	g_autoptr(GVariant) next = pending_results(&queued, 0, NULL);
	assert_step(next, "pin");
	g_autoptr(GVariant) signature = submit(HANDLE2, next, "1234", 0, NULL);
	assert_signature(signature);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 1);
}

static void test_pin_removal(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_autoptr(CertificateToken) token = token_for_fixture(fixture);
	certificate_tokens_emit_event(fixture->tokens, token, FALSE);
	assert_ended(fixture, 0, 2, "token_removed", step);
	wait_events(fixture->events, "SessionInvalidated", 1);
	g_autoptr(GVariant) stale =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
}

static void test_pin_session_close(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	close_session_path(SESSION);
	assert_ended(fixture, 0, 2, "no_such_session", step);
	g_autoptr(GVariant) stale =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
}

static void test_pin_owner_gone(Fixture* fixture, gconstpointer data)
{
	grant(HANDLE, SESSION);
	g_autoptr(GVariant) step = sign_step(HANDLE, SESSION);
	g_dbus_connection_signal_unsubscribe(fixture->frontend, fixture->subscription);
	fixture->subscription = 0;
	g_dbus_connection_close_sync(fixture->frontend, NULL, NULL);
	g_object_unref(fixture->frontend);
	fixture->frontend = connection(fixture->bus);
	own_name(fixture->frontend);
	fixture->subscription = subscribe(fixture->frontend, fixture->events);
	gint64 deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
	while (!certificate_impl_sender_is_frontend(
			   fixture->impl, g_dbus_connection_get_unique_name(fixture->frontend)) &&
		   g_get_monotonic_time() < deadline)
	{
		g_main_context_iteration(NULL, FALSE);
		g_usleep(1000);
	}
	g_autoptr(GVariant) stale =
		submit_fd(HANDLE, number(step, "token"), 0, NULL, 0, 2, "stale_step");
	barrier();
	g_assert_cmpuint(event_count(fixture->events, "OperationEnded"), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&fixture->logins), ==, 0);
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
	g_autoptr(GVariant) constraints =
		g_variant_parse(G_VARIANT_TYPE_VARDICT, text, NULL, NULL, NULL);
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
	const char* mechanism = g_str_equal(algorithm, "EC") ? "ECDSA" : "RSA_PKCS1_V1_5";
	for (guint i = 0; i < 2; i++)
	{
		g_autoptr(GVariant) sign_reply =
			call("Sign", g_variant_new("(oo@a{sv})", HANDLE, SESSION, sign_options(mechanism)));
		g_autoptr(GVariant) signed_result = results(sign_reply, 0, NULL);
		if (i == 0)
		{
			assert_step(signed_result, "pin");
			GVariant* signature = submit(HANDLE, signed_result, "123456", 0, NULL);
			g_variant_unref(signed_result);
			signed_result = signature;
		}
		assert_signature(signed_result);
		g_autoptr(GVariant) bytes =
			g_variant_lookup_value(signed_result, "signature", G_VARIANT_TYPE("ay"));
		gsize size;
		const guint8* buffer = g_variant_get_fixed_array(bytes, &size, 1);
		g_autoptr(GBytes) signature = g_bytes_new(buffer, size);
		g_autoptr(GError) error = NULL;
		g_autoptr(CertificateCandidate) selected = certificate_candidate_new_from_der(
			g_variant_get_fixed_array(der, &size, 1), g_variant_n_children(der), &error);
		g_assert_no_error(error);
		static const guint8 digest[32] = {0x31};
		certificate_test_verify_signature(
			selected,
			g_str_equal(algorithm, "EC") ? GNUTLS_SIGN_ECDSA_SHA256 : GNUTLS_SIGN_RSA_SHA256,
			digest, sizeof(digest), signature, g_str_equal(algorithm, "EC"));
	}

	g_assert_cmpuint(fixture->legacy_shows, ==, 0);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
#define ADD(name, function) g_test_add("/handler/" name, Fixture, NULL, setup, function, teardown)
	ADD("stranger", test_stranger);
	ADD("headless-and-isolation", test_headless_and_isolation);
	ADD("tokens-and-kinds", test_tokens_and_kinds);
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
	ADD("pin-correct-and-kinds", test_pin_correct_and_kinds);
	ADD("pin-retry", test_pin_retry);
	ADD("pin-cap", test_pin_cap);
	ADD("pin-final-try", test_pin_final_try);
	ADD("core-stale-submit", test_core_stale_submit);
	ADD("pin-locked", test_pin_locked);
	ADD("pin-device-error", test_pin_device_error);
	ADD("pin-initially-locked", test_pin_initially_locked);
	ADD("pin-pad", test_pin_pad);
	ADD("confirm-accept", test_confirm_accept);
	ADD("confirm-decline", test_confirm_decline);
	ADD("pad-incorrect", test_pad_incorrect);
	ADD("context-pin", test_context_pin);
	ADD("pin-descriptors", test_pin_descriptors);
	ADD("pin-secretmem", test_pin_secretmem);
	ADD("pin-timeout", test_pin_timeout);
	ADD("pad-timeout", test_pad_timeout);
	ADD("confirm-timeout", test_confirm_timeout);
	ADD("pin-login-timeout-submitted", test_pin_login_timeout_submitted);
	ADD("pad-login-timeout-submitted", test_pad_login_timeout_submitted);
	ADD("confirm-login-timeout-submitted", test_confirm_login_timeout_submitted);
	ADD("login-timeout-after-handover", test_login_timeout_after_handover);
	ADD("pin-cancel", test_pin_cancel);
	ADD("cancel-submitted", test_cancel_submitted);
	ADD("pin-handover", test_pin_handover);
	ADD("timeout-handover", test_timeout_handover);
	ADD("pin-shared-login", test_pin_shared_login);
	ADD("pin-queue-cancel", test_pin_queue_cancel);
	ADD("pin-queue-turn", test_pin_queue_turn);
	ADD("pin-removal", test_pin_removal);
	ADD("pin-session-close", test_pin_session_close);
	ADD("pin-owner-gone", test_pin_owner_gone);
	g_test_add("/handler/softhsm-rsa", Fixture, "RSA", setup, test_softhsm, teardown);
	g_test_add("/handler/softhsm-ec", Fixture, "EC", setup, test_softhsm, teardown);
	return g_test_run();
}
