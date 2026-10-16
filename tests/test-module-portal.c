/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

/* The fake portal runs on its own context thread so tests can make blocking PKCS#11 calls. */

#include <string.h>

#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <p11-kit/p11-kit.h>

#include "module/constants.h"

#ifndef CERTIFICATE_FIXTURE_DIR
#define CERTIFICATE_FIXTURE_DIR "tests/fixtures"
#endif

/* Keep in step with the private PRE_HASHED_LIMIT in src/module/module.c. */
#define PREHASH_LIMIT 512

#define WAIT_MS 5000

static const char introspection[] =
    "<node>"
    "  <interface name='org.freedesktop.portal.experimental.Certificate1'>"
    "    <method name='GetCapabilities'>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='a{sv}' name='capabilities' direction='out'/>"
    "    </method>"
    "    <method name='CreateSession'>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='o' name='handle' direction='out'/>"
    "    </method>"
    "    <method name='Sign'>"
    "      <arg type='o' direction='in'/><arg type='s' direction='in'/>"
    "      <arg type='a{sv}' direction='in'/><arg type='o' direction='out'/>"
    "    </method>"
    "    <method name='Decrypt'>"
    "      <arg type='o' direction='in'/><arg type='s' direction='in'/>"
    "      <arg type='a{sv}' direction='in'/><arg type='o' direction='out'/>"
    "    </method>"
    "    <method name='AcquireCredential'>"
    "      <arg type='o' name='session_handle' direction='in'/>"
    "      <arg type='s' name='parent_window' direction='in'/>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='o' name='handle' direction='out'/>"
    "    </method>"
    "  </interface>"
    "  <interface name='org.freedesktop.portal.Request'>"
    "    <method name='Close'/>"
    "    <signal name='Response'>"
    "      <arg type='u' name='response'/>"
    "      <arg type='a{sv}' name='results'/>"
    "    </signal>"
    "  </interface>"
    "  <interface name='org.freedesktop.portal.Session'>"
    "    <method name='Close'/>"
    "    <signal name='Closed'><arg type='a{sv}' name='details'/></signal>"
    "  </interface>"
    "</node>";

typedef enum
{
	ACQUIRE_ANSWER,
	ACQUIRE_STALL,
	ACQUIRE_HOLD_REPLY, /* Hold the reply, then return an unpredicted request path. */
	ACQUIRE_FAIL,
} AcquireMode;

typedef struct
{
	GMainContext* context;
	GMainLoop* loop;
	GThread* thread;
	GDBusConnection* connection;
	guint owner_id;
	GDBusNodeInfo* nodes;
	guint certificate_id;
	GBytes* certificate;

	GMutex lock;
	GCond cond;
	gboolean ready;

	AcquireMode acquire_mode;
	guint acquire_count;
	guint sign_count;
	guint decrypt_count;
	guint64 expires_at;
	char* acquire_path;
	char* acquire_sender;
	/* Owns the held invocation until the test releases the method reply. */
	GDBusMethodInvocation* held;
	char* held_path;
	GPtrArray* closed;
	GPtrArray* closed_sessions;
	char* session_path;
	/* Keep fixture objects distinct across module initializations, which restart request tokens. */
	GArray* exported;
} FakePortal;

static FakePortal fake;

static GBytes* fixture_der(const char* name)
{
	g_autofree char* path = g_build_filename(CERTIFICATE_FIXTURE_DIR, name, NULL);
	g_autofree char* pem = NULL;
	gsize length = 0;
	gnutls_x509_crt_t certificate = NULL;
	gnutls_datum_t input;
	gnutls_datum_t der = { NULL, 0 };
	GBytes* bytes = NULL;

	g_assert_true(g_file_get_contents(path, &pem, &length, NULL));

	input.data = (unsigned char*) pem;
	input.size = (unsigned int) length;

	g_assert_cmpint(gnutls_x509_crt_init(&certificate), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_import(certificate, &input, GNUTLS_X509_FMT_PEM), ==, 0);
	g_assert_cmpint(gnutls_x509_crt_export2(certificate, GNUTLS_X509_FMT_DER, &der), ==, 0);

	bytes = g_bytes_new(der.data, der.size);
	gnutls_free(der.data);
	gnutls_x509_crt_deinit(certificate);

	return bytes;
}

/* Match the module's predicted request path to exercise ordinary subscription timing. */
static char* portal_object_path(const char* prefix, const char* sender, const char* token)
{
	g_autofree char* escaped = g_strdup(sender[0] == ':' ? sender + 1 : sender);

	for (char* c = escaped; *c != '\0'; c++)
	{
		if (*c == '.')
			*c = '_';
	}

	return g_strdup_printf("%s/%s/%s/%s", PKCS11_PORTAL_OBJECT_PATH, prefix, escaped, token);
}

static void on_request_call(GDBusConnection* connection, const char* sender, const char* path,
                            const char* interface, const char* method, GVariant* parameters,
                            GDBusMethodInvocation* invocation, gpointer user_data)
{
	if (strcmp(method, "Close") == 0)
	{
		g_mutex_lock(&fake.lock);
		g_ptr_array_add(fake.closed, g_strdup(path));
		g_cond_broadcast(&fake.cond);
		g_mutex_unlock(&fake.lock);

		g_dbus_method_invocation_return_value(invocation, NULL);
		return;
	}

	g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD,
	                                      "no %s", method);
}

static const GDBusInterfaceVTable request_vtable = { on_request_call, NULL, NULL, { 0 } };

static void on_session_call(GDBusConnection* connection, const char* sender, const char* path,
                            const char* interface, const char* method, GVariant* parameters,
                            GDBusMethodInvocation* invocation, gpointer user_data)
{
	g_mutex_lock(&fake.lock);
	g_ptr_array_add(fake.closed_sessions, g_strdup(path));
	g_cond_broadcast(&fake.cond);
	g_mutex_unlock(&fake.lock);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static const GDBusInterfaceVTable session_vtable = { on_session_call, NULL, NULL, { 0 } };

static guint export_object(const char* path, const char* interface,
                           const GDBusInterfaceVTable* vtable)
{
	g_autoptr(GError) error = NULL;
	guint id;

	id = g_dbus_connection_register_object(
	    fake.connection, path, g_dbus_node_info_lookup_interface(fake.nodes, interface), vtable,
	    NULL, NULL, &error);
	g_assert_no_error(error);

	return id;
}

static void export_transient(const char* path, const char* interface,
                             const GDBusInterfaceVTable* vtable)
{
	guint id = export_object(path, interface, vtable);

	g_mutex_lock(&fake.lock);
	g_array_append_val(fake.exported, id);
	g_mutex_unlock(&fake.lock);
}

static void unexport_objects(void)
{
	g_mutex_lock(&fake.lock);
	for (guint i = 0; i < fake.exported->len; i++)
		g_dbus_connection_unregister_object(fake.connection,
		                                    g_array_index(fake.exported, guint, i));
	g_array_set_size(fake.exported, 0);
	g_mutex_unlock(&fake.lock);
}

static void emit_response(const char* destination, const char* path, guint32 response,
                          GVariant* results)
{
	g_dbus_connection_emit_signal(fake.connection, destination, path,
	                              PKCS11_PORTAL_REQUEST_INTERFACE, "Response",
	                              g_variant_new("(u@a{sv})", response, results), NULL);
}

static GVariant* empty_results(void)
{
	GVariantBuilder builder;

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

	return g_variant_builder_end(&builder);
}

static GVariant* credential_results(void)
{
	static const char* const mechanisms[] = {
		"RSA_PKCS1_V1_5", "RSA_PSS", "ECDSA", "RSA_OAEP", NULL
	};
	static const char* const operations[] = { "sign", "decrypt", NULL };
	gsize size = 0;
	const guint8* data;
	GVariantBuilder builder;

	g_mutex_lock(&fake.lock);
	data = g_bytes_get_data(fake.certificate, &size);
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "certificate_der",
	                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, size, 1));
	g_variant_builder_add(&builder, "{sv}", "key_type", g_variant_new_string("RSA"));
	g_variant_builder_add(&builder, "{sv}", "key_size", g_variant_new_uint32(2048));
	g_variant_builder_add(&builder, "{sv}", "expires_at", g_variant_new_uint64(fake.expires_at));
	g_variant_builder_add(&builder, "{sv}", "supported_mechanisms",
	                      g_variant_new_strv(mechanisms, -1));
	g_variant_builder_add(&builder, "{sv}", "permitted_operations",
	                      g_variant_new_strv(operations, -1));
	g_mutex_unlock(&fake.lock);

	return g_variant_builder_end(&builder);
}

static void acquire_seen(const char* request_path, const char* sender, AcquireMode* mode)
{
	g_mutex_lock(&fake.lock);
	*mode = fake.acquire_mode;
	fake.acquire_count++;
	g_free(fake.acquire_path);
	fake.acquire_path = g_strdup(request_path);
	g_free(fake.acquire_sender);
	fake.acquire_sender = g_strdup(sender);
	g_cond_broadcast(&fake.cond);
	g_mutex_unlock(&fake.lock);
}

static void on_certificate_call(GDBusConnection* connection, const char* sender,
                                const char* path, const char* interface, const char* method,
                                GVariant* parameters, GDBusMethodInvocation* invocation,
                                gpointer user_data)
{
	g_autoptr(GVariant) options = NULL;
	g_autofree char* handle_token = NULL;
	g_autofree char* request_path = NULL;
	AcquireMode mode;

	if (strcmp(method, "GetCapabilities") == 0)
	{
		static const char* const mechanisms[] = {
			"RSA_PKCS1_V1_5", "RSA_PSS", "ECDSA", "RSA_OAEP", NULL
		};
		GVariantBuilder capabilities;

		g_variant_builder_init(&capabilities, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_add(&capabilities, "{sv}", "mechanisms",
		                      g_variant_new_strv(mechanisms, -1));
		g_dbus_method_invocation_return_value(invocation,
		                                      g_variant_new("(a{sv})", &capabilities));
		return;
	}

	if (strcmp(method, "CreateSession") == 0)
		options = g_variant_get_child_value(parameters, 0);
	else if (strcmp(method, "AcquireCredential") == 0 || strcmp(method, "Sign") == 0 ||
	         strcmp(method, "Decrypt") == 0)
		options = g_variant_get_child_value(parameters, 2);
	else
	{
		g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR,
		                                      G_DBUS_ERROR_UNKNOWN_METHOD, "no %s", method);
		return;
	}

	g_assert_true(g_variant_lookup(options, "handle_token", "s", &handle_token));
	request_path = portal_object_path("request", sender, handle_token);
	export_transient(request_path, PKCS11_PORTAL_REQUEST_INTERFACE, &request_vtable);

	if (strcmp(method, "CreateSession") == 0)
	{
		g_autofree char* session_token = NULL;
		g_autofree char* session_path = NULL;
		GVariantBuilder results;

		g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", request_path));

		g_assert_true(
		    g_variant_lookup(options, "session_handle_token", "s", &session_token));
		session_path = portal_object_path("session", sender, session_token);
		export_transient(session_path, "org.freedesktop.portal.Session", &session_vtable);
		g_mutex_lock(&fake.lock);
		g_free(fake.session_path);
		fake.session_path = g_strdup(session_path);
		g_mutex_unlock(&fake.lock);

		g_variant_builder_init(&results, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_add(&results, "{sv}", "session_handle",
		                      g_variant_new_object_path(session_path));
		emit_response(sender, request_path, 0, g_variant_builder_end(&results));
		return;
	}

	if (strcmp(method, "Sign") == 0 || strcmp(method, "Decrypt") == 0)
	{
		g_autoptr(GVariant) session = g_variant_get_child_value(parameters, 0);
		guint8 output[32] = { 0 };
		GVariantBuilder results;
		gboolean signing = strcmp(method, "Sign") == 0;

		g_mutex_lock(&fake.lock);
		g_assert_cmpstr(g_variant_get_string(session, NULL), ==, fake.session_path);
		if (signing)
			fake.sign_count++;
		else
			fake.decrypt_count++;
		g_mutex_unlock(&fake.lock);
		g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", request_path));
		g_variant_builder_init(&results, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_add(&results, "{sv}", signing ? "signature" : "plaintext",
		                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, output,
		                                                sizeof(output), 1));
		emit_response(sender, request_path, 0, g_variant_builder_end(&results));
		return;
	}

	acquire_seen(request_path, sender, &mode);

	if (mode == ACQUIRE_FAIL)
	{
		g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
		                                      "no credential for you");
		return;
	}

	if (mode == ACQUIRE_HOLD_REPLY)
	{
		g_autofree char* late_token = g_strdup_printf("%s_late", handle_token);
		g_autofree char* late_path = portal_object_path("request", sender, late_token);

		export_transient(late_path, PKCS11_PORTAL_REQUEST_INTERFACE, &request_vtable);

		g_mutex_lock(&fake.lock);
		fake.held = invocation;
		fake.held_path = g_steal_pointer(&late_path);
		g_cond_broadcast(&fake.cond);
		g_mutex_unlock(&fake.lock);
		return;
	}

	g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", request_path));

	if (mode == ACQUIRE_STALL)
		return;

	emit_response(sender, request_path, 0, credential_results());
}

static const GDBusInterfaceVTable certificate_vtable = { on_certificate_call, NULL, NULL,
	                                                     { 0 } };

static void on_name_acquired(GDBusConnection* connection, const char* name, gpointer user_data)
{
	g_mutex_lock(&fake.lock);
	fake.ready = TRUE;
	g_cond_broadcast(&fake.cond);
	g_mutex_unlock(&fake.lock);
}

static gpointer fake_thread(gpointer data)
{
	g_autoptr(GError) error = NULL;
	GTestDBus* bus = data;

	g_main_context_push_thread_default(fake.context);

	/* Use a separate connection so shared dispatch cannot hide a module bug. */
	fake.connection = g_dbus_connection_new_for_address_sync(
	    g_test_dbus_get_bus_address(bus),
	    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
	        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
	    NULL, NULL, &error);
	g_assert_no_error(error);

	fake.certificate_id = export_object(PKCS11_PORTAL_OBJECT_PATH,
	                                    PKCS11_PORTAL_INTERFACE, &certificate_vtable);

	fake.owner_id = g_bus_own_name_on_connection(fake.connection, PKCS11_PORTAL_BUS_NAME,
	                                             G_BUS_NAME_OWNER_FLAGS_NONE, on_name_acquired,
	                                             NULL, NULL, NULL);

	g_main_loop_run(fake.loop);
	g_main_context_pop_thread_default(fake.context);

	return NULL;
}

static gboolean quit_fake(gpointer data)
{
	g_main_loop_quit(fake.loop);

	return G_SOURCE_REMOVE;
}

static void fake_start(GTestDBus* bus)
{
	g_autoptr(GError) error = NULL;

	g_mutex_init(&fake.lock);
	g_cond_init(&fake.cond);
	fake.closed = g_ptr_array_new_with_free_func(g_free);
	fake.closed_sessions = g_ptr_array_new_with_free_func(g_free);
	fake.exported = g_array_new(FALSE, FALSE, sizeof(guint));
	fake.certificate = fixture_der("client-auth-rsa.pem");
	fake.nodes = g_dbus_node_info_new_for_xml(introspection, &error);
	g_assert_no_error(error);

	fake.context = g_main_context_new();
	fake.loop = g_main_loop_new(fake.context, FALSE);
	fake.thread = g_thread_new("fake-portal", fake_thread, bus);

	g_mutex_lock(&fake.lock);
	while (!fake.ready)
		g_cond_wait(&fake.cond, &fake.lock);
	g_mutex_unlock(&fake.lock);
}

static void fake_stop(void)
{
	GSource* source = g_idle_source_new();

	g_source_set_callback(source, quit_fake, NULL, NULL);
	g_source_attach(source, fake.context);
	g_source_unref(source);

	g_thread_join(fake.thread);

	unexport_objects();
	g_dbus_connection_unregister_object(fake.connection, fake.certificate_id);
	g_bus_unown_name(fake.owner_id);
	g_dbus_connection_close_sync(fake.connection, NULL, NULL);
	g_clear_object(&fake.connection);
	g_clear_pointer(&fake.loop, g_main_loop_unref);
	g_clear_pointer(&fake.context, g_main_context_unref);
	g_clear_pointer(&fake.nodes, g_dbus_node_info_unref);
	g_clear_pointer(&fake.certificate, g_bytes_unref);
	g_clear_pointer(&fake.closed, g_ptr_array_unref);
	g_clear_pointer(&fake.closed_sessions, g_ptr_array_unref);
	g_clear_pointer(&fake.session_path, g_free);
	g_clear_pointer(&fake.exported, g_array_unref);
	g_clear_pointer(&fake.acquire_path, g_free);
	g_clear_pointer(&fake.acquire_sender, g_free);
	g_cond_clear(&fake.cond);
	g_mutex_clear(&fake.lock);
}

static void fake_reset(AcquireMode mode)
{
	unexport_objects();

	g_mutex_lock(&fake.lock);
	g_assert_null(fake.held);
	fake.acquire_mode = mode;
	fake.acquire_count = 0;
	fake.sign_count = 0;
	fake.decrypt_count = 0;
	fake.expires_at = 0;
	g_clear_pointer(&fake.certificate, g_bytes_unref);
	fake.certificate = fixture_der("client-auth-rsa.pem");
	g_clear_pointer(&fake.acquire_path, g_free);
	g_clear_pointer(&fake.acquire_sender, g_free);
	g_clear_pointer(&fake.held_path, g_free);
	g_ptr_array_set_size(fake.closed, 0);
	g_ptr_array_set_size(fake.closed_sessions, 0);
	g_clear_pointer(&fake.session_path, g_free);
	g_mutex_unlock(&fake.lock);
}

static guint fake_acquire_count(void)
{
	guint count;

	g_mutex_lock(&fake.lock);
	count = fake.acquire_count;
	g_mutex_unlock(&fake.lock);

	return count;
}

static guint fake_wait_for_second_acquire(guint ms)
{
	gint64 deadline = g_get_monotonic_time() + ms * G_TIME_SPAN_MILLISECOND;
	guint count;

	g_mutex_lock(&fake.lock);
	while (fake.acquire_count < 2)
	{
		if (!g_cond_wait_until(&fake.cond, &fake.lock, deadline))
			break;
	}
	count = fake.acquire_count;
	g_mutex_unlock(&fake.lock);

	return count;
}

static guint fake_close_count(void)
{
	guint count;

	g_mutex_lock(&fake.lock);
	count = fake.closed->len;
	g_mutex_unlock(&fake.lock);

	return count;
}

static char* fake_wait_for_acquire(guint ms)
{
	gint64 deadline = g_get_monotonic_time() + ms * G_TIME_SPAN_MILLISECOND;
	char* path = NULL;

	g_mutex_lock(&fake.lock);
	while (fake.acquire_path == NULL)
	{
		if (!g_cond_wait_until(&fake.cond, &fake.lock, deadline))
			break;
	}
	path = g_strdup(fake.acquire_path);
	g_mutex_unlock(&fake.lock);

	return path;
}

static gboolean fake_wait_for_close(const char* path, guint ms)
{
	gint64 deadline = g_get_monotonic_time() + ms * G_TIME_SPAN_MILLISECOND;
	gboolean closed = FALSE;

	g_mutex_lock(&fake.lock);
	for (;;)
	{
		for (guint i = 0; i < fake.closed->len && !closed; i++)
			closed = g_strcmp0(g_ptr_array_index(fake.closed, i), path) == 0;

		if (closed || !g_cond_wait_until(&fake.cond, &fake.lock, deadline))
			break;
	}
	g_mutex_unlock(&fake.lock);

	return closed;
}

static char* fake_wait_for_held_reply(guint ms)
{
	gint64 deadline = g_get_monotonic_time() + ms * G_TIME_SPAN_MILLISECOND;
	char* path = NULL;

	g_mutex_lock(&fake.lock);
	while (fake.held == NULL)
	{
		if (!g_cond_wait_until(&fake.cond, &fake.lock, deadline))
			break;
	}
	path = g_strdup(fake.held_path);
	g_mutex_unlock(&fake.lock);

	return path;
}

static gboolean release_reply(gpointer data)
{
	GDBusMethodInvocation* invocation;
	g_autofree char* path = NULL;

	g_mutex_lock(&fake.lock);
	invocation = fake.held;
	fake.held = NULL;
	path = g_steal_pointer(&fake.held_path);
	g_mutex_unlock(&fake.lock);

	if (invocation != NULL)
		g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", path));

	return G_SOURCE_REMOVE;
}

static void fake_release_held_reply(void)
{
	GSource* source = g_idle_source_new();

	g_source_set_callback(source, release_reply, NULL, NULL);
	g_source_attach(source, fake.context);
	g_source_unref(source);
}

static gboolean answer_acquire(gpointer data)
{
	guint32 response = GPOINTER_TO_UINT(data);
	/* credential_results() takes fake.lock itself. */
	GVariant* results = response == 0 ? credential_results() : empty_results();

	g_mutex_lock(&fake.lock);
	emit_response(fake.acquire_sender, fake.acquire_path, response, results);
	g_mutex_unlock(&fake.lock);

	return G_SOURCE_REMOVE;
}

static void fake_answer_acquire(guint32 response)
{
	GSource* source = g_idle_source_new();

	g_source_set_callback(source, answer_acquire, GUINT_TO_POINTER(response), NULL);
	g_source_attach(source, fake.context);
	g_source_unref(source);
}

static CK_FUNCTION_LIST* functions;

static CK_SESSION_HANDLE open_session(void)
{
	CK_SESSION_HANDLE session = 0;

	g_assert_cmpuint(functions->C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &session), ==,
	                 CKR_OK);

	return session;
}

typedef struct
{
	CK_OBJECT_CLASS object_class;
	CK_ATTRIBUTE templ[2];
	unsigned long count;
	CK_SESSION_HANDLE session;
	CK_RV rv;

	GMutex lock;
	GCond cond;
	gboolean done;
} Search;

static void search_init(Search* search, CK_SESSION_HANDLE session)
{
	memset(search, 0, sizeof(*search));
	search->object_class = CKO_PRIVATE_KEY;
	search->templ[0].type = CKA_CLASS;
	search->templ[0].pValue = &search->object_class;
	search->templ[0].ulValueLen = sizeof(search->object_class);
	search->count = 1;
	search->session = session;
	search->rv = CKR_FUNCTION_FAILED;
	g_mutex_init(&search->lock);
	g_cond_init(&search->cond);
}

static void search_init_by_label(Search* search, CK_SESSION_HANDLE session)
{
	search_init(search, session);
	search->templ[1].type = CKA_LABEL;
	search->templ[1].pValue = (void*) PKCS11_PORTAL_OBJECT_LABEL;
	search->templ[1].ulValueLen = strlen(PKCS11_PORTAL_OBJECT_LABEL);
	search->count = 2;
}

static void search_clear(Search* search)
{
	g_cond_clear(&search->cond);
	g_mutex_clear(&search->lock);
}

static void search_done(Search* search)
{
	g_mutex_lock(&search->lock);
	search->done = TRUE;
	g_cond_signal(&search->cond);
	g_mutex_unlock(&search->lock);
}

static gboolean search_wait(Search* search, guint ms)
{
	gint64 deadline = g_get_monotonic_time() + ms * G_TIME_SPAN_MILLISECOND;
	gboolean done;

	g_mutex_lock(&search->lock);
	while (!search->done)
	{
		if (!g_cond_wait_until(&search->cond, &search->lock, deadline))
			break;
	}
	done = search->done;
	g_mutex_unlock(&search->lock);

	return done;
}

static gpointer find_thread(gpointer data)
{
	Search* search = data;

	search->rv = functions->C_FindObjectsInit(search->session, search->templ, search->count);
	search_done(search);

	return NULL;
}

/* Finalize on another thread while this thread services portal replies. */
static gpointer finalize_thread(gpointer data)
{
	Search* search = data;

	search->rv = functions->C_Finalize(NULL);
	search_done(search);

	return NULL;
}

static gpointer session_info_thread(gpointer data)
{
	Search* search = data;
	CK_SESSION_INFO info;

	search->rv = functions->C_GetSessionInfo(search->session, &info);
	search_done(search);

	return NULL;
}

static void test_the_chooser_does_not_hold_the_module_lock(void)
{
	Search find;
	Search info;
	GThread* finder;
	GThread* other;
	g_autofree char* acquired = NULL;
	CK_SESSION_HANDLE first;
	CK_SESSION_HANDLE second;

	fake_reset(ACQUIRE_STALL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	first = open_session();
	second = open_session();

	search_init(&find, first);
	search_init(&info, second);

	finder = g_thread_new("find", find_thread, &find);

	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);

	other = g_thread_new("info", session_info_thread, &info);
	g_assert_true(search_wait(&info, WAIT_MS));
	g_assert_cmpuint(info.rv, ==, CKR_OK);
	g_thread_join(other);

	g_assert_false(search_wait(&find, 0));

	fake_answer_acquire(1);
	g_assert_true(search_wait(&find, WAIT_MS));
	g_assert_cmpuint(find.rv, ==, CKR_OK);
	g_thread_join(finder);

	search_clear(&find);
	search_clear(&info);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_finalize_while_the_chooser_is_up(void)
{
	Search find;
	GThread* finder;
	g_autofree char* acquired = NULL;

	fake_reset(ACQUIRE_STALL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);

	search_init(&find, open_session());
	finder = g_thread_new("find", find_thread, &find);

	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);

	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	g_assert_true(search_wait(&find, WAIT_MS));
	g_thread_join(finder);
	search_clear(&find);

	g_assert_true(fake_wait_for_close(acquired, WAIT_MS));
}

static void test_a_late_reply_closes_the_path_it_names(void)
{
	Search find;
	Search finalize;
	GThread* finder;
	GThread* finisher;
	g_autofree char* predicted = NULL;
	g_autofree char* late = NULL;

	fake_reset(ACQUIRE_HOLD_REPLY);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);

	search_init(&find, open_session());
	search_init(&finalize, 0);
	finder = g_thread_new("find", find_thread, &find);

	predicted = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(predicted);
	late = fake_wait_for_held_reply(WAIT_MS);
	g_assert_nonnull(late);
	g_assert_cmpstr(late, !=, predicted);

	finisher = g_thread_new("finalize", finalize_thread, &finalize);
	g_assert_true(search_wait(&find, WAIT_MS));
	g_thread_join(finder);

	fake_release_held_reply();

	g_assert_true(fake_wait_for_close(predicted, WAIT_MS));
	g_assert_true(fake_wait_for_close(late, WAIT_MS));

	g_assert_true(search_wait(&finalize, WAIT_MS));
	g_assert_cmpuint(finalize.rv, ==, CKR_OK);
	g_thread_join(finisher);

	search_clear(&find);
	search_clear(&finalize);
}

static void test_a_refused_call_closes_nothing(void)
{
	CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE templ[] = { { CKA_CLASS, &object_class, sizeof(object_class) } };
	CK_OBJECT_HANDLE handles[4];
	unsigned long count = 1;
	CK_SESSION_HANDLE session;

	fake_reset(ACQUIRE_FAIL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();

	g_assert_cmpuint(functions->C_FindObjectsInit(session, templ, 1), ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjects(session, handles, G_N_ELEMENTS(handles), &count),
	                 ==, CKR_OK);
	g_assert_cmpuint(count, ==, 0);
	g_assert_cmpuint(functions->C_FindObjectsFinal(session), ==, CKR_OK);

	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	g_assert_cmpuint(fake_acquire_count(), ==, 1);
	g_assert_cmpuint(fake_close_count(), ==, 0);
}

static void test_two_searches_share_one_chooser(void)
{
	Search first;
	Search second;
	GThread* one;
	GThread* two;
	CK_OBJECT_HANDLE handles[4];
	unsigned long count = 0;
	g_autofree char* acquired = NULL;

	fake_reset(ACQUIRE_STALL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);

	search_init(&first, open_session());
	search_init(&second, open_session());

	one = g_thread_new("first", find_thread, &first);
	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);

	two = g_thread_new("second", find_thread, &second);
	g_assert_false(search_wait(&second, 200));

	fake_answer_acquire(0);

	g_assert_true(search_wait(&first, WAIT_MS));
	g_assert_true(search_wait(&second, WAIT_MS));
	g_assert_cmpuint(first.rv, ==, CKR_OK);
	g_assert_cmpuint(second.rv, ==, CKR_OK);
	g_thread_join(one);
	g_thread_join(two);

	g_assert_cmpuint(fake_acquire_count(), ==, 1);

	g_assert_cmpuint(functions->C_FindObjects(second.session, handles, G_N_ELEMENTS(handles),
	                                          &count),
	                 ==, CKR_OK);
	g_assert_cmpuint(count, ==, 1);

	search_clear(&first);
	search_clear(&second);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_a_session_closed_during_the_wait_asks_for_nothing(void)
{
	Search first;
	Search second;
	GThread* one;
	GThread* two;
	g_autofree char* acquired = NULL;

	fake_reset(ACQUIRE_STALL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);

	search_init(&first, open_session());
	search_init_by_label(&second, open_session());

	one = g_thread_new("first", find_thread, &first);
	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);

	two = g_thread_new("second", find_thread, &second);
	g_assert_false(search_wait(&second, 200));

	g_assert_cmpuint(functions->C_CloseSession(second.session), ==, CKR_OK);

	/* Refuse the first acquisition so the queued search cannot inherit a grant. */
	fake_answer_acquire(1);

	g_assert_true(search_wait(&first, WAIT_MS));
	g_assert_cmpuint(fake_wait_for_second_acquire(200), ==, 1);

	g_assert_true(search_wait(&second, WAIT_MS));
	g_thread_join(one);
	g_thread_join(two);

	g_assert_cmpuint(first.rv, ==, CKR_OK);
	g_assert_cmpuint(second.rv, ==, CKR_SESSION_HANDLE_INVALID);

	search_clear(&first);
	search_clear(&second);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_a_search_does_not_survive_reinitialization(void)
{
	Search first;
	Search second;
	Search finalize;
	GThread* one;
	GThread* two;
	GThread* finisher;
	CK_SESSION_HANDLE reused;
	g_autofree char* acquired = NULL;

	fake_reset(ACQUIRE_STALL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);

	search_init(&first, open_session());
	search_init_by_label(&second, open_session());
	search_init(&finalize, 0);

	one = g_thread_new("first", find_thread, &first);
	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);

	two = g_thread_new("second", find_thread, &second);
	g_assert_false(search_wait(&second, 200));

	finisher = g_thread_new("finalize", finalize_thread, &finalize);
	g_assert_true(search_wait(&finalize, WAIT_MS));
	g_assert_cmpuint(finalize.rv, ==, CKR_OK);
	g_assert_true(search_wait(&first, WAIT_MS));
	g_thread_join(finisher);
	g_thread_join(one);

	/* Reinitialization reuses the waiting search's numeric handle. */
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	reused = open_session();
	g_assert_cmpuint(reused, ==, first.session);

	g_assert_cmpuint(fake_wait_for_second_acquire(200), ==, 1);

	g_assert_true(search_wait(&second, WAIT_MS));
	g_assert_cmpuint(second.rv, !=, CKR_OK);
	g_thread_join(two);

	search_clear(&first);
	search_clear(&second);
	search_clear(&finalize);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_a_timed_out_request_is_closed(void)
{
	CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE templ[] = { { CKA_CLASS, &object_class, sizeof(object_class) } };
	g_autofree char* acquired = NULL;
	CK_SESSION_HANDLE session;

	fake_reset(ACQUIRE_STALL);
	g_setenv(PKCS11_PORTAL_ENV_TIMEOUT, "300", TRUE);

	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();

	g_assert_cmpuint(functions->C_FindObjectsInit(session, templ, 1), ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjectsFinal(session), ==, CKR_OK);

	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);
	g_assert_true(fake_wait_for_close(acquired, WAIT_MS));

	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
	g_unsetenv(PKCS11_PORTAL_ENV_TIMEOUT);
}

static CK_OBJECT_HANDLE find_the_private_key(CK_SESSION_HANDLE session)
{
	CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE templ[] = { { CKA_CLASS, &object_class, sizeof(object_class) } };
	CK_OBJECT_HANDLE handles[4];
	unsigned long count = 0;

	g_assert_cmpuint(functions->C_FindObjectsInit(session, templ, 1), ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjects(session, handles, G_N_ELEMENTS(handles), &count),
	                 ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjectsFinal(session), ==, CKR_OK);
	g_assert_cmpuint(count, ==, 1);

	return handles[0];
}

static guint find_count(CK_SESSION_HANDLE session, CK_ATTRIBUTE* templ, CK_ULONG count)
{
	CK_OBJECT_HANDLE handles[4];
	CK_ULONG found = 0;

	g_assert_cmpuint(functions->C_FindObjectsInit(session, templ, count), ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjects(session, handles, G_N_ELEMENTS(handles), &found),
	                 ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjectsFinal(session), ==, CKR_OK);

	return found;
}

static void test_configuration_enables_enumeration(void)
{
	CK_C_INITIALIZE_ARGS args = { .flags = CKF_OS_LOCKING_OK };
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
	CK_ATTRIBUTE templ = { CKA_CLASS, &certificate, sizeof(certificate) };

	g_unsetenv(PKCS11_PORTAL_ENV_ENUMERATE);
	fake_reset(ACQUIRE_ANSWER);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	g_assert_cmpuint(find_count(session, &templ, 1), ==, 0);
	g_assert_cmpuint(fake_acquire_count(), ==, 0);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	args.pReserved = (void*) "enumerate=1";
	g_assert_cmpuint(functions->C_Initialize(&args), ==, CKR_OK);
	session = open_session();
	g_assert_cmpuint(find_count(session, &templ, 1), ==, 1);
	g_assert_cmpuint(fake_acquire_count(), ==, 1);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	fake_reset(ACQUIRE_ANSWER);
	args.pReserved = (void*) "enumerate=0";
	g_assert_cmpuint(functions->C_Initialize(&args), ==, CKR_OK);
	session = open_session();
	g_assert_cmpuint(find_count(session, &templ, 1), ==, 0);
	g_setenv(PKCS11_PORTAL_ENV_ENUMERATE, "1", TRUE);
	g_assert_cmpuint(find_count(session, &templ, 1), ==, 1);
	g_unsetenv(PKCS11_PORTAL_ENV_ENUMERATE);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	args.pReserved = (void*) "unknown=1";
	g_assert_cmpuint(functions->C_Initialize(&args), ==, CKR_ARGUMENTS_BAD);
}

static void test_p11kit_forwards_configuration(void)
{
	if (g_test_subprocess())
	{
		CK_FUNCTION_LIST** modules = p11_kit_modules_load(NULL, 0);
		CK_FUNCTION_LIST* module;
		CK_SESSION_HANDLE session;
		CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
		CK_ATTRIBUTE templ = { CKA_CLASS, &certificate, sizeof(certificate) };

		g_assert_nonnull(modules);
		module = p11_kit_module_for_name(modules, PKCS11_PORTAL_MODULE_NAME);
		g_assert_nonnull(module);
		g_assert_cmpuint(p11_kit_module_initialize(module), ==, CKR_OK);
		functions = module;
		session = open_session();
		g_assert_cmpuint(find_count(session, &templ, 1), ==, 1);
		g_assert_cmpuint(fake_acquire_count(), ==, 1);
		g_assert_cmpuint(p11_kit_module_finalize(module), ==, CKR_OK);
		p11_kit_modules_release(modules);
		return;
	}

	g_autofree char* directory = g_dir_make_tmp("certificate-module-XXXXXX", NULL);
	g_autofree char* modules_dir = g_build_filename(directory, "pkcs11", "modules", NULL);
	g_autofree char* pkcs11_dir = g_path_get_dirname(modules_dir);
	g_autofree char* config_path = g_build_filename(modules_dir,
	                                               XDG_PORTAL_CERTIFICATE_MODULE_CONFIG, NULL);
	g_autofree char* program = g_path_get_basename(g_get_prgname());
	g_autofree char* config = g_strdup_printf("module: %s\nenable-in: %s\n"
	                                         "x-init-reserved: enumerate=1\n",
	                                         PORTAL_MODULE_PATH, program);
	g_autofree char* previous = g_strdup(g_getenv("XDG_CONFIG_HOME"));

	g_assert_nonnull(directory);
	g_assert_cmpint(g_mkdir_with_parents(modules_dir, 0700), ==, 0);
	g_assert_true(g_file_set_contents(config_path, config, -1, NULL));
	g_setenv("XDG_CONFIG_HOME", directory, TRUE);
	g_unsetenv(PKCS11_PORTAL_ENV_ENUMERATE);
	g_test_trap_subprocess(NULL, 10 * G_USEC_PER_SEC, G_TEST_SUBPROCESS_DEFAULT);
	if (previous != NULL)
		g_setenv("XDG_CONFIG_HOME", previous, TRUE);
	else
		g_unsetenv("XDG_CONFIG_HOME");
	g_assert_cmpint(g_remove(config_path), ==, 0);
	g_assert_cmpint(g_rmdir(modules_dir), ==, 0);
	g_assert_cmpint(g_rmdir(pkcs11_dir), ==, 0);
	g_assert_cmpint(g_rmdir(directory), ==, 0);
	g_test_trap_assert_passed();
}

static void assert_session_closed(const char* path)
{
	gint64 deadline = g_get_monotonic_time() + WAIT_MS * G_TIME_SPAN_MILLISECOND;
	gboolean closed = FALSE;

	g_mutex_lock(&fake.lock);
	for (;;)
	{
		for (guint i = 0; i < fake.closed_sessions->len && !closed; i++)
			closed = g_strcmp0(g_ptr_array_index(fake.closed_sessions, i), path) == 0;

		if (closed || !g_cond_wait_until(&fake.cond, &fake.lock, deadline))
			break;
	}
	g_mutex_unlock(&fake.lock);
	g_assert_true(closed);
}

static char* current_portal_session(void)
{
	char* path;

	g_mutex_lock(&fake.lock);
	path = g_strdup(fake.session_path);
	g_mutex_unlock(&fake.lock);

	return path;
}

static void test_logout_releases_the_grant(void)
{
	CK_SESSION_HANDLE session;
	CK_SESSION_HANDLE other;
	CK_OBJECT_HANDLE key;
	CK_ATTRIBUTE label = { CKA_LABEL, NULL, 0 };
	g_autofree char* path = NULL;

	fake_reset(ACQUIRE_ANSWER);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	other = open_session();
	key = find_the_private_key(session);
	path = current_portal_session();
	g_assert_cmpuint(functions->C_Login(session, CKU_USER, NULL, 0), ==, CKR_OK);
	g_assert_cmpuint(functions->C_Logout(session), ==, CKR_OK);
	assert_session_closed(path);
	g_assert_cmpuint(functions->C_GetAttributeValue(other, key, &label, 1), ==,
	                 CKR_OBJECT_HANDLE_INVALID);
	g_assert_cmpuint(find_the_private_key(other), !=, key);
	g_assert_cmpuint(fake_acquire_count(), ==, 2);
	g_clear_pointer(&path, g_free);
	path = current_portal_session();
	g_assert_cmpuint(functions->C_Logout(other), ==, CKR_USER_NOT_LOGGED_IN);
	assert_session_closed(path);
	find_the_private_key(session);
	g_assert_cmpuint(fake_acquire_count(), ==, 3);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_close_all_sessions_releases_the_grant(void)
{
	CK_SESSION_HANDLE session;
	g_autofree char* path = NULL;

	fake_reset(ACQUIRE_ANSWER);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	find_the_private_key(session);
	path = current_portal_session();
	g_assert_cmpuint(functions->C_CloseSession(session), ==, CKR_OK);
	session = open_session();
	find_the_private_key(session);
	g_assert_cmpuint(fake_acquire_count(), ==, 1);
	g_assert_cmpuint(functions->C_CloseAllSessions(1), ==, CKR_OK);
	assert_session_closed(path);
	session = open_session();
	find_the_private_key(session);
	g_assert_cmpuint(fake_acquire_count(), ==, 2);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_portal_session_closure_drops_the_grant(void)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;
	CK_OBJECT_HANDLE replacement = CK_INVALID_HANDLE;
	g_autofree char* path = NULL;
	gint64 deadline;

	fake_reset(ACQUIRE_ANSWER);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	key = find_the_private_key(session);
	path = current_portal_session();
	g_dbus_connection_emit_signal(fake.connection, NULL, path,
	                              "org.freedesktop.portal.Session", "Closed",
	                              g_variant_new("(@a{sv})", empty_results()), NULL);

	deadline = g_get_monotonic_time() + WAIT_MS * G_TIME_SPAN_MILLISECOND;
	do
	{
		replacement = find_the_private_key(session);
		if (replacement != key)
			break;
		g_usleep(1000);
	} while (g_get_monotonic_time() < deadline);
	g_assert_cmpuint(replacement, !=, key);
	g_assert_cmpuint(fake_acquire_count(), ==, 2);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_only_issued_identifiers_acquire(void)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;
	guint8 identifier[20];
	guint8 unknown[20] = { 1, 2, 3, 4 };
	CK_ATTRIBUTE query = { CKA_ID, identifier, sizeof(identifier) };
	CK_ATTRIBUTE by_id = { CKA_ID, unknown, sizeof(unknown) };
	g_autofree char* path = NULL;

	fake_reset(ACQUIRE_ANSWER);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	g_assert_cmpuint(find_count(session, &by_id, 1), ==, 0);
	g_assert_cmpuint(fake_acquire_count(), ==, 0);
	key = find_the_private_key(session);
	g_assert_cmpuint(functions->C_GetAttributeValue(session, key, &query, 1), ==, CKR_OK);
	path = current_portal_session();
	g_assert_cmpuint(functions->C_CloseAllSessions(1), ==, CKR_OK);
	assert_session_closed(path);
	session = open_session();
	g_setenv(PKCS11_PORTAL_ENV_ENUMERATE, "1", TRUE);
	g_assert_cmpuint(find_count(session, &by_id, 1), ==, 0);
	g_assert_cmpuint(fake_acquire_count(), ==, 1);
	by_id.pValue = identifier;
	by_id.ulValueLen = query.ulValueLen;
	g_assert_cmpuint(find_count(session, &by_id, 1), ==, 3);
	g_assert_cmpuint(fake_acquire_count(), ==, 2);
	g_unsetenv(PKCS11_PORTAL_ENV_ENUMERATE);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	g_assert_cmpuint(find_count(session, &by_id, 1), ==, 0);
	g_assert_cmpuint(fake_acquire_count(), ==, 2);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_logout_discards_an_acquisition_in_progress(void)
{
	Search search;
	GThread* finder;
	g_autofree char* acquired = NULL;
	g_autofree char* path = NULL;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handles[4];
	CK_ULONG count = 0;

	fake_reset(ACQUIRE_STALL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	g_assert_cmpuint(functions->C_Login(session, CKU_USER, NULL, 0), ==, CKR_OK);
	search_init(&search, session);
	finder = g_thread_new("find", find_thread, &search);
	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);
	path = current_portal_session();
	g_assert_cmpuint(functions->C_Logout(session), ==, CKR_OK);
	fake_answer_acquire(0);
	g_assert_true(search_wait(&search, WAIT_MS));
	g_thread_join(finder);
	g_assert_cmpuint(search.rv, ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjects(session, handles, G_N_ELEMENTS(handles), &count),
	                 ==, CKR_OK);
	g_assert_cmpuint(count, ==, 0);
	g_assert_cmpuint(functions->C_FindObjectsFinal(session), ==, CKR_OK);
	assert_session_closed(path);
	search_clear(&search);
	g_mutex_lock(&fake.lock);
	fake.acquire_mode = ACQUIRE_ANSWER;
	g_mutex_unlock(&fake.lock);
	find_the_private_key(session);
	g_assert_cmpuint(fake_acquire_count(), ==, 2);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_cancel_suppresses_different_templates(void)
{
	Search first;
	Search second;
	GThread* finder;
	g_autofree char* acquired = NULL;
	CK_SESSION_HANDLE session;

	fake_reset(ACQUIRE_STALL);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	search_init(&first, session);
	finder = g_thread_new("find", find_thread, &first);
	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);
	fake_answer_acquire(1);
	g_assert_true(search_wait(&first, WAIT_MS));
	g_thread_join(finder);
	g_assert_cmpuint(first.rv, ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjectsFinal(session), ==, CKR_OK);

	g_mutex_lock(&fake.lock);
	fake.acquire_mode = ACQUIRE_ANSWER;
	g_mutex_unlock(&fake.lock);
	search_init_by_label(&second, open_session());
	g_assert_cmpuint(find_count(second.session, second.templ, second.count), ==, 0);
	g_assert_cmpuint(fake_acquire_count(), ==, 1);
	search_clear(&first);
	search_clear(&second);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static CK_RV sign_init(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_ULONG salt_length)
{
	CK_RSA_PKCS_PSS_PARAMS parameters = { CKM_SHA256, CKG_MGF1_SHA256, salt_length };
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_PSS, &parameters, sizeof(parameters) };

	return functions->C_SignInit(session, &mechanism, key);
}

static void init_pending_operations(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_RSA_PKCS_OAEP_PARAMS parameters = {
		CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, NULL, 0
	};
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_OAEP, &parameters, sizeof(parameters) };

	g_assert_cmpuint(sign_init(session, key, 32), ==, CKR_OK);
	g_assert_cmpuint(functions->C_DecryptInit(session, &mechanism, key), ==, CKR_OK);
}

static void test_pending_operations_do_not_survive_grant_release(gconstpointer data)
{
	const char* release = data;
	CK_SESSION_HANDLE session;
	CK_SESSION_HANDLE pending;
	CK_OBJECT_HANDLE key;
	CK_OBJECT_HANDLE replacement;
	g_autofree char* path = NULL;
	guint64 expires_at = 0;
	gint64 deadline;
	guint8 input[32] = { 0 };
	guint8 signature[256];
	guint8 plaintext[256];
	CK_ULONG signature_len = sizeof(signature);
	CK_ULONG plaintext_len = sizeof(plaintext);
	CK_RV sign_rv;
	CK_RV decrypt_rv;
	CK_RV expected = CKR_OPERATION_NOT_INITIALIZED;

	fake_reset(ACQUIRE_ANSWER);
	if (strcmp(release, "expiry") == 0)
	{
		expires_at = g_get_real_time() / G_USEC_PER_SEC + 2;
		g_mutex_lock(&fake.lock);
		fake.expires_at = expires_at;
		g_mutex_unlock(&fake.lock);
	}
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	pending = open_session();
	key = find_the_private_key(session);
	path = current_portal_session();
	init_pending_operations(pending, key);

	if (strcmp(release, "logout") == 0)
	{
		g_assert_cmpuint(functions->C_Login(session, CKU_USER, NULL, 0), ==, CKR_OK);
		g_assert_cmpuint(functions->C_Logout(session), ==, CKR_OK);
		assert_session_closed(path);
	}
	else if (strcmp(release, "close-all") == 0)
	{
		g_assert_cmpuint(functions->C_CloseAllSessions(1), ==, CKR_OK);
		assert_session_closed(path);
		session = open_session();
		expected = CKR_SESSION_HANDLE_INVALID;
	}
	else if (strcmp(release, "closed") == 0)
	{
		g_dbus_connection_emit_signal(fake.connection, NULL, path,
		                              "org.freedesktop.portal.Session", "Closed",
		                              g_variant_new("(@a{sv})", empty_results()), NULL);
	}
	else
	{
		while ((guint64) (g_get_real_time() / G_USEC_PER_SEC) < expires_at)
			g_usleep(1000);
	}

	/* The next search must select credential B, with a different certificate and key. */
	g_mutex_lock(&fake.lock);
	g_clear_pointer(&fake.certificate, g_bytes_unref);
	fake.certificate = fixture_der("email-sign-and-encipher.pem");
	fake.expires_at = 0;
	g_mutex_unlock(&fake.lock);
	deadline = g_get_monotonic_time() + WAIT_MS * G_TIME_SPAN_MILLISECOND;
	do
	{
		replacement = find_the_private_key(session);
		if (replacement != key)
			break;
		g_usleep(1000);
	} while (g_get_monotonic_time() < deadline);
	g_assert_cmpuint(replacement, !=, key);
	g_assert_cmpuint(fake_acquire_count(), ==, 2);

	sign_rv = functions->C_Sign(pending, input, sizeof(input), signature, &signature_len);
	decrypt_rv = functions->C_Decrypt(pending, input, sizeof(input), plaintext, &plaintext_len);
	g_mutex_lock(&fake.lock);
	g_assert_cmpuint(fake.sign_count, ==, 0);
	g_assert_cmpuint(fake.decrypt_count, ==, 0);
	g_mutex_unlock(&fake.lock);
	g_assert_cmpuint(sign_rv, ==, expected);
	g_assert_cmpuint(decrypt_rv, ==, expected);

	/* Fresh operations may use B, proving that the fake portal observes both methods. */
	init_pending_operations(session, replacement);
	g_assert_cmpuint(functions->C_Sign(session, input, sizeof(input), signature, &signature_len),
	                 ==, CKR_OK);
	g_assert_cmpuint(functions->C_Decrypt(session, input, sizeof(input), plaintext, &plaintext_len),
	                 ==, CKR_OK);
	g_mutex_lock(&fake.lock);
	g_assert_cmpuint(fake.sign_count, ==, 1);
	g_assert_cmpuint(fake.decrypt_count, ==, 1);
	g_mutex_unlock(&fake.lock);
	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

static void test_caller_lengths_are_bounded_before_they_are_narrowed(void)
{
	guint8 block[PREHASH_LIMIT];
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;

	memset(block, 0x41, sizeof(block));

	fake_reset(ACQUIRE_ANSWER);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	session = open_session();
	key = find_the_private_key(session);

	g_assert_cmpuint(sign_init(session, key, 32), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, PREHASH_LIMIT), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, 1), ==, CKR_DATA_LEN_RANGE);

	g_assert_cmpuint(sign_init(session, key, 32), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, 100), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, G_MAXULONG - 50), ==,
	                 CKR_DATA_LEN_RANGE);

	/* The uint32 salt boundary must reach the backend, which validates it against the key. */
	g_assert_cmpuint(sign_init(session, key, G_MAXUINT32), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, G_MAXULONG), ==,
	                 CKR_DATA_LEN_RANGE);

	if (sizeof(CK_ULONG) > sizeof(guint32))
	{
		g_assert_cmpuint(sign_init(session, key, ((CK_ULONG) G_MAXUINT32) + 1), ==,
		                 CKR_MECHANISM_PARAM_INVALID);
		g_assert_cmpuint(sign_init(session, key, ((CK_ULONG) G_MAXUINT32) + 33), ==,
		                 CKR_MECHANISM_PARAM_INVALID);
	}

	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);
}

int main(int argc, char** argv)
{
	GTestDBus* bus = NULL;
	int result;

	g_test_init(&argc, &argv, NULL);

	/* Use one bus because the module's shared GDBus connection survives individual fixtures. */
	bus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_up(bus);
	fake_start(bus);

	g_assert_cmpuint(C_GetFunctionList(&functions), ==, CKR_OK);

	g_test_add_func("/module/portal/chooser-does-not-hold-the-lock",
	                test_the_chooser_does_not_hold_the_module_lock);
	g_test_add_func("/module/portal/finalize-during-the-chooser",
	                test_finalize_while_the_chooser_is_up);
	g_test_add_func("/module/portal/late-reply-closes-its-own-path",
	                test_a_late_reply_closes_the_path_it_names);
	g_test_add_func("/module/portal/refused-call-closes-nothing",
	                test_a_refused_call_closes_nothing);
	g_test_add_func("/module/portal/two-searches-one-chooser",
	                test_two_searches_share_one_chooser);
	g_test_add_func("/module/portal/session-closed-during-the-wait",
	                test_a_session_closed_during_the_wait_asks_for_nothing);
	g_test_add_func("/module/portal/reinitialization-strands-the-waiter",
	                test_a_search_does_not_survive_reinitialization);
	g_test_add_func("/module/portal/timeout-closes-the-request",
	                test_a_timed_out_request_is_closed);
	g_test_add_func("/module/portal/caller-lengths",
	                test_caller_lengths_are_bounded_before_they_are_narrowed);
	g_test_add_data_func("/module/portal/pending-operations/logout", "logout",
	                     test_pending_operations_do_not_survive_grant_release);
	g_test_add_data_func("/module/portal/pending-operations/close-all", "close-all",
	                     test_pending_operations_do_not_survive_grant_release);
	g_test_add_data_func("/module/portal/pending-operations/closed", "closed",
	                     test_pending_operations_do_not_survive_grant_release);
	g_test_add_data_func("/module/portal/pending-operations/expiry", "expiry",
	                     test_pending_operations_do_not_survive_grant_release);

	g_test_add_func("/module/portal/config-enumeration",
	                test_configuration_enables_enumeration);
	g_test_add_func("/module/portal/p11kit-configuration",
	                test_p11kit_forwards_configuration);
	g_test_add_func("/module/portal/logout-releases-grant",
	                test_logout_releases_the_grant);
	g_test_add_func("/module/portal/close-all-releases-grant",
	                test_close_all_sessions_releases_the_grant);
	g_test_add_func("/module/portal/portal-session-closed",
	                test_portal_session_closure_drops_the_grant);
	g_test_add_func("/module/portal/issued-identifiers",
	                test_only_issued_identifiers_acquire);
	g_test_add_func("/module/portal/logout-during-acquisition",
	                test_logout_discards_an_acquisition_in_progress);
	g_test_add_func("/module/portal/cancel-different-template",
	                test_cancel_suppresses_different_templates);

	result = g_test_run();

	fake_stop();

	/* Use stop() and retain the fixture because down() waits for the application's singleton connection. */
	g_test_dbus_stop(bus);

	return result;
}
