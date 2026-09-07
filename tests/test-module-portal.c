/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * The client-side PKCS#11 module driven through C_GetFunctionList, against a
 * portal that is stood up here rather than mocked out. tests/test-module.c
 * covers the parts that need no bus; these three need one, because what they
 * are about is what the module does while a request is outstanding:
 *
 *   - the process-wide lock is NOT held across the chooser;
 *   - a request that times out is Closed at the portal rather than abandoned;
 *   - the lengths a caller can put in a CK_MECHANISM are bounded before they
 *     are narrowed.
 *
 * The fake portal runs on its own thread with its own GMainContext, so a test
 * body can make blocking PKCS#11 calls on the main thread exactly as an
 * application does.
 */

#include <string.h>

#include <gio/gio.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <p11-kit/pkcs11.h>

#include "module/constants.h"

#ifndef CERTIFICATE_FIXTURE_DIR
#define CERTIFICATE_FIXTURE_DIR "tests/fixtures"
#endif

/* PRE_HASHED_LIMIT in src/module/module.c. A private constant deliberately, so
 * the boundary is restated here rather than shared: a change to either has to
 * be a change to both. */
#define PREHASH_LIMIT 512

#define WAIT_MS 5000

/* ----------------------------------------------------------- the fake portal */

static const char introspection[] =
    "<node>"
    "  <interface name='org.freedesktop.portal.experimental.Certificate'>"
    "    <method name='GetCapabilities'>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='a{sv}' name='capabilities' direction='out'/>"
    "    </method>"
    "    <method name='CreateSession'>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='o' name='handle' direction='out'/>"
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
    "  </interface>"
    "</node>";

/* What the fake does with the next AcquireCredential. */
typedef enum
{
	ACQUIRE_ANSWER,     /* reply, then Response with a credential */
	ACQUIRE_STALL,      /* reply, and no Response ever */
	ACQUIRE_HOLD_REPLY, /* not even the method reply, until the test lets go --
	                     * and then it names a path the module never predicted */
	ACQUIRE_FAIL,       /* a D-Bus error, so there is no request object at all */
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

	/* Knobs and observations. Written on the fake's thread, read by the
	 * test's. */
	AcquireMode acquire_mode;
	guint acquire_count;
	char* acquire_path;
	char* acquire_sender;
	/* The held AcquireCredential: the invocation is owned here until the test
	 * releases it, which is how a reply is made to lose a race on purpose. */
	GDBusMethodInvocation* held;
	char* held_path;
	GPtrArray* closed;
	/* Request and Session objects, so that one test's paths do not collide with
	 * the next one's: the module's tokens restart at C_Initialize and the bus
	 * name is the same connection throughout. */
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

/* The same rule as request_path_for() in src/module/portal.c: the module
 * predicts this path and subscribes to it before it makes the call, so a fake
 * that answered on a path of its own would be testing the recovery and not the
 * ordinary case. */
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

/* A request or a session object, which lasts as long as the test that provoked
 * it. The interface object itself is not one of these. */
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
	static const char* const mechanisms[] = { "RSA_PKCS1_V1_5", "RSA_PSS", "ECDSA", NULL };
	static const char* const operations[] = { "sign", NULL };
	gsize size = 0;
	const guint8* data = g_bytes_get_data(fake.certificate, &size);
	GVariantBuilder builder;

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "certificate_der",
	                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, size, 1));
	g_variant_builder_add(&builder, "{sv}", "key_type", g_variant_new_string("RSA"));
	g_variant_builder_add(&builder, "{sv}", "key_size", g_variant_new_uint32(2048));
	g_variant_builder_add(&builder, "{sv}", "expires_at", g_variant_new_uint64(0));
	g_variant_builder_add(&builder, "{sv}", "supported_mechanisms",
	                      g_variant_new_strv(mechanisms, -1));
	g_variant_builder_add(&builder, "{sv}", "permitted_operations",
	                      g_variant_new_strv(operations, -1));

	return g_variant_builder_end(&builder);
}

/* Recorded before the reply, so a test can wait for the call itself and not for
 * whatever the fake decides to do about it. */
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
		static const char* const mechanisms[] = { "RSA_PKCS1_V1_5", "RSA_PSS", "ECDSA", NULL };
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
	else if (strcmp(method, "AcquireCredential") == 0)
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

		g_variant_builder_init(&results, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_add(&results, "{sv}", "session_handle",
		                      g_variant_new_object_path(session_path));
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

		/* The portal picks the request object's path, and nothing says it has
		 * to be the one the caller predicted. */
		export_transient(late_path, PKCS11_PORTAL_REQUEST_INTERFACE, &request_vtable);

		g_mutex_lock(&fake.lock);
		fake.held = invocation;
		fake.held_path = g_steal_pointer(&late_path);
		g_cond_broadcast(&fake.cond);
		g_mutex_unlock(&fake.lock);
		return;
	}

	g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", request_path));

	/* THE CHOOSER IS ON SCREEN AND NOTHING ANSWERS. Everything about the
	 * module's behaviour during a request is only visible here. */
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

	/* Deliberately not g_bus_get_sync(): the singleton belongs to the module
	 * under test, and two users of one connection would hide a dispatch bug. */
	fake.connection = g_dbus_connection_new_for_address_sync(
	    g_test_dbus_get_bus_address(bus),
	    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
	        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
	    NULL, NULL, &error);
	g_assert_no_error(error);

	fake.certificate_id =
	    export_object(PKCS11_PORTAL_OBJECT_PATH, PKCS11_PORTAL_INTERFACE, &certificate_vtable);

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
	g_clear_pointer(&fake.acquire_path, g_free);
	g_clear_pointer(&fake.acquire_sender, g_free);
	g_clear_pointer(&fake.held_path, g_free);
	g_ptr_array_set_size(fake.closed, 0);
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

/** The AcquireCredential count, after waiting up to @ms for a second one to
 *  turn up. A bounded wait for something that must not happen: it is what makes
 *  "no second chooser" an assertion and not a hope. */
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

/** The request path AcquireCredential was called on, or NULL after @ms. */
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

/** The path the held AcquireCredential reply will name, or NULL after @ms. */
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

/** Answer the stalled AcquireCredential, so the blocked caller comes back. */
static gboolean answer_acquire(gpointer data)
{
	guint32 response = GPOINTER_TO_UINT(data);

	g_mutex_lock(&fake.lock);
	emit_response(fake.acquire_sender, fake.acquire_path, response,
	              response == 0 ? credential_results() : empty_results());
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

/* --------------------------------------------------------------- the module */

static CK_FUNCTION_LIST* functions;

static CK_SESSION_HANDLE open_session(void)
{
	CK_SESSION_HANDLE session = 0;

	g_assert_cmpuint(functions->C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &session), ==,
	                 CKR_OK);

	return session;
}

/* The private-key search, which is the template that acquires a credential. */
typedef struct
{
	CK_OBJECT_CLASS object_class;
	guint8 identifier[4];
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

/* The same search with a key identifier in it. It acquires exactly as the plain
 * one does, but its refusal fingerprint is a different one -- so a refusal
 * another search collected does not silence it, which is what makes it usable
 * as the SECOND search in these tests. */
static void search_init_by_id(Search* search, CK_SESSION_HANDLE session)
{
	static const guint8 identifier[4] = { 1, 2, 3, 4 };

	search_init(search, session);
	memcpy(search->identifier, identifier, sizeof(identifier));
	search->templ[1].type = CKA_ID;
	search->templ[1].pValue = search->identifier;
	search->templ[1].ulValueLen = sizeof(search->identifier);
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

/* C_Finalize off the main thread, so that a test can keep answering the portal
 * while it drains. */
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

/* M1 OF THE 2026 REVIEW. C_FindObjectsInit used to hold the module's one global
 * lock across the acquire, so a browser that opened a second connection while
 * the chooser was up wedged its whole crypto stack -- for up to the five-minute
 * request timeout. */
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

	/* The chooser is up on the other thread. This one is a different PKCS#11
	 * session doing something the portal is not involved in at all. */
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

/* THE OTHER SIDE OF THE SAME CHANGE. With the lock down across the acquire, the
 * thread that is blocked on the chooser owns the portal client, so C_Finalize
 * cannot simply free it -- and it must not wait out the request timeout either.
 * It abandons the request instead. */
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

/* THE REPLY THE PORTAL HAD NOT SENT YET. Cancelling a request Closes the path
 * the caller predicted, but the portal chooses the path, and its reply can name
 * a different one. If the client's context is torn down before that reply is
 * dispatched, the request object it names is one nothing will ever close -- a
 * chooser left on screen -- and the callback's own references are stranded on a
 * context nobody runs again. */
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

	/* Finalize with the reply still in the portal's hands. */
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

/* A method call the portal REFUSES leaves no request object behind, at either
 * path, so there is nothing to Close -- and a Close sent anyway is a message to
 * an object that never existed. */
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

	/* No credential is not an error: it is an empty search. */
	g_assert_cmpuint(functions->C_FindObjectsInit(session, templ, 1), ==, CKR_OK);
	g_assert_cmpuint(functions->C_FindObjects(session, handles, G_N_ELEMENTS(handles), &count),
	                 ==, CKR_OK);
	g_assert_cmpuint(count, ==, 0);
	g_assert_cmpuint(functions->C_FindObjectsFinal(session), ==, CKR_OK);

	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	g_assert_cmpuint(fake_acquire_count(), ==, 1);
	g_assert_cmpuint(fake_close_count(), ==, 0);
}

/* Two searches on two threads, one chooser. The second waits for the first
 * rather than opening a window of its own, and then finds what the first one
 * was given. */
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

/* A SESSION CLOSED WHILE ITS SEARCH WAS QUEUED behind somebody else's chooser.
 * The wait is not a place where the handle keeps its meaning: by the time this
 * search runs there is no session to answer, and opening a second chooser for
 * it would be a window nobody asked for. */
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
	search_init_by_id(&second, open_session());

	one = g_thread_new("first", find_thread, &first);
	acquired = fake_wait_for_acquire(WAIT_MS);
	g_assert_nonnull(acquired);

	two = g_thread_new("second", find_thread, &second);
	g_assert_false(search_wait(&second, 200));

	g_assert_cmpuint(functions->C_CloseSession(second.session), ==, CKR_OK);

	/* Refused, so the waiting search does not simply inherit a grant. */
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

/* THE SAME HANDLE, A DIFFERENT MODULE. C_Initialize hands the session handles
 * out again from 1, so a search that was queued across a finalize wakes into a
 * module where its handle names somebody else's session -- and used to acquire
 * a credential through the new client and publish into that session. */
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
	search_init_by_id(&second, open_session());
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

	/* The handles start again, so this is the number the waiting search is
	 * still holding. */
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

/* A timed-out request used to be dropped on the floor: this side stopped
 * waiting, and the chooser -- or a PIN prompt behind it -- stayed up with a
 * grant nobody was going to collect. */
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

	/* Times out rather than answering, and a search that acquired nothing is
	 * an empty search and not an error. */
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

static CK_RV sign_init(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_ULONG salt_length)
{
	CK_RSA_PKCS_PSS_PARAMS parameters = { CKM_SHA256, CKG_MGF1_SHA256, salt_length };
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_PSS, &parameters, sizeof(parameters) };

	return functions->C_SignInit(session, &mechanism, key);
}

/* The two lengths a caller chooses that used to be narrowed instead of
 * refused: the PSS salt length, and the amount fed to a mechanism that does not
 * hash. */
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

	/* The pre-hash buffer, at the boundary and one byte past it. */
	g_assert_cmpuint(sign_init(session, key, 32), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, PREHASH_LIMIT), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, 1), ==, CKR_DATA_LEN_RANGE);

	/* And past it by so much that len + size wraps back under it. The old
	 * check added, so this one was accepted and then truncated into a guint. */
	g_assert_cmpuint(sign_init(session, key, 32), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, 100), ==, CKR_OK);
	g_assert_cmpuint(functions->C_SignUpdate(session, block, G_MAXULONG - 50), ==,
	                 CKR_DATA_LEN_RANGE);

	/* The PSS salt length is a CK_ULONG and the interface carries a uint32. The
	 * largest that fits is this module's business to forward and the backend's
	 * to refuse against the key. */
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

	/* One bus for the whole process: the module reaches it through
	 * g_bus_get_sync(), whose singleton outlives any one GTestDBus. */
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

	result = g_test_run();

	fake_stop();

	/* stop() and not down(): down() waits for the GDBusConnection singleton to
	 * be destroyed, and this module reaches the bus through g_bus_get_sync()
	 * precisely because the connection belongs to the application and not to
	 * it. A request abandoned at C_Finalize can also leave one reply
	 * outstanding on a context nobody runs again. The GTestDBus is not unreffed
	 * either: disposing one runs down(). */
	g_test_dbus_stop(bus);

	return result;
}
