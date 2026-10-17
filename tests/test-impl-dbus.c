/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <adwaita.h>
#include <gio/gio.h>
#include <glib.h>
#include <string.h>

#include "certificate-impl.h"
#include "fixture-util.h"
#include "fake-chooser-provider.h"
#include "request-impl.h"
#include "session-impl.h"
#include "tokens/filter.h"
#include "core/chooser.h"
#include "core/pin.h"
#include "ui/pin-backends.h"
#include "ui/chooser.h"

#define FRONTEND_NAME "org.freedesktop.portal.Desktop"
#define IMPL_PATH "/org/freedesktop/portal/desktop"
#define IMPL_INTERFACE "org.freedesktop.impl.portal.experimental.Certificate1"

#define SESSION_PATH "/org/freedesktop/portal/desktop/session/test/one"
#define REQUEST_PATH "/org/freedesktop/portal/desktop/request/test/one"

#define APP_A "org.example.AppA"
#define APP_B "org.example.AppB"

typedef struct
{
	GTestDBus* bus;
	GDBusConnection* backend;
	GDBusConnection* frontend;
	GDBusConnection* stranger;
	guint owner_id;
	CertificateTokens* tokens;
	CertificateImpl* impl;
	gboolean has_softhsm;
} Fixture;

/* Address the backend by its unique connection name; no well-known backend name is owned. */
static const char* backend_name = NULL;
static gboolean has_display = FALSE;

/* Use a fresh connection because the session-bus singleton outlives individual GTestDBus fixtures. */
static GDBusConnection* open_connection(GTestDBus* bus)
{
	g_autoptr(GError) error = NULL;
	GDBusConnection* connection = g_dbus_connection_new_for_address_sync(
	    g_test_dbus_get_bus_address(bus),
	    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
	        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
	    NULL, NULL, &error);

	g_assert_no_error(error);
	return connection;
}

static void on_name_acquired(GDBusConnection* connection, const char* name, gpointer user_data)
{
	gboolean* acquired = user_data;

	*acquired = TRUE;
}

static void fixture_set_up(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	gboolean acquired = FALSE;
	const char* modules[2] = { NULL, NULL };
	g_autofree char* module = NULL;
	g_autofree char* directory = NULL;

	certificate_ui_set_has_display(FALSE);

	fixture->bus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_up(fixture->bus);

	fixture->backend = open_connection(fixture->bus);
	fixture->frontend = open_connection(fixture->bus);
	fixture->stranger = open_connection(fixture->bus);
	backend_name = g_dbus_connection_get_unique_name(fixture->backend);

	/* Allow direct replacement without releasing the name first, so teardown cannot invalidate the sessions under test. */
	fixture->owner_id =
	    g_bus_own_name_on_connection(fixture->frontend, FRONTEND_NAME,
	                                 G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT, on_name_acquired,
	                                 NULL, &acquired, NULL);

	while (!acquired)
		g_main_context_iteration(NULL, TRUE);

	directory = g_strdup(g_getenv("SOFTHSM_FIXTURE_DIR"));
	if (directory == NULL)
	{
		g_autofree char* fallback =
		    g_build_filename(g_get_tmp_dir(), "xdp-certificate-softhsm", NULL);

		if (g_file_test(fallback, G_FILE_TEST_IS_DIR))
			directory = g_steal_pointer(&fallback);
	}

	if (directory != NULL)
	{
		g_autofree char* module_path = g_build_filename(directory, "module-path", NULL);
		g_autofree char* config = g_build_filename(directory, "softhsm2.conf", NULL);

		if (g_file_get_contents(module_path, &module, NULL, NULL))
		{
			g_setenv("SOFTHSM2_CONF", config, TRUE);
			modules[0] = module;
			fixture->has_softhsm = TRUE;
		}
	}

	fixture->tokens = certificate_tokens_new(modules[0] != NULL ? modules : NULL, &error);
	g_assert_no_error(error);

	fixture->impl = certificate_impl_new(fixture->backend, fixture->tokens, &error);
	g_assert_no_error(error);
	g_assert_nonnull(fixture->impl);
}

static void fixture_tear_down(Fixture* fixture, gconstpointer user_data)
{
	certificate_impl_shutdown(fixture->impl);
	certificate_impl_free(fixture->impl);
	g_clear_pointer(&fixture->tokens, certificate_tokens_free);

	if (fixture->owner_id != 0)
		g_bus_unown_name(fixture->owner_id);
	g_dbus_connection_close_sync(fixture->frontend, NULL, NULL);
	g_dbus_connection_close_sync(fixture->stranger, NULL, NULL);
	g_dbus_connection_close_sync(fixture->backend, NULL, NULL);
	g_clear_object(&fixture->frontend);
	g_clear_object(&fixture->stranger);
	g_clear_object(&fixture->backend);
	backend_name = NULL;

	g_test_dbus_down(fixture->bus);
	g_clear_object(&fixture->bus);
}

/* Make test calls asynchronously because the backend uses this process's main context. */
typedef struct
{
	GVariant* reply;
	GError* error;
	gboolean done;
} Call;

static void on_call_done(GObject* source, GAsyncResult* result, gpointer user_data)
{
	Call* call = user_data;

	call->reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &call->error);
	call->done = TRUE;
}

static GVariant* call_sync(GDBusConnection* connection, const char* path, const char* interface,
                           const char* method, GVariant* parameters, GError** error)
{
	Call call = { NULL, NULL, FALSE };

	g_dbus_connection_call(connection, backend_name, path, interface, method, parameters, NULL,
	                       G_DBUS_CALL_FLAGS_NONE, 5000, NULL, on_call_done, &call);

	while (!call.done)
		g_main_context_iteration(NULL, TRUE);

	if (call.error != NULL)
	{
		g_propagate_error(error, call.error);
		return NULL;
	}

	return call.reply;
}

static GVariant* impl_call(GDBusConnection* connection, const char* method, GVariant* parameters,
                           GError** error)
{
	return call_sync(connection, IMPL_PATH, IMPL_INTERFACE, method, parameters, error);
}

static GVariant* empty_options(void)
{
	GVariantBuilder builder;

	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	return g_variant_builder_end(&builder);
}

static GVariant* acquire_options(const char* extra)
{
	g_autofree char* text =
	    g_strdup_printf("{'purpose': <'client_auth'>, 'app_identity_level': <'host'>%s%s}",
	                    extra != NULL ? ", " : "", extra != NULL ? extra : "");
	/* Callers own the full variant reference; acquire() consumes it. */
	GVariant* options = g_variant_parse(G_VARIANT_TYPE_VARDICT, text, NULL, NULL, NULL);

	g_assert_nonnull(options);
	return options;
}

static guint32 create_session(Fixture* fixture, const char* path, const char* app_id)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	guint32 response = 99;

	reply = impl_call(fixture->frontend, "CreateSession",
	                  g_variant_new("(oos@a{sv})", REQUEST_PATH, path, app_id, empty_options()),
	                  &error);
	g_assert_no_error(error);
	g_variant_get(reply, "(u@a{sv})", &response, NULL);

	return response;
}

/* Consumes @options. */
static void acquire(Fixture* fixture, const char* session_path, const char* app_id,
                    GVariant* options, guint32* response, char** code)
{
	g_autoptr(GVariant) owned = options;
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GVariant) results = NULL;

	reply = impl_call(fixture->frontend, "AcquireCredential",
	                  g_variant_new("(ooss@a{sv})", REQUEST_PATH, session_path, app_id, "",
	                                owned),
	                  &error);
	g_assert_no_error(error);
	g_variant_get(reply, "(u@a{sv})", response, &results);

	*code = NULL;
	g_variant_lookup(results, "error", "s", code);
}

static void test_stranger_is_refused(Fixture* fixture, gconstpointer user_data)
{
	static const char* const interactive[] = { "AcquireCredential", "Sign", NULL };

	{
		g_autoptr(GError) error = NULL;
		g_autoptr(GVariant) reply =
		    impl_call(fixture->stranger, "CreateSession",
		              g_variant_new("(oos@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A,
		                            empty_options()),
		              &error);

		g_assert_null(reply);
		g_assert_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	}

	for (gsize i = 0; interactive[i] != NULL; i++)
	{
		g_autoptr(GError) error = NULL;
		g_autoptr(GVariant) reply =
		    impl_call(fixture->stranger, interactive[i],
		              g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "",
		                            empty_options()),
		              &error);

		g_assert_null(reply);
		g_assert_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	}

	{
		g_autoptr(GError) error = NULL;
		g_autoptr(GVariant) reply =
		    impl_call(fixture->stranger, "GetCapabilities",
		              g_variant_new("(s@a{sv})", APP_A, empty_options()), &error);

		g_assert_null(reply);
		g_assert_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	}
}

static void test_session_close_is_authorised(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	reply = call_sync(fixture->stranger, SESSION_PATH, "org.freedesktop.impl.portal.Session",
	                  "Close", NULL, &error);
	g_assert_null(reply);
	g_assert_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	g_clear_error(&error);

	reply = call_sync(fixture->frontend, SESSION_PATH, "org.freedesktop.impl.portal.Session",
	                  "Close", NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(reply);
}

/* Export the Request manually to avoid racing a short-lived real request. */
static void test_request_close_is_authorised(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(CertificateImplRequest) request =
	    certificate_impl_request_new(g_dbus_connection_get_unique_name(fixture->frontend), APP_A,
	                                 REQUEST_PATH);
	GCancellable* cancellable = certificate_impl_request_get_cancellable(request);
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;

	g_assert_true(certificate_impl_request_export(request, fixture->backend, &error));
	g_assert_no_error(error);

	reply = call_sync(fixture->stranger, REQUEST_PATH, "org.freedesktop.impl.portal.Request",
	                  "Close", NULL, &error);
	g_assert_null(reply);
	g_assert_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	g_clear_error(&error);
	g_assert_false(g_cancellable_is_cancelled(cancellable));

	reply = call_sync(fixture->frontend, REQUEST_PATH, "org.freedesktop.impl.portal.Request",
	                  "Close", NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(reply);
	g_assert_true(g_cancellable_is_cancelled(cancellable));
}

static void test_session_is_bound_to_app_id(Fixture* fixture, gconstpointer user_data)
{
	guint32 response = 0;
	g_autofree char* code = NULL;
	g_autoptr(GVariant) options = acquire_options(NULL);

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	acquire(fixture, SESSION_PATH, APP_B, g_steal_pointer(&options), &response, &code);
	g_assert_cmpuint(response, ==, 2);
	g_assert_cmpstr(code, ==, "no_such_session");
}

static void test_identity_level_cannot_rise(Fixture* fixture, gconstpointer user_data)
{
	guint32 response = 0;
	g_autofree char* code = NULL;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	/* The unidentified acquisition records its identity level before failing discovery or display checks. */
	{
		g_autoptr(GVariant) options = g_variant_parse(
		    G_VARIANT_TYPE_VARDICT,
		    "{'purpose': <'client_auth'>, 'app_identity_level': <'unidentified'>}", NULL, NULL,
		    NULL);

		acquire(fixture, SESSION_PATH, APP_A, g_steal_pointer(&options), &response, &code);
		g_assert_cmpuint(response, ==, 2);
		g_clear_pointer(&code, g_free);
	}

	{
		g_autoptr(GVariant) options = g_variant_parse(
		    G_VARIANT_TYPE_VARDICT,
		    "{'purpose': <'client_auth'>, 'app_identity_level': <'sandboxed'>}", NULL,
		    NULL, NULL);

		acquire(fixture, SESSION_PATH, APP_A, g_steal_pointer(&options), &response, &code);
		g_assert_cmpuint(response, ==, 2);
		g_assert_cmpstr(code, ==, "no_such_session");
	}
}

static void test_session_path_is_reusable(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 2);

	reply = call_sync(fixture->frontend, SESSION_PATH, "org.freedesktop.impl.portal.Session",
	                  "Close", NULL, &error);
	g_assert_no_error(error);

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);
}

static void test_options_are_validated(Fixture* fixture, gconstpointer user_data)
{
	static const struct
	{
		const char* options;
		const char* code;
	} cases[] = {
		{ "{'purpose': <'client_auth'>, 'app_identity_level': <'root'>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'app_identity_level': <42>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'interaction_mode': <'whenever'>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'lifetime': <'300'>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'lifetime': <uint32 0>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'reason': <42>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'operation_policy': <{'decrypt': <true>}>}",
		  "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'operation_policy': <{'sign': <'yes'>}>}",
		  "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'operation_policy': <{'delete': <true>}>}",
		  "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'operation_policy': <'sign'>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'certificate_filter': <'anything'>}", "invalid_filter" },
		{ "{'purpose': <'client_auth'>, 'certificate_filter': <{'unknown': <true>}>}",
		  "invalid_filter" },
		{ "{'purpose': <'client_auth'>, 'certificate_filter': <{'piv_slot': <'nine'>}>}",
		  "invalid_filter" },
		{ "{'purpose': <'nonsense'>}", "invalid_purpose" },
		{ "{}", "invalid_purpose" },
	};

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		guint32 response = 0;
		g_autofree char* code = NULL;
		GVariant* options =
		    g_variant_parse(G_VARIANT_TYPE_VARDICT, cases[i].options, NULL, NULL, NULL);

		g_assert_nonnull(options);
		acquire(fixture, SESSION_PATH, APP_A, options, &response, &code);

		if (response != 2 || g_strcmp0(code, cases[i].code) != 0)
			g_error("options %s answered %u/%s, expected 2/%s", cases[i].options, response,
			        code != NULL ? code : "(none)", cases[i].code);
	}
}

static void test_results_types(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, TRUE);
	g_autoptr(GVariant) results = NULL;
	static const struct
	{
		const char* key;
		const char* type;
		gboolean required;
	} expected[] = {
		{ "certificate_der", "ay", TRUE },      { "chain_der", "aay", TRUE },
		{ "chain_status", "s", TRUE },          { "token_display", "a{sv}", TRUE },
		{ "key_type", "s", TRUE },              { "key_size", "u", TRUE },
		{ "key_curve", "s", FALSE },            { "supported_mechanisms", "as", TRUE },
		{ "permitted_operations", "as", TRUE }, { "may_prompt_later", "b", TRUE },
	};

	results = g_variant_ref_sink(certificate_impl_acquire_results(candidate, TRUE));

	for (gsize i = 0; i < G_N_ELEMENTS(expected); i++)
	{
		g_autoptr(GVariant) value =
		    g_variant_lookup_value(results, expected[i].key, G_VARIANT_TYPE(expected[i].type));

		if (value == NULL && expected[i].required)
			g_error("results has no %s of type %s", expected[i].key, expected[i].type);
	}

	{
		g_autoptr(GVariant) operations =
		    g_variant_lookup_value(results, "permitted_operations", G_VARIANT_TYPE_STRING_ARRAY);
		g_autoptr(GVariant) mechanisms =
		    g_variant_lookup_value(results, "supported_mechanisms", G_VARIANT_TYPE_STRING_ARRAY);

		g_assert_cmpuint(g_variant_n_children(operations), >, 0);
		g_assert_cmpuint(g_variant_n_children(mechanisms), >, 0);
	}

	{
		g_autoptr(GVariant) display =
		    g_variant_lookup_value(results, "token_display", G_VARIANT_TYPE_VARDICT);
		g_autoptr(GVariant) serial = g_variant_lookup_value(display, "serial", NULL);

		g_assert_null(serial);
	}
}

typedef struct
{
	char* reason;
	guint count;
} InvalidationWatch;

static void on_session_invalidated_signal(GDBusConnection* connection, const char* sender,
                                          const char* path, const char* interface,
                                          const char* signal, GVariant* parameters,
                                          gpointer user_data)
{
	InvalidationWatch* watch = user_data;
	const char* session_path = NULL;
	const char* reason = NULL;

	g_variant_get(parameters, "(&o&s)", &session_path, &reason);
	g_free(watch->reason);
	watch->reason = g_strdup(reason);
	watch->count++;
}

static void test_shutdown_reason_is_in_the_vocabulary(Fixture* fixture, gconstpointer user_data)
{
	InvalidationWatch watch = { NULL, 0 };
	guint id;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	id = g_dbus_connection_signal_subscribe(fixture->frontend, NULL, IMPL_INTERFACE,
	                                        "SessionInvalidated", IMPL_PATH, NULL,
	                                        G_DBUS_SIGNAL_FLAGS_NONE,
	                                        on_session_invalidated_signal, &watch, NULL);

	certificate_impl_shutdown(fixture->impl);

	while (watch.count == 0)
		g_main_context_iteration(NULL, TRUE);

	g_dbus_connection_signal_unsubscribe(fixture->frontend, id);

	g_assert_cmpstr(watch.reason, ==, "backend_gone");
	g_free(watch.reason);
}

static void test_sign_without_grant(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GVariant) results = NULL;
	g_autoptr(GVariant) options = g_variant_parse(
	    G_VARIANT_TYPE_VARDICT,
	    "{'mechanism': <'RSA_PKCS1_V1_5'>, 'parameters': <{'hash': <'SHA256'>}>, 'data': "
	    "<b'0123456789abcdef0123456789abcdef'>}",
	    NULL, NULL, NULL);
	guint32 response = 0;

	g_assert_nonnull(options);
	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	reply = impl_call(fixture->frontend, "Sign",
	                  g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "", options),
	                  &error);
	g_assert_no_error(error);
	g_variant_get(reply, "(u@a{sv})", &response, &results);
	g_assert_cmpuint(response, ==, 2);
}

static void test_capabilities(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GVariant) capabilities = NULL;
	g_auto(GStrv) operations = NULL;

	reply = impl_call(fixture->frontend, "GetCapabilities",
	                  g_variant_new("(s@a{sv})", APP_A, empty_options()), &error);
	g_assert_no_error(error);
	g_variant_get(reply, "(@a{sv})", &capabilities);

	g_assert_true(g_variant_lookup(capabilities, "operations", "^as", &operations));
	g_assert_true(g_strv_contains((const char* const*) operations, "sign"));
	g_assert_false(g_strv_contains((const char* const*) operations, "decrypt"));
}

/* Use an explicit empty module list so installed host modules cannot affect absence cases. */
static void use_empty_modules(Fixture* fixture)
{
	const char* modules[] = { NULL };
	g_autoptr(GError) error = NULL;

	certificate_impl_shutdown(fixture->impl);
	certificate_impl_free(fixture->impl);
	certificate_tokens_free(fixture->tokens);
	fixture->tokens = certificate_tokens_new(modules, &error);
	g_assert_no_error(error);
	fixture->impl = certificate_impl_new(fixture->backend, fixture->tokens, &error);
	g_assert_no_error(error);
}

static gboolean require_matching_fixture(Fixture* fixture)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) candidates = NULL;
	g_autoptr(GPtrArray) matching = NULL;
	g_autoptr(GVariant) options = acquire_options(NULL);
	CertificateFilter filter = { 0 };

	if (!fixture->has_softhsm)
	{
		g_test_skip("SoftHSM fixture unavailable");
		return FALSE;
	}
	candidates = certificate_tokens_enumerate(fixture->tokens, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(candidates);
	if (candidates->len == 0)
	{
		g_test_skip("the SoftHSM fixture has no certificates; rebuild it");
		return FALSE;
	}
	g_assert_true(certificate_filter_parse(options, CERTIFICATE_PURPOSE_CLIENT_AUTH,
	                                       CERTIFICATE_OPERATION_SIGN, &filter, &error));
	g_assert_no_error(error);
	matching = certificate_filter_apply(candidates, &filter);
	certificate_filter_clear(&filter);
	g_assert_cmpuint(matching->len, >, 0);
	return TRUE;
}

static void assert_acquire_code(Fixture* fixture, const char* extra, const char* expected)
{
	guint32 response = 0;
	g_autofree char* code = NULL;

	acquire(fixture, SESSION_PATH, APP_A, acquire_options(extra), &response, &code);
	g_assert_cmpuint(response, ==, 2);
	g_assert_cmpstr(code, ==, expected);
}

static void test_preconsent_uniform(Fixture* fixture, gconstpointer user_data)
{
	gboolean forbidden = GPOINTER_TO_INT(user_data);
	const char* mode = forbidden ? "'interaction_mode': <'forbidden'>" : NULL;
	const char* no_match = forbidden
	    ? "'interaction_mode': <'forbidden'>, "
	      "'certificate_filter': <{'token_label': <'absent-issue-29-token'>}>"
	    : "'certificate_filter': <{'token_label': <'absent-issue-29-token'>}>";
	const char* expected = forbidden ? "interaction_required" : "no_display";

	if (!require_matching_fixture(fixture))
		return;
	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);
	assert_acquire_code(fixture, mode, expected);
	assert_acquire_code(fixture, no_match, expected);

	use_empty_modules(fixture);
	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);
	assert_acquire_code(fixture, mode, expected);
	assert_acquire_code(fixture, no_match, expected);
}

static GVariant* get_capabilities(Fixture* fixture)
{
	g_autoptr(GError) error = NULL;
	GVariant* reply = impl_call(fixture->frontend, "GetCapabilities",
	                            g_variant_new("(s@a{sv})", APP_A, empty_options()), &error);

	g_assert_no_error(error);
	g_assert_nonnull(reply);
	return reply;
}

static void test_capabilities_uniform(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GVariant) present = NULL;
	g_autoptr(GVariant) absent = NULL;
	g_autoptr(GVariant) capabilities = NULL;
	g_auto(GStrv) mechanisms = NULL;
	gboolean protected_path = FALSE;
	static const char* const expected[] = {
		"RSA_PKCS1_V1_5", "RSA_PSS", "RSA_OAEP", "ECDSA", NULL
	};

	if (!require_matching_fixture(fixture))
		return;
	present = get_capabilities(fixture);
	use_empty_modules(fixture);
	absent = get_capabilities(fixture);
	g_assert_true(g_variant_equal(present, absent));
	g_variant_get(present, "(@a{sv})", &capabilities);
	g_assert_true(g_variant_lookup(capabilities, "mechanisms", "^as", &mechanisms));
	g_assert_cmpstrv((const char* const*) mechanisms, expected);
	g_assert_true(g_variant_lookup(capabilities, "protected_authentication_path", "b",
	                               &protected_path));
	g_assert_true(protected_path);
}

/* A synchronous bus round trip proves earlier messages were routed without dispatching the backend's main context. */
static void bus_round_trip(GDBusConnection* connection)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = g_dbus_connection_call_sync(
	    connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
	    "GetId", NULL, G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);

	g_assert_no_error(error);
	g_assert_nonnull(reply);
}

/* Queue the former owner's call, replace its name synchronously, then dispatch with the stale owner cache. */
static void test_replaced_frontend_is_refused(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GDBusConnection) successor = open_connection(fixture->bus);
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GVariant) results = NULL;
	Call call = { NULL, NULL, FALSE };
	guint32 response = 0;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	g_dbus_connection_call(fixture->frontend, backend_name, IMPL_PATH, IMPL_INTERFACE,
	                       "CreateSession",
	                       g_variant_new("(oos@a{sv})", REQUEST_PATH,
	                                     "/org/freedesktop/portal/desktop/session/test/two", APP_A,
	                                     empty_options()),
	                       NULL, G_DBUS_CALL_FLAGS_NONE, 5000, NULL, on_call_done, &call);

	bus_round_trip(fixture->frontend);

	/* RequestName runs synchronously so replacement completes before backend dispatch. */
	{
		g_autoptr(GError) request_error = NULL;
		g_autoptr(GVariant) request = g_dbus_connection_call_sync(
		    successor, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
		    "RequestName",
		    g_variant_new("(su)", FRONTEND_NAME, (guint32) 2 /* DBUS_NAME_FLAG_REPLACE_EXISTING. */),
		    G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &request_error);
		guint32 result = 0;

		g_assert_no_error(request_error);
		g_variant_get(request, "(u)", &result);
		/* DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER. */
		g_assert_cmpuint(result, ==, 1);
	}

	while (!call.done)
		g_main_context_iteration(NULL, TRUE);

	g_assert_null(call.reply);
	g_assert_error(call.error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	g_clear_error(&call.error);

	reply = impl_call(successor, "GetCapabilities",
	                  g_variant_new("(s@a{sv})", APP_A, empty_options()), &error);
	g_assert_no_error(error);
	g_assert_nonnull(reply);

	{
		guint32 acquire_response = 0;
		g_autofree char* code = NULL;
		g_autoptr(GVariant) options = acquire_options(NULL);
		g_autoptr(GError) call_error = NULL;
		g_autoptr(GVariant) answer =
		    impl_call(successor, "AcquireCredential",
		              g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "", options),
		              &call_error);
		g_autoptr(GVariant) acquire_results = NULL;

		g_assert_no_error(call_error);
		g_variant_get(answer, "(u@a{sv})", &acquire_response, &acquire_results);
		g_variant_lookup(acquire_results, "error", "s", &code);
		g_assert_cmpuint(acquire_response, ==, 2);
		g_assert_cmpstr(code, ==, "no_such_session");
	}

	reply = impl_call(fixture->frontend, "GetCapabilities",
	                  g_variant_new("(s@a{sv})", APP_A, empty_options()), &error);
	g_assert_null(reply);
	g_assert_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	g_clear_error(&error);

	(void) response;
	(void) results;
}

static void test_frontend_vanishing_answers_pending_calls(Fixture* fixture,
                                                          gconstpointer user_data)
{
	Call call = { NULL, NULL, FALSE };
	g_autoptr(GVariant) results = NULL;
	g_autofree char* code = NULL;
	guint32 response = 0;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	{
		g_autoptr(GVariant) options = acquire_options(NULL);

		g_dbus_connection_call(fixture->frontend, backend_name, IMPL_PATH, IMPL_INTERFACE,
		                       "AcquireCredential",
		                       g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "",
		                                     options),
		                       NULL, G_DBUS_CALL_FLAGS_NONE, 20000, NULL, on_call_done, &call);
	}

	/* Dispatch the handler once so it exports the Request and starts discovery. */
	g_main_context_iteration(NULL, TRUE);

	/* Release the name but keep the connection open to receive the pending reply. */
	g_bus_unown_name(fixture->owner_id);
	fixture->owner_id = 0;

	while (!call.done)
		g_main_context_iteration(NULL, TRUE);

	g_assert_no_error(call.error);
	g_variant_get(call.reply, "(u@a{sv})", &response, &results);
	g_variant_lookup(results, "error", "s", &code);

	g_assert_cmpuint(response, ==, 2);
	g_assert_cmpstr(code, ==, "owner_gone");

	g_variant_unref(call.reply);
}

static void test_close_mid_flight(Fixture* fixture, gconstpointer user_data)
{
	Call call = { NULL, NULL, FALSE };
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) closed = NULL;
	g_autoptr(GVariant) results = NULL;
	guint32 response = 0;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	{
		g_autoptr(GVariant) options = acquire_options(NULL);

		g_dbus_connection_call(fixture->frontend, backend_name, IMPL_PATH, IMPL_INTERFACE,
		                       "AcquireCredential",
		                       g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "",
		                                     options),
		                       NULL, G_DBUS_CALL_FLAGS_NONE, 5000, NULL, on_call_done, &call);
	}

	/* Dispatch the handler once so the Request is exported while discovery runs. */
	g_main_context_iteration(NULL, TRUE);

	closed = call_sync(fixture->frontend, REQUEST_PATH, "org.freedesktop.impl.portal.Request",
	                   "Close", NULL, &error);
	/* Discovery may complete before Close() reaches the Request. */
	if (error != NULL)
		g_assert_false(g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED));

	while (!call.done)
		g_main_context_iteration(NULL, TRUE);

	g_assert_no_error(call.error);
	g_variant_get(call.reply, "(u@a{sv})", &response, &results);

	if (error == NULL)
		g_assert_cmpuint(response, ==, 1);
	else
		g_assert_cmpuint(response, !=, 0);

	g_clear_error(&error);
	g_variant_unref(call.reply);
}

typedef struct
{
	GMutex lock;
	GCond cond;
	gint entered;
	gboolean released;
} EnumerateGate;

static void hold_enumeration(gpointer user_data)
{
	EnumerateGate* gate = user_data;
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;

	g_mutex_lock(&gate->lock);
	g_atomic_int_set(&gate->entered, TRUE);
	while (!gate->released)
		g_assert_true(g_cond_wait_until(&gate->cond, &gate->lock, deadline));
	g_mutex_unlock(&gate->lock);
}

static GtkWidget* find_chooser_list(GtkWidget* widget)
{
	if (GTK_IS_LIST_BOX(widget))
		return widget;
	for (GtkWidget* child = gtk_widget_get_first_child(widget); child != NULL;
	     child = gtk_widget_get_next_sibling(child))
	{
		GtkWidget* list = find_chooser_list(child);

		if (list != NULL)
			return list;
	}
	return NULL;
}

typedef enum
{
	DEFERRED_CLOSE,
	DEFERRED_REMOVAL,
	DEFERRED_SUCCESS,
	DEFERRED_CANCEL
} DeferredOutcome;

#define DEFERRED_FAKE_UI 4

static void test_deferred_consent(Fixture* fixture, gconstpointer user_data)
{
	DeferredOutcome outcome = GPOINTER_TO_INT(user_data) & 3;
	gboolean fake_ui = (GPOINTER_TO_INT(user_data) & DEFERRED_FAKE_UI) != 0;
	FakeChooserProvider fake;
	EnumerateGate gate = { 0 };
	Call call = { 0 };
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) closed = NULL;
	g_autoptr(GVariant) results = NULL;
	g_autoptr(GVariant) options = NULL;
	g_autofree char* code = NULL;
	g_autoptr(GtkWindow) window = NULL;
	g_autoptr(CertificateToken) token = NULL;
	GtkWidget* list = NULL;
	GtkListBoxRow* row = NULL;
	CertificateCandidate* candidate;
	guint32 response = 99;
	gint64 deadline;

	if (!fake_ui && !has_display)
	{
		g_test_skip("no display: the chooser window cannot be opened");
		return;
	}
	if (!require_matching_fixture(fixture))
		return;
	if (fake_ui)
	{
		fake_chooser_provider_init(&fake);
		certificate_chooser_set_provider(&fake.provider);
	}
	else
		certificate_ui_set_has_display(TRUE);
	certificate_tokens_stop_watch(fixture->tokens);
	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);
	options = acquire_options(NULL);
	g_dbus_connection_call(fixture->frontend, backend_name, IMPL_PATH, IMPL_INTERFACE,
	                       "AcquireCredential",
	                       g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "", options),
	                       NULL, G_DBUS_CALL_FLAGS_NONE, 20000, NULL, on_call_done, &call);
	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while ((fake_ui ? fake.id == 0 : g_list_model_get_n_items(gtk_window_get_toplevels()) == 0) &&
	       !call.done && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);
	g_assert_false(call.done);
	if (fake_ui)
	{
		g_assert_cmpuint(fake.shows, ==, 1);
		g_assert_cmpuint(fake.view.n_candidates, >, 0);
	}
	else
	{
		g_assert_cmpuint(g_list_model_get_n_items(gtk_window_get_toplevels()), ==, 1);
		window = g_list_model_get_item(gtk_window_get_toplevels(), 0);
		list = find_chooser_list(GTK_WIDGET(window));
		g_assert_nonnull(list);
		row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0);
		g_assert_nonnull(row);
	}
	/* The UI exposes IDs; obtain the corresponding fixture token from discovery. */
	{
		g_autoptr(GPtrArray) candidates = certificate_tokens_enumerate(fixture->tokens, NULL, &error);
		g_autoptr(GPtrArray) matching = NULL;
		CertificateFilter filter = { 0 };

		g_assert_no_error(error);
		g_assert_true(certificate_filter_parse(options, CERTIFICATE_PURPOSE_CLIENT_AUTH,
		                                       CERTIFICATE_OPERATION_SIGN, &filter, &error));
		g_assert_no_error(error);
		matching = certificate_filter_apply(candidates, &filter);
		certificate_filter_clear(&filter);
		g_assert_cmpuint(matching->len, >, 0);
		candidate = g_ptr_array_index(matching, 0);
		token = certificate_token_ref(candidate->token);
	}

	g_mutex_init(&gate.lock);
	g_cond_init(&gate.cond);
	certificate_tokens_set_enumerate_gate(hold_enumeration, &gate);
	certificate_tokens_emit_event(fixture->tokens, token, TRUE);
	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (!g_atomic_int_get(&gate.entered) && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);
	g_assert_true(g_atomic_int_get(&gate.entered));
	if (fake_ui)
	{
		if (outcome == DEFERRED_CANCEL)
			fake_chooser_provider_cancel(&fake);
		else
			fake_chooser_provider_choose(&fake, 0);
		g_assert_cmpuint(fake.closes, ==, 1);
	}
	else
	{
		gtk_list_box_select_row(GTK_LIST_BOX(list), row);
		g_signal_emit_by_name(list, "row-activated", row);
		g_assert_cmpuint(g_list_model_get_n_items(gtk_window_get_toplevels()), ==, 0);
	}
	g_assert_false(call.done);

	if (outcome == DEFERRED_CLOSE)
	{
		closed = call_sync(fixture->frontend, REQUEST_PATH, "org.freedesktop.impl.portal.Request",
		                   "Close", NULL, &error);
		g_assert_no_error(error);
		g_assert_nonnull(closed);
	}
	else if (outcome == DEFERRED_REMOVAL)
		certificate_tokens_emit_event(fixture->tokens, token, FALSE);
	g_assert_false(call.done);

	g_mutex_lock(&gate.lock);
	gate.released = TRUE;
	g_cond_broadcast(&gate.cond);
	g_mutex_unlock(&gate.lock);
	deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (!call.done && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, FALSE);
	g_assert_true(call.done);
	g_assert_no_error(call.error);
	g_variant_get(call.reply, "(u@a{sv})", &response, &results);
	g_variant_lookup(results, "error", "s", &code);
	if (outcome == DEFERRED_CLOSE || outcome == DEFERRED_CANCEL)
	{
		g_assert_cmpuint(response, ==, CERTIFICATE_RESPONSE_CANCELLED);
		g_assert_cmpuint(g_variant_n_children(results), ==, 0);
	}
	else if (outcome == DEFERRED_REMOVAL)
	{
		g_assert_cmpuint(response, ==, CERTIFICATE_RESPONSE_OTHER);
		g_assert_cmpstr(code, ==, "token_removed");
	}
	else
	{
		g_autoptr(GVariant) der = g_variant_lookup_value(results, "certificate_der",
		                                               G_VARIANT_TYPE("ay"));

		g_assert_cmpuint(response, ==, CERTIFICATE_RESPONSE_SUCCESS);
		g_assert_nonnull(der);
	}
	certificate_tokens_set_enumerate_gate(NULL, NULL);
	g_mutex_clear(&gate.lock);
	g_cond_clear(&gate.cond);
	g_variant_unref(call.reply);
	if (fake_ui)
	{
		fake_chooser_provider_clear(&fake);
		certificate_chooser_set_provider(certificate_chooser_provider_gtk());
	}
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	certificate_pin_set_provider(certificate_pin_provider_gtk());
	certificate_chooser_set_provider(certificate_chooser_provider_gtk());
	/* Keep toolkit settings and accessibility off the private service bus. */
	g_setenv("GTK_A11Y", "test", TRUE);
	g_setenv("ADW_DISABLE_PORTAL", "1", TRUE);
	g_setenv("GSETTINGS_BACKEND", "memory", TRUE);
	/* gvfs would hold a connection to the private bus past g_test_dbus_down(). */
	g_setenv("GIO_USE_VFS", "local", TRUE);
	/* GTestDBus forks a watcher; Mesa's exit handlers deadlock in a forked child. */
	g_setenv("GDK_DISABLE", "gl,egl,vulkan", TRUE);
	g_setenv("GSK_RENDERER", "cairo", TRUE);
	/* Initialize GTK before GTestDBus changes the session bus environment. */
	has_display = gtk_init_check();
	if (has_display)
		adw_init();

#define ADD(path, function) \
	g_test_add(path, Fixture, NULL, fixture_set_up, function, fixture_tear_down)

	ADD("/impl/stranger-is-refused", test_stranger_is_refused);
	ADD("/impl/session-close-is-authorised", test_session_close_is_authorised);
	ADD("/impl/request-close-is-authorised", test_request_close_is_authorised);
	ADD("/impl/session-is-bound-to-app-id", test_session_is_bound_to_app_id);
	ADD("/impl/identity-level-cannot-rise", test_identity_level_cannot_rise);
	ADD("/impl/session-path-is-reusable", test_session_path_is_reusable);
	ADD("/impl/options-are-validated", test_options_are_validated);
	ADD("/impl/results-types", test_results_types);
	ADD("/impl/sign-without-grant", test_sign_without_grant);
	ADD("/impl/capabilities", test_capabilities);
	ADD("/impl/replaced-frontend-is-refused", test_replaced_frontend_is_refused);
	ADD("/impl/close-mid-flight", test_close_mid_flight);
	ADD("/impl/frontend-vanishing-answers-pending-calls",
	    test_frontend_vanishing_answers_pending_calls);
	ADD("/impl/shutdown-reason-is-in-the-vocabulary", test_shutdown_reason_is_in_the_vocabulary);

	g_test_add("/impl/preconsent-forbidden", Fixture, GINT_TO_POINTER(TRUE),
	           fixture_set_up, test_preconsent_uniform, fixture_tear_down);
	g_test_add("/impl/preconsent-no-display", Fixture, GINT_TO_POINTER(FALSE),
	           fixture_set_up, test_preconsent_uniform, fixture_tear_down);
	ADD("/impl/capabilities-uniform", test_capabilities_uniform);
	g_test_add("/impl/deferred-consent-close", Fixture, GINT_TO_POINTER(DEFERRED_CLOSE),
	           fixture_set_up, test_deferred_consent, fixture_tear_down);
	g_test_add("/impl/deferred-consent-removal", Fixture, GINT_TO_POINTER(DEFERRED_REMOVAL),
	           fixture_set_up, test_deferred_consent, fixture_tear_down);
	g_test_add("/impl/deferred-consent-success", Fixture, GINT_TO_POINTER(DEFERRED_SUCCESS),
	           fixture_set_up, test_deferred_consent, fixture_tear_down);

	g_test_add("/impl/fake-deferred-consent-close", Fixture,
	           GINT_TO_POINTER(DEFERRED_FAKE_UI | DEFERRED_CLOSE),
	           fixture_set_up, test_deferred_consent, fixture_tear_down);
	g_test_add("/impl/fake-deferred-consent-removal", Fixture,
	           GINT_TO_POINTER(DEFERRED_FAKE_UI | DEFERRED_REMOVAL),
	           fixture_set_up, test_deferred_consent, fixture_tear_down);
	g_test_add("/impl/fake-deferred-consent-success", Fixture,
	           GINT_TO_POINTER(DEFERRED_FAKE_UI | DEFERRED_SUCCESS),
	           fixture_set_up, test_deferred_consent, fixture_tear_down);
	g_test_add("/impl/fake-cancel-during-refresh", Fixture,
	           GINT_TO_POINTER(DEFERRED_FAKE_UI | DEFERRED_CANCEL),
	           fixture_set_up, test_deferred_consent, fixture_tear_down);

#undef ADD

	return g_test_run();
}
