/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * THE D-BUS BOUNDARY, on a private bus, with no card and no display.
 *
 * Everything in certificate-impl.c, request-impl.c and session-impl.c used to
 * have no automated coverage at all: the four unit tests linked the core
 * library and none of them linked the service. That is the layer where a
 * stranger calls Close(), where a session handle is or is not bound to an app
 * id, and where a malformed option is or is not treated as an absent one, so it
 * is the layer where the consequences are worst.
 *
 * The shape here is three connections to one GTestDBus bus:
 *
 *   the BACKEND    the object under test, exporting the impl interface
 *   the FRONTEND   owns org.freedesktop.portal.Desktop, so it may call
 *   a STRANGER     owns nothing, so it may not
 *
 * No display is needed: every path that would open a window answers no_display
 * first, and the paths under test end before that.
 */

#include <gio/gio.h>
#include <glib.h>
#include <string.h>

#include "certificate-impl.h"
#include "fixture-util.h"
#include "request-impl.h"
#include "session-impl.h"
#include "ui/pin.h"

#define FRONTEND_NAME "org.freedesktop.portal.Desktop"
#define IMPL_PATH "/org/freedesktop/portal/desktop"
#define IMPL_INTERFACE "org.freedesktop.impl.portal.experimental.Certificate"

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
} Fixture;

/* The backend owns no well-known name in this suite: it is addressed by the
 * unique name of the connection it was exported on. */
static const char* backend_name = NULL;

/* Deliberately NOT g_bus_get_sync(): a cached session-bus singleton outlives
 * one GTestDBus and is the classic way a suite like this hangs in teardown. */
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

	/* No windows, ever, in this suite. */
	certificate_ui_set_has_display(FALSE);

	fixture->bus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_up(fixture->bus);

	fixture->backend = open_connection(fixture->bus);
	fixture->frontend = open_connection(fixture->bus);
	fixture->stranger = open_connection(fixture->bus);
	backend_name = g_dbus_connection_get_unique_name(fixture->backend);

	/* ALLOW_REPLACEMENT from the start, so that the replacement test can take
	 * the name over WITHOUT the fixture first giving it up: unowning it fires
	 * NameOwnerChanged(... -> '') and destroys every session before the
	 * successor exists, which made the old version of that test assert
	 * something its own teardown had already produced. */
	fixture->owner_id =
	    g_bus_own_name_on_connection(fixture->frontend, FRONTEND_NAME,
	                                 G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT, on_name_acquired,
	                                 NULL, &acquired, NULL);

	while (!acquired)
		g_main_context_iteration(NULL, TRUE);

	/* A module list, so that discovery is deterministic: the SoftHSM fixture
	 * when there is one, and p11-kit's configured modules otherwise. Nothing in
	 * this suite depends on a token being present. */
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

	/* A test may have given the name up on purpose. */
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

/* The backend runs in this process, on the main context, so every call from a
 * test connection has to be made without blocking it. */
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
	    g_strdup_printf("{'purpose': <'client_auth'>, 'app_identity_level': <'derived_host'>%s%s}",
	                    extra != NULL ? ", " : "", extra != NULL ? extra : "");
	/* A FULL reference, which is what g_variant_parse() returns. Callers own
	 * it; acquire() consumes it, and anything passing it to g_variant_new()
	 * itself has to drop its own reference afterwards. */
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

/* TAKES OWNERSHIP of @options. g_variant_parse() hands back a FULL reference,
 * not a floating one, so g_variant_new("@a{sv}", ...) adds a second reference
 * rather than adopting it -- and every one of those was a leak the old
 * lsan.supp hid behind `leak:libglib-2.0`. */
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

/* ------------------------------------------------------------- the tests */

/* EVERY METHOD, from a peer that owns nothing. The documents say "only the
 * owner of org.freedesktop.portal.Desktop may call any method"; this is what
 * makes that sentence checkable. */
static void test_stranger_is_refused(Fixture* fixture, gconstpointer user_data)
{
	static const char* const interactive[] = { "AcquireCredential", "Sign", "Decrypt", NULL };

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

/* Session.Close() from a stranger used to log the card out and destroy every
 * grant on the machine. */
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

/* Request.Close() from a stranger used to cancel consent dialogs and PIN
 * prompts as they appeared. The Request is exported by hand here because a
 * request object only exists while a call is in flight, and a test that raced a
 * real one would be a test that passed by luck. */
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

/* A session handle is not a bearer token for whatever app id the caller feels
 * like naming. */
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

/* The identity level may fall and must never rise. */
static void test_identity_level_cannot_rise(Fixture* fixture, gconstpointer user_data)
{
	guint32 response = 0;
	g_autofree char* code = NULL;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	/* First call: unidentified. It gets as far as discovery and fails there,
	 * with no display and (usually) no matching certificate -- either way it
	 * has recorded the level. */
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
		    "{'purpose': <'client_auth'>, 'app_identity_level': <'verified_sandboxed'>}", NULL,
		    NULL, NULL);

		acquire(fixture, SESSION_PATH, APP_A, g_steal_pointer(&options), &response, &code);
		g_assert_cmpuint(response, ==, 2);
		g_assert_cmpstr(code, ==, "no_such_session");
	}
}

/* Applications pass a fixed session_handle_token, so the frontend hands this
 * backend the same object path every time. A closed entry left in the table
 * made every later CreateSession from that application fail for the life of the
 * process. */
static void test_session_path_is_reusable(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	/* A LIVE session at that path is still refused. */
	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 2);

	reply = call_sync(fixture->frontend, SESSION_PATH, "org.freedesktop.impl.portal.Session",
	                  "Close", NULL, &error);
	g_assert_no_error(error);

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);
}

/* Present with the wrong type, or with a value nobody recognised, is refused.
 * It used to be treated as absent, which is how a filter stops filtering and an
 * unknown interaction_mode becomes "prompting is allowed". */
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
		{ "{'purpose': <'client_auth'>, 'allow_selection_memory': <'yes'>}", "invalid_request" },
		{ "{'purpose': <'client_auth'>, 'allow_selection_memory': <uint32 1>}",
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

/* allow_selection_memory decides whether the chooser draws the "remember this"
 * checkbox at all, so the two values that mean "do not offer it" -- absent and
 * explicit false -- must both be accepted and must not be confused with a
 * malformed request. The wrong-type cases are in test_options_are_validated;
 * these are the ones that have to get PAST validation.
 *
 * What this cannot check from out here is the checkbox itself: with no token
 * in the machine the request never reaches the chooser. The window is covered
 * by tools/ui-smoke.sh. */
static void test_selection_memory_is_accepted(Fixture* fixture, gconstpointer user_data)
{
	static const char* const cases[] = {
		"{'purpose': <'client_auth'>}",
		"{'purpose': <'client_auth'>, 'allow_selection_memory': <false>}",
		"{'purpose': <'client_auth'>, 'allow_selection_memory': <true>}",
	};

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		guint32 response = 0;
		g_autofree char* code = NULL;
		GVariant* options = g_variant_parse(G_VARIANT_TYPE_VARDICT, cases[i], NULL, NULL, NULL);

		g_assert_nonnull(options);
		acquire(fixture, SESSION_PATH, APP_A, options, &response, &code);

		/* No card, so the answer is a refusal either way. It must not be the
		 * one that means "this request was malformed". */
		if (g_strcmp0(code, "invalid_request") == 0)
			g_error("options %s were rejected as malformed", cases[i]);
	}
}

/* THE FRONTEND TYPE-CHECKS ONE KEY. `signature` and `plaintext` are the only
 * results it looks at; everything else is passed through with type == NULL, so
 * a wrong type here reaches applications and a missing key turns into a grant
 * that can never sign. */
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
		{ "certificate_der", "ay", TRUE },       { "chain_der", "aay", TRUE },
		{ "chain_status", "s", TRUE },           { "token_display", "a{sv}", TRUE },
		{ "key_type", "s", TRUE },               { "key_size", "u", TRUE },
		{ "key_curve", "s", FALSE },             { "supported_mechanisms", "as", TRUE },
		{ "permitted_operations", "as", TRUE },  { "may_prompt_later", "b", TRUE },
		{ "certificate_id", "s", TRUE },         { "remember_selection", "b", TRUE },
	};

	results = g_variant_ref_sink(certificate_impl_acquire_results(candidate, TRUE, TRUE, TRUE));

	for (gsize i = 0; i < G_N_ELEMENTS(expected); i++)
	{
		g_autoptr(GVariant) value =
		    g_variant_lookup_value(results, expected[i].key, G_VARIANT_TYPE(expected[i].type));

		if (value == NULL && expected[i].required)
			g_error("results has no %s of type %s", expected[i].key, expected[i].type);
	}

	/* A usable grant reports at least one operation and one mechanism: the
	 * frontend intersects both, and an empty list there is a grant that
	 * succeeds and can do nothing. */
	{
		g_autoptr(GVariant) operations =
		    g_variant_lookup_value(results, "permitted_operations", G_VARIANT_TYPE_STRING_ARRAY);
		g_autoptr(GVariant) mechanisms =
		    g_variant_lookup_value(results, "supported_mechanisms", G_VARIANT_TYPE_STRING_ARRAY);

		g_assert_cmpuint(g_variant_n_children(operations), >, 0);
		g_assert_cmpuint(g_variant_n_children(mechanisms), >, 0);
	}

	/* AND NO SERIAL, EVER. */
	{
		g_autoptr(GVariant) display =
		    g_variant_lookup_value(results, "token_display", G_VARIANT_TYPE_VARDICT);
		g_autoptr(GVariant) serial = g_variant_lookup_value(display, "serial", NULL);

		g_assert_null(serial);
	}
}

/* THE BROADCAST SIGNALS SAY A TOKEN IS THERE AND NOTHING ELSE. The frontend
 * re-emits TokenAdded/TokenRemoved to every client on the session bus, before
 * anyone has consented to anything, and a PIV card's label is routinely the
 * cardholder's name. The interface names two keys; this asserts there are two
 * keys, that the id is not the serial or the label or anything derived from
 * them by a rule somebody else could apply, and that it is stable. */
static void test_token_presence_carries_no_identity(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_autoptr(GVariant) presence = NULL;
	g_autoptr(GVariant) again = NULL;
	const char* token_id = NULL;
	const char* second = NULL;
	gboolean protected_path = TRUE;

	presence = g_variant_ref_sink(certificate_impl_token_presence(candidate->token));

	g_assert_cmpuint(g_variant_n_children(presence), ==, 2);
	g_assert_true(g_variant_lookup(presence, "token_id", "&s", &token_id));
	g_assert_true(g_variant_lookup(presence, "protected_authentication_path", "b",
	                               &protected_path));
	g_assert_false(protected_path);

	/* Not the serial, not the label, and not a substring of either: the point
	 * of the id is that a second party cannot recompute it. */
	g_assert_cmpstr(token_id, !=, candidate->token->serial);
	g_assert_cmpstr(token_id, !=, candidate->token->label);
	g_assert_null(strstr(token_id, candidate->token->serial));

	/* Stable for as long as the token is present, which is what pairs an
	 * added token with its removal. */
	again = g_variant_ref_sink(certificate_impl_token_presence(candidate->token));
	g_assert_true(g_variant_lookup(again, "token_id", "&s", &second));
	g_assert_cmpstr(token_id, ==, second);
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

/* THE REASON IS AN INTERFACE VALUE, NOT A WORD THIS BACKEND CHOSE. The frontend
 * forwards it verbatim into GrantInvalidated, so an invented value reaches
 * applications with a documented list that says it cannot happen. Shutting the
 * backend down is the one reason a test can produce without hardware, and the
 * spelling used to be "backend_shutdown", which is in neither vocabulary. */
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

	g_assert_cmpstr(watch.reason, ==, "service_shutdown");
	g_free(watch.reason);
}

/* Sign on a session that never acquired anything is refused, and a Close() in
 * flight is answered as a cancellation rather than a device failure. */
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

	/* NOT g_steal_pointer(): the reference is full, so g_variant_new() takes
	 * one of its own and this one still has to be dropped. */
	reply = impl_call(fixture->frontend, "Sign",
	                  g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "", options),
	                  &error);
	g_assert_no_error(error);
	g_variant_get(reply, "(u@a{sv})", &response, &results);
	g_assert_cmpuint(response, ==, 2);
}

/* v1.5 IS REFUSED BEFORE THE CARD IS TOUCHED, and so is every other signing
 * mechanism, and so is a malformed OAEP request. RSA_OAEP is the only thing
 * Decrypt will look at, and a well-formed OAEP request on a session with no
 * grant is refused for that reason instead -- which is the point: the two are
 * different refusals, and neither reaches the token. */
static void test_decrypt_takes_oaep_only(Fixture* fixture, gconstpointer user_data)
{
	static const char* const refused[] = {
		"{'mechanism': <'RSA_PKCS1_V1_5'>, 'parameters': <{'hash': <'SHA256'>}>, "
		"'ciphertext': <b'0123456789abcdef'>}",
		"{'mechanism': <'RSA_PSS'>, 'parameters': <{'hash': <'SHA256'>}>, "
		"'ciphertext': <b'0123456789abcdef'>}",
		"{'mechanism': <'ECDSA'>, 'parameters': <{'hash': <'SHA256'>}>, "
		"'ciphertext': <b'0123456789abcdef'>}",
		/* OAEP with parameters this backend refuses to forward. */
		"{'mechanism': <'RSA_OAEP'>, 'ciphertext': <b'0123456789abcdef'>}",
		"{'mechanism': <'RSA_OAEP'>, 'parameters': <{'hash': <'SHA3-256'>}>, "
		"'ciphertext': <b'0123456789abcdef'>}",
		"{'mechanism': <'RSA_OAEP'>, 'parameters': <{'hash': <'SHA256'>, "
		"'mgf1_hash': <'SHA1'>}>, 'ciphertext': <b'0123456789abcdef'>}",
		/* A well-formed OAEP request. Refused too, because this session holds
		 * no grant -- but by the grant check, not the mechanism one. */
		"{'mechanism': <'RSA_OAEP'>, 'parameters': <{'hash': <'SHA256'>}>, "
		"'ciphertext': <b'0123456789abcdef'>}",
		NULL,
	};

	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	for (gsize i = 0; refused[i] != NULL; i++)
	{
		g_autoptr(GError) error = NULL;
		g_autoptr(GVariant) reply = NULL;
		g_autoptr(GVariant) results = NULL;
		g_autoptr(GVariant) options =
		    g_variant_parse(G_VARIANT_TYPE_VARDICT, refused[i], NULL, NULL, NULL);
		guint32 response = 0;

		g_assert_nonnull(options);

		reply = impl_call(fixture->frontend, "Decrypt",
		                  g_variant_new("(ooss@a{sv})", REQUEST_PATH, SESSION_PATH, APP_A, "",
		                                options),
		                  &error);
		g_assert_no_error(error);
		g_variant_get(reply, "(u@a{sv})", &response, &results);

		if (response != 2)
			g_error("Decrypt options %s answered %u, expected 2", refused[i], response);
	}
}

/* GetCapabilities advertises what this backend implements, and it must answer
 * while the main loop is free -- it runs the PKCS#11 calls on a worker, and
 * this test is what proves it still answers at all. Decrypt is now among them,
 * with RSA_OAEP in `mechanisms` as the only thing it will decrypt with; the
 * pairing is what an application reads to decide whether to ask. */
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
	g_assert_true(g_strv_contains((const char* const*) operations, "decrypt"));

	{
		g_auto(GStrv) mechanisms = NULL;

		g_assert_true(g_variant_lookup(capabilities, "mechanisms", "^as", &mechanisms));
		g_assert_true(g_strv_contains((const char* const*) mechanisms, "RSA_OAEP"));
	}
}

/* A round trip that does not involve the backend, made SYNCHRONOUSLY on
 * @connection. GDBus services its own I/O on a worker thread, so this returns
 * without the caller's main context turning even once -- which is the whole
 * trick below. Because the bus daemon processes one connection's messages in
 * order, its answer to this proves it has already routed everything that
 * connection sent before it. */
static void bus_round_trip(GDBusConnection* connection)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = g_dbus_connection_call_sync(
	    connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
	    "GetId", NULL, G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);

	g_assert_no_error(error);
	g_assert_nonnull(reply);
}

/* THE NAME CHANGES HANDS WHILE THE OLD OWNER'S CALL IS ALREADY IN THE
 * BACKEND'S QUEUE, which is the race a cached owner cannot see: D-Bus does not
 * order NameOwnerChanged against the messages of the process that lost the
 * name, so by the time the backend reads the call, the cache still names the
 * sender as the frontend and the bus no longer does.
 *
 * It is reproduced rather than hoped for. Nothing here turns the backend's main
 * loop until the very end:
 *
 *   1. the old owner's CreateSession is SENT (async, no loop iteration);
 *   2. a round trip on the same connection proves the daemon has routed it;
 *   3. the successor takes the name with a synchronous RequestName;
 *   4. only now does the loop turn -- and the backend dispatches the
 *      CreateSession first, from a cache that still says the sender is the
 *      frontend.
 *
 * A positive answer is never served from that cache, so it is refused. */
static void test_replaced_frontend_is_refused(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GDBusConnection) successor = open_connection(fixture->bus);
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GVariant) results = NULL;
	Call call = { NULL, NULL, FALSE };
	guint32 response = 0;

	/* The original owner works, and its session exists. */
	g_assert_cmpuint(create_session(fixture, SESSION_PATH, APP_A), ==, 0);

	/* (1) sent, not answered: nothing iterates the main context here. */
	g_dbus_connection_call(fixture->frontend, backend_name, IMPL_PATH, IMPL_INTERFACE,
	                       "CreateSession",
	                       g_variant_new("(oos@a{sv})", REQUEST_PATH,
	                                     "/org/freedesktop/portal/desktop/session/test/two", APP_A,
	                                     empty_options()),
	                       NULL, G_DBUS_CALL_FLAGS_NONE, 5000, NULL, on_call_done, &call);

	/* (2) the daemon has now routed it to the backend. */
	bus_round_trip(fixture->frontend);

	/* (3) the name moves. RequestName by hand rather than g_bus_own_name(),
	 * which would need the main loop to deliver its callback. */
	{
		g_autoptr(GError) request_error = NULL;
		g_autoptr(GVariant) request = g_dbus_connection_call_sync(
		    successor, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
		    "RequestName",
		    g_variant_new("(su)", FRONTEND_NAME, (guint32) 2 /* REPLACE_EXISTING */),
		    G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &request_error);
		guint32 result = 0;

		g_assert_no_error(request_error);
		g_variant_get(request, "(u)", &result);
		/* 1 = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER */
		g_assert_cmpuint(result, ==, 1);
	}

	/* (4) and only now does the backend get to run. */
	while (!call.done)
		g_main_context_iteration(NULL, TRUE);

	g_assert_null(call.reply);
	g_assert_error(call.error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	g_clear_error(&call.error);

	/* The successor is the frontend now. */
	reply = impl_call(successor, "GetCapabilities",
	                  g_variant_new("(s@a{sv})", APP_A, empty_options()), &error);
	g_assert_no_error(error);
	g_assert_nonnull(reply);

	/* AND THE OLD OWNER'S GRANT WENT WITH THE NAME. Nothing in this test gave
	 * the name up, so this is the replacement doing it and not a teardown: a
	 * successor portal is a different process with different callers and must
	 * not inherit a session it never created. */
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

	/* And the old owner is still refused now that the change has been seen. */
	reply = impl_call(fixture->frontend, "GetCapabilities",
	                  g_variant_new("(s@a{sv})", APP_A, empty_options()), &error);
	g_assert_null(reply);
	g_assert_error(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED);
	g_clear_error(&error);

	(void) response;
	(void) results;
}

/* THE FRONTEND GOES AWAY WHILE A CALL IS IN FLIGHT. Every window this backend
 * has up belongs to a request the frontend made; if the frontend is gone, the
 * request has no caller and a trusted window asking the user to consent on its
 * behalf is the worst thing this process could leave on screen. The pending
 * call is answered -- with owner_gone, which is NOT response 1: an application
 * told "cancelled" is entitled to read that as "the user said no". */
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

	/* One turn, so the handler has run, exported the Request and put discovery
	 * on its worker. */
	g_main_context_iteration(NULL, TRUE);

	/* The name goes. The connection stays open, so the reply can still be
	 * delivered and this test can read it. */
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

/* Request.Close() while the call is genuinely in flight. What is asserted is
 * the invariant, not the timing: the pending AcquireCredential is answered
 * exactly once, and never with success. */
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

	/* One turn of the loop, so the method handler has run and exported the
	 * Request, and discovery is on its worker. */
	g_main_context_iteration(NULL, TRUE);

	closed = call_sync(fixture->frontend, REQUEST_PATH, "org.freedesktop.impl.portal.Request",
	                   "Close", NULL, &error);
	/* Either the Request was still exported and answered, or discovery had
	 * already finished and taken it down. Never AccessDenied. */
	if (error != NULL)
		g_assert_false(g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED));

	while (!call.done)
		g_main_context_iteration(NULL, TRUE);

	g_assert_no_error(call.error);
	g_variant_get(call.reply, "(u@a{sv})", &response, &results);

	/* A CONTROL, not just "not success". If the Close() went through, the
	 * request WAS still in flight and the only correct answer is 1: response 2
	 * is what an ordinary no_display refusal returns, so asserting != 0 would
	 * pass with the cancellation path deleted. When Close() came back an error
	 * the request had already answered itself, and there is nothing to
	 * assert. */
	if (error == NULL)
		g_assert_cmpuint(response, ==, 1);
	else
		g_assert_cmpuint(response, !=, 0);

	g_clear_error(&error);
	g_variant_unref(call.reply);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

#define ADD(path, function) \
	g_test_add(path, Fixture, NULL, fixture_set_up, function, fixture_tear_down)

	ADD("/impl/stranger-is-refused", test_stranger_is_refused);
	ADD("/impl/session-close-is-authorised", test_session_close_is_authorised);
	ADD("/impl/request-close-is-authorised", test_request_close_is_authorised);
	ADD("/impl/session-is-bound-to-app-id", test_session_is_bound_to_app_id);
	ADD("/impl/identity-level-cannot-rise", test_identity_level_cannot_rise);
	ADD("/impl/session-path-is-reusable", test_session_path_is_reusable);
	ADD("/impl/options-are-validated", test_options_are_validated);
	ADD("/impl/selection-memory-is-accepted", test_selection_memory_is_accepted);
	ADD("/impl/results-types", test_results_types);
	ADD("/impl/token-presence-carries-no-identity", test_token_presence_carries_no_identity);
	ADD("/impl/sign-without-grant", test_sign_without_grant);
	ADD("/impl/decrypt-takes-oaep-only", test_decrypt_takes_oaep_only);
	ADD("/impl/capabilities", test_capabilities);
	ADD("/impl/replaced-frontend-is-refused", test_replaced_frontend_is_refused);
	ADD("/impl/close-mid-flight", test_close_mid_flight);
	ADD("/impl/frontend-vanishing-answers-pending-calls",
	    test_frontend_vanishing_answers_pending_calls);
	ADD("/impl/shutdown-reason-is-in-the-vocabulary", test_shutdown_reason_is_in_the_vocabulary);

#undef ADD

	return g_test_run();
}
