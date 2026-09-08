/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "portal.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "constants.h"

#define METHOD_TIMEOUT_MS 30000
#define CAPABILITIES_TIMEOUT_MS 5000
#define DEFAULT_REQUEST_TIMEOUT_MS 300000

/* How long portal_client_free() waits for outstanding method replies before it
 * cancels them, and again before it gives up on them. Two seconds is what the
 * backend gives its own workers at shutdown, for the same reason: the thing
 * being waited for is a message, not a person. */
#define DRAIN_GRACE_MS 2000

struct _PortalClient
{
	GDBusConnection* connection;
	GMainContext* context;
	GMainLoop* loop;
	GThread* thread;

	GStrv mechanisms;
	gboolean available;

	int request_timeout_ms;
	gint counter;

	/* Requests that have started and not yet completed, and the flag that
	 * refuses new ones. Both are touched on the client's thread only, like
	 * PortalRequest.completed and for the same reason. */
	GSList* live;
	gboolean cancelled;

	/* Method calls whose callback has not run yet, and the teardown that waits
	 * for them. Client's thread only, again. */
	guint calls;
	gboolean draining;
	GCancellable* call_cancellable;

	/* Written by the signal handler on the client's own thread, read by
	 * PKCS#11 callers. Its own lock, never the module's. */
	GMutex invalid_lock;
	GHashTable* invalidated;
	guint invalidated_subscription;
};

/* Reference counted, because the caller stops waiting as soon as the Response
 * arrives while the method call's own callback may still be outstanding on the
 * client's thread. Every source that can call back holds a reference. */
typedef struct
{
	gint references;

	PortalClient* client;
	const char* method;
	GVariant* parameters;
	/* Owned, because the method call's callback can outlive the caller that
	 * supplied the path, and closing a timed-out request needs it. */
	char* request_path;
	char* returned_path;
	char* closed_path;

	GMutex lock;
	GCond cond;
	gboolean done;
	gboolean completed;
	gboolean responded;
	gboolean sent;
	gboolean method_failed;

	guint32 response;
	GVariant* results;
	GError* error;

	guint subscription;
	guint timeout_id;
} PortalRequest;

static PortalRequest* request_ref(PortalRequest* request)
{
	g_atomic_int_inc(&request->references);

	return request;
}

static void request_unref(gpointer data)
{
	PortalRequest* request = data;

	if (!g_atomic_int_dec_and_test(&request->references))
		return;

	g_clear_pointer(&request->results, g_variant_unref);
	g_clear_error(&request->error);
	g_free(request->request_path);
	g_free(request->returned_path);
	g_free(request->closed_path);
	g_cond_clear(&request->cond);
	g_mutex_clear(&request->lock);
	g_free(request);
}

/* --------------------------------------------------------------- the thread */

static gpointer worker_thread(gpointer data)
{
	PortalClient* client = data;

	g_main_context_push_thread_default(client->context);
	g_main_loop_run(client->loop);
	g_main_context_pop_thread_default(client->context);

	return NULL;
}

static void schedule(PortalClient* client, GSourceFunc function, gpointer data)
{
	GSource* source = g_idle_source_new();

	g_source_set_priority(source, G_PRIORITY_DEFAULT);
	g_source_set_callback(source, function, data, NULL);
	g_source_attach(source, client->context);
	g_source_unref(source);
}

/* ------------------------------------------------------------ invalidation */

static void on_grant_invalidated(GDBusConnection* connection, const char* sender,
                                 const char* path, const char* interface, const char* signal,
                                 GVariant* parameters, gpointer user_data)
{
	PortalClient* client = user_data;
	const char* session = NULL;
	const char* reason = NULL;

	g_variant_get(parameters, "(&o&s)", &session, &reason);

	g_debug("grant invalidated: %s", reason);

	g_mutex_lock(&client->invalid_lock);
	g_hash_table_add(client->invalidated, g_strdup(session));
	g_mutex_unlock(&client->invalid_lock);
}

static gboolean subscribe_invalidated(gpointer data)
{
	PortalClient* client = data;

	client->invalidated_subscription = g_dbus_connection_signal_subscribe(
	    client->connection, PKCS11_PORTAL_BUS_NAME, PKCS11_PORTAL_INTERFACE, "GrantInvalidated",
	    PKCS11_PORTAL_EXPERIMENTAL_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
	    on_grant_invalidated, client, NULL);

	return G_SOURCE_REMOVE;
}

gboolean portal_client_grant_gone(PortalClient* client, const PortalGrant* grant)
{
	gboolean gone;

	if (client == NULL || grant == NULL || grant->session_handle == NULL)
		return TRUE;

	g_mutex_lock(&client->invalid_lock);
	gone = g_hash_table_contains(client->invalidated, grant->session_handle);
	g_mutex_unlock(&client->invalid_lock);

	return gone;
}

/* ------------------------------------------------------------- the requests */

/* Close(), sent with no reply expected because nothing here reads one -- and
 * because a pending reply is dispatched on the client's own context, which
 * C_Finalize stops: a Close that waited for an answer would be a Close that was
 * still outstanding when the process finished with the module. */
static void send_close(PortalClient* client, const char* path, const char* interface)
{
	g_autoptr(GDBusMessage) message =
	    g_dbus_message_new_method_call(PKCS11_PORTAL_BUS_NAME, path, interface, "Close");

	g_dbus_message_set_flags(message, G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED);
	g_dbus_connection_send_message(client->connection, message,
	                               G_DBUS_SEND_MESSAGE_FLAGS_NONE, NULL, NULL);
}

/* Request.Close on the portal's request object.
 *
 * A REQUEST THAT ENDS WITHOUT A RESPONSE IS STILL RUNNING AT THE PORTAL. The
 * timeout only stops this side waiting; the chooser or the PIN window it put up
 * stays on screen, and the grant it would produce is one nobody is waiting for.
 * The Response signal is the portal's own end of the request, so a request that
 * received one is already closed and is not closed again. */
static void request_close_at_portal(PortalRequest* request, const char* path)
{
	if (path == NULL || g_strcmp0(path, request->closed_path) == 0)
		return;

	g_free(request->closed_path);
	request->closed_path = g_strdup(path);

	send_close(request->client, path, PKCS11_PORTAL_REQUEST_INTERFACE);
}

/* Runs on the client's thread only, so `completed` needs no lock of its own. */
static void request_complete(PortalRequest* request)
{
	if (request->completed)
		return;
	request->completed = TRUE;
	request->client->live = g_slist_remove(request->client->live, request);

	if (request->sent && !request->responded && !request->method_failed)
	{
		/* The predicted path until the method has returned one: the portal
		 * exports the request object before it answers the call. */
		request_close_at_portal(request, request->returned_path != NULL
		                                     ? request->returned_path
		                                     : request->request_path);
	}

	if (request->timeout_id != 0)
	{
		GSource* source = g_main_context_find_source_by_id(request->client->context,
		                                                   request->timeout_id);

		if (source != NULL)
			g_source_destroy(source);
		request->timeout_id = 0;
	}

	if (request->subscription != 0)
	{
		g_dbus_connection_signal_unsubscribe(request->client->connection,
		                                     request->subscription);
		request->subscription = 0;
	}

	g_mutex_lock(&request->lock);
	request->done = TRUE;
	g_cond_signal(&request->cond);
	g_mutex_unlock(&request->lock);
}

static void on_response(GDBusConnection* connection, const char* sender, const char* path,
                        const char* interface, const char* signal, GVariant* parameters,
                        gpointer user_data)
{
	PortalRequest* request = user_data;

	if (request->completed)
		return;

	g_variant_get(parameters, "(u@a{sv})", &request->response, &request->results);
	request->responded = TRUE;
	request_complete(request);
}

static void subscribe_response(PortalRequest* request, const char* path)
{
	if (request->subscription != 0)
		g_dbus_connection_signal_unsubscribe(request->client->connection,
		                                     request->subscription);

	request->subscription = g_dbus_connection_signal_subscribe(
	    request->client->connection, PKCS11_PORTAL_BUS_NAME, PKCS11_PORTAL_REQUEST_INTERFACE,
	    "Response", path, NULL, G_DBUS_SIGNAL_FLAGS_NONE, on_response, request_ref(request),
	    request_unref);
}

static gboolean on_request_timeout(gpointer data)
{
	PortalRequest* request = data;

	request->timeout_id = 0;
	g_set_error(&request->error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_TIMEOUT,
	            "%s produced no Response in time", request->method);
	request_complete(request);

	return G_SOURCE_REMOVE;
}

/* The last outstanding callback stops the loop, so that a client being freed
 * does not drop the context a reply still in flight has to land on. */
static void call_finished(PortalClient* client)
{
	client->calls--;

	if (!client->draining || client->calls > 0)
		return;

	/* A Close this callback has just sent is still in the output queue. */
	g_dbus_connection_flush_sync(client->connection, NULL, NULL);
	g_main_loop_quit(client->loop);
}

static void on_method_returned(GObject* source, GAsyncResult* result, gpointer user_data)
{
	PortalRequest* request = user_data;
	PortalClient* client = request->client;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GError) error = NULL;
	const char* returned = NULL;

	reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);

	if (reply != NULL)
		g_variant_get(reply, "(&o)", &returned);

	if (request->completed)
	{
		/* THE REPLY LOST THE RACE with the timeout or with C_Finalize, and it
		 * names a request object at a path this side has never seen. Nothing
		 * else will ever close it, which is why the client is kept alive until
		 * this callback has run. */
		if (returned != NULL && !request->responded)
			request_close_at_portal(request, returned);
	}
	else if (reply == NULL)
	{
		/* The portal refused the call, so it has no request object at either
		 * path and there is nothing to close. A call THIS SIDE cancelled is
		 * different: the portal may have exported one before the cancellation
		 * reached it, so that one is still closed at the predicted path. */
		request->method_failed = !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
		request->error = g_steal_pointer(&error);
		request_complete(request);
	}
	else
	{
		g_free(request->returned_path);
		request->returned_path = g_strdup(returned);

		if (g_strcmp0(returned, request->request_path) != 0)
			subscribe_response(request, returned);
	}

	request_unref(request);
	call_finished(client);
}

static gboolean request_start(gpointer data)
{
	PortalRequest* request = data;
	GSource* source = NULL;

	if (request->client->cancelled)
	{
		g_variant_unref(g_variant_ref_sink(request->parameters));
		request->parameters = NULL;
		g_set_error(&request->error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_CANCELLED,
		            "%s was abandoned", request->method);
		request_complete(request);
		return G_SOURCE_REMOVE;
	}

	request->client->live = g_slist_prepend(request->client->live, request);
	request->sent = TRUE;

	subscribe_response(request, request->request_path);

	request->client->calls++;
	g_dbus_connection_call(request->client->connection, PKCS11_PORTAL_BUS_NAME,
	                       PKCS11_PORTAL_EXPERIMENTAL_OBJECT_PATH, PKCS11_PORTAL_INTERFACE,
	                       request->method,
	                       request->parameters, G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE,
	                       METHOD_TIMEOUT_MS, request->client->call_cancellable,
	                       on_method_returned, request_ref(request));

	source = g_timeout_source_new(request->client->request_timeout_ms);
	g_source_set_callback(source, on_request_timeout, request_ref(request), request_unref);
	request->timeout_id = g_source_attach(source, request->client->context);
	g_source_unref(source);

	return G_SOURCE_REMOVE;
}

/* Runs on the client's thread, so it can complete requests the same way the
 * response and the timeout do. */
static gboolean cancel_requests(gpointer data)
{
	PortalClient* client = data;

	client->cancelled = TRUE;

	while (client->live != NULL)
	{
		PortalRequest* request = client->live->data;

		if (request->error == NULL)
			g_set_error(&request->error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_CANCELLED,
			            "%s was abandoned", request->method);

		/* Drops it from the list, Closes it at the portal and wakes its
		 * caller, which may free it as soon as the lock inside is released. */
		request_complete(request);
	}

	return G_SOURCE_REMOVE;
}

void portal_client_cancel(PortalClient* client)
{
	if (client == NULL || client->thread == NULL)
		return;

	schedule(client, cancel_requests, client);
}

static char* request_token(PortalClient* client, const char* prefix)
{
	int counter = g_atomic_int_add(&client->counter, 1);

	return g_strdup_printf("%s%d_%d", prefix, (int) getpid(), counter);
}

static char* request_path_for(PortalClient* client, const char* token)
{
	const char* unique = g_dbus_connection_get_unique_name(client->connection);
	g_autofree char* sender = NULL;

	if (unique == NULL)
		return NULL;

	sender = g_strdup(unique[0] == ':' ? unique + 1 : unique);
	for (char* c = sender; *c != '\0'; c++)
	{
		if (*c == '.')
			*c = '_';
	}

	return g_strdup_printf("%s/request/%s/%s", PKCS11_PORTAL_OBJECT_PATH, sender, token);
}

/** Make one Request-shaped call and block until its single Response arrives.
 *  @parameters is consumed. */
static GVariant* portal_request(PortalClient* client, const char* method, GVariant* parameters,
                                const char* request_path, GError** error)
{
	PortalRequest* request = g_new0(PortalRequest, 1);
	GSource* source = g_idle_source_new();
	GVariant* results = NULL;

	request->references = 1;
	request->client = client;
	request->method = method;
	request->parameters = parameters;
	request->request_path = g_strdup(request_path);
	g_mutex_init(&request->lock);
	g_cond_init(&request->cond);

	g_source_set_callback(source, request_start, request_ref(request), request_unref);
	g_source_attach(source, client->context);
	g_source_unref(source);

	g_mutex_lock(&request->lock);
	while (!request->done)
		g_cond_wait(&request->cond, &request->lock);
	g_mutex_unlock(&request->lock);

	if (request->error != NULL)
	{
		g_propagate_error(error, g_steal_pointer(&request->error));
	}
	else if (request->response == 1)
	{
		g_set_error(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_CANCELLED,
		            "%s was cancelled", method);
	}
	else if (request->response != 0)
	{
		g_set_error(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED, "%s answered %u",
		            method, request->response);
	}
	else
	{
		results = g_steal_pointer(&request->results);
	}

	request_unref(request);

	return results;
}

/* ------------------------------------------------------------------ options */

static const char* chosen_purpose(void)
{
	static const char* const purposes[] = { "client_auth", "signing", "email", "ssh", NULL };
	const char* value = g_getenv(PKCS11_PORTAL_ENV_PURPOSE);

	if (value != NULL)
	{
		for (gsize i = 0; purposes[i] != NULL; i++)
		{
			if (strcmp(value, purposes[i]) == 0)
				return purposes[i];
		}

		g_message("ignoring an unknown %s", PKCS11_PORTAL_ENV_PURPOSE);
	}

	return PKCS11_PORTAL_DEFAULT_PURPOSE;
}

/* Application-supplied text, so it is bounded, valid UTF-8, and free of control
 * characters before it is handed to a window this module does not draw. */
static char* chosen_reason(void)
{
	const char* value = g_getenv(PKCS11_PORTAL_ENV_REASON);
	g_autofree char* truncated = NULL;
	GString* clean = NULL;

	if (value == NULL || *value == '\0')
		return NULL;

	if (!g_utf8_validate(value, -1, NULL))
		return NULL;

	truncated = g_utf8_substring(value, 0,
	                             MIN(g_utf8_strlen(value, -1), PKCS11_PORTAL_REASON_MAX));
	clean = g_string_new(NULL);

	for (const char* c = truncated; *c != '\0'; c = g_utf8_next_char(c))
	{
		gunichar character = g_utf8_get_char(c);

		g_string_append_unichar(clean, g_unichar_iscntrl(character) ? ' ' : character);
	}

	return g_string_free(clean, FALSE);
}

static void add_certificate_filter(GVariantBuilder* options)
{
	const char* value = g_getenv(PKCS11_PORTAL_ENV_KEY_ALGORITHMS);
	g_auto(GStrv) algorithms = NULL;
	GVariantBuilder filter;

	if (value == NULL || *value == '\0')
		return;

	algorithms = g_strsplit(value, ",", -1);

	g_variant_builder_init(&filter, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&filter, "{sv}", "key_algorithms",
	                      g_variant_new_strv((const char* const*) algorithms, -1));
	g_variant_builder_add(options, "{sv}", "certificate_filter",
	                      g_variant_builder_end(&filter));
}

/* SIGNING, WHICH IS THE WHOLE OF THE INTERFACE. The public interface has one
 * operation and one method to reach it with; a policy naming anything else is
 * refused by the frontend, so there is nothing here to select between. */
static void add_operation_policy(GVariantBuilder* options)
{
	GVariantBuilder policy;

	g_variant_builder_init(&policy, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&policy, "{sv}", "sign", g_variant_new_boolean(TRUE));
	g_variant_builder_add(options, "{sv}", "operation_policy", g_variant_builder_end(&policy));
}

/* ------------------------------------------------------------------- client */

/* THE TWO PROGRAMS THAT WOULD RECURSE, BY EXACT NAME. The frontend routes the
 * calls this module makes, and the certificate backend enumerates p11-kit's
 * modules to find tokens -- loading this one in either would make a search for a
 * token a call back into the searcher.
 *
 * THIS USED TO BE A PREFIX MATCH ON "xdg-desktop-portal", AND THAT WAS WRONG.
 * It refused in every process whose name merely began that way, which includes
 * xdg-desktop-portal-webauth -- the first consumer this module was written for,
 * and a process that enumerates nothing, owns no card and calls the portal
 * exactly as an application does. A portal BACKEND is not the portal; only these
 * two are, and only they recurse. The installed module file's `enable-in:` list
 * names neither of them, and PKCS11_PORTAL_CERTIFICATE_DISABLE=1 is the switch
 * for anything else that has to be kept out. */
static const char* const portal_excluded_programs[] = {
	"xdg-desktop-portal",
	"xdg-desktop-portal-certificate",
};

gboolean portal_program_is_excluded(const char* program)
{
	gsize i;

	if (program == NULL)
		return FALSE;

	for (i = 0; i < G_N_ELEMENTS(portal_excluded_programs); i++)
	{
		if (strcmp(program, portal_excluded_programs[i]) == 0)
			return TRUE;
	}

	return FALSE;
}


gboolean portal_client_self_excluded(void)
{
	g_autofree char* target = g_file_read_link("/proc/self/exe", NULL);
	g_autofree char* name = NULL;

	if (g_strcmp0(g_getenv(PKCS11_PORTAL_ENV_DISABLE), "1") == 0)
		return TRUE;

	if (target == NULL)
		return FALSE;

	name = g_path_get_basename(target);

	return portal_program_is_excluded(name);
}

static void probe_capabilities(PortalClient* client)
{
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GVariant) capabilities = NULL;
	g_autoptr(GError) error = NULL;
	GVariantBuilder empty;

	g_variant_builder_init(&empty, G_VARIANT_TYPE_VARDICT);

	reply = g_dbus_connection_call_sync(
	    client->connection, PKCS11_PORTAL_BUS_NAME, PKCS11_PORTAL_EXPERIMENTAL_OBJECT_PATH,
	    PKCS11_PORTAL_INTERFACE, "GetCapabilities",
	    g_variant_new("(a{sv})", &empty), G_VARIANT_TYPE("(a{sv})"),
	    G_DBUS_CALL_FLAGS_NO_AUTO_START, CAPABILITIES_TIMEOUT_MS, NULL, &error);

	if (reply == NULL)
	{
		/* THE MESSAGE, not just the fact. "not available" alone is what a
		 * consumer sees when the portal is absent, when no certificate backend
		 * is configured behind it, and when the frontend refuses to identify
		 * this process -- three different problems with three different fixes,
		 * and no way to tell them apart without the error. */
		g_debug("the Certificate portal is not available: %s", error->message);
		return;
	}

	capabilities = g_variant_get_child_value(reply, 0);
	g_variant_lookup(capabilities, "mechanisms", "^as", &client->mechanisms);

	if (client->mechanisms == NULL || client->mechanisms[0] == NULL)
	{
		g_debug("the Certificate portal advertises no mechanism");
		g_clear_pointer(&client->mechanisms, g_strfreev);
		return;
	}

	client->available = TRUE;
	g_debug("the Certificate portal offers %u mechanisms",
	        g_strv_length(client->mechanisms));
}

PortalClient* portal_client_new(void)
{
	PortalClient* client = g_new0(PortalClient, 1);
	g_autoptr(GError) error = NULL;
	const char* timeout = g_getenv(PKCS11_PORTAL_ENV_TIMEOUT);

	g_mutex_init(&client->invalid_lock);
	client->invalidated = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	client->request_timeout_ms = DEFAULT_REQUEST_TIMEOUT_MS;

	if (timeout != NULL)
	{
		int value = atoi(timeout);

		if (value > 0)
			client->request_timeout_ms = value;
	}

	client->connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (client->connection == NULL)
	{
		g_debug("no session bus");
		return client;
	}

	client->context = g_main_context_new();
	client->loop = g_main_loop_new(client->context, FALSE);
	client->call_cancellable = g_cancellable_new();
	client->thread = g_thread_new("portal-certificate", worker_thread, client);

	schedule(client, subscribe_invalidated, client);

	probe_capabilities(client);

	return client;
}

static gboolean drain_expired(gpointer data)
{
	PortalClient* client = data;

	if (!g_cancellable_is_cancelled(client->call_cancellable))
	{
		/* The portal has not answered. Cancelling fails the calls now instead
		 * of at METHOD_TIMEOUT_MS, and their callbacks end the loop. */
		g_cancellable_cancel(client->call_cancellable);
		return G_SOURCE_CONTINUE;
	}

	g_debug("a portal reply never arrived; the client is torn down without it");
	g_main_loop_quit(client->loop);

	return G_SOURCE_REMOVE;
}

/* THE LOOP STOPS WHEN THE LAST METHOD CALL HAS LANDED, not when the caller asks
 * for the client to be freed. A reply still in flight names a request object at
 * the portal -- at a path this side may never have seen, since the portal
 * chooses it -- and dropping the context here would leave that one open with
 * nothing left to Close it. The wait is bounded by DRAIN_GRACE_MS twice over.
 *
 * The thread is joined rather than detached: a PKCS#11 module can be dlclose()d
 * the moment C_Finalize returns, and a thread of ours still running then would
 * be running code that is no longer mapped. */
static gboolean begin_drain(gpointer data)
{
	PortalClient* client = data;
	GSource* source = NULL;

	client->cancelled = TRUE;
	client->draining = TRUE;

	if (client->calls == 0)
	{
		g_main_loop_quit(client->loop);
		return G_SOURCE_REMOVE;
	}

	source = g_timeout_source_new(DRAIN_GRACE_MS);
	g_source_set_callback(source, drain_expired, client, NULL);
	g_source_attach(source, client->context);
	g_source_unref(source);

	return G_SOURCE_REMOVE;
}

void portal_client_free(PortalClient* client)
{
	if (client == NULL)
		return;

	if (client->thread != NULL)
	{
		if (client->invalidated_subscription != 0)
			g_dbus_connection_signal_unsubscribe(client->connection,
			                                     client->invalidated_subscription);

		/* The last Close may still be queued, and this is the last chance it
		 * has to reach the bus. */
		g_dbus_connection_flush_sync(client->connection, NULL, NULL);

		schedule(client, begin_drain, client);
		g_thread_join(client->thread);
	}

	g_clear_pointer(&client->loop, g_main_loop_unref);
	g_clear_pointer(&client->context, g_main_context_unref);
	g_clear_object(&client->call_cancellable);
	g_clear_object(&client->connection);
	g_clear_pointer(&client->mechanisms, g_strfreev);
	g_clear_pointer(&client->invalidated, g_hash_table_unref);
	g_mutex_clear(&client->invalid_lock);
	g_free(client);
}

gboolean portal_client_available(PortalClient* client)
{
	return client != NULL && client->available;
}

const char* const* portal_client_mechanisms(PortalClient* client)
{
	return client != NULL ? (const char* const*) client->mechanisms : NULL;
}

/* ------------------------------------------------------------------ acquire */

/* Session.Close() on the session object, which is how a grant is released:
 * the interface has no method of its own for it. Releasing a grant that is
 * already gone is not an error worth reporting. */
static void close_session(PortalClient* client, const char* session)
{
	if (session == NULL)
		return;

	send_close(client, session, "org.freedesktop.portal.Session");
}

static char* create_session(PortalClient* client, GError** error)
{
	g_autofree char* handle_token = request_token(client, "pkcs11c");
	g_autofree char* session_token = request_token(client, "pkcs11s");
	g_autofree char* path = request_path_for(client, handle_token);
	g_autoptr(GVariant) results = NULL;
	GVariantBuilder options;
	char* session = NULL;

	if (path == NULL)
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_UNAVAILABLE,
		                    "The bus connection has no name");
		return NULL;
	}

	g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(handle_token));
	g_variant_builder_add(&options, "{sv}", "session_handle_token",
	                      g_variant_new_string(session_token));

	results = portal_request(client, "CreateSession", g_variant_new("(a{sv})", &options), path,
	                         error);
	if (results == NULL)
		return NULL;

	/* `o`, as the XML types it. The frontend used to send `s` here; the fix
	 * is xdg-desktop-portal a4c1f62 "certificate: Return session_handle as
	 * the object path it is typed as". */
	if (!g_variant_lookup(results, "session_handle", "o", &session))
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		                    "CreateSession returned no session handle");
		return NULL;
	}

	return session;
}

PortalGrant* portal_client_acquire(PortalClient* client, GError** error)
{
	g_autofree char* session = NULL;
	g_autofree char* handle_token = NULL;
	g_autofree char* path = NULL;
	g_autofree char* reason = NULL;
	g_autoptr(GVariant) results = NULL;
	g_autoptr(GVariant) certificate = NULL;
	g_autoptr(PortalGrant) grant = NULL;
	g_auto(GStrv) operations = NULL;
	const char* purpose = chosen_purpose();
	GVariantBuilder options;

	if (!portal_client_available(client))
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_UNAVAILABLE,
		                    "The Certificate portal is not available");
		return NULL;
	}

	session = create_session(client, error);
	if (session == NULL)
		return NULL;

	handle_token = request_token(client, "pkcs11a");
	path = request_path_for(client, handle_token);
	reason = chosen_reason();

	g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(handle_token));
	g_variant_builder_add(&options, "{sv}", "purpose", g_variant_new_string(purpose));
	if (reason != NULL)
		g_variant_builder_add(&options, "{sv}", "reason", g_variant_new_string(reason));
	add_operation_policy(&options);
	add_certificate_filter(&options);

	results = portal_request(client, "AcquireCredential",
	                         g_variant_new("(osa{sv})", session, "", &options), path, error);
	if (results == NULL)
	{
		close_session(client, session);
		return NULL;
	}

	grant = g_new0(PortalGrant, 1);
	grant->session_handle = g_steal_pointer(&session);

	certificate = g_variant_lookup_value(results, "certificate_der", G_VARIANT_TYPE("ay"));
	if (certificate == NULL)
	{
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		                    "AcquireCredential returned no certificate");
		portal_client_release(client, grant);
		return NULL;
	}
	grant->certificate_der = g_variant_get_data_as_bytes(certificate);

	g_variant_lookup(results, "key_type", "s", &grant->key_type);
	g_variant_lookup(results, "key_curve", "s", &grant->key_curve);
	g_variant_lookup(results, "key_size", "u", &grant->key_size);
	g_variant_lookup(results, "expires_at", "t", &grant->expires_at);
	g_variant_lookup(results, "supported_mechanisms", "^as", &grant->supported_mechanisms);

	if (g_variant_lookup(results, "permitted_operations", "^as", &operations))
	{
		grant->may_sign = g_strv_contains((const char* const*) operations, "sign");
		grant->may_decrypt = g_strv_contains((const char* const*) operations, "decrypt");
	}

	if (grant->key_type == NULL)
		grant->key_type = g_strdup("RSA");
	if (grant->supported_mechanisms == NULL)
		grant->supported_mechanisms = g_new0(char*, 1);

	/* THE HANDLE ITSELF IS NOT LOGGED. A session handle is the capability that
	 * holds the grant. */
	g_debug("grant acquired: %s %u bits, sign=%d", grant->key_type, grant->key_size,
	        grant->may_sign);

	return g_steal_pointer(&grant);
}

void portal_client_release(PortalClient* client, const PortalGrant* grant)
{
	if (client == NULL || client->connection == NULL || grant == NULL ||
	    grant->session_handle == NULL)
		return;

	close_session(client, grant->session_handle);
}

/* --------------------------------------------------------- sign and decrypt */

static gboolean operation(PortalClient* client, const PortalGrant* grant, const char* method,
                          const char* mechanism, GVariant* parameters, const char* data_key,
                          const guint8* data, gsize size, const char* result_key, GBytes** out,
                          GError** error)
{
	g_autofree char* handle_token = request_token(client, "pkcs11o");
	g_autofree char* path = request_path_for(client, handle_token);
	g_autoptr(GVariant) results = NULL;
	g_autoptr(GVariant) value = NULL;
	GVariantBuilder options;

	if (portal_client_grant_gone(client, grant))
	{
		g_variant_unref(g_variant_ref_sink(parameters));
		g_set_error_literal(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_INVALIDATED,
		                    "The grant is gone");
		return FALSE;
	}

	g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(handle_token));
	g_variant_builder_add(&options, "{sv}", "mechanism", g_variant_new_string(mechanism));
	g_variant_builder_add(&options, "{sv}", "parameters", parameters);
	g_variant_builder_add(&options, "{sv}", data_key,
	                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, size, 1));

	results = portal_request(client, method,
	                         g_variant_new("(osa{sv})", grant->session_handle, "", &options),
	                         path, error);
	if (results == NULL)
		return FALSE;

	value = g_variant_lookup_value(results, result_key, G_VARIANT_TYPE("ay"));
	if (value == NULL)
	{
		g_set_error(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_FAILED,
		            "%s returned no %s", method, result_key);
		return FALSE;
	}

	*out = g_variant_get_data_as_bytes(value);
	return TRUE;
}

gboolean portal_client_sign(PortalClient* client, const PortalGrant* grant,
                            const char* mechanism, const char* hash, const char* mgf,
                            gboolean have_salt_length, guint32 salt_length, const guint8* data,
                            gsize size, GBytes** signature, GError** error)
{
	GVariantBuilder parameters;

	g_variant_builder_init(&parameters, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&parameters, "{sv}", "hash", g_variant_new_string(hash));
	if (mgf != NULL)
		g_variant_builder_add(&parameters, "{sv}", "mgf", g_variant_new_string(mgf));
	if (have_salt_length)
		g_variant_builder_add(&parameters, "{sv}", "salt_length",
		                      g_variant_new_uint32(salt_length));

	return operation(client, grant, "Sign", mechanism, g_variant_builder_end(&parameters),
	                 "data", data, size, "signature", signature, error);
}

gboolean portal_client_decrypt(PortalClient* client, const PortalGrant* grant, const char* hash,
                               const char* mgf1_hash, GBytes* label, const guint8* data,
                               gsize size, GBytes** plaintext, GError** error)
{
	GVariantBuilder parameters;

	g_variant_builder_init(&parameters, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&parameters, "{sv}", "hash", g_variant_new_string(hash));
	if (mgf1_hash != NULL)
		g_variant_builder_add(&parameters, "{sv}", "mgf1_hash", g_variant_new_string(mgf1_hash));
	if (label != NULL)
	{
		gsize label_size = 0;
		const guint8* label_data = g_bytes_get_data(label, &label_size);

		g_variant_builder_add(&parameters, "{sv}", "label",
		                      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, label_data,
		                                                label_size, 1));
	}

	return operation(client, grant, "Decrypt", "RSA_OAEP",
	                 g_variant_builder_end(&parameters), "ciphertext", data, size, "plaintext",
	                 plaintext, error);
}
