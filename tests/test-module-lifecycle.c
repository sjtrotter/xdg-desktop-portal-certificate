/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <gio/gio.h>
#include <p11-kit/p11-kit.h>

#include "module/constants.h"

#define WAIT_MS 5000

static struct
{
	GMutex lock;
	GCond cond;
	gboolean unwatch_entered;
	gboolean signals_queued;
	GWeakRef context_marker;
} lifecycle;

GMainLoop* __real_g_main_loop_new(GMainContext* context, gboolean running);
GMainLoop* __wrap_g_main_loop_new(GMainContext* context, gboolean running);
void __real_g_bus_unwatch_name(guint watcher_id);
void __wrap_g_bus_unwatch_name(guint watcher_id);

static gboolean marker_expired(gpointer data)
{
	g_assert_not_reached();

	return G_SOURCE_REMOVE;
}

GMainLoop* __wrap_g_main_loop_new(GMainContext* context, gboolean running)
{
	GObject* marker = g_object_new(G_TYPE_OBJECT, NULL);
	GSource* source = g_timeout_source_new_seconds(3600);

	/* The context owns the source and its marker; the test holds only a weak reference. */
	g_weak_ref_set(&lifecycle.context_marker, marker);
	g_source_set_callback(source, marker_expired, marker, g_object_unref);
	g_source_attach(source, context);
	g_source_unref(source);

	return __real_g_main_loop_new(context, running);
}

void __wrap_g_bus_unwatch_name(guint watcher_id)
{
	gint64 deadline = g_get_monotonic_time() + WAIT_MS * G_TIME_SPAN_MILLISECOND;

	/* Hold the private context while owner signals queue behind its teardown callback. */
	g_mutex_lock(&lifecycle.lock);
	lifecycle.unwatch_entered = TRUE;
	g_cond_broadcast(&lifecycle.cond);
	while (!lifecycle.signals_queued)
		g_assert_true(g_cond_wait_until(&lifecycle.cond, &lifecycle.lock, deadline));
	g_mutex_unlock(&lifecycle.lock);

	__real_g_bus_unwatch_name(watcher_id);
}

static guint32 name_call(GDBusConnection* connection, const char* method,
                         GVariant* parameters)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = g_dbus_connection_call_sync(
	    connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
	    method, parameters, G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, WAIT_MS, NULL, &error);
	guint32 result;

	g_assert_no_error(error);
	g_assert_nonnull(reply);
	g_variant_get(reply, "(u)", &result);

	return result;
}

static void assert_released(GWeakRef* reference, const char* name)
{
	gint64 deadline = g_get_monotonic_time() + WAIT_MS * G_TIME_SPAN_MILLISECOND;

	do
	{
		GObject* object = g_weak_ref_get(reference);

		if (object == NULL)
			return;
		g_object_unref(object);
		g_usleep(1000);
	} while (g_get_monotonic_time() < deadline);

	g_error("%s retained after C_Finalize", name);
}

static gpointer finalize_thread(gpointer data)
{
	CK_FUNCTION_LIST* functions = data;

	g_assert_cmpuint(functions->C_Finalize(NULL), ==, CKR_OK);

	return NULL;
}

static void test_finalize_drains_owner_signals(void)
{
	g_autoptr(GTestDBus) test_bus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_autoptr(GError) error = NULL;
	g_autoptr(GDBusConnection) frontend = NULL;
	g_autoptr(GDBusConnection) connection = NULL;
	g_autoptr(GVariant) barrier = NULL;
	CK_FUNCTION_LIST* functions;
	GThread* finalizer;
	GWeakRef connection_ref;
	gint64 deadline;

	g_mutex_init(&lifecycle.lock);
	g_cond_init(&lifecycle.cond);
	g_weak_ref_init(&lifecycle.context_marker, NULL);
	g_test_dbus_up(test_bus);
	frontend = g_dbus_connection_new_for_address_sync(
	    g_test_dbus_get_bus_address(test_bus),
	    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
	        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
	g_assert_no_error(error);
	g_assert_cmpuint(name_call(frontend, "RequestName",
	    g_variant_new("(su)", PKCS11_PORTAL_BUS_NAME, G_BUS_NAME_OWNER_FLAGS_DO_NOT_QUEUE)), ==, 1);
	connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	g_assert_no_error(error);
	g_weak_ref_init(&connection_ref, connection);

	g_assert_cmpuint(C_GetFunctionList(&functions), ==, CKR_OK);
	g_assert_cmpuint(functions->C_Initialize(NULL), ==, CKR_OK);
	{
		g_autoptr(GObject) marker = g_weak_ref_get(&lifecycle.context_marker);

		g_assert_nonnull(marker);
	}
	finalizer = g_thread_new("finalize", finalize_thread, functions);
	deadline = g_get_monotonic_time() + WAIT_MS * G_TIME_SPAN_MILLISECOND;
	g_mutex_lock(&lifecycle.lock);
	while (!lifecycle.unwatch_entered)
		g_assert_true(g_cond_wait_until(&lifecycle.cond, &lifecycle.lock, deadline));
	g_mutex_unlock(&lifecycle.lock);

	for (guint i = 0; i < 4; i++)
	{
		g_assert_cmpuint(name_call(frontend, "ReleaseName",
		    g_variant_new("(s)", PKCS11_PORTAL_BUS_NAME)), ==, 1);
		g_assert_cmpuint(name_call(frontend, "RequestName",
		    g_variant_new("(su)", PKCS11_PORTAL_BUS_NAME, G_BUS_NAME_OWNER_FLAGS_DO_NOT_QUEUE)), ==, 1);
	}
	/* The shared connection receives all preceding owner signals before this reply. */
	barrier = g_dbus_connection_call_sync(
	    connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
	    "GetId", NULL, G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, WAIT_MS, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(barrier);
	g_mutex_lock(&lifecycle.lock);
	lifecycle.signals_queued = TRUE;
	g_cond_broadcast(&lifecycle.cond);
	g_mutex_unlock(&lifecycle.lock);
	g_thread_join(finalizer);

	g_clear_object(&connection);
	assert_released(&lifecycle.context_marker, "Private context");
	assert_released(&connection_ref, "Shared connection");
	g_weak_ref_clear(&connection_ref);
	g_weak_ref_clear(&lifecycle.context_marker);
	g_assert_true(g_dbus_connection_close_sync(frontend, NULL, &error));
	g_assert_no_error(error);
	g_clear_object(&frontend);
	g_test_dbus_down(test_bus);
	g_cond_clear(&lifecycle.cond);
	g_mutex_clear(&lifecycle.lock);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/module/lifecycle/finalize-owner-signals", test_finalize_drains_owner_signals);

	return g_test_run();
}
