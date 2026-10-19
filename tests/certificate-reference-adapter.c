/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Test-only headless frontend to the real reference adapter. No UI or PIN entry.
 * Usage: SOFTHSM_MODULE=... SOFTHSM2_CONF=... certificate-reference-adapter BUS_ADDRESS
 * Prints its unique bus name once ready; SIGTERM drains the core before exit. */
#include <glib-unix.h>
#include <signal.h>
#include <stdio.h>

#include "certificate-impl.h"
#include "ui/chooser-provider.h"

static void choose_first(gpointer data, XccUiId id, const XccChooserView* view)
{
	const XccChooserCandidateView* row = xcc_chooser_view_candidate(view, 0);
	if (row != NULL)
		certificate_chooser_choose(id, view->revision, row->id);
	else
		certificate_chooser_cancel(id);
}

static void close_ui(gpointer data, XccUiId id)
{
}

static gboolean stop(gpointer data)
{
	g_main_loop_quit(data);
	return G_SOURCE_CONTINUE;
}

int main(int argc, char** argv)
{
	if (argc != 2 || g_getenv("SOFTHSM_MODULE") == NULL || g_getenv("SOFTHSM2_CONF") == NULL)
	{
		g_printerr("Supply a private bus address, SOFTHSM_MODULE and SOFTHSM2_CONF\n");
		return 2;
	}
	g_autoptr(GError) error = NULL;
	g_autoptr(GDBusConnection) connection = g_dbus_connection_new_for_address_sync(
	    argv[1], G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
	                 G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
	    NULL, NULL, &error);
	if (connection == NULL)
		g_error("private bus: %s", error->message);
	const char* modules[] = {g_getenv("SOFTHSM_MODULE"), NULL};
	g_autoptr(CertificateTokens) tokens = certificate_tokens_new(modules, &error);
	if (tokens == NULL)
		g_error("SoftHSM module: %s", error->message);
	certificate_tokens_set_allow_software(tokens, TRUE);
	CertificateChooserProvider chooser = {.name = "test-first-candidate",
	                                      .chooser_show = choose_first,
	                                      .chooser_update = choose_first,
	                                      .close = close_ui};
	certificate_chooser_set_provider(&chooser);
	CertificateImpl* impl = certificate_impl_new(connection, tokens, &error);
	if (impl == NULL)
		g_error("reference adapter: %s", error->message);
	g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);
	guint signal_id = g_unix_signal_add(SIGTERM, stop, loop);
	g_print("%s\n", g_dbus_connection_get_unique_name(connection));
	fflush(stdout);
	g_main_loop_run(loop);
	g_source_remove(signal_id);
	certificate_impl_free(impl);
	g_dbus_connection_close_sync(connection, NULL, NULL);
	return 0;
}
