/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * A SYSTEM PROMPTER FOR tools/ui-smoke.sh, and for nothing else.
 *
 * tests/test-pin-system.c drives the same code in-process. The UI smoke run
 * cannot: the backend there is a separate process on a private bus, so the
 * prompter has to be one too. This is main() around tests/pin-prompter.c.
 *
 * IT REFUSES TO RUN WHERE A REAL PROMPTER IS. If anything already owns
 * org.gnome.keyring.SystemPrompter on the bus it was pointed at, this exits
 * rather than competing for the name: the one thing that must never happen is
 * a test fixture standing between a user and a password request.
 */

#include <stdio.h>

#include <gio/gio.h>

#include "pin-prompter.h"

#define PROMPTER_NAME "org.gnome.keyring.SystemPrompter"

int main(int argc, char** argv)
{
	g_autoptr(GDBusConnection) connection = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GMainLoop) loop = NULL;
	CertificateTestPrompter* prompter = NULL;
	const char* pin = g_getenv("TEST_PROMPTER_PIN");
	gboolean has_owner = TRUE;

	if (pin == NULL)
	{
		g_printerr("%s: TEST_PROMPTER_PIN is not set.\n", argv[0]);
		g_printerr("It goes through the environment rather than argv because "
		           "/proc/*/cmdline is world readable.\n");
		return 64;
	}

	connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (connection == NULL)
	{
		g_printerr("%s: no session bus: %s\n", argv[0], error->message);
		return 40;
	}

	reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                                    "org.freedesktop.DBus", "NameHasOwner",
	                                    g_variant_new("(s)", PROMPTER_NAME), G_VARIANT_TYPE("(b)"),
	                                    G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);
	if (reply == NULL)
	{
		g_printerr("%s: could not ask the bus about %s: %s\n", argv[0], PROMPTER_NAME,
		           error->message);
		return 40;
	}

	g_variant_get(reply, "(b)", &has_owner);
	if (has_owner)
	{
		g_printerr("%s: %s already has an owner on this bus.\n", argv[0], PROMPTER_NAME);
		g_printerr("That is a real prompter, and this fixture will not compete with it. "
		           "Run it on a private bus.\n");
		return 40;
	}

	certificate_test_prompter_set_default_password(pin);
	prompter = certificate_test_prompter_start(connection, PROMPTER_NAME);

	/* The line tools/ui-smoke.sh waits for, flushed so that it is not sitting
	 * in a pipe buffer while the backend asks the bus whether a prompter is
	 * there. */
	g_print("test-prompter: serving %s\n", PROMPTER_NAME);
	fflush(stdout);

	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);

	certificate_test_prompter_stop(prompter);
	return 0;
}
