/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * smartcard-portal-frontend - the portal FRONTEND for certificate-backed private keys.
 *
 * Copyright (C) 2026 the smartcard-portal authors
 *
 * This would be the D-Bus activated per-user service that owns
 * io.github.sjtrotter.portal.Desktop and exports
 * io.github.sjtrotter.portal.Smartcard1 -- our stand-in for
 * org.freedesktop.portal.Desktop, plumbed exactly as xdg-desktop-portal plumbs a
 * portal.
 *
 * IT DRAWS NOTHING AND TOUCHES NO HARDWARE. It resolves the caller's app id,
 * validates the purpose and the options, applies policy, permissions and rate
 * limits, owns the Request and Session objects and the grant registry, selects a
 * backend from the installed *.portal files, and forwards to that backend with the
 * app id attached. The chooser, the PIN prompt, the PKCS#11 session and the
 * signature all live in the backend (smartcard-portal-gtk).
 *
 * At upstreaming this binary DISAPPEARS: its portal becomes one more file in
 * xdg-desktop-portal, and applications call org.freedesktop.portal.Desktop instead.
 * See docs/UPSTREAMING.md.
 *
 * Nothing is implemented: this is a design sketch, so every verb exits 70.
 */

#include <stdio.h>

#include <glib.h>

/* Exit codes, chosen to match the backend and the sibling webauth-service so a
 * supervisor sees one scheme across all of them. */
#define SMARTCARD_EXIT_SUCCESS 0
#define SMARTCARD_EXIT_UNAVAILABLE 40 /* no session bus, or no backend implements the impl
                                         interface */
#define SMARTCARD_EXIT_USAGE 64
#define SMARTCARD_EXIT_INTERNAL 70

#define SMARTCARD_VERSION "0.0.0"
#define SMARTCARD_BUS_NAME "io.github.sjtrotter.portal.Desktop"
#define SMARTCARD_OBJECT_PATH "/io/github/sjtrotter/portal/desktop"
#define SMARTCARD_IMPL_INTERFACE "io.github.sjtrotter.impl.portal.Smartcard1"

static void frontend_usage(FILE* out)
{
	fprintf(out,
	        "smartcard-portal-frontend - portal frontend for certificate-backed private keys\n"
	        "\n"
	        "USAGE\n"
	        "  smartcard-portal-frontend [options]\n"
	        "\n"
	        "  Normally started by D-Bus activation, not from a shell. It owns\n"
	        "    " SMARTCARD_BUS_NAME "\n"
	        "  on the session bus, exporting\n"
	        "    " SMARTCARD_OBJECT_PATH "\n"
	        "  This is the ONLY name an application talks to.\n"
	        "\n"
	        "OPTIONS\n"
	        "  --replace              take the name from a running instance\n"
	        "  --no-activate          do not request the bus name; run for inspection only\n"
	        "  --list-backends        list installed *.portal files and which one would be\n"
	        "                         selected for " SMARTCARD_IMPL_INTERFACE ", then exit\n"
	        "  --verbose              raise the log level on stderr\n"
	        "  --help, --version      print this, or the version, and exit\n"
	        "\n"
	        "EXIT CODES\n"
	        "   0 clean shutdown        40 unavailable (no session bus, no backend)\n"
	        "  64 usage                 70 internal / not implemented\n"
	        "\n"
	        "WHAT IT WOULD DO\n"
	        "  An application calls AcquireCredential naming a purpose. THE FRONTEND\n"
	        "  resolves who is calling (Flatpak, Snap, host cgroup, or unidentified),\n"
	        "  validates the purpose and options, applies policy and rate limits, reads\n"
	        "  any remembered certificate SELECTION from the permission store, picks a\n"
	        "  backend from the *.portal files, and calls that backend with app_id\n"
	        "  attached. The backend shows the chooser and the PIN prompt and holds the\n"
	        "  token session; the frontend keeps the grant, its expiry and its ownership,\n"
	        "  and relays the results -- including the experimental PKCS#11 endpoint fd,\n"
	        "  which the backend creates and the frontend passes through.\n"
	        "\n"
	        "  The PIN never crosses D-Bus. The private key never leaves the token.\n"
	        "  The application never learns the backend's name.\n"
	        "\n"
	        "STATUS\n"
	        "  EXPERIMENTAL DESIGN SKETCH. Nothing is implemented; every verb exits 70.\n"
	        "  The interface has NOT been proposed to anyone and is expected to change,\n"
	        "  including its name. Do not depend on this.\n"
	        "\n"
	        "  The frontend/backend split is deliberate and early: it is the shape this\n"
	        "  would have inside xdg-desktop-portal, and building it now makes the\n"
	        "  eventual upstream patch a rename rather than a redesign. See\n"
	        "  docs/decisions/0008-build-to-the-upstream-shape.md and docs/UPSTREAMING.md.\n");
}

int main(int argc, char** argv)
{
	gboolean list_backends = FALSE;

	for (int i = 1; i < argc; i++)
	{
		const char* arg = argv[i];

		if (g_strcmp0(arg, "--help") == 0 || g_strcmp0(arg, "-h") == 0)
		{
			frontend_usage(stdout);
			return SMARTCARD_EXIT_SUCCESS;
		}

		if (g_strcmp0(arg, "--version") == 0 || g_strcmp0(arg, "-V") == 0)
		{
			printf("smartcard-portal-frontend " SMARTCARD_VERSION
			       " (design sketch, not implemented; interface version 1, experimental)\n");
			return SMARTCARD_EXIT_SUCCESS;
		}

		if (g_strcmp0(arg, "--list-backends") == 0)
		{
			list_backends = TRUE;
			continue;
		}

		if (g_strcmp0(arg, "--replace") == 0 || g_strcmp0(arg, "--no-activate") == 0 ||
		    g_strcmp0(arg, "--verbose") == 0)
			continue;

		fprintf(stderr, "smartcard-portal-frontend: unknown option '%s'\n", arg);
		fprintf(stderr, "Try 'smartcard-portal-frontend --help'.\n");
		return SMARTCARD_EXIT_USAGE;
	}

	if (list_backends)
	{
		/* This would drive src/portal-impl.h: scan the portal directories, read
		 * DBusName and Interfaces from each *.portal file, apply portals.conf, and
		 * print which backend would serve SMARTCARD_IMPL_INTERFACE. It prints
		 * configuration, never anything about a card. */
		fprintf(stderr,
		        "smartcard-portal-frontend: --list-backends: not implemented (design sketch)\n");
		return SMARTCARD_EXIT_INTERNAL;
	}

	/* Everything past this point would connect to the session bus, export
	 * src/smartcard.h's interface, load the backend configuration (src/portal-impl.h),
	 * connect to the permission store (src/permission-store.h), and run a main loop.
	 * None of that exists. */
	fprintf(stderr, "smartcard-portal-frontend: not implemented (design sketch)\n");
	return SMARTCARD_EXIT_INTERNAL;
}
