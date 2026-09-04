/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate - an out-of-tree xdg-desktop-portal BACKEND for
 * certificate-backed private keys.
 *
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * This would be the D-Bus activated per-user service that owns
 * org.freedesktop.impl.portal.desktop.certificate and implements
 * org.freedesktop.impl.portal.experimental.Certificate at
 * /org/freedesktop/portal/desktop -- the object path every portal backend
 * exports on. It is laid out like every other out-of-tree backend
 * (xdg-desktop-portal-gtk, xdg-desktop-portal-termfilechooser): src/ holds one
 * file per portal interface implemented, data/ holds the .portal file, the D-Bus
 * service file and the interface XML.
 *
 * IT IS NOT FOR APPLICATIONS. Only xdg-desktop-portal calls it, the app id
 * arrives as an ARGUMENT rather than being derived from the peer, and it must
 * never trust a caller directly. See docs/IMPL-INTERFACE.md.
 *
 * THE FRONTEND IS NOT IN THIS REPOSITORY. It is a branch of xdg-desktop-portal
 * itself, experimental/certificate-webauthentication, which exports
 * org.freedesktop.portal.experimental.Certificate only when
 * XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL contains "certificate". See
 * docs/decisions/0010-backend-only-frontend-lives-upstream.md.
 *
 * WHAT LIVES HERE: the chooser (src/ui/chooser.h), the PIN prompt (src/ui/pin.h),
 * token and certificate discovery (src/tokens/), the broker that holds the PKCS#11
 * session and performs Sign and Decrypt (src/broker/operations.h), and the
 * synthetic PKCS#11 facade (src/export/facade.h) -- which the branch's interface
 * does not yet have a method for, because OpenPkcs11Endpoint was deliberately
 * deferred there.
 *
 * Nothing is implemented: this is a design sketch, so every verb exits 70.
 */

#include <stdio.h>

#include <glib.h>

/* Process exit codes. Unchanged from the two-binary sketch that preceded this,
 * so a supervisor sees one scheme. They have nothing to do with the D-Bus
 * response codes 0, 1 and 2. */
#define CERTIFICATE_EXIT_SUCCESS 0
#define CERTIFICATE_EXIT_UNAVAILABLE 40 /* no session bus, no p11-kit, no reader, no display */
#define CERTIFICATE_EXIT_USAGE 64
#define CERTIFICATE_EXIT_INTERNAL 70

#define CERTIFICATE_VERSION "0.0.0"
#define CERTIFICATE_IMPL_BUS_NAME "org.freedesktop.impl.portal.desktop.certificate"
#define CERTIFICATE_IMPL_OBJECT_PATH "/org/freedesktop/portal/desktop"
#define CERTIFICATE_IMPL_INTERFACE "org.freedesktop.impl.portal.experimental.Certificate"
#define CERTIFICATE_PUBLIC_INTERFACE "org.freedesktop.portal.experimental.Certificate"

static void backend_usage(FILE* out)
{
	fprintf(out,
	        "xdg-desktop-portal-certificate - a backend for the experimental Certificate portal\n"
	        "\n"
	        "WHAT THIS IS\n"
	        "  An out-of-tree BACKEND of xdg-desktop-portal. It draws the certificate\n"
	        "  chooser and the PIN prompt, discovers PKCS#11 tokens, and performs private\n"
	        "  key operations on behalf of the portal. It is not a portal frontend, it\n"
	        "  owns no public interface, and no application talks to it.\n"
	        "\n"
	        "USAGE\n"
	        "  xdg-desktop-portal-certificate [options]\n"
	        "\n"
	        "  Normally started by D-Bus activation when xdg-desktop-portal selects this\n"
	        "  backend, not from a shell. It owns\n"
	        "    " CERTIFICATE_IMPL_BUS_NAME "\n"
	        "  on the session bus, exporting\n"
	        "    " CERTIFICATE_IMPL_OBJECT_PATH "\n"
	        "  and implementing\n"
	        "    " CERTIFICATE_IMPL_INTERFACE "\n"
	        "  as declared in data/certificate.portal.\n"
	        "\n"
	        "  ONLY xdg-desktop-portal CALLS THIS. The app id is an argument supplied by\n"
	        "  the portal; a caller that reached this bus name directly would be naming\n"
	        "  itself. Calls from anything but the portal are refused.\n"
	        "\n"
	        "ENABLING THE FRONTEND\n"
	        "  The public interface\n"
	        "    " CERTIFICATE_PUBLIC_INTERFACE "\n"
	        "  lives in xdg-desktop-portal itself, on the branch\n"
	        "    experimental/certificate-webauthentication\n"
	        "  and is EXPERIMENTAL: it is not exported unless the portal is started with\n"
	        "    XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate\n"
	        "  (\"all\" and a comma separated list also work). With the gate off, the\n"
	        "  interface is absent from introspection and this backend is never called.\n"
	        "  tools/dev-stack.sh wires a development frontend, this backend and a test\n"
	        "  call together on a private bus.\n"
	        "\n"
	        "OPTIONS\n"
	        "  --replace              take the name from a running instance\n"
	        "  --no-activate          do not request the bus name; run for inspection only\n"
	        "  --list-tokens          list PKCS#11 tokens visible to this user and exit\n"
	        "  --verbose              raise the log level on stderr\n"
	        "  --help, --version      print this, or the version, and exit\n"
	        "\n"
	        "EXIT CODES\n"
	        "   0 clean shutdown        40 unavailable (no bus, no p11-kit, no reader)\n"
	        "  64 usage                 70 internal / not implemented\n"
	        "\n"
	        "WHAT IT WOULD DO\n"
	        "  The portal calls AcquireCredential(handle, session_handle, app_id,\n"
	        "  parent_window, options). THIS SERVICE enumerates the tokens, filters the\n"
	        "  certificates, and shows a chooser naming the application the portal\n"
	        "  identified, HOW WELL it identified it (app_identity_level), the purpose in\n"
	        "  this service's own words, and the candidate certificates. It returns what\n"
	        "  was chosen. The portal then calls Sign; this service prompts for the PIN in\n"
	        "  its own window, logs into its OWN PKCS#11 session, and signs.\n"
	        "\n"
	        "  The PIN never leaves this process. The private key never leaves the token.\n"
	        "\n"
	        "STATUS\n"
	        "  EXPERIMENTAL DESIGN SKETCH. Nothing is implemented; every verb exits 70.\n"
	        "\n"
	        "  The PKCS#11 compatibility endpoint is NOT part of the interface above:\n"
	        "  OpenPkcs11Endpoint was deliberately left out of the frontend branch,\n"
	        "  because an fd-returning method needs its own review. src/export/facade.h\n"
	        "  describes what it would have to be. Separately, stock 'p11-kit server'\n"
	        "  exports a TOKEN, not an object, and does not carry login state across the\n"
	        "  forwarding boundary; see\n"
	        "  docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md.\n");
}

int main(int argc, char** argv)
{
	gboolean list_tokens = FALSE;

	for (int i = 1; i < argc; i++)
	{
		const char* arg = argv[i];

		if (g_strcmp0(arg, "--help") == 0 || g_strcmp0(arg, "-h") == 0)
		{
			backend_usage(stdout);
			return CERTIFICATE_EXIT_SUCCESS;
		}

		if (g_strcmp0(arg, "--version") == 0 || g_strcmp0(arg, "-V") == 0)
		{
			printf("xdg-desktop-portal-certificate " CERTIFICATE_VERSION
			       " (design sketch, not implemented; impl interface version 1, experimental)\n");
			return CERTIFICATE_EXIT_SUCCESS;
		}

		if (g_strcmp0(arg, "--list-tokens") == 0)
		{
			list_tokens = TRUE;
			continue;
		}

		if (g_strcmp0(arg, "--replace") == 0 || g_strcmp0(arg, "--no-activate") == 0 ||
		    g_strcmp0(arg, "--verbose") == 0)
			continue;

		fprintf(stderr, "xdg-desktop-portal-certificate: unknown option '%s'\n", arg);
		fprintf(stderr, "Try 'xdg-desktop-portal-certificate --help'.\n");
		return CERTIFICATE_EXIT_USAGE;
	}

	if (list_tokens)
	{
		/* This would drive src/tokens/discovery.h and print token DISPLAY identity
		 * only -- never object labels, key ids or serials, per src/redact.h. */
		fprintf(stderr,
		        "xdg-desktop-portal-certificate: --list-tokens: not implemented (design sketch)\n");
		return CERTIFICATE_EXIT_INTERNAL;
	}

	/* Everything past this point would connect to the session bus, claim the impl bus
	 * name, export src/certificate-impl.h's interface plus the impl Request and Session
	 * objects (src/request-impl.h, src/session-impl.h), start token discovery
	 * (src/tokens/discovery.h), and run a GTK main loop. None of that exists. */
	fprintf(stderr, "xdg-desktop-portal-certificate: not implemented (design sketch)\n");
	return CERTIFICATE_EXIT_INTERNAL;
}
