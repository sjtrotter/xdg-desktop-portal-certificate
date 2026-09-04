/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * certificate-portal-gtk - the reference portal BACKEND for certificate-backed keys.
 *
 * Copyright (C) 2026 the smartcard-portal authors
 *
 * This would be the D-Bus activated per-user service that owns
 * io.github.sjtrotter.impl.portal.Certificate.gtk and implements
 * io.github.sjtrotter.impl.portal.Certificate1 at /io/github/sjtrotter/portal/Certificate --
 * laid out exactly like xdg-desktop-portal-gtk, which registers
 * org.freedesktop.impl.portal.desktop.gtk, ships a data/gtk.portal describing which
 * impl interfaces it implements, and puts one file per portal in src/.
 *
 * IT IS NOT FOR APPLICATIONS. Only the frontend calls it, the app id arrives as an
 * ARGUMENT rather than being derived from the peer, and it must never trust a caller
 * directly. See docs/IMPL-INTERFACE.md.
 *
 * WHAT LIVES HERE: the chooser (src/ui/chooser.h), the PIN prompt (src/ui/pin.h),
 * token and certificate discovery (src/tokens/), the broker that holds the PKCS#11
 * session and performs Sign and Decrypt (src/broker/operations.h), and the
 * experimental synthetic PKCS#11 facade whose endpoint fd the frontend relays
 * (src/export/facade.h).
 *
 * Nothing is implemented: this is a design sketch, so every verb exits 70.
 */

#include <stdio.h>

#include <glib.h>

/* The same exit-code scheme as the frontend, so a supervisor sees one scheme. */
#define CERTIFICATE_EXIT_SUCCESS 0
#define CERTIFICATE_EXIT_UNAVAILABLE 40 /* no session bus, no p11-kit, no reader, no display */
#define CERTIFICATE_EXIT_USAGE 64
#define CERTIFICATE_EXIT_INTERNAL 70

#define CERTIFICATE_VERSION "0.0.0"
#define CERTIFICATE_IMPL_BUS_NAME "io.github.sjtrotter.impl.portal.Certificate.gtk"
#define CERTIFICATE_IMPL_OBJECT_PATH "/io/github/sjtrotter/portal/Certificate"
#define CERTIFICATE_IMPL_INTERFACE "io.github.sjtrotter.impl.portal.Certificate1"

static void backend_usage(FILE* out)
{
	fprintf(out,
	        "certificate-portal-gtk - GTK portal backend for certificate-backed private keys\n"
	        "\n"
	        "USAGE\n"
	        "  certificate-portal-gtk [options]\n"
	        "\n"
	        "  Normally started by D-Bus activation when the frontend selects this\n"
	        "  backend, not from a shell. It owns\n"
	        "    " CERTIFICATE_IMPL_BUS_NAME "\n"
	        "  on the session bus, exporting\n"
	        "    " CERTIFICATE_IMPL_OBJECT_PATH "\n"
	        "  and implementing\n"
	        "    " CERTIFICATE_IMPL_INTERFACE "\n"
	        "  as declared in data/gtk.portal.\n"
	        "\n"
	        "  THIS INTERFACE IS NOT FOR APPLICATIONS. The app id is an argument supplied\n"
	        "  by the frontend; a caller that reached this bus name directly would be\n"
	        "  naming itself. Calls from anything but the frontend are refused.\n"
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
	        "  The frontend calls AcquireCredential(handle, session_handle, app_id,\n"
	        "  parent_window, options). THIS SERVICE enumerates the tokens, filters the\n"
	        "  certificates, and shows a chooser naming the application the frontend\n"
	        "  identified, HOW WELL it identified it, the purpose in this service's own\n"
	        "  words, and the candidate certificates. It returns what was chosen. The\n"
	        "  frontend then calls Sign; this service prompts for the PIN in its own\n"
	        "  window, logs into its OWN PKCS#11 session, and signs.\n"
	        "\n"
	        "  The PIN never leaves this process. The private key never leaves the token.\n"
	        "  The experimental PKCS#11 endpoint fd is created here, because the token\n"
	        "  session is here, and the frontend passes it through to the application.\n"
	        "\n"
	        "STATUS\n"
	        "  EXPERIMENTAL DESIGN SKETCH. Nothing is implemented; every verb exits 70.\n"
	        "\n"
	        "  In particular: stock 'p11-kit server' exports a TOKEN, not an object, and\n"
	        "  does not carry login state across the forwarding boundary. Object and\n"
	        "  operation scoping needs a broker-controlled synthetic PKCS#11 facade,\n"
	        "  which is substantial security-sensitive engineering and is not written.\n"
	        "  See docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md.\n");
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
			printf("certificate-portal-gtk " CERTIFICATE_VERSION
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

		fprintf(stderr, "certificate-portal-gtk: unknown option '%s'\n", arg);
		fprintf(stderr, "Try 'certificate-portal-gtk --help'.\n");
		return CERTIFICATE_EXIT_USAGE;
	}

	if (list_tokens)
	{
		/* This would drive src/tokens/discovery.h and print token DISPLAY identity
		 * only -- never object labels, key ids or serials, per shared/redact.h. */
		fprintf(stderr, "certificate-portal-gtk: --list-tokens: not implemented (design sketch)\n");
		return CERTIFICATE_EXIT_INTERNAL;
	}

	/* Everything past this point would connect to the session bus, claim the impl bus
	 * name, export src/certificate.h's impl interface plus the impl Request and Session
	 * objects (src/request.h, src/session.h), start token discovery
	 * (src/tokens/discovery.h), and run a GTK main loop. None of that exists. */
	fprintf(stderr, "certificate-portal-gtk: not implemented (design sketch)\n");
	return CERTIFICATE_EXIT_INTERNAL;
}
