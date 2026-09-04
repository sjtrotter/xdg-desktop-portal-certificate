/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * smartcard-portal - brokered use of certificate-backed private keys, over D-Bus.
 *
 * Copyright (C) 2026 the smartcard-portal authors
 *
 * This would be the D-Bus activated per-user service that owns
 * io.github.sjtrotter.Smartcard1: it enumerates PKCS#11 tokens, filters certificates,
 * shows a service-owned chooser and PIN prompt, and performs signatures on the
 * application's behalf. The application never holds the key, never sees the PIN, and
 * never holds a PKCS#11 handle unless it explicitly requests the experimental
 * compatibility endpoint.
 *
 * Version 0 is deliberately ONE service with in-process interfaces: there is no
 * org.freedesktop.impl.portal.* backend ABI, and the name is a project-controlled one
 * rather than a freedesktop portal name it has not been granted -- and is expected to
 * change, because the conceptual boundary is a client certificate rather than a card.
 *
 * See data/io.github.sjtrotter.Smartcard1.xml for the interface and docs/ for what it
 * means. Start with docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md,
 * which is why the architecture is not the obvious one.
 *
 * Nothing is implemented: this is a design sketch, so every verb exits 70.
 */

#include <stdio.h>

#include <glib.h>

/* Exit codes, chosen to match the sibling webauth-service so a supervisor sees one
 * scheme across both. */
#define SMARTCARD_EXIT_SUCCESS 0
#define SMARTCARD_EXIT_UNAVAILABLE 40 /* no session bus, no p11-kit, no pcscd, no display */
#define SMARTCARD_EXIT_USAGE 64
#define SMARTCARD_EXIT_INTERNAL 70

#define SMARTCARD_VERSION "0.0.0"
#define SMARTCARD_BUS_NAME "io.github.sjtrotter.Smartcard1"
#define SMARTCARD_OBJECT_PATH "/io/github/sjtrotter/Smartcard1"

static void smartcard_usage(FILE* out)
{
	fprintf(out,
	        "smartcard-portal - brokered use of certificate-backed private keys\n"
	        "\n"
	        "USAGE\n"
	        "  smartcard-portal [options]\n"
	        "\n"
	        "  Normally started by D-Bus activation, not from a shell. It owns\n"
	        "    " SMARTCARD_BUS_NAME "\n"
	        "  on the session bus, exporting\n"
	        "    " SMARTCARD_OBJECT_PATH "\n"
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
	        "  An application calls AcquireCredential naming a purpose. THIS SERVICE shows\n"
	        "  a chooser naming the verified application, whether it is sandboxed, the\n"
	        "  purpose in its own words, and the candidate certificates. It returns a\n"
	        "  grant: the certificate, its chain, what the key can do, for how long.\n"
	        "  The application then calls Sign. This service prompts for the PIN in its\n"
	        "  own window, logs into its OWN PKCS#11 session, and signs.\n"
	        "\n"
	        "  The PIN never crosses D-Bus. The private key never leaves the token.\n"
	        "\n"
	        "STATUS\n"
	        "  EXPERIMENTAL DESIGN SKETCH. Nothing is implemented; every verb exits 70.\n"
	        "  The interface has NOT been proposed to anyone and is expected to change,\n"
	        "  including its name. Do not depend on this.\n"
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
			smartcard_usage(stdout);
			return SMARTCARD_EXIT_SUCCESS;
		}

		if (g_strcmp0(arg, "--version") == 0 || g_strcmp0(arg, "-V") == 0)
		{
			printf("smartcard-portal " SMARTCARD_VERSION
			       " (design sketch, not implemented; interface version 1, experimental)\n");
			return SMARTCARD_EXIT_SUCCESS;
		}

		if (g_strcmp0(arg, "--list-tokens") == 0)
		{
			list_tokens = TRUE;
			continue;
		}

		if (g_strcmp0(arg, "--replace") == 0 || g_strcmp0(arg, "--no-activate") == 0 ||
		    g_strcmp0(arg, "--verbose") == 0)
			continue;

		fprintf(stderr, "smartcard-portal: unknown option '%s'\n", arg);
		fprintf(stderr, "Try 'smartcard-portal --help'.\n");
		return SMARTCARD_EXIT_USAGE;
	}

	if (list_tokens)
	{
		/* This would drive src/tokens/discovery.h and print token DISPLAY identity
		 * only -- never object labels, key ids or serials, per src/log/redact.h. */
		fprintf(stderr, "smartcard-portal: --list-tokens: not implemented (design sketch)\n");
		return SMARTCARD_EXIT_INTERNAL;
	}

	/* Everything past this point would connect to the session bus, export the
	 * transaction layer (src/dbus/service.h), start token discovery
	 * (src/tokens/discovery.h), and run a main loop. None of that exists. */
	fprintf(stderr, "smartcard-portal: not implemented (design sketch)\n");
	return SMARTCARD_EXIT_INTERNAL;
}
