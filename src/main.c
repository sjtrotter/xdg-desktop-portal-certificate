/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate - an out-of-tree xdg-desktop-portal BACKEND for
 * certificate-backed private keys.
 *
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * The D-Bus activated per-user service that owns
 * org.freedesktop.impl.portal.desktop.certificate and implements
 * org.freedesktop.impl.portal.experimental.Certificate at
 * /org/freedesktop/portal/desktop -- the object path every portal backend
 * exports on. It is laid out like every other out-of-tree backend
 * (xdg-desktop-portal-gtk, xdg-desktop-portal-termfilechooser): src/ holds one
 * file per portal interface implemented, data/ holds the .portal file, the
 * D-Bus service file and the interface XML.
 *
 * IT IS NOT FOR APPLICATIONS. Only xdg-desktop-portal calls it, the app id
 * arrives as an ARGUMENT rather than being derived from the peer, and calls from
 * anything that does not own org.freedesktop.portal.Desktop are refused. See
 * docs/IMPL-INTERFACE.md.
 *
 * THE FRONTEND IS NOT IN THIS REPOSITORY. It is a branch of xdg-desktop-portal
 * itself, experimental/certificate-webauthentication, which exports
 * org.freedesktop.portal.experimental.Certificate only when
 * XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL contains "certificate". See
 * docs/decisions/0010-backend-only-frontend-lives-upstream.md.
 *
 * The main() shape -- gtk_init plus a plain GMainLoop rather than GtkApplication,
 * g_bus_own_name with ALLOW_REPLACEMENT always and REPLACE under --replace, and
 * quitting on name-lost -- is xdg-desktop-portal-gtk's, LGPL-2.1-or-later,
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#include <gio/gio.h>
#include <glib-unix.h>

#include "certificate.h"
#include "config.h"
#include "redact.h"
#include "tokens/discovery.h"
#include "tokens/filter.h"

static CertificateTokens* tokens = NULL;

static gboolean opt_replace = FALSE;
static gboolean opt_verbose = FALSE;
static gboolean opt_version = FALSE;
static gboolean opt_list_tokens = FALSE;
static gboolean opt_no_activate = FALSE;
static char** opt_modules = NULL;

static const GOptionEntry entries[] = {
	{ "replace", 'r', 0, G_OPTION_ARG_NONE, &opt_replace, "Replace a running instance", NULL },
	{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Log decisions and breadcrumbs on stderr",
	  NULL },
	{ "module", 'm', 0, G_OPTION_ARG_FILENAME_ARRAY, &opt_modules,
	  "Use only this PKCS#11 module; repeatable", "PATH" },
	{ "list-tokens", 0, 0, G_OPTION_ARG_NONE, &opt_list_tokens,
	  "List the security tokens visible to this user and exit", NULL },
	{ "no-activate", 0, 0, G_OPTION_ARG_NONE, &opt_no_activate,
	  "Do not request the bus name; start, check the modules, and exit", NULL },
	{ "version", 0, 0, G_OPTION_ARG_NONE, &opt_version, "Print the version and exit", NULL },
	{ NULL, 0, 0, 0, NULL, NULL, NULL },
};

static const char* description =
    "WHAT THIS IS\n"
    "  An out-of-tree BACKEND of xdg-desktop-portal. It draws the certificate\n"
    "  chooser and the PIN prompt, discovers PKCS#11 tokens, and performs private\n"
    "  key operations on behalf of the portal. It is not a portal frontend, it\n"
    "  owns no public interface, and no application talks to it.\n"
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
    "  itself. Calls from any sender that does not own\n"
    "  org.freedesktop.portal.Desktop are refused with AccessDenied.\n"
    "\n"
    "ENABLING THE FRONTEND\n"
    "  The public interface\n"
    "    org.freedesktop.portal.experimental.Certificate\n"
    "  lives in xdg-desktop-portal itself, on the branch\n"
    "    experimental/certificate-webauthentication\n"
    "  and is EXPERIMENTAL: it is not exported unless the portal is started with\n"
    "    XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate\n"
    "  (\"all\" and a comma separated list also work). With the gate off, the\n"
    "  interface is absent from introspection and this backend is never called.\n"
    "  tools/dev-stack.sh wires a development frontend, this backend and an\n"
    "  end-to-end client together on a private bus; docs/TESTING.md has the\n"
    "  commands for a run against a real card.\n"
    "\n"
    "WHAT IT DOES\n"
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
    "EXIT CODES\n"
    "   0 clean shutdown        40 unavailable (no bus, no p11-kit, no module)\n"
    "  64 usage                 70 internal error\n"
    "\n"
    "STATUS\n"
    "  EXPERIMENTAL. The interface it implements is a branch nobody has merged.\n"
    "  The PKCS#11 compatibility endpoint is NOT part of it: OpenPkcs11Endpoint\n"
    "  was deliberately left out of the frontend branch, because an fd-returning\n"
    "  method needs its own review.";

static int list_tokens(void)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) present = NULL;

	present = certificate_tokens_list(tokens, &error);
	if (present == NULL)
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		return CERTIFICATE_EXIT_UNAVAILABLE;
	}

	if (present->len == 0)
	{
		g_print("No security token is present.\n");
		g_print("\n");
		g_print("If a card is in a reader, check that pcscd is running and that the\n");
		g_print("PKCS#11 module for it is configured for p11-kit, or name it with\n");
		g_print("--module /usr/lib64/pkcs11/opensc-pkcs11.so.\n");
	}

	for (guint i = 0; i < present->len; i++)
	{
		CertificateToken* token = g_ptr_array_index(present, i);
		g_autofree char* serial = certificate_redact_serial(token->serial);

		g_print("Token %u\n", i + 1);
		g_print("  label         %s\n", token->label);
		g_print("  manufacturer  %s\n", token->manufacturer);
		g_print("  model         %s\n", token->model);
		g_print("  serial        %s\n", serial);
		g_print("  reader        %s\n", token->reader_name);
		g_print("  module        %s\n", token->module_name != NULL ? token->module_name : "?");
		g_print("  login         %s\n", token->login_required ? "required" : "not required");
		g_print("  PIN entry     %s\n",
		        token->protected_authentication_path ? "on the reader (protected path)"
		                                             : "on screen");
		if (token->pin_locked)
			g_print("  PIN state     LOCKED\n");
		else if (token->pin_final_try)
			g_print("  PIN state     final attempt before locking\n");
		else if (token->pin_count_low)
			g_print("  PIN state     recent failed attempts\n");
		g_print("\n");
	}

	{
		g_autoptr(GPtrArray) candidates = certificate_tokens_enumerate(tokens, NULL, &error);

		if (candidates == NULL)
		{
			g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
			return CERTIFICATE_EXIT_UNAVAILABLE;
		}

		g_print("%u usable certificate%s\n", candidates->len, candidates->len == 1 ? "" : "s");

		for (guint i = 0; i < candidates->len; i++)
		{
			CertificateCandidate* candidate = g_ptr_array_index(candidates, i);
			g_autoptr(GDateTime) not_after = g_date_time_new_from_unix_local(candidate->not_after);
			g_autofree char* expiry =
			    not_after != NULL ? g_date_time_format(not_after, "%F") : g_strdup("unknown");
			g_autofree char* mechanisms =
			    g_strjoinv(", ", candidate->supported_mechanisms);
			g_autofree char* purposes = NULL;
			g_autoptr(GStrvBuilder) purpose_builder = g_strv_builder_new();
			g_auto(GStrv) purpose_list = NULL;

			for (int p = CERTIFICATE_PURPOSE_CLIENT_AUTH; p <= CERTIFICATE_PURPOSE_SSH; p++)
			{
				if (certificate_purpose_matches(candidate, (CertificatePurpose) p))
					g_strv_builder_add(purpose_builder,
					                   certificate_purpose_to_string((CertificatePurpose) p));
			}
			purpose_list = g_strv_builder_end(purpose_builder);
			purposes = g_strjoinv(", ", purpose_list);

			g_print("\n  %u. %s\n", i + 1, candidate->subject_display);
			g_print("     issuer      %s\n", candidate->issuer_display);
			g_print("     expires     %s%s\n", expiry,
			        certificate_candidate_is_expired(candidate,
			                                         g_get_real_time() / G_USEC_PER_SEC)
			            ? "  (EXPIRED)"
			            : "");
			g_print("     key         %s %u-bit%s%s\n", candidate->key_type, candidate->key_size,
			        candidate->key_curve != NULL ? " " : "",
			        candidate->key_curve != NULL ? candidate->key_curve : "");
			g_print("     mechanisms  %s\n", mechanisms);
			g_print("     purposes    %s\n", *purposes != '\0' ? purposes : "(none)");
			if (candidate->piv_slot != NULL)
				g_print("     PIV slot    %s\n", candidate->piv_slot);
			g_print("     token       %s\n", candidate->token->label);
			g_print("     id          %s\n", candidate->certificate_id);
		}

		g_print("\n");
	}

	return CERTIFICATE_EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
	g_autoptr(GOptionContext) context = NULL;
	g_autoptr(GError) error = NULL;
	int status = CERTIFICATE_EXIT_SUCCESS;

	(void) opt_replace;
	(void) opt_no_activate;

	setlocale(LC_ALL, "");

	/* Avoid pointless and confusing recursion: this process must not route its
	 * own dialogs through the portal it is a backend of. */
	g_unsetenv("GTK_USE_PORTAL");
	g_unsetenv("GDK_DEBUG");

	g_set_prgname("xdg-desktop-portal-certificate");

	context = g_option_context_new("- a backend for the experimental Certificate portal");
	g_option_context_add_main_entries(context, entries, NULL);
	g_option_context_set_description(context, description);

	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		g_printerr("Try 'xdg-desktop-portal-certificate --help'.\n");
		return CERTIFICATE_EXIT_USAGE;
	}

	if (opt_version)
	{
		g_print("xdg-desktop-portal-certificate " PACKAGE_VERSION
		        " (impl interface version %u, experimental)\n",
		        CERTIFICATE_IMPL_INTERFACE_VERSION);
		return CERTIFICATE_EXIT_SUCCESS;
	}

	certificate_log_set_verbose(opt_verbose);
	if (!opt_verbose)
		g_log_writer_default_set_debug_domains(NULL);

	tokens = certificate_tokens_new((const char* const*) opt_modules, &error);
	if (tokens == NULL)
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		return CERTIFICATE_EXIT_UNAVAILABLE;
	}

	if (opt_list_tokens)
	{
		status = list_tokens();
		g_clear_pointer(&tokens, certificate_tokens_free);
		return status;
	}

	/* THE SERVICE ITSELF IS NOT HERE YET. This commit is the half that needs no
	 * display and no bus: module loading, token discovery, certificate parsing
	 * and the purpose rules, reachable through --list-tokens so that the author
	 * can check a card before anything is wired to xdg-desktop-portal. */
	g_printerr("xdg-desktop-portal-certificate: the D-Bus backend is not built yet; "
	           "try --list-tokens\n");
	g_clear_pointer(&tokens, certificate_tokens_free);
	g_strfreev(opt_modules);

	return CERTIFICATE_EXIT_INTERNAL;
}
