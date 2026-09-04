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
 * g_bus_own_name with REPLACE under --replace, and quitting on name-lost -- is
 * xdg-desktop-portal-gtk's, LGPL-2.1-or-later, Copyright (C) 2016 Red Hat, Inc.
 * ALLOW_REPLACEMENT is where this backend deliberately differs from it: it is a
 * separate --allow-replacement flag that nothing installed passes, so an
 * upgrade is a restart rather than a --replace. See harden() and the comment
 * over g_bus_own_name_on_connection() below.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include <adwaita.h>
#include <gio/gio.h>
#include <glib-unix.h>
#include <gtk/gtk.h>

#include "certificate.h"
#include "certificate-impl.h"
#include "config.h"
#include "redact.h"
#include "tokens/discovery.h"
#include "tokens/filter.h"
#include "ui/pin.h"

static GMainLoop* loop = NULL;
static CertificateImpl* impl = NULL;
static CertificateTokens* tokens = NULL;

static gboolean opt_replace = FALSE;
static gboolean opt_allow_replacement = FALSE;
static gboolean opt_verbose = FALSE;
static gboolean opt_version = FALSE;
static gboolean opt_list_tokens = FALSE;
static gboolean opt_no_activate = FALSE;
static gboolean opt_allow_core = FALSE;
static gboolean opt_allow_software_tokens = FALSE;
static char** opt_modules = NULL;
static char* opt_pin_prompt = NULL;
static int opt_login_timeout = -1;

static const GOptionEntry entries[] = {
	{ "replace", 'r', 0, G_OPTION_ARG_NONE, &opt_replace,
	  "Take the bus name from a running instance that permitted it", NULL },
	{ "allow-replacement", 0, 0, G_OPTION_ARG_NONE, &opt_allow_replacement,
	  "Let a later instance take the bus name from this one", NULL },
	{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Log decisions and breadcrumbs on stderr",
	  NULL },
	{ "module", 'm', 0, G_OPTION_ARG_FILENAME_ARRAY, &opt_modules,
	  "Use only this PKCS#11 module; repeatable", "PATH" },
	{ "allow-software-tokens", 0, 0, G_OPTION_ARG_NONE, &opt_allow_software_tokens,
	  "Also offer tokens whose slot does not set CKF_HW_SLOT", NULL },
	{ "login-timeout", 0, 0, G_OPTION_ARG_INT, &opt_login_timeout,
	  "Give up on a C_Login that has not returned after N seconds (0 disables)", "N" },
	{ "list-tokens", 0, 0, G_OPTION_ARG_NONE, &opt_list_tokens,
	  "List the security tokens visible to this user and exit", NULL },
	{ "no-activate", 0, 0, G_OPTION_ARG_NONE, &opt_no_activate,
	  "Do not request the bus name; start, check the modules, and exit", NULL },
	{ "debug-allow-core", 0, 0, G_OPTION_ARG_NONE, &opt_allow_core,
	  "DEVELOPMENT ONLY: leave core dumps and ptrace attach enabled", NULL },
	{ "version", 0, 0, G_OPTION_ARG_NONE, &opt_version, "Print the version and exit", NULL },
	{ NULL, 0, 0, 0, NULL, NULL, NULL },
};

#if HAVE_GCR
/* ONLY WHEN THE BUILD HAS GCR. An option that names a prompt this binary cannot
 * draw would be an option that fails at the worst moment. */
static const GOptionEntry gcr_entries[] = {
	{ "pin-prompt", 0, 0, G_OPTION_ARG_STRING, &opt_pin_prompt,
	  "Where the PIN is typed: auto (default), gtk, or system", "WHICH" },
	{ NULL, 0, 0, 0, NULL, NULL, NULL },
};
#endif

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
    "WHICH TOKENS ARE OFFERED\n"
    "  By default only tokens in a slot the module reports as HARDWARE\n"
    "  (CKF_HW_SLOT). p11-kit on an ordinary desktop also presents software key\n"
    "  stores as tokens -- the GNOME keyring's module is the usual one -- and a\n"
    "  window headed \"security token\" that offers keys from the user's home\n"
    "  directory says something untrue about where the key is.\n"
    "  --allow-software-tokens turns the default off; a module named with\n"
    "  --module is exempt already, because naming it is the same act.\n"
    "  --list-tokens says which tokens were skipped and why.\n"
    "  CKF_HW_SLOT is a claim by a module already loaded here, so this is a\n"
    "  default and NOT a security boundary.\n"
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

/* THREE LINES THAT DECIDE WHERE THE PIN CAN END UP, run before anything else
 * can crash.
 *
 * PR_SET_DUMPABLE(0) stops a core dump being written at all AND makes
 * /proc/self/mem, /proc/self/maps and the rest root-owned, which is what blocks
 * a same-uid ptrace attach on a normal kernel. docs/SECURITY.md is careful to
 * say the split does not defend against a hostile process running as the user;
 * this converts part of that from "open problem" to "partial mitigation", and
 * the document says which part.
 *
 * RLIMIT_CORE 0 is the belt to that braces: dumpability can be re-enabled by a
 * later execve or by a kernel that treats the flag differently, and a zero core
 * limit is checked independently.
 *
 * WHY IT MATTERS HERE MORE THAN ELSEWHERE: between the moment the PIN is
 * copied into the locked page and the moment it is wiped, a SIGSEGV would hand
 * systemd-coredump a file containing it, kept under /var/lib/systemd/coredump
 * for days by default. */
static void harden(void)
{
	struct rlimit no_core = { 0, 0 };

	/* THE ONE WAY OUT, and it is a command-line flag rather than an environment
	 * variable on purpose: an installed service file's Exec line is fixed, so
	 * nothing that merely shares the session can turn the hardening off the way
	 * dbus-update-activation-environment could. It exists because a
	 * non-dumpable process cannot be attached to by gdb either, and
	 * docs/TESTING.md has to be able to tell somebody how to debug a crash. */
	if (opt_allow_core)
	{
		g_message("process-not-hardened detail=debug-allow-core");
		return;
	}

	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
		g_message("process-not-hardened detail=prctl-dumpable-failed");

	if (setrlimit(RLIMIT_CORE, &no_core) != 0)
		g_message("process-not-hardened detail=rlimit-core-failed");
}

/* THE WINDOWS FOLLOW THE SESSION'S LIGHT/DARK SETTING, AND THEY HAVE TO BE TOLD
 * IT DIRECTLY. This is a consequence of harden(), and it was a visible bug: the
 * chooser and the PIN prompt came up light on a dark desktop.
 *
 * WHY. libadwaita takes the colour scheme from the SETTINGS PORTAL. Asking the
 * portal makes it look the caller up by /proc/<pid>, and PR_SET_DUMPABLE(0)
 * makes this process's /proc entries root-owned on purpose, so the portal
 * answers AccessDenied ("Unable to open /proc/<pid>/root") and GDK says so in a
 * warning. libadwaita's remaining fallbacks did not recover the setting here:
 * measured on Fedora 44 with the session set to prefer-dark, this process came
 * up LIGHT with the hardening on and DARK with --debug-allow-core.
 *
 * THE CHOICE, recorded because both options were real:
 *
 *   drop PR_SET_DUMPABLE(0) and rely on RLIMIT_CORE 0, MADV_DONTDUMP and Yama
 *     -- which would trade a same-uid ptrace defence for a theme. Yama's
 *     ptrace_scope is not guaranteed to be set, and the thing a tracer would
 *     read is the page a PIN is in.
 *
 *   read the setting ourselves, which is this. GSettings talks to dconf over
 *     D-Bus and does not look anybody up by pid, so it works in a process the
 *     portal cannot identify.
 *
 * The schema is looked up rather than assumed: org.gnome.desktop.interface is
 * not present on every desktop, and a missing schema aborts in g_settings_new().
 * Where it is absent, libadwaita's own answer stands. */
static void on_dark_changed(GObject* manager, GParamSpec* spec, gpointer user_data)
{
	certificate_log_debug(CERTIFICATE_REASON_COLOUR_SCHEME,
	                      adw_style_manager_get_dark(ADW_STYLE_MANAGER(manager))
	                          ? "dark"
	                          : "light");
}

static void apply_colour_scheme(GSettings* settings, const char* key, gpointer user_data)
{
	g_autofree char* scheme = g_settings_get_string(settings, "color-scheme");
	AdwColorScheme wanted = ADW_COLOR_SCHEME_DEFAULT;

	if (g_strcmp0(scheme, "prefer-dark") == 0)
		wanted = ADW_COLOR_SCHEME_PREFER_DARK;
	else if (g_strcmp0(scheme, "prefer-light") == 0)
		wanted = ADW_COLOR_SCHEME_PREFER_LIGHT;

	adw_style_manager_set_color_scheme(adw_style_manager_get_default(), wanted);
}

static void follow_colour_scheme(void)
{
	GSettingsSchemaSource* source = g_settings_schema_source_get_default();
	g_autoptr(GSettingsSchema) schema = NULL;
	AdwStyleManager* manager = adw_style_manager_get_default();

	g_signal_connect(manager, "notify::dark", G_CALLBACK(on_dark_changed), NULL);

	/* libadwaita's own override wins, because it exists to be able to. It is
	 * how tools/ui-smoke.sh checks that a dark scheme actually reaches the
	 * windows without depending on what the machine running the test has its
	 * desktop set to. */
	{
		const char* forced = g_getenv("ADW_DEBUG_COLOR_SCHEME");

		if (forced != NULL && *forced != '\0')
		{
			certificate_log_debug(CERTIFICATE_REASON_COLOUR_SCHEME, "forced");
			on_dark_changed(G_OBJECT(manager), NULL, NULL);
			return;
		}
	}

	if (source != NULL)
		schema = g_settings_schema_source_lookup(source, "org.gnome.desktop.interface", TRUE);

	if (schema != NULL && g_settings_schema_has_key(schema, "color-scheme"))
	{
		/* Leaked on purpose: it lives for the life of the process and the
		 * "changed" handler is what keeps the windows following the session. */
		GSettings* settings = g_settings_new("org.gnome.desktop.interface");

		g_signal_connect(settings, "changed::color-scheme", G_CALLBACK(apply_colour_scheme),
		                 NULL);
		apply_colour_scheme(settings, "color-scheme", NULL);
	}
	else
	{
		certificate_log_debug(CERTIFICATE_REASON_COLOUR_SCHEME, "no-schema");
	}

	on_dark_changed(G_OBJECT(manager), NULL, NULL);
}


static gboolean on_signal(gpointer user_data)
{
	g_debug("terminating on a signal");
	g_main_loop_quit(loop);
	return G_SOURCE_REMOVE;
}

static void on_bus_acquired(GDBusConnection* connection, const char* name, gpointer user_data)
{
	g_autoptr(GError) error = NULL;

	impl = certificate_impl_new(connection, tokens, &error);
	if (impl == NULL)
	{
		g_warning("Could not export the backend interface: %s", error->message);
		g_main_loop_quit(loop);
	}
}

static void on_name_acquired(GDBusConnection* connection, const char* name, gpointer user_data)
{
	g_debug("owning %s", name);
}

static void on_name_lost(GDBusConnection* connection, const char* name, gpointer user_data)
{
	/* Either another instance replaced this one, or the name could not be
	 * taken. Either way this process is done: a backend that stays running
	 * without the name is a backend holding a card session nobody can reach. */
	g_debug("lost %s", name);
	g_main_loop_quit(loop);
}

static int list_tokens(void)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) present = NULL;

	/* THE LIST THAT REPORTS RATHER THAN FILTERS. An operator working out
	 * whether this backend can see their card has to be told about a token that
	 * is present and is not being offered, and why. */
	present = certificate_tokens_list_all(tokens, &error);
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
		/* SANITISED LIKE EVERY OTHER CARD STRING. This is the one output path
		 * that used to print them raw, and docs/TESTING.md 3.2 has an operator
		 * run it against an unknown card as the first thing they do: a label
		 * carrying a CSI sequence can rewrite the lines above it, and a bidi
		 * override can make a serial read backwards, in a terminal where the
		 * operator is deciding whether to trust the card. */
		g_autofree char* label =
		    certificate_display_text(token->label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "(unnamed)");
		g_autofree char* manufacturer = certificate_display_text(
		    token->manufacturer, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "(unknown)");
		g_autofree char* model =
		    certificate_display_text(token->model, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "(unknown)");
		g_autofree char* reader =
		    certificate_display_text(token->reader_name, CERTIFICATE_DISPLAY_MAX_READER, "(unknown)");

		g_print("Token %u\n", i + 1);
		g_print("  label         %s\n", label);
		g_print("  manufacturer  %s\n", manufacturer);
		g_print("  model         %s\n", model);
		g_print("  serial        %s\n", serial);
		g_print("  reader        %s\n", reader);
		g_print("  module        %s\n", token->module_name != NULL ? token->module_name : "?");
		g_print("  hardware      %s\n",
		        token->hardware ? "yes (CKF_HW_SLOT)" : "no (CKF_HW_SLOT clear)");
		g_print("  login         %s\n", token->login_required ? "required" : "not required");
		g_print("  PIN entry     %s\n",
		        token->protected_authentication_path ? "on the reader (protected path)"
		                                             : "on screen");
		if (token->skip_reason != NULL)
			g_print("  SKIPPED       %s\n", token->skip_reason);
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

		g_print("%u usable certificate%s", candidates->len, candidates->len == 1 ? "" : "s");
		if (opt_allow_software_tokens)
			g_print("  (software tokens allowed)");
		g_print("\n");

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
				CertificateOperations operations =
				    certificate_purpose_operations(candidate, (CertificatePurpose) p);
				const char* name = certificate_purpose_to_string((CertificatePurpose) p);

				if (operations == CERTIFICATE_OPERATION_NONE)
					continue;

				/* A key-management certificate is a real credential for mail
				 * and no use at all for signing one, and the listing has to
				 * say which, or a card with one on it reads as a card with a
				 * certificate that does not work. */
				if (operations == CERTIFICATE_OPERATION_DECRYPT)
				{
					g_autofree char* text = g_strdup_printf("%s (decrypt only)", name);

					g_strv_builder_add(purpose_builder, text);
				}
				else
				{
					g_strv_builder_add(purpose_builder, name);
				}
			}
			purpose_list = g_strv_builder_end(purpose_builder);
			purposes = g_strjoinv(", ", purpose_list);

			g_autofree char* subject = certificate_display_text(
			    candidate->subject_display, CERTIFICATE_DISPLAY_MAX_SUBJECT, "(unnamed)");
			g_autofree char* issuer = certificate_display_text(
			    candidate->issuer_display, CERTIFICATE_DISPLAY_MAX_ISSUER, "(unnamed)");
			g_autofree char* token_label =
			    certificate_display_text(candidate->token->label,
			                             CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "(unnamed)");

			g_print("\n  %u. %s\n", i + 1, subject);
			g_print("     issuer      %s\n", issuer);
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
			g_print("     token       %s\n", token_label);
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
	g_autoptr(GDBusConnection) connection = NULL;
	guint owner_id = 0;
	int status = CERTIFICATE_EXIT_SUCCESS;

	setlocale(LC_ALL, "");

	/* Avoid pointless and confusing recursion: this process must not route its
	 * own dialogs through the portal it is a backend of. */
	g_unsetenv("GTK_USE_PORTAL");
	g_unsetenv("GDK_DEBUG");

	g_set_prgname("xdg-desktop-portal-certificate");

	context = g_option_context_new("- a backend for the experimental Certificate portal");
	g_option_context_add_main_entries(context, entries, NULL);
#if HAVE_GCR
	g_option_context_add_main_entries(context, gcr_entries, NULL);
#endif
	g_option_context_set_description(context, description);

	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		g_printerr("Try 'xdg-desktop-portal-certificate --help'.\n");
		return CERTIFICATE_EXIT_USAGE;
	}

	/* AS EARLY AS THE OPTIONS ALLOW. Everything before this point is
	 * g_option_context_parse() on a fixed argv, which cannot fault on anything
	 * a PIN could be next to, because there is no PIN yet. */
	harden();

	if (opt_version)
	{
		g_print("xdg-desktop-portal-certificate " PACKAGE_VERSION
		        " (impl interface version %u, experimental)\n",
		        CERTIFICATE_IMPL_INTERFACE_VERSION);
		return CERTIFICATE_EXIT_SUCCESS;
	}

	certificate_log_set_verbose(opt_verbose);

	/* --verbose PROMISES BREADCRUMBS, so it has to turn the debug level on as
	 * well: every certificate_log_debug() is a g_debug(), and GLib's default
	 * writer drops those unless a domain is enabled. Without this the flag
	 * enabled the calls and then threw away what they printed, which is how the
	 * colour-scheme line below was invisible in a log that had asked for it. */
	if (opt_verbose)
	{
		const char* domains[] = { "all", NULL };

		g_log_writer_default_set_debug_domains(domains);
	}
	else
	{
		g_log_writer_default_set_debug_domains(NULL);
	}

	/* WHERE THE PIN IS TYPED. The module default is the in-process window; the
	 * PROGRAM default is auto, which is the system prompter when the session
	 * has one. Set before anything can prompt, and refused rather than
	 * defaulted when it is misspelt -- for the same reason a mistyped mechanism
	 * parameter is an error. */
	if (!certificate_pin_set_prompt_kind(opt_pin_prompt != NULL ? opt_pin_prompt : "auto",
	                                     &error))
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		return CERTIFICATE_EXIT_USAGE;
	}

	tokens = certificate_tokens_new((const char* const*) opt_modules, &error);
	if (tokens == NULL)
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		return CERTIFICATE_EXIT_UNAVAILABLE;
	}

	certificate_tokens_set_allow_software(tokens, opt_allow_software_tokens);

	/* Negative means "not given", which is how a default of 60 and an explicit
	 * 0 stay different things. */
	if (opt_login_timeout >= 0)
		certificate_pin_set_login_timeout((guint) opt_login_timeout);

	if (opt_list_tokens)
	{
		status = list_tokens();
		g_clear_pointer(&tokens, certificate_tokens_free);
		return status;
	}

	/* A display is not required to START: GetCapabilities has to answer on a
	 * headless machine, and the honest answer there is has_display = false plus
	 * a clean refusal of anything that would need a window. gtk_init() would
	 * abort instead, so the check is the _check() form. */
	if (gtk_init_check())
	{
		adw_init();
		certificate_ui_set_has_display(TRUE);
		follow_colour_scheme();
	}
	else
	{
		/* GetCapabilities still answers; anything needing a window is refused. */
		g_message("no-display detail=window-requests-refused");
		certificate_ui_set_has_display(FALSE);
	}

	loop = g_main_loop_new(NULL, FALSE);

	connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (connection == NULL)
	{
		g_printerr("xdg-desktop-portal-certificate: no session bus: %s\n", error->message);
		g_clear_pointer(&tokens, certificate_tokens_free);
		return CERTIFICATE_EXIT_UNAVAILABLE;
	}

	if (opt_no_activate)
	{
		g_print("xdg-desktop-portal-certificate " PACKAGE_VERSION
		        ": modules loaded, session bus reachable, display %s. "
		        "Not requesting the bus name.\n",
		        certificate_ui_has_display() ? "available" : "absent");
		g_clear_pointer(&tokens, certificate_tokens_free);
		return CERTIFICATE_EXIT_SUCCESS;
	}

	g_unix_signal_add(SIGINT, on_signal, NULL);
	g_unix_signal_add(SIGTERM, on_signal, NULL);

	/* REPLACEMENT IS NOT OFFERED TO ANYONE UNLESS IT IS ASKED FOR, AND THE TWO
	 * HALVES ARE SEPARATE FLAGS.
	 *
	 * xdg-desktop-portal-gtk sets ALLOW_REPLACEMENT unconditionally, and for a
	 * file chooser that is reasonable. Here it means any process running as the
	 * user can take org.freedesktop.impl.portal.desktop.certificate at will and
	 * become the thing the portal calls -- receiving AcquireCredential and Sign
	 * with a real app id and identity level, and drawing the window that asks
	 * for the PIN. The trusted dialog is the one thing docs/SECURITY.md says
	 * this repository owns outright.
	 *
	 * D-BUS CANNOT AUTHENTICATE A REPLACEMENT. ALLOW_REPLACEMENT is not "let
	 * the package manager replace me"; it is "let whoever asks next replace
	 * me", and the bus offers nothing finer -- no uid check, no peer identity,
	 * nothing the current owner can inspect before yielding. So the choice is
	 * between a name anybody can take and a name nobody can take, and this
	 * backend takes the second:
	 *
	 *   --allow-replacement   this instance may be replaced. NOT the default,
	 *                         and NOT in the installed .service file.
	 *   --replace             this instance asks to replace the current owner,
	 *                         which works only if that owner allowed it.
	 *
	 * WHICH MEANS AN UPGRADE IS A RESTART, not a --replace: the D-Bus activated
	 * instance permits no replacement, so a new binary takes over by stopping
	 * the old one (the service manager, or a SIGTERM) and letting activation
	 * start the new one on the next call. --replace exists for a development
	 * loop where the running instance was deliberately started with
	 * --allow-replacement; tools/dev-stack.sh --live does exactly that.
	 * docs/TESTING.md 3.5 has the recipe. */
	owner_id = g_bus_own_name_on_connection(
	    connection, CERTIFICATE_IMPL_BUS_NAME,
	    (opt_allow_replacement ? G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT
	                           : G_BUS_NAME_OWNER_FLAGS_NONE) |
	        (opt_replace ? G_BUS_NAME_OWNER_FLAGS_REPLACE : G_BUS_NAME_OWNER_FLAGS_NONE),
	    on_name_acquired, on_name_lost, NULL, NULL);

	on_bus_acquired(connection, CERTIFICATE_IMPL_BUS_NAME, NULL);

	if (impl != NULL)
		g_main_loop_run(loop);
	else
		status = CERTIFICATE_EXIT_INTERNAL;

	certificate_impl_shutdown(impl);

	/* The invalidations emitted above have to reach the bus before the process
	 * goes away, or the frontend learns about the loss by timing out. */
	g_dbus_connection_flush_sync(connection, NULL, NULL);

	certificate_impl_free(impl);
	g_bus_unown_name(owner_id);
	g_main_loop_unref(loop);
	g_clear_pointer(&tokens, certificate_tokens_free);
	g_strfreev(opt_modules);
	g_free(opt_pin_prompt);

	return status;
}
