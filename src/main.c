/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * xdg-desktop-portal-certificate - an out-of-tree xdg-desktop-portal BACKEND for
 * certificate-backed private keys.
 *
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * The main() shape -- gtk_init plus a plain GMainLoop rather than GtkApplication,
 * g_bus_own_name with REPLACE under --replace, and quitting on name-lost -- is
 * xdg-desktop-portal-gtk's, LGPL-2.1-or-later, Copyright (C) 2016 Red Hat, Inc.
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
#include "core/pin.h"
#include "ui/pin-backends.h"
#include "ui/chooser.h"

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
	{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Log decisions and debug events to stderr",
	  NULL },
	{ "module", 'm', 0, G_OPTION_ARG_FILENAME_ARRAY, &opt_modules,
	  "Use only this PKCS#11 module; repeatable", "PATH" },
	{ "allow-software-tokens", 0, 0, G_OPTION_ARG_NONE, &opt_allow_software_tokens,
	  "Also offer tokens whose slot does not set CKF_HW_SLOT", NULL },
	{ "login-timeout", 0, 0, G_OPTION_ARG_INT, &opt_login_timeout,
	  "Hide the PIN prompt after N seconds of C_Login (default 60; 0 disables)", "N" },
	{ "pin-prompt", 0, 0, G_OPTION_ARG_STRING, &opt_pin_prompt,
	  "Where the PIN is typed: auto (default), gtk, or system (requires gcr-4)", "WHICH" },
	{ "list-tokens", 0, 0, G_OPTION_ARG_NONE, &opt_list_tokens,
	  "List the security tokens visible to this user and exit", NULL },
	{ "no-activate", 0, 0, G_OPTION_ARG_NONE, &opt_no_activate,
	  "Do not request the bus name; start, check the modules, and exit", NULL },
	{ "debug-allow-core", 0, 0, G_OPTION_ARG_NONE, &opt_allow_core,
	  "Leave core dumps and ptrace attach enabled for debugging", NULL },
	{ "version", 0, 0, G_OPTION_ARG_NONE, &opt_version, "Print the version and exit", NULL },
	{ NULL, 0, 0, 0, NULL, NULL, NULL },
};

static const char* description =
    "Certificate backend for xdg-desktop-portal, started through D-Bus activation.\n"
    "Bus name: " CERTIFICATE_IMPL_BUS_NAME "\n"
    "Object path: " CERTIFICATE_IMPL_OBJECT_PATH "\n"
    "Interface: " CERTIFICATE_IMPL_INTERFACE "\n"
    "Only the owner of org.freedesktop.portal.Desktop may call this backend.\n"
    "\n"
    "The frontend requires branch experimental/certificate, a configured backend\n"
    "and XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=Certificate1 in its environment.\n"
    "It establishes caller identity; this backend draws consent and PIN dialogs\n"
    "and performs private-key operations on the token.\n"
    "\n"
    "Hardware slots are offered by default. --allow-software-tokens includes\n"
    "software tokens; --module also overrides this filter for selected modules.\n"
    "Hardware flags are module claims. --list-tokens includes skip reasons.\n"
    "\n"
    "Without gcr-4, --pin-prompt=auto uses GTK; --pin-prompt=system is unavailable.\n"
    "\n"
    "Exit codes: 0 clean shutdown, 40 unavailable, 64 usage, 70 internal error.\n"
    "See docs/TESTING.md for development setup and hardware checks.";

/* Disable dumps and same-UID ptrace before handling PINs; see docs/SECURITY.md for limits. */
static void harden(void)
{
	struct rlimit no_core = { 0, 0 };

	/* Only an explicit command-line debug flag disables hardening; activation environment changes cannot do so. */
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

/* Dump hardening prevents portal PID lookup, so read the optional desktop color-scheme schema directly. */
static void follow_colour_scheme(void)
{
	GSettingsSchemaSource* source = g_settings_schema_source_get_default();
	g_autoptr(GSettingsSchema) schema = NULL;
	AdwStyleManager* manager = adw_style_manager_get_default();

	g_signal_connect(manager, "notify::dark", G_CALLBACK(on_dark_changed), NULL);

	/* Preserve libadwaita's explicit color-scheme override. */
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
		/* Process-lifetime settings reference keeps the change handler active. */
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
	g_debug("Shutdown signal received");
	g_main_loop_quit(loop);
	return G_SOURCE_REMOVE;
}

static void on_bus_acquired(GDBusConnection* connection, const char* name, gpointer user_data)
{
	g_autoptr(GError) error = NULL;

	impl = certificate_impl_new(connection, tokens, &error);
	if (impl == NULL)
	{
		g_warning("Backend interface export failed: %s", error->message);
		g_main_loop_quit(loop);
	}
}

static void on_name_acquired(GDBusConnection* connection, const char* name, gpointer user_data)
{
	g_debug("owning %s", name);
}

static void on_name_lost(GDBusConnection* connection, const char* name, gpointer user_data)
{
	g_debug("lost %s", name);
	g_main_loop_quit(loop);
}

static int list_tokens(void)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) present = NULL;

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
		/* Token strings are untrusted terminal input and require control-character and bidi sanitization. */
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
			g_print("  skipped       %s\n", token->skip_reason);
		if (token->pin_locked)
			g_print("  PIN state     locked\n");
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

typedef struct
{
	const char* const* paths;
	GError* error;
} ModuleLoad;
static gpointer load_tokens_worker(gpointer data)
{
	ModuleLoad* load = data;
	return certificate_tokens_new(load->paths, &load->error);
}
static gpointer free_tokens_worker(gpointer data)
{
	certificate_tokens_free(data);
	return NULL;
}
static void release_tokens(CertificateTokens* collection)
{
	if (collection != NULL)
		g_thread_join(g_thread_new("certificate-unload", free_tokens_worker, collection));
}
static gpointer list_tokens_worker(gpointer data)
{
	return GINT_TO_POINTER(list_tokens());
}

int main(int argc, char** argv)
{
	g_autoptr(GOptionContext) context = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GDBusConnection) connection = NULL;
	guint owner_id = 0;
	int status = CERTIFICATE_EXIT_SUCCESS;

	setlocale(LC_ALL, "");

	/* Backend dialogs must not recurse through the portal. */
	g_unsetenv("GTK_USE_PORTAL");
	/* Non-dumpable hardening prevents Settings portal identification; GSettings supplies the colour scheme. */
	g_setenv("GDK_DEBUG", "no-portals", TRUE);
	g_setenv("ADW_DISABLE_PORTAL", "1", TRUE);

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

#if !HAVE_GCR
	if (opt_pin_prompt != NULL && g_ascii_strcasecmp(opt_pin_prompt, "system") == 0)
	{
		g_printerr("xdg-desktop-portal-certificate: "
		           "--pin-prompt=system requires a build with gcr-4\n");
		return CERTIFICATE_EXIT_USAGE;
	}
#endif

	harden();

	if (opt_version)
	{
		g_print("xdg-desktop-portal-certificate " PACKAGE_VERSION
		        " (impl interface version %u, experimental)\n",
		        CERTIFICATE_IMPL_INTERFACE_VERSION);
		return CERTIFICATE_EXIT_SUCCESS;
	}

	certificate_log_set_verbose(opt_verbose);

	if (!certificate_pin_set_prompt_kind(opt_pin_prompt != NULL ? opt_pin_prompt : "auto",
	                                     &error))
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		return CERTIFICATE_EXIT_USAGE;
	}

	certificate_chooser_set_provider(certificate_chooser_provider_gtk());

	ModuleLoad load = {.paths = (const char* const*)opt_modules};
	tokens = g_thread_join(g_thread_new("certificate-load", load_tokens_worker, &load));
	error = load.error;
	if (tokens == NULL)
	{
		g_printerr("xdg-desktop-portal-certificate: %s\n", error->message);
		return CERTIFICATE_EXIT_UNAVAILABLE;
	}

	certificate_tokens_set_allow_software(tokens, opt_allow_software_tokens);

	/* A negative value distinguishes omission from an explicit zero. */
	if (opt_login_timeout >= 0)
		certificate_pin_set_login_timeout((guint) opt_login_timeout);

	if (opt_list_tokens)
	{
		status = GPOINTER_TO_INT(
			g_thread_join(g_thread_new("certificate-list", list_tokens_worker, NULL)));
		g_clear_pointer(&tokens, release_tokens);
		return status;
	}

	/* Headless startup must still serve GetCapabilities; gtk_init() would abort. */
	if (gtk_init_check())
	{
		adw_init();
		certificate_ui_set_has_display(TRUE);
		follow_colour_scheme();
	}
	else
	{
		g_message("no-display detail=window-requests-refused");
		certificate_ui_set_has_display(FALSE);
	}

	loop = g_main_loop_new(NULL, FALSE);

	connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (connection == NULL)
	{
		g_printerr("xdg-desktop-portal-certificate: no session bus: %s\n", error->message);
		g_clear_pointer(&tokens, release_tokens);
		return CERTIFICATE_EXIT_UNAVAILABLE;
	}

	if (opt_no_activate)
	{
		g_print("xdg-desktop-portal-certificate " PACKAGE_VERSION
		        ": modules loaded, session bus reachable, display %s. "
		        "Not requesting the bus name.\n",
		        certificate_ui_has_display() ? "available" : "absent");
		g_clear_pointer(&tokens, release_tokens);
		return CERTIFICATE_EXIT_SUCCESS;
	}

	g_unix_signal_add(SIGINT, on_signal, NULL);
	g_unix_signal_add(SIGTERM, on_signal, NULL);

	/* Name replacement permits any requesting peer to take the PIN dialog's service name; see docs/SECURITY.md. */
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

	/* Flush invalidations before exiting so the frontend receives them. */
	g_dbus_connection_flush_sync(connection, NULL, NULL);

	certificate_impl_free(impl);
	g_bus_unown_name(owner_id);
	g_main_loop_unref(loop);
	g_clear_pointer(&tokens, release_tokens);
	g_strfreev(opt_modules);
	g_free(opt_pin_prompt);

	return status;
}
