/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_FRONTEND_PORTAL_IMPL_H
#define SMARTCARD_FRONTEND_PORTAL_IMPL_H

#include <glib.h>

/** @file
 *  Finding and choosing a backend. Modelled on xdg-desktop-portal's
 *  desktop-portal/xdp-portal-config.c (which was src/portal-impl.c before the upstream
 *  tree was reorganised), and on the two file formats it reads.
 *
 *  *.PORTAL FILES describe an installed backend. Key file, group "portal", keys:
 *
 *    DBusName    the backend's D-Bus activation name
 *    Interfaces  semicolon-separated impl interfaces it implements
 *    UseIn       legacy desktop matching, deprecated upstream in favour of portals.conf
 *                and kept for the same reason: a system with no configuration should
 *                still work
 *
 *  Scanned, highest priority first, from:
 *
 *    $SMARTCARD_PORTAL_DIR                     (testing only; mirrors XDG_DESKTOP_PORTAL_DIR)
 *    $XDG_DATA_HOME/smartcard-portal/portals
 *    $XDG_DATA_DIRS/smartcard-portal/portals
 *    ${datadir}/smartcard-portal/portals
 *
 *  PORTALS.CONF selects between them. Key file, group "preferred", one key per impl
 *  interface plus "default"; each value is a semicolon-separated list of *.portal
 *  basenames tried in order, where "none" disables the interface and "*" means the first
 *  available backend in alphabetical order. Searched in the upstream order --
 *  $XDG_CONFIG_HOME, $XDG_CONFIG_DIRS, ${sysconfdir}, $XDG_DATA_HOME, $XDG_DATA_DIRS,
 *  ${datadir} -- preferring $DESKTOP-portals.conf for each lowercased entry in
 *  $XDG_CURRENT_DESKTOP before falling back to portals.conf.
 *    https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html
 *
 *  WHY THIS EXISTS IN A PROJECT WITH ONE BACKEND. Because the second one is a KDE
 *  chooser and PIN prompt, it is a prerequisite for ever proposing this upstream, and
 *  the alternative -- a compile-time toolkit choice -- is the thing that makes a service
 *  unshippable on the desktop it was not built for. Discovering the backend from a file
 *  is also what makes "run the reference backend against a test frontend" a
 *  configuration change rather than a patch.
 *
 *  SECURITY NOTES, because this is a lookup that decides who draws the trusted window:
 *
 *   - A *.portal file is INSTALLED SYSTEM DATA. A user-writable one is a user deciding
 *     who draws their own consent dialog, which is their right; an APPLICATION-writable
 *     one would be a privilege escalation, and no path here is inside anything an
 *     application controls.
 *   - The frontend calls the backend it selected AND NO OTHER, on the name from the
 *     *.portal file. A backend does not get to volunteer at run time.
 *   - If no backend implements SMARTCARD_IMPL_INTERFACE, every method fails with
 *     BackendUnavailable. There is no in-frontend fallback UI: a frontend that could
 *     draw a chooser would be a frontend that has to know about cards, and the split
 *     would be decorative.
 *
 *  Sketch only; nothing here is implemented.
 */

#define SMARTCARD_PORTAL_DIR_ENV "SMARTCARD_PORTAL_DIR"
#define SMARTCARD_PORTAL_SUBDIR "smartcard-portal"
#define SMARTCARD_PORTAL_FILE_SUFFIX ".portal"

/** One installed backend, as read from a *.portal file. */
typedef struct
{
	char* source;    /**< the *.portal basename, for diagnostics and for portals.conf */
	char* dbus_name; /**< DBusName */
	char** interfaces; /**< Interfaces */
	char** use_in;   /**< UseIn, legacy */
} SmartcardImplConfig;

typedef struct SmartcardPortalConfig SmartcardPortalConfig;

/** Scan the portal directories and load the configuration. Done once at startup and on
 *  demand when a directory changes; a backend installed later is picked up without
 *  restarting the frontend. */
SmartcardPortalConfig* smartcard_portal_config_load(void);

/** The backend to use for @interface, or NULL if the configuration says "none" or
 *  nothing implements it. Follows the documented order: the desktop-specific config
 *  file, then the generic one, then the legacy UseIn matching, then -- with a warning,
 *  exactly as upstream does -- the first available backend as a last resort. */
const SmartcardImplConfig* smartcard_portal_config_find(SmartcardPortalConfig* config,
                                                        const char* interface);

/** The proxy for the selected backend, activating it if necessary. D-Bus activation is
 *  the whole point: a backend is not running until someone needs a window drawn.
 *
 *  The frontend WATCHES the name. If the backend vanishes, every grant it was holding a
 *  token session for is dead: the frontend invalidates them with reason "backend_gone"
 *  rather than leaving a caller holding a handle to nothing. */
GDBusProxy* smartcard_portal_impl_proxy(SmartcardPortalConfig* config, const char* interface,
                                        GError** error);

#endif /* SMARTCARD_FRONTEND_PORTAL_IMPL_H */
