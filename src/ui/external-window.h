/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 * SPDX-FileCopyrightText: 2016 Red Hat, Inc.
 *
 * xdg-desktop-portal-certificate
 *
 * Derived from xdg-desktop-portal-gtk's src/externalwindow*.c and from
 * libgxdp's gxdp-external-window*.c, by Jonas Ådahl.
 */
#ifndef CERTIFICATE_UI_EXTERNAL_WINDOW_H
#define CERTIFICATE_UI_EXTERNAL_WINDOW_H

#include <gtk/gtk.h>

/** @file
 *  Parenting one of this backend's windows to the application window that
 *  provoked it, from the portal window-identifier string.
 *
 *  AN INVALID OR EXPIRED PARENT MUST NOT FAIL THE REQUEST. Every failure here
 *  degrades to an unparented, service-controlled window, which is what the
 *  chooser has to be able to draw anyway: a caller may legitimately pass "".
 *  A backend that refused to ask for consent because a window handle had gone
 *  stale would be a backend that fails closed in the one place where failing
 *  closed means the user cannot sign in.
 */

/** Realize @window, parent it to @parent_window, and present it.
 *  @parent_window uses the portal convention: "wayland:<xdg_foreign handle>",
 *  "x11:<hex XID>", or "" for none. @activation_token authorises focus; a
 *  background caller without one does not steal it. */
void certificate_external_window_present(GtkWindow* window, const char* parent_window,
                                         const char* activation_token);

#endif /* CERTIFICATE_UI_EXTERNAL_WINDOW_H */
