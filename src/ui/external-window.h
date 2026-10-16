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

/** Invalid or expired parent handles must fall back to an unparented backend window. */

/** Parent handles use wayland:<handle>, x11:<hex XID> or empty; activation tokens authorize focus. */
void certificate_external_window_present(GtkWindow* window, const char* parent_window,
                                         const char* activation_token);

#endif
