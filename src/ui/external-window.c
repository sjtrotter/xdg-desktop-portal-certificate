/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 * SPDX-FileCopyrightText: 2016 Red Hat, Inc.
 *
 * xdg-desktop-portal-certificate
 *
 * Derived from xdg-desktop-portal-gtk's src/externalwindow-wayland.c and
 * src/externalwindow-x11.c and from libgxdp's gxdp-external-window-*.c,
 * by Jonas Ådahl.
 */

#include "external-window.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#if HAVE_GTK_WAYLAND
#include <gdk/wayland/gdkwayland.h>
#endif

#if HAVE_GTK_X11
#include <X11/Xatom.h>
#include <gdk/x11/gdkx.h>
#endif

#define WAYLAND_PREFIX "wayland:"
#define X11_PREFIX "x11:"

#if HAVE_GTK_X11
static void set_x11_parent(GdkSurface* surface, const char* handle)
{
	GdkDisplay* display = gdk_display_get_default();
	Display* xdisplay = NULL;
	Atom window_type;
	Atom dialog;
	unsigned long xid = 0;
	char* end = NULL;

	/* GTK4 lacks a replacement for raw-XID transient parenting. */
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS

	errno = 0;
	xid = strtoul(handle, &end, 16);
	if (errno != 0 || end == handle || *end != '\0' || xid == 0)
	{
		g_warning("parent-window-ignored detail=invalid-x11-handle");
		return;
	}

	xdisplay = gdk_x11_display_get_xdisplay(display);

	XSetTransientForHint(xdisplay, GDK_SURFACE_XID(surface), (Window) xid);

	/* Set window-manager hints directly because GTK4 lacks raw-XID transient parenting. */
	window_type = gdk_x11_get_xatom_by_name_for_display(display, "_NET_WM_WINDOW_TYPE");
	dialog = gdk_x11_get_xatom_by_name_for_display(display, "_NET_WM_WINDOW_TYPE_DIALOG");
	XChangeProperty(xdisplay, GDK_SURFACE_XID(surface), window_type, XA_ATOM, 32, PropModeReplace,
	                (unsigned char*) &dialog, 1);
	G_GNUC_END_IGNORE_DEPRECATIONS
}
#endif

static void set_parent_of(GdkSurface* surface, const char* parent_window)
{
	GdkDisplay* display = gdk_display_get_default();

	if (surface == NULL || parent_window == NULL || *parent_window == '\0')
		return;

#if HAVE_GTK_WAYLAND
	if (GDK_IS_WAYLAND_DISPLAY(display) && g_str_has_prefix(parent_window, WAYLAND_PREFIX))
	{
		if (!gdk_wayland_toplevel_set_transient_for_exported(
		        GDK_TOPLEVEL(surface), parent_window + strlen(WAYLAND_PREFIX)))
			g_debug("Parent window import failed; showing unparented");
		return;
	}
#endif

#if HAVE_GTK_X11
	if (GDK_IS_X11_DISPLAY(display) && g_str_has_prefix(parent_window, X11_PREFIX))
	{
		set_x11_parent(surface, parent_window + strlen(X11_PREFIX));
		return;
	}
#endif

	/* Unsupported display-server handles fall back to an unparented window. */
	g_debug("Parent window type is unsupported; showing unparented");
}

void certificate_external_window_present(GtkWindow* window, const char* parent_window,
                                         const char* activation_token)
{
	GdkSurface* surface = NULL;

	/* Realization must precede parenting because it creates the surface. */
	gtk_widget_realize(GTK_WIDGET(window));

	surface = gtk_native_get_surface(GTK_NATIVE(window));
	set_parent_of(surface, parent_window);

	if (activation_token != NULL && *activation_token != '\0')
	{
		gtk_window_set_startup_id(window, activation_token);
	}

	gtk_window_present(window);
}
