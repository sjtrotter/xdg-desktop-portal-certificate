/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_UI_ROUTING_H
#define XCC_UI_ROUTING_H
#include <gio/gio.h>

/* Only core sessions mark cancellables; wire options never reach this flag. */
static inline gboolean xcc_cancellable_is_handler(GCancellable* cancellable)
{
	return cancellable != NULL &&
		   g_object_get_data(G_OBJECT(cancellable), "xcc-handler-ui") != NULL;
}

static inline void xcc_cancellable_set_handler(GCancellable* cancellable, gboolean handler)
{
	g_object_set_data(G_OBJECT(cancellable), "xcc-handler-ui", GINT_TO_POINTER(handler));
}

#endif
