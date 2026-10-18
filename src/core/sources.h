/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_SOURCES_H
#define XCC_SOURCES_H
#include <glib.h>

G_BEGIN_DECLS
guint xcc_idle_add(GMainContext*, GSourceFunc, void*, GDestroyNotify);
guint xcc_timeout_add(guint, GSourceFunc, void*);
void xcc_source_remove(guint);
G_END_DECLS

#endif
