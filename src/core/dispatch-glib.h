/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_DISPATCH_GLIB_H
#define XCC_DISPATCH_GLIB_H
#include "core.h"
#include <glib.h>

G_BEGIN_DECLS
/* Optional bridge: requires glib-2.0 development headers.
 * Keep context alive until shutdown completion and all queued callbacks have drained. */
XCC_API XccDispatch xcc_dispatch_glib(GMainContext* context);
G_END_DECLS

#endif
