/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_DISPATCH_GLIB_H
#define XCC_DISPATCH_GLIB_H
#include "core.h"

G_BEGIN_DECLS
/* Keep context alive until shutdown completion and all queued callbacks have drained. */
XccDispatch xcc_dispatch_glib(GMainContext* context);
G_END_DECLS

#endif
