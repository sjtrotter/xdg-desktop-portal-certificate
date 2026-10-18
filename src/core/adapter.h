/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_ADAPTER_H
#define XCC_ADAPTER_H
#include "core.h"

G_BEGIN_DECLS
/* Keep wire validation precedence without admitting variants to the typed API. */
XccErrorCode xcc_session_check_principal(XccSession*, const XccPrincipal*);
XccRequest* xcc_sign_async_parsed(XccSession*, const XccSignSpec*, bool valid_parameters, XccDone,
								  void*);
G_END_DECLS

#endif
