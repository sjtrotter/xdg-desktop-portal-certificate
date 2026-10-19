/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_ADAPTER_H
#define XCC_ADAPTER_H
#include "core.h"
#include "../tokens/discovery.h"

G_BEGIN_DECLS
/* Keep wire validation precedence without admitting variants to the typed API. */
XCC_API XccErrorCode xcc_session_check_principal(XccSession*, const XccPrincipal*);
XCC_API XccRequest* xcc_sign_async_parsed(XccSession*, const XccSignSpec*, bool valid_parameters,
										  XccDone, void*);
/* Repository-only compatibility bridge, not installed as SDK. */
XCC_API XccContext* xcc_context_new_for_tokens(const XccConfig*, const XccUiV1*, const XccDispatch*,
											   XccError*, CertificateTokens*);
XCC_API const CertificateCandidate* xcc_candidate_internal(const XccCandidate*);
XCC_API void xcc_adapter_settings(bool verbose, uint32_t login_timeout);
G_END_DECLS

#endif
