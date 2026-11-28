/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef CERTIFICATE_HANDLER_IMPL_H
#define CERTIFICATE_HANDLER_IMPL_H
#include "certificate-impl.h"
#include "core/ui.h"

typedef struct CertificateHandler CertificateHandler;
#define CERTIFICATE_HANDLER_INTERFACE "org.freedesktop.handler.portal.experimental.Certificate1"

CertificateHandler* certificate_handler_new(CertificateImpl*, GDBusConnection*, GError**);
void certificate_handler_free(CertificateHandler*);
void certificate_handler_owner_changed(CertificateHandler*);
void certificate_handler_session_closed(CertificateHandler*, CertificateImplSession*, const char*);
void certificate_handler_session_invalidated(CertificateHandler*, CertificateImplSession*,
											 const char*);
void certificate_handler_chooser(CertificateHandler*, XccUiId, const XccChooserView*);
void certificate_handler_ui_closed(CertificateHandler*, XccUiId);
/* Test hook; production callers use the 300 second default. */
void certificate_handler_set_chooser_timeout_for_tests(CertificateHandler*, guint milliseconds);
#endif
