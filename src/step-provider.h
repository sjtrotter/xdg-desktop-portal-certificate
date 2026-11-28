/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef CERTIFICATE_STEP_PROVIDER_H
#define CERTIFICATE_STEP_PROVIDER_H
#include "handler-impl.h"
typedef struct CertificateStepProvider CertificateStepProvider;
CertificateStepProvider* certificate_step_provider_new(XccContext*, CertificateHandler*);
void certificate_step_provider_free(CertificateStepProvider*);
#endif
