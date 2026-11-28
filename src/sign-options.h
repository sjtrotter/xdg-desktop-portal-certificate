/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef CERTIFICATE_SIGN_OPTIONS_H
#define CERTIFICATE_SIGN_OPTIONS_H
#include <gio/gio.h>
#include "core/core.h"

typedef struct
{
	XccSignSpec spec;
	GVariant *mechanism, *parameters, *payload, *hash, *mgf, *encoding;
	gboolean valid_parameters;
} CertificateSignOptions;

gboolean certificate_sign_options_parse(GVariant*, CertificateSignOptions*);
void certificate_sign_options_clear(CertificateSignOptions*);
GVariant* certificate_sign_results(const XccResult*);
#endif
