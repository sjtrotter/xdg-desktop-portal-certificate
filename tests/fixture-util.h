/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_TESTS_FIXTURE_UTIL_H
#define CERTIFICATE_TESTS_FIXTURE_UTIL_H

#include <glib.h>
#include <gnutls/gnutls.h>

#include "tokens/discovery.h"

CertificateCandidate* certificate_test_candidate(const char* name, gboolean can_sign,
                                                 gboolean can_decrypt);

void certificate_test_attach_token(CertificateCandidate* candidate, const char* label,
                                   const char* piv_slot);

/* Verify using the returned certificate; @ecdsa converts r||s to DER first. */
void certificate_test_verify_signature(CertificateCandidate* candidate,
                                       gnutls_sign_algorithm_t algorithm, const guint8* digest,
                                       gsize digest_length, GBytes* signature, gboolean ecdsa);

#endif
