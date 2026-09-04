/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_TESTS_FIXTURE_UTIL_H
#define CERTIFICATE_TESTS_FIXTURE_UTIL_H

#include <glib.h>
#include <gnutls/gnutls.h>

#include "tokens/discovery.h"

/** Load a PEM fixture from tests/fixtures and build the candidate the discovery
 *  code would have built from a token holding it. @key_type, @can_sign and
 *  @can_decrypt stand in for what a real token would have said about the
 *  private key, because a fixture file has no token behind it. */
CertificateCandidate* certificate_test_candidate(const char* name, gboolean can_sign,
                                                 gboolean can_decrypt);

/** Attach a fake token, so that the token_label and piv_slot filter fields have
 *  something to match against. */
void certificate_test_attach_token(CertificateCandidate* candidate, const char* label,
                                   const char* piv_slot);

/** Verify @signature over @digest with GnuTLS, FROM THE CERTIFICATE THE TOKEN
 *  HANDED BACK -- not from the key a fixture script generated. If those two ever
 *  disagree, the wrong key signed, which is the only way a "successful"
 *  signature can be a security defect. Aborts the test if it does not verify.
 *
 *  @ecdsa re-encodes the PKCS#11 r||s pair as an ECDSA-Sig-Value first. */
void certificate_test_verify_signature(CertificateCandidate* candidate,
                                       gnutls_sign_algorithm_t algorithm, const guint8* digest,
                                       gsize digest_length, GBytes* signature, gboolean ecdsa);

#endif /* CERTIFICATE_TESTS_FIXTURE_UTIL_H */
