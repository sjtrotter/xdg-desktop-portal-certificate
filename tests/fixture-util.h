/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_TESTS_FIXTURE_UTIL_H
#define CERTIFICATE_TESTS_FIXTURE_UTIL_H

#include <glib.h>

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

#endif /* CERTIFICATE_TESTS_FIXTURE_UTIL_H */
