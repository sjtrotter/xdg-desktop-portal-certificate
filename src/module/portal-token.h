/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

/* Constants are shared with xdg-desktop-portal-webauth/backend/src/tls/portal-token.h; keep their values synchronized. */
#ifndef WEBAUTH_TLS_PORTAL_TOKEN_H
#define WEBAUTH_TLS_PORTAL_TOKEN_H

/** Shared token identity and URI contract; see docs/decisions/0011-client-side-pkcs11-module.md. */

#define XDG_PORTAL_CERTIFICATE_TOKEN_LABEL "Portal Certificate"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER "freedesktop.org"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MODEL "portal-cert"

/** Every object shares the token's constant label so URIs can be built before credential selection. */
#define XDG_PORTAL_CERTIFICATE_OBJECT_LABEL XDG_PORTAL_CERTIFICATE_TOKEN_LABEL

#define XDG_PORTAL_CERTIFICATE_MODULE_CONFIG "xdg-desktop-portal-certificate.module"

#define XDG_PORTAL_CERTIFICATE_TOKEN_URI                                                           \
	"pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate"

/** GnuTLS single-object import requires object= or id=; the constant object label is known before selection. */
#define XDG_PORTAL_CERTIFICATE_OBJECT_URI                                                          \
	XDG_PORTAL_CERTIFICATE_TOKEN_URI ";object=Portal%20Certificate"

#define XDG_PORTAL_CERTIFICATE_CERT_URI XDG_PORTAL_CERTIFICATE_OBJECT_URI ";type=cert"
#define XDG_PORTAL_CERTIFICATE_KEY_URI XDG_PORTAL_CERTIFICATE_OBJECT_URI ";type=private"

#endif
