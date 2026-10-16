/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#ifndef WEBAUTH_TLS_PORTAL_TOKEN_H
#define WEBAUTH_TLS_PORTAL_TOKEN_H

/* Identical copies: xdg-desktop-portal-certificate src/module/portal-token.h and
 * xdg-desktop-portal-webauth src/tls/portal-token.h. Change both together. */

/** Identity of the single token the certificate portal's PKCS#11 module exposes. The token
 *  sets CKF_PROTECTED_AUTHENTICATION_PATH: the portal collects the PIN, and a consumer must
 *  never ask for it. */

#define XDG_PORTAL_CERTIFICATE_TOKEN_LABEL "Portal Certificate"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER "freedesktop.org"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MODEL "portal-cert"

/** Paired objects share CKA_ID and use the token label as CKA_LABEL so consumers can name them before selection. */
#define XDG_PORTAL_CERTIFICATE_OBJECT_LABEL XDG_PORTAL_CERTIFICATE_TOKEN_LABEL

/** Installed in $XDG_CONFIG_HOME/pkcs11/modules or $datadir/p11-kit/modules. */
#define XDG_PORTAL_CERTIFICATE_MODULE_CONFIG "xdg-desktop-portal-certificate.module"

/** Token URI for enumeration, using p11-kit percent encoding. */
#define XDG_PORTAL_CERTIFICATE_TOKEN_URI                                                           \
	"pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate"

/** GnuTLS single-object import requires object= or id= in addition to token identity. */
#define XDG_PORTAL_CERTIFICATE_OBJECT_URI                                                          \
	XDG_PORTAL_CERTIFICATE_TOKEN_URI ";object=Portal%20Certificate"

#define XDG_PORTAL_CERTIFICATE_CERT_URI XDG_PORTAL_CERTIFICATE_OBJECT_URI ";type=cert"
#define XDG_PORTAL_CERTIFICATE_KEY_URI XDG_PORTAL_CERTIFICATE_OBJECT_URI ";type=private"

#endif /* WEBAUTH_TLS_PORTAL_TOKEN_H */
