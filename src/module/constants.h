/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_CONSTANTS_H
#define PKCS11_PORTAL_CONSTANTS_H

#include "portal-token.h"

/* The process-derived token serial must not appear in persistent URIs. */
#define PKCS11_PORTAL_TOKEN_SERIAL_PREFIX "XDP"
#define PKCS11_PORTAL_TOKEN_SERIAL_SIZE 16

#define PKCS11_PORTAL_SLOT_DESCRIPTION "Certificate portal"
#define PKCS11_PORTAL_LIBRARY_DESCRIPTION "Certificate portal PKCS#11"

/* The frontend and backend exclude this module by its library and p11-kit configuration names. */
#define PKCS11_PORTAL_MODULE_BASENAME "libpkcs11-portal-certificate.so"
#define PKCS11_PORTAL_MODULE_NAME "xdg-desktop-portal-certificate"

/* Constant object labels allow consumers to construct URIs before acquisition; see portal-token.h. */
#define PKCS11_PORTAL_OBJECT_LABEL XDG_PORTAL_CERTIFICATE_OBJECT_LABEL
#define PKCS11_PORTAL_URI_OBJECT_ATTRIBUTE ";object=Portal%20Certificate"

#define PKCS11_PORTAL_BUS_NAME "org.freedesktop.portal.Desktop"
#define PKCS11_PORTAL_OBJECT_PATH "/org/freedesktop/portal/desktop"
#define PKCS11_PORTAL_INTERFACE "org.freedesktop.portal.experimental.Certificate1"
#define PKCS11_PORTAL_REQUEST_INTERFACE "org.freedesktop.portal.Request"

#define PKCS11_PORTAL_ENV_PURPOSE "PKCS11_PORTAL_CERTIFICATE_PURPOSE"
#define PKCS11_PORTAL_ENV_LIFETIME "PKCS11_PORTAL_CERTIFICATE_REQUESTED_LIFETIME"
#define PKCS11_PORTAL_ENV_REASON "PKCS11_PORTAL_CERTIFICATE_REASON"
/* The environment supplies the certificate filter because PKCS#11 has no equivalent selection channel. */
#define PKCS11_PORTAL_ENV_KEY_ALGORITHMS "PKCS11_PORTAL_CERTIFICATE_KEY_ALGORITHMS"
#define PKCS11_PORTAL_ENV_TIMEOUT "PKCS11_PORTAL_CERTIFICATE_TIMEOUT_MS"
#define PKCS11_PORTAL_ENV_DISABLE "PKCS11_PORTAL_CERTIFICATE_DISABLE"

/* Class-only enumeration may acquire credentials when explicitly enabled for NSS; see objects.c. */
#define PKCS11_PORTAL_ENV_ENUMERATE "PKCS11_PORTAL_CERTIFICATE_ENUMERATE"

#define PKCS11_PORTAL_DEFAULT_PURPOSE "client_auth"

/* The reason limit matches the frontend's 256-character limit. */
#define PKCS11_PORTAL_REASON_MAX 256

/* Cache refusals briefly to avoid repeated choosers during search loops. */
#define PKCS11_PORTAL_REFUSAL_GRACE_SECONDS 10

#define PKCS11_PORTAL_LOG_DOMAIN "pkcs11-portal-certificate"

#endif
