/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_CONSTANTS_H
#define PKCS11_PORTAL_CONSTANTS_H

#include "portal-token.h"

/** @file
 *  Everything the module needs that is NOT in the shared contract.
 *  portal-token.h holds the names two repositories agreed on; this holds the
 *  ones only this module uses.
 */

/* CK_TOKEN_INFO.serialNumber is 16 bytes. The value is derived from the process
 * so that two processes holding two grants are two tokens; it is not a hardware
 * identifier and names nothing outside this process. It is deliberately NOT in
 * the shared contract: no URI may be written down that depends on it. */
#define PKCS11_PORTAL_TOKEN_SERIAL_PREFIX "XDP"
#define PKCS11_PORTAL_TOKEN_SERIAL_SIZE 16

#define PKCS11_PORTAL_SLOT_DESCRIPTION "Certificate portal"
#define PKCS11_PORTAL_LIBRARY_DESCRIPTION "Certificate portal PKCS#11"

/* The shared object, and the p11-kit module NAME -- which p11-kit derives from
 * the configuration file's basename with the extension removed. Anything that
 * enumerates p11-kit modules and must not load this one -- the certificate
 * backend and the portal frontend above all -- matches on these. */
#define PKCS11_PORTAL_MODULE_BASENAME "libpkcs11-portal-certificate.so"
#define PKCS11_PORTAL_MODULE_NAME "xdg-desktop-portal-certificate"

/* CKA_LABEL IS A CONSTANT AND NOT THE SUBJECT CN, and the reason is in
 * portal-token.h beside the URIs it explains: GnuTLS's single-object import
 * refuses a URI that names no object, and a consumer has to write the URI down
 * before anything has been chosen.
 *
 * The shared contract now carries the attribute itself --
 * XDG_PORTAL_CERTIFICATE_CERT_URI and _KEY_URI are what a single-object import
 * takes, XDG_PORTAL_CERTIFICATE_TOKEN_URI is what an enumerating consumer
 * takes. This is the attribute on its own, for the tests and for anything
 * building a URI a piece at a time. */
#define PKCS11_PORTAL_OBJECT_LABEL XDG_PORTAL_CERTIFICATE_OBJECT_LABEL
#define PKCS11_PORTAL_URI_OBJECT_ATTRIBUTE ";object=Portal%20Certificate"

/* The public portal interface. The module is an ordinary application client of
 * it and never speaks to any impl interface. */
#define PKCS11_PORTAL_BUS_NAME "org.freedesktop.portal.Desktop"
#define PKCS11_PORTAL_OBJECT_PATH "/org/freedesktop/portal/desktop"
#define PKCS11_PORTAL_INTERFACE "org.freedesktop.portal.experimental.Certificate"
#define PKCS11_PORTAL_REQUEST_INTERFACE "org.freedesktop.portal.Request"

#define PKCS11_PORTAL_ENV_PURPOSE "PKCS11_PORTAL_CERTIFICATE_PURPOSE"
#define PKCS11_PORTAL_ENV_REASON "PKCS11_PORTAL_CERTIFICATE_REASON"
#define PKCS11_PORTAL_ENV_OPERATIONS "PKCS11_PORTAL_CERTIFICATE_OPERATIONS"
/* The one certificate_filter field the module offers. A PKCS#11 consumer has no
 * way to say "I can only use an RSA key", and the environment is the only
 * channel a module loaded by p11-kit has. */
#define PKCS11_PORTAL_ENV_KEY_ALGORITHMS "PKCS11_PORTAL_CERTIFICATE_KEY_ALGORITHMS"
#define PKCS11_PORTAL_ENV_TIMEOUT "PKCS11_PORTAL_CERTIFICATE_TIMEOUT_MS"
#define PKCS11_PORTAL_ENV_DISABLE "PKCS11_PORTAL_CERTIFICATE_DISABLE"

/* Opt back into acquiring a credential for a class-only enumeration -- a search
 * that names no object and no key identifier. NSS searches that way and cannot
 * be told to do otherwise; nothing else needs this, and a process that sets it
 * gets choosers that it would not otherwise get. See objects.c. */
#define PKCS11_PORTAL_ENV_ENUMERATE "PKCS11_PORTAL_CERTIFICATE_ENUMERATE"

#define PKCS11_PORTAL_DEFAULT_PURPOSE "client_auth"

/* The frontend truncates `reason` at 256 characters; so does this. */
#define PKCS11_PORTAL_REASON_MAX 256

/* How long a refusal is remembered, so that an application searching in a loop
 * does not put the chooser up again immediately. */
#define PKCS11_PORTAL_REFUSAL_GRACE_SECONDS 10

#define PKCS11_PORTAL_LOG_DOMAIN "pkcs11-portal-certificate"

#endif /* PKCS11_PORTAL_CONSTANTS_H */
