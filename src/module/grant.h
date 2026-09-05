/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_GRANT_H
#define PKCS11_PORTAL_GRANT_H

#include <glib.h>

/** What one AcquireCredential returned. No key material, no PIN, no PKCS#11
 *  handle: this is the whole of what the module knows about the credential. */
typedef struct
{
	char* session_handle;         /**< the Session object path; the grant handle */
	char* grant_id;               /**< a log identifier, never passed back */
	GBytes* certificate_der;      /**< the chosen leaf */
	char* key_type;               /**< "RSA" or "EC" */
	guint key_size;               /**< modulus bits, or curve size */
	char* key_curve;              /**< curve name for EC, or NULL */
	GStrv supported_mechanisms;   /**< the grant's own list, already clamped */
	gboolean may_sign;
	gboolean may_decrypt;
	gint64 expires_at;
} PortalGrant;

void portal_grant_free(PortalGrant* grant);

#define PKCS11_PORTAL_ERROR (portal_module_error_quark())
GQuark portal_module_error_quark(void);

typedef enum
{
	PKCS11_PORTAL_ERROR_FAILED,
	/** The user cancelled, or policy refused. Not retried immediately. */
	PKCS11_PORTAL_ERROR_CANCELLED,
	/** No portal, or the experimental gate is off. Never an error to report to
	 *  an application: it means this token is not present. */
	PKCS11_PORTAL_ERROR_UNAVAILABLE,
	/** The grant went away: expiry, token removal, a dead backend. */
	PKCS11_PORTAL_ERROR_INVALIDATED,
	PKCS11_PORTAL_ERROR_TIMEOUT
} PortalModuleErrorCode;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PortalGrant, portal_grant_free)

#endif /* PKCS11_PORTAL_GRANT_H */
