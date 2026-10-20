/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_GRANT_H
#define PKCS11_PORTAL_GRANT_H

#include <glib.h>

typedef struct
{
	char* session_handle;
	GBytes* certificate_der;
	char* key_type;               /**< RSA or EC. */
	guint key_size;               /**< RSA modulus bits or EC curve size. */
	char* key_curve;              /**< NULL for RSA. */
	GStrv supported_mechanisms;   /**< Grant mechanism list after frontend restrictions. */
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
	/** User or policy refusal is not retried immediately. */
	PKCS11_PORTAL_ERROR_CANCELLED,
	/** An unavailable portal presents as an absent token. */
	PKCS11_PORTAL_ERROR_UNAVAILABLE,
	PKCS11_PORTAL_ERROR_INVALIDATED,
	PKCS11_PORTAL_ERROR_TIMEOUT,
	PKCS11_PORTAL_ERROR_PIN_LOCKED,
	PKCS11_PORTAL_ERROR_DEVICE,
	PKCS11_PORTAL_ERROR_LOGIN_REQUIRED,
	PKCS11_PORTAL_ERROR_INVALID_REQUEST
} PortalModuleErrorCode;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PortalGrant, portal_grant_free)

#endif
