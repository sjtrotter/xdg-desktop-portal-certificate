/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_TOKENS_PKCS11_UTIL_H
#define CERTIFICATE_TOKENS_PKCS11_UTIL_H

#include <glib.h>

#include <p11-kit/p11-kit.h>
#include <p11-kit/pkcs11.h>

#define CERTIFICATE_PKCS11_ERROR (certificate_pkcs11_error_quark())
GQuark certificate_pkcs11_error_quark(void);

typedef enum
{
	CERTIFICATE_PKCS11_ERROR_FAILED,
	CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT,
	CERTIFICATE_PKCS11_ERROR_PIN_LOCKED,
	CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
	CERTIFICATE_PKCS11_ERROR_CANCELLED,
	CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED,
	/* The token remains present, but its private key is unavailable after login. */
	CERTIFICATE_PKCS11_ERROR_NO_PRIVATE_KEY,
	/* A login timeout stops waiting; the submitted attempt may still consume a retry or succeed. */
	CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT,
	CERTIFICATE_PKCS11_ERROR_NO_DISPLAY
} CertificatePkcs11ErrorCode;

void certificate_pkcs11_set_error(GError** error, CK_RV rv, const char* what);

CertificatePkcs11ErrorCode certificate_pkcs11_error_code(CK_RV rv);

/** Returns valid UTF-8; an all-blank field becomes an empty string. */
char* certificate_pkcs11_string(const CK_UTF8CHAR* field, gsize size);

/** Absent attributes return NULL without setting an error. */
GByteArray* certificate_pkcs11_get_attribute(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                             CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type);

/** Absent attributes use @fallback. */
gboolean certificate_pkcs11_get_bool(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                                     gboolean fallback);

/** Absent attributes return FALSE. */
gboolean certificate_pkcs11_get_ulong(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                                      CK_ULONG* out);

GArray* certificate_pkcs11_find_objects(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                        CK_ATTRIBUTE* template_, CK_ULONG count, GError** error);

gboolean certificate_pkcs11_has_mechanism(CK_FUNCTION_LIST* module, CK_SLOT_ID slot,
                                          CK_MECHANISM_TYPE mechanism);

#endif
