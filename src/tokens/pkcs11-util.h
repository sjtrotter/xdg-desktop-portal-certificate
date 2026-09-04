/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_TOKENS_PKCS11_UTIL_H
#define CERTIFICATE_TOKENS_PKCS11_UTIL_H

#include <glib.h>

#include <p11-kit/p11-kit.h>
#include <p11-kit/pkcs11.h>

/** @file
 *  The thin layer between PKCS#11's calling convention and GLib's.
 *
 *  Nothing here makes a policy decision. It exists so that the rest of the
 *  backend never has to write the two-call length-then-value dance, and so that
 *  every CK_RV turns into a GError with a message that has already been through
 *  src/redact.h.
 */

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
	/* The token is present and the session is open, but the private key object
	 * for this certificate cannot be seen even after logging in. Distinct from
	 * TOKEN_REMOVED, which used to carry it: reporting a card that is sitting
	 * in the reader as removed made the backend emit
	 * SessionInvalidated("token_removed") about healthy hardware. */
	CERTIFICATE_PKCS11_ERROR_NO_PRIVATE_KEY,
	/* C_Login was submitted and the module has not answered within the login
	 * timeout. Distinct from FAILED because the attempt may still be spent and
	 * may still succeed: PKCS#11 cannot withdraw a submitted login, so this
	 * says "we stopped waiting", not "the token said no". */
	CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT
} CertificatePkcs11ErrorCode;

/** Turn @rv into a GError. The message is p11_kit_strerror()'s, already passed
 *  through certificate_redact_error_text(). */
void certificate_pkcs11_set_error(GError** error, CK_RV rv, const char* what);

/** CKR_* to the error code above. CKR_PIN_INCORRECT, CKR_PIN_LOCKED and the
 *  removal codes are distinguished deliberately: collapsing them is how a user
 *  blocks a card while being told "authentication failed". */
CertificatePkcs11ErrorCode certificate_pkcs11_error_code(CK_RV rv);

/** A CK_UTF8CHAR blank-padded field as a trimmed, valid-UTF-8 C string. Never
 *  returns NULL; returns "" for an all-blank field. */
char* certificate_pkcs11_string(const CK_UTF8CHAR* field, gsize size);

/** Read one attribute, doing the length-then-value dance. Returns NULL and sets
 *  no error when the object simply does not have the attribute, which is normal
 *  and not a failure. */
GByteArray* certificate_pkcs11_get_attribute(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                             CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type);

/** Read a CK_BBOOL attribute, defaulting to @fallback when it is absent. */
gboolean certificate_pkcs11_get_bool(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                                     gboolean fallback);

/** Read a CK_ULONG attribute. Returns FALSE when it is absent. */
gboolean certificate_pkcs11_get_ulong(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                                      CK_ULONG* out);

/** C_FindObjects over a whole template, collecting every handle. */
GArray* certificate_pkcs11_find_objects(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                        CK_ATTRIBUTE* template_, CK_ULONG count, GError** error);

/** Whether the token in @slot advertises @mechanism. */
gboolean certificate_pkcs11_has_mechanism(CK_FUNCTION_LIST* module, CK_SLOT_ID slot,
                                          CK_MECHANISM_TYPE mechanism);

#endif /* CERTIFICATE_TOKENS_PKCS11_UTIL_H */
