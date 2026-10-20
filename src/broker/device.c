/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "device.h"

#include <string.h>

static void find_private_key(CertificateDevice* device, const CertificateCandidate* candidate)
{
	CK_OBJECT_CLASS private_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE template_[2];
	g_autoptr(GArray) keys = NULL;

	template_[0].type = CKA_CLASS;
	template_[0].pValue = &private_class;
	template_[0].ulValueLen = sizeof(private_class);
	template_[1].type = CKA_ID;
	template_[1].pValue = candidate->cka_id->data;
	template_[1].ulValueLen = candidate->cka_id->len;

	keys = certificate_pkcs11_find_objects(device->module, device->session, template_, 2, NULL);
	if (keys != NULL && keys->len > 0)
		device->private_key = g_array_index(keys, CK_OBJECT_HANDLE, 0);
}

/* Certificate hashes and token identities must both match before reusing a device. */
static gboolean device_is_bound_to(const CertificateDevice* device,
                                   const CertificateCandidate* candidate)
{
	if (device->candidate == NULL || candidate == NULL)
		return FALSE;

	return g_strcmp0(device->candidate->certificate_id, candidate->certificate_id) == 0 &&
	       certificate_token_same(device->candidate->token, candidate->token);
}

gboolean certificate_device_open(CertificateDevice* device, CertificateTokens* tokens,
                                 const CertificateCandidate* candidate, GError** error)
{
	if (device->module != NULL)
	{
		if (device_is_bound_to(device, candidate))
			return certificate_device_refresh_login(device, error);

		/* A replacement credential requires a fresh session and login. */
		certificate_device_close(device);
	}

	device->private_key = CK_INVALID_HANDLE;
	device->session = CK_INVALID_HANDLE;

	if (!certificate_tokens_open_session(tokens, candidate->token, &device->module,
	                                     &device->session, error))
	{
		device->module = NULL;
		return FALSE;
	}

	device->logged_in = FALSE;
	device->candidate = certificate_candidate_ref((CertificateCandidate*) candidate);
	find_private_key(device, candidate);

	return certificate_device_refresh_login(device, error);
}

gboolean certificate_device_refresh_login(CertificateDevice* device, GError** error)
{
	CK_SESSION_INFO info;
	CK_RV rv;
	gboolean logged_in;

	if (device->module == NULL || device->session == CK_INVALID_HANDLE)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		return FALSE;
	}

	rv = device->module->C_GetSessionInfo(device->session, &info);
	if (rv != CKR_OK)
	{
		certificate_pkcs11_set_error(error, rv, "C_GetSessionInfo");
		return FALSE;
	}

	logged_in = info.state == CKS_RO_USER_FUNCTIONS || info.state == CKS_RW_USER_FUNCTIONS;
	if (device->logged_in && !logged_in)
		device->private_key = CK_INVALID_HANDLE;
	device->logged_in = logged_in;

	if (logged_in && device->private_key == CK_INVALID_HANDLE)
		find_private_key(device, device->candidate);

	return TRUE;
}

gboolean certificate_device_login(CertificateDevice* device,
                                  const CertificateCandidate* candidate, const char* pin,
                                  GError** error)
{
	CK_RV rv;

	if (device->module == NULL || device->session == CK_INVALID_HANDLE)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		return FALSE;
	}

	/* A NULL PIN selects the token's protected authentication path. */
	rv = device->module->C_Login(device->session, CKU_USER,
	                             pin != NULL ? (CK_UTF8CHAR_PTR) pin : NULL,
	                             pin != NULL ? (CK_ULONG) strlen(pin) : 0);

	if (rv == CKR_USER_ALREADY_LOGGED_IN)
		rv = CKR_OK;

	if (rv != CKR_OK)
	{
		certificate_pkcs11_set_error(error, rv, "C_Login");
		return FALSE;
	}

	device->logged_in = TRUE;

	/* Some tokens expose private keys only after login. */
	if (device->private_key == CK_INVALID_HANDLE)
		find_private_key(device, candidate);

	return TRUE;
}

gboolean certificate_device_login_context(CertificateDevice* device, const char* pin,
                                          GError** error)
{
	CK_RV rv;

	if (device->module == NULL || device->session == CK_INVALID_HANDLE)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		return FALSE;
	}

	rv = device->module->C_Login(device->session, CKU_CONTEXT_SPECIFIC,
	                             pin != NULL ? (CK_UTF8CHAR_PTR) pin : NULL,
	                             pin != NULL ? (CK_ULONG) strlen(pin) : 0);
	if (rv != CKR_OK)
	{
		certificate_pkcs11_set_error(error, rv, "C_Login");
		return FALSE;
	}

	return TRUE;
}

GBytes* certificate_device_perform(CertificateDevice* device, gboolean decrypt,
                                   CertificateMechanism* mechanism, GBytes* payload,
                                   CertificateDeviceAuthenticate authenticate, gpointer auth_data,
                                   GError** error)
{
	CK_MECHANISM ck_mechanism;
	gsize payload_size = 0;
	const guint8* bytes = g_bytes_get_data(payload, &payload_size);
	g_autofree CK_BYTE* buffer = NULL;
	CK_ULONG length = 0;
	CK_RV rv;
	gboolean always_authenticate;

	if (device->module == NULL)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		return NULL;
	}

	if (device->private_key == CK_INVALID_HANDLE)
	{
		/* A missing private key does not imply token removal. */
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_NO_PRIVATE_KEY,
		                    "No private key is available on this token");
		return NULL;
	}

	always_authenticate = certificate_pkcs11_get_bool(device->module, device->session,
	                                                  device->private_key,
	                                                  CKA_ALWAYS_AUTHENTICATE, FALSE);
	certificate_mechanism_to_ck(mechanism, &ck_mechanism);

	if (decrypt)
		rv = device->module->C_DecryptInit(device->session, &ck_mechanism, device->private_key);
	else
		rv = device->module->C_SignInit(device->session, &ck_mechanism, device->private_key);

	if (rv != CKR_OK)
	{
		certificate_pkcs11_set_error(error, rv, decrypt ? "C_DecryptInit" : "C_SignInit");
		return NULL;
	}

	if (always_authenticate)
	{
		if (authenticate == NULL)
			g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
			                    CERTIFICATE_PKCS11_ERROR_FAILED,
			                    "Key requires authentication for this operation");

		if (authenticate == NULL || !authenticate(auth_data, error))
		{
			/* Closing the session discards the initialized operation and any late authentication. */
			certificate_device_close(device);
			return NULL;
		}
	}

	if (decrypt)
		rv = device->module->C_Decrypt(device->session, (CK_BYTE_PTR) bytes,
		                               (CK_ULONG) payload_size, NULL, &length);
	else
		rv = device->module->C_Sign(device->session, (CK_BYTE_PTR) bytes,
		                            (CK_ULONG) payload_size, NULL, &length);

	if (rv != CKR_OK)
	{
		certificate_pkcs11_set_error(error, rv, decrypt ? "C_Decrypt" : "C_Sign");
		return NULL;
	}

	buffer = g_malloc0(length);

	if (decrypt)
		rv = device->module->C_Decrypt(device->session, (CK_BYTE_PTR) bytes,
		                               (CK_ULONG) payload_size, buffer, &length);
	else
		rv = device->module->C_Sign(device->session, (CK_BYTE_PTR) bytes,
		                            (CK_ULONG) payload_size, buffer, &length);

	if (rv != CKR_OK)
	{
		certificate_pkcs11_set_error(error, rv, decrypt ? "C_Decrypt" : "C_Sign");
		return NULL;
	}

	return g_bytes_new(buffer, length);
}

void certificate_device_close(CertificateDevice* device)
{
	g_clear_pointer(&device->candidate, certificate_candidate_unref);

	if (device->module == NULL)
		return;

	if (device->session != CK_INVALID_HANDLE)
	{
		/* C_Logout would also revoke other grants' sessions on this token. */
		device->module->C_CloseSession(device->session);
	}

	device->module = NULL;
	device->session = CK_INVALID_HANDLE;
	device->private_key = CK_INVALID_HANDLE;
	device->logged_in = FALSE;
}
