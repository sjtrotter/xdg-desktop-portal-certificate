/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
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

/* Whether an already open device is the one this candidate needs. The
 * certificate id is the SHA-256 of the DER, so two candidates compare equal
 * only when they are the same certificate, and the token comparison catches the
 * same certificate present on two cards. */
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
			return TRUE;

		/* A DIFFERENT CREDENTIAL, SO A DIFFERENT SESSION. The grant this device
		 * was opened for has been replaced -- a second AcquireCredential on a
		 * live session, which the interface permits -- and everything the old
		 * one left behind is wrong for the new one: the private key handle
		 * belongs to the previous certificate, the login state was spent on it,
		 * and the token may not even be the same card. Logging out and closing
		 * here is what makes the next operation prompt for the PIN and sign
		 * with the key the application was told about. */
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

	/* A protected authentication path gets a NULL PIN: the token or the reader
	 * collects the secret and this process never sees it. */
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

	/* Some tokens only reveal the private key object once the session is
	 * authenticated, so this is the second and decisive attempt to find it. */
	if (device->private_key == CK_INVALID_HANDLE)
		find_private_key(device, candidate);

	return TRUE;
}

GBytes* certificate_device_perform(CertificateDevice* device, gboolean decrypt,
                                   CertificateMechanism* mechanism, GBytes* payload,
                                   GError** error)
{
	CK_MECHANISM ck_mechanism;
	gsize payload_size = 0;
	const guint8* bytes = g_bytes_get_data(payload, &payload_size);
	g_autofree CK_BYTE* buffer = NULL;
	CK_ULONG length = 0;
	CK_RV rv;

	if (device->module == NULL)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		return NULL;
	}

	if (device->private_key == CK_INVALID_HANDLE)
	{
		/* NOT "token removed". The card is in the reader; what is missing is a
		 * private key object for this certificate, which is a different thing
		 * to tell a user and must not invalidate the grant as though the
		 * hardware had gone. */
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR,
		                    CERTIFICATE_PKCS11_ERROR_NO_PRIVATE_KEY,
		                    "No private key is available on this token");
		return NULL;
	}

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

	/* Length first, then the value: the module is the authority on how big its
	 * answer is, and a fixed buffer here would be a truncation bug on the first
	 * key size nobody thought of. */
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
	/* Cleared whether or not a module was ever loaded, so that a device that
	 * failed to open cannot be mistaken for one bound to the candidate it
	 * failed on. */
	g_clear_pointer(&device->candidate, certificate_candidate_unref);

	if (device->module == NULL)
		return;

	if (device->session != CK_INVALID_HANDLE)
	{
		/* C_Logout is issued because the token may honour it. NOTHING HERE MAY
		 * CLAIM THE CARD HAS FORGOTTEN. */
		if (device->logged_in)
			device->module->C_Logout(device->session);

		device->module->C_CloseSession(device->session);
	}

	device->module = NULL;
	device->session = CK_INVALID_HANDLE;
	device->private_key = CK_INVALID_HANDLE;
	device->logged_in = FALSE;
}
