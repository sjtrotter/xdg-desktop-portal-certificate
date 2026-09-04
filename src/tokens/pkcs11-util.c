/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "pkcs11-util.h"

#include <string.h>

#include "../redact.h"

G_DEFINE_QUARK(certificate-pkcs11-error, certificate_pkcs11_error)

CertificatePkcs11ErrorCode certificate_pkcs11_error_code(CK_RV rv)
{
	switch (rv)
	{
		case CKR_PIN_INCORRECT:
		case CKR_PIN_INVALID:
		case CKR_PIN_LEN_RANGE:
			return CERTIFICATE_PKCS11_ERROR_PIN_INCORRECT;
		case CKR_PIN_LOCKED:
			return CERTIFICATE_PKCS11_ERROR_PIN_LOCKED;
		case CKR_TOKEN_NOT_PRESENT:
		case CKR_DEVICE_REMOVED:
		case CKR_SESSION_HANDLE_INVALID:
			return CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED;
		case CKR_CANCEL:
		case CKR_FUNCTION_CANCELED:
			return CERTIFICATE_PKCS11_ERROR_CANCELLED;
		case CKR_MECHANISM_INVALID:
		case CKR_MECHANISM_PARAM_INVALID:
		case CKR_FUNCTION_NOT_SUPPORTED:
			return CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED;
		default:
			return CERTIFICATE_PKCS11_ERROR_FAILED;
	}
}

void certificate_pkcs11_set_error(GError** error, CK_RV rv, const char* what)
{
	g_autofree char* text = NULL;

	/* p11_kit_strerror() is a library string and OpenSC has been seen to put a
	 * PKCS#11 URI into one. It goes through the redactor like every other
	 * library message; see src/redact.h. */
	text = certificate_redact_error_text(p11_kit_strerror(rv));

	g_set_error(error, CERTIFICATE_PKCS11_ERROR, certificate_pkcs11_error_code(rv),
	            "%s: %s (0x%lx)", what != NULL ? what : "PKCS#11 call failed", text,
	            (unsigned long) rv);
}

char* certificate_pkcs11_string(const CK_UTF8CHAR* field, gsize size)
{
	g_autofree char* raw = NULL;

	if (field == NULL || size == 0)
		return g_strdup("");

	raw = p11_kit_space_strdup(field, size);
	if (raw == NULL)
		return g_strdup("");

	/* A token is a device and its strings come off a wire. Anything that is not
	 * valid UTF-8 is replaced rather than passed on to a GVariant, which would
	 * abort, or to a label, which would render as mojibake. */
	if (!g_utf8_validate(raw, -1, NULL))
	{
		char* clean = g_utf8_make_valid(raw, -1);
		return clean;
	}

	return g_steal_pointer(&raw);
}

GByteArray* certificate_pkcs11_get_attribute(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                             CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type)
{
	CK_ATTRIBUTE attribute = { type, NULL, 0 };
	GByteArray* value = NULL;
	CK_RV rv;

	rv = module->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK || attribute.ulValueLen == (CK_ULONG) -1 || attribute.ulValueLen == 0)
		return NULL;

	value = g_byte_array_sized_new(attribute.ulValueLen);
	g_byte_array_set_size(value, attribute.ulValueLen);
	attribute.pValue = value->data;

	rv = module->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK)
	{
		g_byte_array_unref(value);
		return NULL;
	}

	g_byte_array_set_size(value, attribute.ulValueLen);
	return value;
}

gboolean certificate_pkcs11_get_bool(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                                     gboolean fallback)
{
	CK_BBOOL value = CK_FALSE;
	CK_ATTRIBUTE attribute = { type, &value, sizeof(value) };

	if (module->C_GetAttributeValue(session, object, &attribute, 1) != CKR_OK)
		return fallback;

	return value != CK_FALSE;
}

gboolean certificate_pkcs11_get_ulong(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                                      CK_ULONG* out)
{
	CK_ULONG value = 0;
	CK_ATTRIBUTE attribute = { type, &value, sizeof(value) };

	if (module->C_GetAttributeValue(session, object, &attribute, 1) != CKR_OK)
		return FALSE;

	if (out != NULL)
		*out = value;

	return TRUE;
}

GArray* certificate_pkcs11_find_objects(CK_FUNCTION_LIST* module, CK_SESSION_HANDLE session,
                                        CK_ATTRIBUTE* template_, CK_ULONG count, GError** error)
{
	GArray* handles = NULL;
	CK_RV rv;

	rv = module->C_FindObjectsInit(session, template_, count);
	if (rv != CKR_OK)
	{
		certificate_pkcs11_set_error(error, rv, "C_FindObjectsInit");
		return NULL;
	}

	handles = g_array_new(FALSE, FALSE, sizeof(CK_OBJECT_HANDLE));

	for (;;)
	{
		CK_OBJECT_HANDLE batch[32];
		CK_ULONG found = 0;

		rv = module->C_FindObjects(session, batch, G_N_ELEMENTS(batch), &found);
		if (rv != CKR_OK)
		{
			certificate_pkcs11_set_error(error, rv, "C_FindObjects");
			g_array_unref(handles);
			module->C_FindObjectsFinal(session);
			return NULL;
		}

		if (found == 0)
			break;

		g_array_append_vals(handles, batch, found);

		if (found < G_N_ELEMENTS(batch))
			break;
	}

	module->C_FindObjectsFinal(session);
	return handles;
}

gboolean certificate_pkcs11_has_mechanism(CK_FUNCTION_LIST* module, CK_SLOT_ID slot,
                                          CK_MECHANISM_TYPE mechanism)
{
	g_autofree CK_MECHANISM_TYPE* list = NULL;
	CK_ULONG count = 0;

	if (module->C_GetMechanismList(slot, NULL, &count) != CKR_OK || count == 0)
		return FALSE;

	list = g_new0(CK_MECHANISM_TYPE, count);
	if (module->C_GetMechanismList(slot, list, &count) != CKR_OK)
		return FALSE;

	for (CK_ULONG i = 0; i < count; i++)
	{
		if (list[i] == mechanism)
			return TRUE;
	}

	return FALSE;
}
