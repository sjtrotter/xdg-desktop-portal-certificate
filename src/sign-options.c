/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "sign-options.h"
#include <string.h>

static gboolean take(GVariant* options, const char* key, const GVariantType* type, GVariant** value)
{
	*value = g_variant_lookup_value(options, key, NULL);
	return *value == NULL || g_variant_is_of_type(*value, type);
}

gboolean certificate_sign_options_parse(GVariant* options, CertificateSignOptions* parsed)
{
	XccSignSpec* spec = &parsed->spec;
	*spec = (XccSignSpec){.struct_size = sizeof(*spec), .abi_version = XCC_ABI_VERSION};
	if (!take(options, "mechanism", G_VARIANT_TYPE_STRING, &parsed->mechanism) ||
		parsed->mechanism == NULL ||
		!take(options, "parameters", G_VARIANT_TYPE_VARDICT, &parsed->parameters) ||
		!take(options, "data", G_VARIANT_TYPE_BYTESTRING, &parsed->payload) ||
		parsed->payload == NULL)
		return FALSE;
	spec->mechanism = g_variant_get_string(parsed->mechanism, NULL);
	spec->data = (XccBytes){.struct_size = sizeof(XccBytes), .abi_version = XCC_ABI_VERSION};
	spec->data.data = g_variant_get_fixed_array(parsed->payload, &spec->data.size, 1);
	parsed->valid_parameters = TRUE;
	if (parsed->parameters != NULL)
	{
		static const char* const keys[] = {"hash", "mgf", "salt_length", "signature_encoding",
										   NULL};
		GVariantIter iter;
		const char* key;
		g_variant_iter_init(&iter, parsed->parameters);
		while (g_variant_iter_next(&iter, "{&sv}", &key, NULL))
			if (!g_strv_contains(keys, key))
				parsed->valid_parameters = FALSE;
#define STRING(key, member, present, field)                                                        \
	if (!take(parsed->parameters, key, G_VARIANT_TYPE_STRING, &parsed->member))                    \
		parsed->valid_parameters = FALSE;                                                          \
	else if (parsed->member != NULL)                                                               \
	{                                                                                              \
		spec->present = TRUE;                                                                      \
		spec->field = g_variant_get_string(parsed->member, NULL);                                  \
	}
		STRING("hash", hash, hash_present, hash);
		STRING("signature_encoding", encoding, encoding_present, signature_encoding);
		if (g_str_equal(spec->mechanism, "RSA_PSS"))
		{
			STRING("mgf", mgf, mgf_present, mgf);
			g_autoptr(GVariant) salt = NULL;
			if (!take(parsed->parameters, "salt_length", G_VARIANT_TYPE_UINT32, &salt))
				parsed->valid_parameters = FALSE;
			else if (salt != NULL)
			{
				spec->salt_length_present = TRUE;
				spec->salt_length = g_variant_get_uint32(salt);
			}
		}
#undef STRING
	}
	return TRUE;
}

void certificate_sign_options_clear(CertificateSignOptions* parsed)
{
	g_clear_pointer(&parsed->mechanism, g_variant_unref);
	g_clear_pointer(&parsed->parameters, g_variant_unref);
	g_clear_pointer(&parsed->payload, g_variant_unref);
	g_clear_pointer(&parsed->hash, g_variant_unref);
	g_clear_pointer(&parsed->mgf, g_variant_unref);
	g_clear_pointer(&parsed->encoding, g_variant_unref);
}

GVariant* certificate_sign_results(const XccResult* result)
{
	GVariantBuilder builder;
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "signature",
						  g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, result->signature.data,
													result->signature.size, 1));
	return g_variant_builder_end(&builder);
}
