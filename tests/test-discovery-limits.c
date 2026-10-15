/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <glib.h>
#include <string.h>

#include "broker/mechanism.h"
#include "tokens/pkcs11-util.h"

/* Keep in step with CERTIFICATE_PKCS11_ATTRIBUTE_MAX in tokens/pkcs11-util.c. */
#define ATTRIBUTE_MAX (64 * 1024)

/* The sizing and value reads can report different lengths. */
static CK_ULONG stub_first_length;
static CK_ULONG stub_second_length;
static gboolean stub_wrote_value;

static CK_RV stub_get_attribute_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                                      CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	g_assert_cmpuint(count, ==, 1);

	if (templ[0].pValue == NULL)
	{
		templ[0].ulValueLen = stub_first_length;
		return CKR_OK;
	}

	/* Claim a larger length without writing past the supplied buffer. */
	memset(templ[0].pValue, 0xab, MIN(stub_first_length, stub_second_length));
	stub_wrote_value = TRUE;
	templ[0].ulValueLen = stub_second_length;
	return CKR_OK;
}

static GByteArray* read_attribute(CK_ULONG first_length, CK_ULONG second_length)
{
	CK_FUNCTION_LIST module;

	memset(&module, 0, sizeof(module));
	module.C_GetAttributeValue = stub_get_attribute_value;

	stub_first_length = first_length;
	stub_second_length = second_length;
	stub_wrote_value = FALSE;

	return certificate_pkcs11_get_attribute(&module, 1, 1, CKA_ID);
}

static void test_attribute_length_is_capped(void)
{
	g_autoptr(GByteArray) ordinary = read_attribute(20, 20);
	g_autoptr(GByteArray) at_cap = read_attribute(ATTRIBUTE_MAX, ATTRIBUTE_MAX);
	GByteArray* over_cap = read_attribute(ATTRIBUTE_MAX + 1, ATTRIBUTE_MAX + 1);
	GByteArray* unavailable = read_attribute((CK_ULONG) -1, 0);
	GByteArray* empty = read_attribute(0, 0);

	g_assert_nonnull(ordinary);
	g_assert_cmpuint(ordinary->len, ==, 20);
	g_assert_cmpuint(ordinary->data[0], ==, 0xab);

	g_assert_nonnull(at_cap);
	g_assert_cmpuint(at_cap->len, ==, ATTRIBUTE_MAX);

	g_assert_null(over_cap);
	g_assert_null(unavailable);
	g_assert_null(empty);
}

static void test_a_second_length_beyond_the_buffer_is_refused(void)
{
	GByteArray* grown = read_attribute(20, 4096);
	g_autoptr(GByteArray) shrunk = read_attribute(20, 8);

	g_assert_null(grown);

	g_assert_nonnull(shrunk);
	g_assert_cmpuint(shrunk->len, ==, 8);
}

static void test_pss_salt_bound(void)
{
	struct
	{
		const char* parameters;
		guint key_size;
		gboolean accepted;
	} cases[] = {
		/* For a 2048-bit RSA key and SHA-256, the maximum PSS salt is 222 bytes. */
		{ "{'hash': <'SHA256'>, 'salt_length': <uint32 222>}", 2048, TRUE },
		{ "{'hash': <'SHA256'>, 'salt_length': <uint32 223>}", 2048, FALSE },
		{ "{'hash': <'SHA256'>, 'salt_length': <uint32 0>}", 2048, TRUE },
		{ "{'hash': <'SHA256'>, 'salt_length': <uint32 4294967295>}", 2048, FALSE },
		{ "{'hash': <'SHA256'>, 'salt_length': <uint32 4294967262>}", 2048, FALSE },
		{ "{'hash': <'SHA512'>, 'salt_length': <uint32 4294967230>}", 4096, FALSE },
	};

	for (gsize i = 0; i < G_N_ELEMENTS(cases); i++)
	{
		g_autoptr(GVariant) parameters =
		    g_variant_parse(G_VARIANT_TYPE_VARDICT, cases[i].parameters, NULL, NULL, NULL);
		CertificateMechanism mechanism;
		g_autoptr(GError) error = NULL;
		gboolean parsed;

		g_assert_nonnull(parameters);
		g_test_message("%s", cases[i].parameters);

		parsed = certificate_mechanism_parse("RSA_PSS", parameters, "RSA", cases[i].key_size,
		                                     FALSE, &mechanism, &error);
		g_assert_cmpint(parsed, ==, cases[i].accepted);

		if (parsed)
		{
			certificate_mechanism_clear(&mechanism);
			continue;
		}

		g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	}
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/limits/attribute-length-capped", test_attribute_length_is_capped);
	g_test_add_func("/limits/attribute-second-length",
	                test_a_second_length_beyond_the_buffer_is_refused);
	g_test_add_func("/limits/pss-salt-bound", test_pss_salt_bound);

	return g_test_run();
}
