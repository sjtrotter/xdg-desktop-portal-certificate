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
/* Keep in step with CERTIFICATE_PKCS11_OBJECT_MAX in tokens/pkcs11-util.c. */
#define OBJECT_MAX 16384

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

static guint find_calls, find_final_calls;
static gboolean find_active, find_fail;

static CK_RV stub_find_init(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	g_assert_cmpuint(session, ==, 1);
	g_assert_false(find_active);
	find_active = TRUE;
	find_calls = find_final_calls = 0;
	return CKR_OK;
}

static CK_RV stub_find(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects,
                       CK_ULONG max, CK_ULONG_PTR count)
{
	static const CK_ULONG batches[] = { 1, 2, 1, 0 };
	static const CK_OBJECT_HANDLE first[] = { 10, 11, 13, 0 };
	g_assert_true(find_active);
	g_assert_cmpuint(find_calls, <, G_N_ELEMENTS(batches));
	guint call = find_calls++;
	if (find_fail && call == 1)
		return CKR_DEVICE_ERROR;

	*count = batches[call];
	g_assert_cmpuint(*count, <=, max);
	for (CK_ULONG i = 0; i < *count; i++)
		objects[i] = first[call] + i;
	return CKR_OK;
}

static CK_RV stub_find_final(CK_SESSION_HANDLE session)
{
	g_assert_true(find_active);
	find_active = FALSE;
	find_final_calls++;
	return CKR_OK;
}

static void test_find_short_batches(void)
{
	CK_FUNCTION_LIST module = {
		.C_FindObjectsInit = stub_find_init,
		.C_FindObjects = stub_find,
		.C_FindObjectsFinal = stub_find_final,
	};
	g_autoptr(GError) error = NULL;
	find_fail = FALSE;
	g_autoptr(GArray) objects = certificate_pkcs11_find_objects(&module, 1, NULL, 0, &error);
	g_assert_no_error(error);
	g_assert_nonnull(objects);
	g_assert_cmpuint(objects->len, ==, 4);
	for (guint i = 0; i < objects->len; i++)
		g_assert_cmpuint(g_array_index(objects, CK_OBJECT_HANDLE, i), ==, 10 + i);
	g_assert_cmpuint(find_calls, ==, 4);
	g_assert_cmpuint(find_final_calls, ==, 1);
	g_assert_false(find_active);

	find_fail = TRUE;
	g_autoptr(GArray) failed = certificate_pkcs11_find_objects(&module, 1, NULL, 0, &error);
	g_assert_null(failed);
	g_assert_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED);
	g_assert_cmpuint(find_calls, ==, 2);
	g_assert_cmpuint(find_final_calls, ==, 1);
	g_assert_false(find_active);
}

static CK_ULONG find_remaining, find_batch;
static gboolean find_never_zero, find_invalid_count;

static CK_RV stub_find_bounded(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects,
                               CK_ULONG max, CK_ULONG_PTR count)
{
	g_assert_true(find_active);
	/* Fail a broken implementation before it can allocate without a bound. */
	g_assert_cmpuint(++find_calls, <=, OBJECT_MAX + 1);
	if (find_invalid_count)
	{
		*count = max + 1;
		return CKR_OK;
	}
	*count = MIN(max, find_batch);
	if (!find_never_zero)
	{
		*count = MIN(*count, find_remaining);
		find_remaining -= *count;
	}
	for (CK_ULONG i = 0; i < *count; i++)
		objects[i] = 42;
	return CKR_OK;
}

static void test_find_budget(gconstpointer data)
{
	const char* mode = data;
	CK_FUNCTION_LIST module = {
		.C_FindObjectsInit = stub_find_init,
		.C_FindObjects = stub_find_bounded,
		.C_FindObjectsFinal = stub_find_final,
	};
	g_autoptr(GError) error = NULL;
	find_batch = g_str_equal(mode, "never-zero-short") ? 1 : 32;
	find_never_zero = g_str_has_prefix(mode, "never-zero");
	find_invalid_count = g_str_equal(mode, "invalid-count");
	find_remaining = OBJECT_MAX + (g_str_equal(mode, "over-limit") ? 1 : 0);
	g_autoptr(GArray) objects = certificate_pkcs11_find_objects(&module, 1, NULL, 0, &error);

	if (g_str_equal(mode, "at-limit"))
	{
		g_assert_no_error(error);
		g_assert_nonnull(objects);
		g_assert_cmpuint(objects->len, ==, OBJECT_MAX);
		g_assert_cmpuint(find_calls, ==, OBJECT_MAX / find_batch + 1);
		for (guint i = 0; i < objects->len; i++)
			g_assert_cmpuint(g_array_index(objects, CK_OBJECT_HANDLE, i), ==, 42);
	}
	else
	{
		g_assert_null(objects);
		g_assert_nonnull(error);
		g_assert_cmpuint(error->domain, ==, CERTIFICATE_PKCS11_ERROR);
		g_assert_cmpuint(find_calls, ==, find_invalid_count ? 1 : OBJECT_MAX / find_batch + 1);
	}
	g_assert_cmpuint(find_final_calls, ==, 1);
	g_assert_false(find_active);
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
	g_test_add_func("/discovery/find-short-batches", test_find_short_batches);
	g_test_add_data_func("/discovery/find-at-limit", "at-limit", test_find_budget);
	g_test_add_data_func("/discovery/find-over-limit", "over-limit", test_find_budget);
	g_test_add_data_func("/discovery/find-never-zero/full", "never-zero", test_find_budget);
	g_test_add_data_func("/discovery/find-never-zero/short", "never-zero-short", test_find_budget);
	g_test_add_data_func("/discovery/find-invalid-count", "invalid-count", test_find_budget);

	return g_test_run();
}
