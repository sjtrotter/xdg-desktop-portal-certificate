/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

/** @file
 *  The client-side module's hostile-input surface, driven by one entry point.
 *
 *  Two producers reach this code and neither is under the module's control: the
 *  portal's reply, whose certificate DER came off a card through two services
 *  that promise nothing about its shape, and a TLS peer, which chooses the
 *  mechanism and the bytes of a CertificateVerify. Both run inside the
 *  CONSUMER's process -- a browser, a mail client -- so a defect here is a
 *  defect in somebody else's address space. docs/SECURITY.md says why that is
 *  the module's problem and not the portal's.
 *
 *  WHAT IS DRIVEN:
 *    - portal_der_read(), walked over the whole input;
 *    - portal_digestinfo_parse(), which a TLS 1.2 CKM_RSA_PKCS signature
 *      reaches directly;
 *    - portal_objects_new() with the input as certificate DER, which is
 *      parse_certificate(), the SubjectPublicKeyInfo split and the leading-zero
 *      strip;
 *    - the same, mutated: each corpus file with bytes replaced and lengths
 *      corrupted, which is the shape a card or a buggy service produces;
 *    - the attribute protocol -- portal_template_wants_credential(),
 *      portal_template_fingerprint(), portal_objects_find() and
 *      portal_object_get_attributes() -- against a template built out of the
 *      input, including the size-query and buffer-too-small paths.
 *
 *  TWO WAYS TO BUILD IT. With clang, meson builds a libFuzzer target as well,
 *  automatically, whenever the compiler accepts -fsanitize=fuzzer:
 *
 *      CC=clang meson setup build-fuzz -Db_sanitize=address,undefined \
 *          -Db_lundef=false
 *      build-fuzz/tests/fuzz-der-libfuzzer -max_total_time=60 \
 *          tests/fixtures/fuzz-corpus
 *
 *  Without it -- and always, so that `meson test` covers this -- the same
 *  function is driven from a main() over a built-in corpus plus a directory of
 *  files, which is what a fuzzing run's findings get checked in as.
 */

#include "config.h"

#include <stdint.h>
#include <string.h>

#include <glib.h>

#include "der.h"
#include "mechanism.h"
#include "objects.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static void drive_der(const uint8_t* data, size_t size)
{
	const guint8* at = data;
	gsize left = size;
	guint depth = 0;

	while (left > 0 && depth < 64)
	{
		PortalDerTlv tlv;

		if (!portal_der_read(at, left, &tlv))
			break;

		g_assert(tlv.consumed <= left);
		g_assert(tlv.length <= left);
		g_assert(tlv.value + tlv.length <= data + size);

		if (tlv.tag == PORTAL_DER_SEQUENCE && tlv.length > 0)
		{
			PortalDerTlv inner;

			if (portal_der_read(tlv.value, tlv.length, &inner))
				g_assert(inner.consumed <= tlv.length);
		}

		{
			g_autoptr(GBytes) round = portal_der_encode(tlv.tag, tlv.value, tlv.length);

			g_assert(round != NULL);
		}

		at += tlv.consumed;
		left -= tlv.consumed;
		depth++;
	}
}

static void drive_digestinfo(const uint8_t* data, size_t size)
{
	const char* hash = NULL;
	const guint8* digest = NULL;
	gsize digest_length = 0;

	if (!portal_digestinfo_parse(data, size, &hash, &digest, &digest_length))
		return;

	g_assert(hash != NULL);
	g_assert(digest != NULL);
	g_assert_cmpuint(digest_length, ==, portal_hash_length(hash));
	g_assert(digest >= data && digest + digest_length <= data + size);
}

/* A template out of the input. Two bytes name an attribute, one gives a value
 * length, and the rest is the value: enough to reach every branch of
 * portal_object_matches() and of the C_GetAttributeValue protocol, including a
 * pValue that is too small and a NULL one. */
static CK_ATTRIBUTE* build_template(const uint8_t* data, size_t size, CK_ULONG* count,
                                    GPtrArray* buffers)
{
	CK_ATTRIBUTE* templ;
	gsize offset = 0;
	CK_ULONG n = 0;

	templ = g_new0(CK_ATTRIBUTE, 16);
	g_ptr_array_add(buffers, templ);

	while (n < 16 && offset + 3 <= size)
	{
		gsize value_length = data[offset + 2];
		CK_ATTRIBUTE_TYPE type = ((CK_ATTRIBUTE_TYPE) data[offset] << 8) | data[offset + 1];

		offset += 3;

		if (value_length > size - offset)
			value_length = size - offset;

		templ[n].type = type;

		if (value_length == 0)
		{
			/* The size query: pValue NULL, ulValueLen answered by the module. */
			templ[n].pValue = NULL_PTR;
			templ[n].ulValueLen = 0;
		}
		else
		{
			guint8* value = g_malloc(value_length);

			memcpy(value, data + offset, value_length);

			g_ptr_array_add(buffers, value);
			templ[n].pValue = value;
			templ[n].ulValueLen = value_length;
			offset += value_length;
		}

		n++;
	}

	*count = n;
	return templ;
}

static void drive_attributes(const uint8_t* data, size_t size)
{
	g_autoptr(GPtrArray) buffers = g_ptr_array_new_with_free_func(g_free);
	g_autoptr(PortalObjects) objects = NULL;
	g_autoptr(GBytes) der = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GArray) found = NULL;
	CK_ATTRIBUTE* templ;
	CK_ULONG count = 0;
	PortalGrant grant;

	templ = build_template(data, size, &count, buffers);

	/* No objects needed: these two answer for a template alone, and the first
	 * decides whether a search may raise a chooser. */
	portal_template_wants_credential(templ, count);
	portal_template_fingerprint(templ, count);

	der = g_bytes_new(data, size);

	memset(&grant, 0, sizeof(grant));
	grant.certificate_der = der;
	grant.key_type = (char*) ((size > 0 && (data[0] & 1)) ? "EC" : "RSA");
	grant.may_sign = TRUE;
	grant.may_decrypt = (size > 0 && (data[0] & 2)) != 0;

	objects = portal_objects_new(&grant, (guint) (size & 0xffff), &error);
	if (objects == NULL)
		return;

	found = portal_objects_find(objects, templ, count);

	for (guint i = 0; found != NULL && i < found->len; i++)
	{
		CK_OBJECT_HANDLE handle = g_array_index(found, CK_OBJECT_HANDLE, i);
		PortalObject* object = portal_objects_lookup(objects, handle);

		g_assert(object != NULL);
		g_assert(portal_object_matches(object, templ, count));
	}

	for (guint i = 0; i < objects->objects->len; i++)
	{
		PortalObject* object = g_ptr_array_index(objects->objects, i);

		portal_object_get_attributes(object, templ, count);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (size > 64 * 1024)
		return 0;

	drive_der(data, size);
	drive_digestinfo(data, size);
	drive_attributes(data, size);

	return 0;
}

#ifndef PKCS11_PORTAL_FUZZING_ENGINE

/* The corpus replay. Everything a fuzzing run has found so far, plus the shapes
 * that made the parsers exist, run under whatever sanitizer the build has. */
static const char* const seeds[] = {
	"",
	"\x30",
	"\x30\x00",
	"\x30\x80",
	"\x30\x84\xff\xff\xff\xff",
	"\x30\x81\x01\x41",
	"\x30\x82\x00\x01\x41",
	"\x1f\x01\x41",
	"\x02\x01\x00",
	"\x03\x02\x00\xff",
	"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	"01234567890123456789012345678901",
	"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
	"01234567890123456789",
	"\x30\x30\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	"0123456789012345678901234567890",
	"\x00\x01\x03\x41\x42\x43\x01\x00\x00",
	"\x01\x00\x00\x01\x62\x00\x01\x63\x00",
};

static const gsize seed_sizes[] = {
	0, 1, 2, 2, 6, 4, 5, 3, 3, 4, 51, 35, 50, 9, 9,
};

static void run_one(const guint8* data, gsize size)
{
	LLVMFuzzerTestOneInput(data, size);
}

static void test_seeds(void)
{
	for (gsize i = 0; i < G_N_ELEMENTS(seeds); i++)
		run_one((const guint8*) seeds[i], seed_sizes[i]);
}

/* Cheap coverage of shapes no hand-written seed reaches: a deterministic PRNG,
 * so a failure is reproducible from the seed and the iteration number alone.
 * PKCS11_PORTAL_FUZZ_RUNS and PKCS11_PORTAL_FUZZ_SEED make a longer run possible
 * without a libFuzzer; `meson test` runs the small default. */
static void test_random(void)
{
	guint64 runs = 4096;
	guint64 seed = 0x5eed1234;
	const char* env;
	GRand* rand;

	env = g_getenv("PKCS11_PORTAL_FUZZ_RUNS");
	if (env != NULL)
		g_ascii_string_to_unsigned(env, 10, 0, G_MAXUINT32, &runs, NULL);

	env = g_getenv("PKCS11_PORTAL_FUZZ_SEED");
	if (env != NULL)
		g_ascii_string_to_unsigned(env, 10, 0, G_MAXUINT32, &seed, NULL);

	rand = g_rand_new_with_seed((guint32) seed);

	for (guint64 i = 0; i < runs; i++)
	{
		guint8 buffer[256];
		gsize size = g_rand_int_range(rand, 0, sizeof(buffer));

		for (gsize j = 0; j < size; j++)
			buffer[j] = (guint8) g_rand_int_range(rand, 0, 256);

		run_one(buffer, size);
	}

	g_rand_free(rand);
}

static const char* corpus_dir(void)
{
	const char* dir_name = g_getenv("PKCS11_PORTAL_FUZZ_CORPUS");

	return dir_name != NULL ? dir_name : CERTIFICATE_FIXTURE_DIR "/fuzz-corpus";
}

/* The seed corpus, plus whatever a libFuzzer run left behind. Two of the files
 * are real certificates, so that portal_objects_new() succeeds and the
 * attribute protocol is reached with objects to answer for. */
static void test_corpus(void)
{
	g_autoptr(GDir) dir = g_dir_open(corpus_dir(), 0, NULL);
	const char* name;

	if (dir == NULL)
	{
		g_test_skip("no corpus directory");
		return;
	}

	while ((name = g_dir_read_name(dir)) != NULL)
	{
		g_autofree char* path = g_build_filename(corpus_dir(), name, NULL);
		g_autofree char* contents = NULL;
		gsize size = 0;

		if (!g_file_get_contents(path, &contents, &size, NULL))
			continue;

		run_one((const guint8*) contents, size);
	}
}

/* WHERE THE INTERESTING INPUTS ARE. Random bytes almost never parse as a
 * certificate, so without this the object and attribute paths are only reached
 * by the clean corpus. Each corpus file is mutated -- bytes replaced, truncated,
 * lengths corrupted -- which is the shape a card, a backend or a portal with a
 * bug would actually produce. */
static void test_mutations(void)
{
	g_autoptr(GDir) dir = g_dir_open(corpus_dir(), 0, NULL);
	GRand* rand = g_rand_new_with_seed(0xc0ffee01);
	const char* name;
	guint64 rounds = 512;
	const char* env = g_getenv("PKCS11_PORTAL_FUZZ_RUNS");

	if (dir == NULL)
	{
		g_rand_free(rand);
		g_test_skip("no corpus directory");
		return;
	}

	if (env != NULL)
		g_ascii_string_to_unsigned(env, 10, 0, G_MAXUINT32, &rounds, NULL);

	while ((name = g_dir_read_name(dir)) != NULL)
	{
		g_autofree char* path = g_build_filename(corpus_dir(), name, NULL);
		g_autofree char* contents = NULL;
		gsize size = 0;

		if (!g_file_get_contents(path, &contents, &size, NULL) || size == 0)
			continue;

		for (guint64 round = 0; round < rounds; round++)
		{
			g_autofree guint8* copy = g_malloc(size);
			gsize length = size;
			int edits = g_rand_int_range(rand, 1, 6);

			memcpy(copy, contents, size);

			if (g_rand_boolean(rand))
				length = (gsize) g_rand_int_range(rand, 1, (gint32) size + 1);

			for (int i = 0; i < edits; i++)
				copy[g_rand_int_range(rand, 0, (gint32) length)] =
				    (guint8) g_rand_int_range(rand, 0, 256);

			run_one(copy, length);
		}
	}

	g_rand_free(rand);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/fuzz/der/seeds", test_seeds);
	g_test_add_func("/fuzz/der/random", test_random);
	g_test_add_func("/fuzz/der/corpus", test_corpus);
	g_test_add_func("/fuzz/der/mutations", test_mutations);

	return g_test_run();
}

#endif /* PKCS11_PORTAL_FUZZING_ENGINE */
