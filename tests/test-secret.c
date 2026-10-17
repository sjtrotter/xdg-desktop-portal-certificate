/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */

#include "core/secret.h"

#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static gboolean fail_lock;
static void* watched_page;
static size_t watched_capacity;
static guint wiped_frees;

int __real_mlock(const void* address, size_t length);
int __wrap_mlock(const void* address, size_t length);
void __real_free(void* pointer);
void __wrap_free(void* pointer);

int __wrap_mlock(const void* address, size_t length)
{
	if (!fail_lock)
		return __real_mlock(address, length);
	errno = ENOMEM;
	return -1;
}

/* Inspect the whole allocation before releasing it, never after free. */
void __wrap_free(void* pointer)
{
	if (pointer != NULL && pointer == watched_page)
	{
		const uint8_t* bytes = pointer;

		for (size_t i = 0; i < watched_capacity; i++)
			g_assert_cmpuint(bytes[i], ==, 0);
		watched_page = NULL;
		wiped_frees++;
	}
	__real_free(pointer);
}

static void test_data(void)
{
	XccSecret* secret = xcc_secret_new();
	size_t capacity;
	uint8_t* data;
	long page = sysconf(_SC_PAGESIZE);

	g_assert_nonnull(secret);
	data = xcc_secret_data(secret, &capacity);
	g_assert_cmpuint(capacity, >=, 512);
	g_assert_cmpuint((uintptr_t) data % (page > 0 ? (size_t) page : 4096), ==, 0);
	for (size_t i = 0; i < capacity; i++)
		g_assert_cmpuint(data[i], ==, 0);
	g_assert_cmpuint(xcc_secret_length(secret), ==, 0);
	g_assert_null(xcc_secret_view(secret));
	data[0] = '1';
	g_assert_true(xcc_secret_set_length(secret, 1));
	g_assert_true(xcc_secret_view(secret) == (const char*) data);
	g_assert_cmpstr(xcc_secret_view(secret), ==, "1");
	g_assert_cmpuint(xcc_secret_length(secret), ==, 1);
	g_assert_true(xcc_secret_data(secret, NULL) == data);
	g_assert_cmpuint(xcc_secret_length(secret), ==, 0);
	g_assert_null(xcc_secret_view(secret));
	xcc_secret_free(secret);
	xcc_secret_free(NULL);
}

static void test_length(void)
{
	const size_t lengths[] = {0, 1, 511, 512, SIZE_MAX};
	XccSecret* secret = xcc_secret_new();
	size_t capacity;
	uint8_t* data;

	g_assert_nonnull(secret);
	for (guint i = 0; i < G_N_ELEMENTS(lengths); i++)
	{
		size_t length = lengths[i];
		gboolean valid = length > 0 && length <= 511;

		data = xcc_secret_data(secret, &capacity);
		memset(data, '1', capacity);
		g_assert_cmpint(xcc_secret_set_length(secret, length), ==, valid);
		g_assert_cmpuint(xcc_secret_length(secret), ==, valid ? length : 0);
		if (valid)
			g_assert_cmpuint(data[length], ==, 0);
		else
		{
			g_assert_null(xcc_secret_view(secret));
			for (size_t j = 0; j < capacity; j++)
				g_assert_cmpuint(data[j], ==, 0);
		}
	}
	xcc_secret_free(secret);
}

static void test_embedded_nul(void)
{
	XccSecret* secret = xcc_secret_new();
	size_t capacity;
	uint8_t* data;

	g_assert_nonnull(secret);
	data = xcc_secret_data(secret, &capacity);
	memset(data, '1', capacity);
	data[2] = '\0';
	g_assert_false(xcc_secret_set_length(secret, 4));
	g_assert_cmpuint(xcc_secret_length(secret), ==, 0);
	g_assert_null(xcc_secret_view(secret));
	xcc_secret_free(secret);
}

static void test_wipe(void)
{
	XccSecret* secret = xcc_secret_new();

	g_assert_nonnull(secret);
	watched_page = xcc_secret_data(secret, &watched_capacity);
	memset(watched_page, '1', watched_capacity);
	g_assert_true(xcc_secret_set_length(secret, 4));
	wiped_frees = 0;
	xcc_secret_free(secret);
	g_assert_null(watched_page);
	g_assert_cmpuint(wiped_frees, ==, 1);
}

static void count_lock_failure(const gchar* domain, GLogLevelFlags level,
                               const gchar* message, gpointer user_data)
{
	guint* messages = user_data;

	g_assert_cmpstr(message, ==, "pin-buffer-unlocked detail=mlock-failed");
	(*messages)++;
}

static void test_lock_failure(void)
{
	if (g_test_subprocess())
	{
		guint messages = 0;
		guint handler = g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
		                                  count_lock_failure, &messages);

		fail_lock = TRUE;
		for (guint i = 0; i < 3; i++)
		{
			XccSecret* secret = xcc_secret_new();
			uint8_t* data;

			g_assert_nonnull(secret);
			data = xcc_secret_data(secret, NULL);
			memcpy(data, "1234", 4);
			g_assert_true(xcc_secret_set_length(secret, 4));
			xcc_secret_free(secret);
		}
		g_assert_cmpuint(messages, ==, 1);
		g_log_remove_handler(G_LOG_DOMAIN, handler);
		return;
	}

	g_test_trap_subprocess(NULL, 0, G_TEST_SUBPROCESS_DEFAULT);
	g_test_trap_assert_passed();
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/secret/data", test_data);
	g_test_add_func("/secret/length", test_length);
	g_test_add_func("/secret/embedded-nul", test_embedded_nul);
	g_test_add_func("/secret/wipe", test_wipe);
	g_test_add_func("/secret/lock-failure-once", test_lock_failure);
	return g_test_run();
}
