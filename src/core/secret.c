/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#define _GNU_SOURCE 1

#include "secret.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct _XccSecret
{
	uint8_t* data;
	size_t capacity;
	size_t length;
	bool locked;
};

static gint mlock_warned;

XccSecret* xcc_secret_new(void)
{
	XccSecret* secret = g_new0(XccSecret, 1);
	long page = sysconf(_SC_PAGESIZE);
	size_t size = page > 0 ? (size_t) page : 4096;

	if (posix_memalign((void**) &secret->data, size, size) != 0)
	{
		g_free(secret);
		return NULL;
	}

	secret->capacity = size;
	memset(secret->data, 0, secret->capacity);
	secret->locked = mlock(secret->data, secret->capacity) == 0;
	if (!secret->locked && g_atomic_int_compare_and_exchange(&mlock_warned, 0, 1))
		g_message("pin-buffer-unlocked detail=mlock-failed");

	/* Process dump hardening remains the caller's responsibility. */
#ifdef MADV_DONTDUMP
	(void) madvise(secret->data, secret->capacity, MADV_DONTDUMP);
#endif
	return secret;
}

uint8_t* xcc_secret_data(XccSecret* secret, size_t* capacity)
{
	if (capacity != NULL)
		*capacity = secret->capacity;
	secret->length = 0;
	return secret->data;
}

bool xcc_secret_set_length(XccSecret* secret, size_t length)
{
	secret->length = 0;
	if (length == 0 || length > 511 || length >= secret->capacity ||
	    memchr(secret->data, '\0', length) != NULL)
	{
		explicit_bzero(secret->data, secret->capacity);
		return false;
	}

	secret->data[length] = '\0';
	secret->length = length;
	return true;
}

const char* xcc_secret_view(const XccSecret* secret)
{
	return secret != NULL && secret->length > 0 ? (const char*) secret->data : NULL;
}

size_t xcc_secret_length(const XccSecret* secret)
{
	return secret != NULL ? secret->length : 0;
}

void xcc_secret_free(XccSecret* secret)
{
	if (secret == NULL)
		return;

	explicit_bzero(secret->data, secret->capacity);
	if (secret->locked)
		munlock(secret->data, secret->capacity);
	free(secret->data);
	g_free(secret);
}
