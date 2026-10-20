/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */

#include <string.h>

#include "tokens/discovery.h"

typedef struct
{
	CK_SLOT_ID slot;
	gboolean added;
} Event;

typedef struct
{
	CertificateTokens* tokens;
	GArray* events;
	GMutex lock;
	GCond cond;
	guint mask, sleeps, permits;
	gboolean stopping, reverse, serial_less;
} Fixture;

static Fixture* active;

/* Advance the real watcher one poll at a time without wall-clock delays. */
void __wrap_g_usleep(gulong microseconds);
void __wrap_g_usleep(gulong microseconds)
{
	Fixture* f = active;
	g_assert_cmpuint(microseconds, ==, 2000 * 1000);
	g_mutex_lock(&f->lock);
	f->sleeps++;
	g_cond_broadcast(&f->cond);
	gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (f->permits == 0 && !f->stopping)
		g_assert_true(g_cond_wait_until(&f->cond, &f->lock, deadline));
	if (f->permits != 0)
		f->permits--;
	g_mutex_unlock(&f->lock);
}

static CK_RV get_slot_list(CK_BBOOL present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	CK_ULONG found = 0;
	for (guint i = 0; i < 3; i++)
	{
		guint bit = active->reverse ? 2 - i : i;
		if ((active->mask & (1u << bit)) == 0)
			continue;
		if (slots != NULL)
		{
			g_assert_cmpuint(found, <, *count);
			slots[found] = bit + 1;
		}
		found++;
	}
	*count = found;
	return CKR_OK;
}

static CK_RV get_slot_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	memset(info->slotDescription, ' ', sizeof(info->slotDescription));
	info->flags = CKF_HW_SLOT | CKF_TOKEN_PRESENT;
	return CKR_OK;
}

static CK_RV get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	memset(info->label, ' ', sizeof(info->label));
	memcpy(info->label, "Test token", strlen("Test token"));
	memset(info->manufacturerID, ' ', sizeof(info->manufacturerID));
	memset(info->model, ' ', sizeof(info->model));
	memset(info->serialNumber, ' ', sizeof(info->serialNumber));
	if (!active->serial_less)
		info->serialNumber[0] = '0' + slot;
	info->flags = CKF_TOKEN_INITIALIZED;
	return CKR_OK;
}

static CK_FUNCTION_LIST module = {
	.C_GetSlotList = get_slot_list,
	.C_GetSlotInfo = get_slot_info,
	.C_GetTokenInfo = get_token_info,
};

CK_FUNCTION_LIST** __wrap_p11_kit_modules_load_and_initialize(int flags);
void __wrap_p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** modules);
char* __wrap_p11_kit_module_get_name(CK_FUNCTION_LIST* value);
char* __wrap_p11_kit_module_get_filename(CK_FUNCTION_LIST* value);

CK_FUNCTION_LIST** __wrap_p11_kit_modules_load_and_initialize(int flags)
{
	CK_FUNCTION_LIST** modules = g_new0(CK_FUNCTION_LIST*, 2);
	modules[0] = &module;
	return modules;
}

void __wrap_p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** modules)
{
	g_free(modules);
}

char* __wrap_p11_kit_module_get_name(CK_FUNCTION_LIST* value)
{
	g_assert_true(value == &module);
	return g_strdup("test-watch-module");
}

char* __wrap_p11_kit_module_get_filename(CK_FUNCTION_LIST* value)
{
	g_assert_true(value == &module);
	return NULL;
}

static void token_event(CertificateToken* token, gboolean added, gpointer data)
{
	Fixture* f = data;
	Event event = { token->slot, added };
	g_array_append_val(f->events, event);
}

static void wait_for_sleep(Fixture* f, guint count)
{
	gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (f->sleeps < count)
		g_assert_true(g_cond_wait_until(&f->cond, &f->lock, deadline));
}

static void setup(Fixture* f, gconstpointer data)
{
	active = f;
	g_mutex_init(&f->lock);
	g_cond_init(&f->cond);
	f->mask = 7;
	f->serial_less = GPOINTER_TO_INT(data);
	f->events = g_array_new(FALSE, FALSE, sizeof(Event));
	g_autoptr(GError) error = NULL;
	f->tokens = certificate_tokens_new(NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(f->tokens);
	certificate_tokens_watch(f->tokens, token_event, f);
	g_mutex_lock(&f->lock);
	wait_for_sleep(f, 1);
	g_mutex_unlock(&f->lock);
}

static void teardown(Fixture* f, gconstpointer data)
{
	g_mutex_lock(&f->lock);
	f->stopping = TRUE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	certificate_tokens_stop_watch(f->tokens);
	certificate_tokens_free(f->tokens);
	g_array_unref(f->events);
	g_mutex_clear(&f->lock);
	g_cond_clear(&f->cond);
	active = NULL;
}

static void poll_snapshot(Fixture* f, guint mask, gboolean reverse)
{
	g_mutex_lock(&f->lock);
	guint next = f->sleeps + 1;
	f->mask = mask;
	f->reverse = reverse;
	f->permits++;
	g_cond_broadcast(&f->cond);
	wait_for_sleep(f, next);
	g_mutex_unlock(&f->lock);
	certificate_tokens_dispatch_pending(f->tokens);
}

static void test_alternating_snapshots(Fixture* f, gconstpointer data)
{
	const guint snapshots[] = { 3, 5, 3, 5, 3 };
	for (guint i = 0; i < G_N_ELEMENTS(snapshots); i++)
	{
		poll_snapshot(f, snapshots[i], FALSE);
		g_assert_cmpuint(f->events->len, ==, 0);
	}

	/* Order does not change a presence snapshot. */
	poll_snapshot(f, 3, TRUE);
	g_assert_cmpuint(f->events->len, ==, 1);
	Event event = g_array_index(f->events, Event, 0);
	g_assert_cmpuint(event.slot, ==, 3);
	g_assert_false(event.added);
	poll_snapshot(f, 3, FALSE);
	g_assert_cmpuint(f->events->len, ==, 1);

	poll_snapshot(f, 7, FALSE);
	g_assert_cmpuint(f->events->len, ==, 1);
	poll_snapshot(f, 7, TRUE);
	g_assert_cmpuint(f->events->len, ==, 2);
	event = g_array_index(f->events, Event, 1);
	g_assert_cmpuint(event.slot, ==, 3);
	g_assert_true(event.added);
}

static void test_baseline_resets_debounce(Fixture* f, gconstpointer data)
{
	poll_snapshot(f, 3, FALSE);
	poll_snapshot(f, 7, TRUE);
	poll_snapshot(f, 3, FALSE);
	g_assert_cmpuint(f->events->len, ==, 0);
	poll_snapshot(f, 3, FALSE);
	g_assert_cmpuint(f->events->len, ==, 1);
	Event event = g_array_index(f->events, Event, 0);
	g_assert_cmpuint(event.slot, ==, 3);
	g_assert_false(event.added);
}

static void assert_event(Fixture* f, guint index, CK_SLOT_ID slot, gboolean added)
{
	g_assert_cmpuint(f->events->len, >, index);
	Event event = g_array_index(f->events, Event, index);
	g_assert_cmpuint(event.slot, ==, slot);
	g_assert_cmpint(event.added, ==, added);
}

static void test_independent_removal(Fixture* f, gconstpointer data)
{
	/* Token 1 stays absent while token 2 flaps. */
	poll_snapshot(f, 6, FALSE);
	g_assert_cmpuint(f->events->len, ==, 0);
	poll_snapshot(f, 4, TRUE);
	g_assert_cmpuint(f->events->len, ==, 1);
	assert_event(f, 0, 1, FALSE);

	const guint snapshots[] = { 6, 4, 6, 4, 6, 4 };
	for (guint i = 0; i < G_N_ELEMENTS(snapshots); i++)
	{
		poll_snapshot(f, snapshots[i], i % 2);
		g_assert_cmpuint(f->events->len, ==, 1);
	}

	poll_snapshot(f, 4, FALSE);
	g_assert_cmpuint(f->events->len, ==, 2);
	assert_event(f, 1, 2, FALSE);
	poll_snapshot(f, 4, TRUE);
	g_assert_cmpuint(f->events->len, ==, 2);
}

static void test_independent_addition(Fixture* f, gconstpointer data)
{
	poll_snapshot(f, 0, FALSE);
	g_assert_cmpuint(f->events->len, ==, 0);
	poll_snapshot(f, 0, FALSE);
	g_assert_cmpuint(f->events->len, ==, 3);
	for (guint i = 0; i < 3; i++)
		assert_event(f, i, i + 1, FALSE);

	/* Token 3 stays present while token 2 flaps. */
	poll_snapshot(f, 6, FALSE);
	g_assert_cmpuint(f->events->len, ==, 3);
	poll_snapshot(f, 4, TRUE);
	g_assert_cmpuint(f->events->len, ==, 4);
	assert_event(f, 3, 3, TRUE);
	const guint snapshots[] = { 6, 4, 6, 4, 6 };
	for (guint i = 0; i < G_N_ELEMENTS(snapshots); i++)
	{
		poll_snapshot(f, snapshots[i], i % 2);
		g_assert_cmpuint(f->events->len, ==, 4);
	}
	poll_snapshot(f, 6, TRUE);
	g_assert_cmpuint(f->events->len, ==, 5);
	assert_event(f, 4, 2, TRUE);
	poll_snapshot(f, 6, FALSE);
	g_assert_cmpuint(f->events->len, ==, 5);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add("/token-watch/alternating-snapshots", Fixture, NULL,
	           setup, test_alternating_snapshots, teardown);
	g_test_add("/token-watch/alternating-serial-less-snapshots", Fixture, GINT_TO_POINTER(1),
	           setup, test_alternating_snapshots, teardown);
	g_test_add("/token-watch/baseline-resets-debounce", Fixture, NULL,
	           setup, test_baseline_resets_debounce, teardown);
	g_test_add("/token-watch/independent-removal", Fixture, NULL,
	           setup, test_independent_removal, teardown);
	g_test_add("/token-watch/independent-serial-less-removal", Fixture, GINT_TO_POINTER(1),
	           setup, test_independent_removal, teardown);
	g_test_add("/token-watch/independent-addition", Fixture, NULL,
	           setup, test_independent_addition, teardown);
	g_test_add("/token-watch/independent-serial-less-addition", Fixture, GINT_TO_POINTER(1),
	           setup, test_independent_addition, teardown);
	return g_test_run();
}
