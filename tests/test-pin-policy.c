/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */

#include "fake-pin-provider.h"
#include <string.h>

#define GOOD_PIN "1234"
#define BAD_PIN "0000"

typedef struct
{
	FakePinProvider ui;
	CertificateTokens* tokens;
	CertificateToken* token;
	GThread* coordinator;
	GCancellable* cancellable;
	guint attempts;
	guint refusals;
	guint refreshes;
	CK_FLAGS flags;
	CK_FLAGS refusal_flags;
	gboolean keep_flags_on_success;
	gboolean keep_session;
	CK_USER_TYPE login_user;
	char label[32];
	gboolean serial_less;
	CK_SESSION_HANDLE session;
	guint sessions;
	guint done_calls;
	guint expected_closes;
	guint abandons;
	guint frees;
	CertificatePinOutcome outcome;
	GMutex lock;
	GCond cond;
	gboolean block;
	gboolean release;
	gboolean block_refresh;
	guint refreshing;
	const char* library_manufacturer;
	CK_BYTE library_minor;
	const char* token_manufacturer;
} Fixture;

static Fixture* active;

static CK_RV get_slot_list(CK_BBOOL present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	if (slots != NULL)
	{
		g_assert_cmpuint(*count, >=, 1);
		slots[0] = 1;
	}
	*count = 1;
	return CKR_OK;
}

static CK_RV get_slot_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	memset(info->slotDescription, ' ', sizeof(info->slotDescription));
	memcpy(info->slotDescription, "Test reader", strlen("Test reader"));
	info->flags = CKF_HW_SLOT | CKF_TOKEN_PRESENT;
	return CKR_OK;
}

static CK_RV get_info(CK_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	memset(info->manufacturerID, ' ', sizeof(info->manufacturerID));
	memcpy(info->manufacturerID, active->library_manufacturer, strlen(active->library_manufacturer));
	info->libraryVersion.minor = active->library_minor;
	return CKR_OK;
}

static CK_RV get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	memset(info, 0, sizeof(*info));
	memset(info->label, ' ', sizeof(info->label));
	memcpy(info->label, active->label, strlen(active->label));
	memset(info->manufacturerID, ' ', sizeof(info->manufacturerID));
	memcpy(info->manufacturerID, active->token_manufacturer, strlen(active->token_manufacturer));
	memset(info->model, ' ', sizeof(info->model));
	memset(info->serialNumber, ' ', sizeof(info->serialNumber));
	if (!active->serial_less)
		memcpy(info->serialNumber, "123456", 6);
	info->flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | active->flags;
	return CKR_OK;
}

static CK_RV module_login(CK_SESSION_HANDLE session, CK_USER_TYPE user,
                           CK_UTF8CHAR_PTR pin, CK_ULONG length)
{
	g_assert_true(g_thread_self() != active->coordinator);
	g_assert_cmpuint(user, ==, active->login_user);
	if (active->attempts <= active->refusals)
	{
		active->flags = active->refusal_flags;
		return CKR_PIN_INCORRECT;
	}
	if (!active->keep_flags_on_success)
		active->flags = 0;
	return CKR_OK;
}

static CK_RV open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application,
                          CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session)
{
	*session = ++active->sessions;
	return CKR_OK;
}

static CK_RV close_session(CK_SESSION_HANDLE session)
{
	return CKR_OK;
}

static CK_FUNCTION_LIST module = {
	.C_GetInfo = get_info,
	.C_GetSlotList = get_slot_list,
	.C_GetSlotInfo = get_slot_info,
	.C_GetTokenInfo = get_token_info,
	.C_OpenSession = open_session,
	.C_CloseSession = close_session,
	.C_Login = module_login,
};

/* Replace only module loading: discovery and C_GetTokenInfo refresh remain real. */
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
	return g_strdup("test-pin-module");
}

char* __wrap_p11_kit_module_get_filename(CK_FUNCTION_LIST* value)
{
	g_assert_true(value == &module);
	return NULL;
}

static gboolean login(const char* pin, gpointer user_data, GError** error)
{
	Fixture* fixture = user_data;
	CK_FUNCTION_LIST* resolved = NULL;
	CK_RV rv;

	if (fixture->token->protected_authentication_path)
		g_assert_null(pin);
	else
	{
		g_assert_true(pin == fixture->ui.submitted_pin);
		g_assert_cmpstr(pin, ==, fixture->attempts < fixture->refusals ? BAD_PIN : GOOD_PIN);
	}

	fixture->attempts++;
	g_mutex_lock(&fixture->lock);
	while (fixture->block && !fixture->release)
		g_cond_wait(&fixture->cond, &fixture->lock);
	g_mutex_unlock(&fixture->lock);
	if (!fixture->token->protected_authentication_path)
		g_assert_cmpstr(pin, ==, fixture->attempts <= fixture->refusals ? BAD_PIN : GOOD_PIN);

	if (fixture->session == CK_INVALID_HANDLE &&
	    !certificate_tokens_open_session(fixture->tokens, fixture->token, &resolved,
	                                      &fixture->session, error))
		return FALSE;
	rv = module.C_Login(fixture->session, fixture->login_user, (CK_UTF8CHAR_PTR) pin,
	                    pin != NULL ? strlen(pin) : 0);
	if (rv == CKR_OK)
		return TRUE;

	certificate_pkcs11_set_error(error, rv, "C_Login");
	return FALSE;
}

static void refresh(CertificateToken* token, gpointer user_data)
{
	Fixture* fixture = user_data;

	g_assert_true(g_thread_self() != fixture->coordinator);
	g_mutex_lock(&fixture->lock);
	g_atomic_int_inc(&fixture->refreshing);
	while (fixture->block_refresh && !fixture->release)
		g_cond_wait(&fixture->cond, &fixture->lock);
	g_mutex_unlock(&fixture->lock);
	certificate_tokens_refresh_flags(fixture->tokens, token);
	fixture->refreshes++;
}

static void done(CertificatePinOutcome outcome, gpointer user_data)
{
	Fixture* fixture = user_data;

	g_assert_cmpuint(fixture->ui.closes, ==, fixture->expected_closes);
	fixture->done_calls++;
	fixture->outcome = outcome;
}

static void abandon(gpointer user_data)
{
	Fixture* fixture = user_data;

	g_assert_cmpuint(fixture->done_calls, ==, 1);
	g_assert_cmpuint(fixture->frees, ==, 0);
	fixture->abandons++;
}

static void login_data_free(gpointer user_data)
{
	Fixture* fixture = user_data;

	g_assert_cmpuint(fixture->done_calls, ==, 1);
	if (!fixture->keep_session && fixture->session != CK_INVALID_HANDLE)
	{
		module.C_CloseSession(fixture->session);
		fixture->session = CK_INVALID_HANDLE;
	}
	g_atomic_int_inc(&fixture->frees);
}

static gboolean tick(gpointer user_data)
{
	return G_SOURCE_CONTINUE;
}

/* Bound main-context waits even when the worker is deliberately held. */
static void wait_for(const guint* counter, guint target)
{
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	guint source = g_timeout_add(10, tick, NULL);

	while ((guint) g_atomic_int_get(counter) < target && g_get_monotonic_time() < deadline)
		g_main_context_iteration(NULL, TRUE);
	g_source_remove(source);
	g_assert_cmpuint(g_atomic_int_get(counter), ==, target);
}

static void fixture_set_up(Fixture* fixture, gconstpointer user_data)
{
	static guint token_id;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) list = NULL;

	active = fixture;
	fixture->login_user = CKU_USER;
	g_snprintf(fixture->label, sizeof(fixture->label), "Test token %u", ++token_id);
	fixture->coordinator = g_thread_self();
	fixture->refusal_flags = CKF_USER_PIN_COUNT_LOW;
	fixture->expected_closes = 1;
	/* OpenSC 0.27 PIV by default: the module that needs the retry-flag workaround. */
	fixture->library_manufacturer = "OpenSC Project";
	fixture->library_minor = 27;
	fixture->token_manufacturer = "piv_II";
	fake_pin_provider_init(&fixture->ui);
	certificate_pin_set_provider(&fixture->ui.provider);
	certificate_ui_set_has_display(FALSE);
	certificate_pin_set_login_timeout(60);
	fixture->tokens = certificate_tokens_new(NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(fixture->tokens);
	list = certificate_tokens_list(fixture->tokens, &error);
	g_assert_no_error(error);
	g_assert_cmpuint(list->len, ==, 1);
	fixture->token = certificate_token_ref(g_ptr_array_index(list, 0));
	fixture->cancellable = g_cancellable_new();
	g_mutex_init(&fixture->lock);
	g_cond_init(&fixture->cond);
}

static void fixture_tear_down(Fixture* fixture, gconstpointer user_data)
{
	g_assert_cmpuint(fixture->done_calls, ==, 1);
	g_assert_cmpuint(fixture->frees, ==, 1);
	g_assert_null(fixture->ui.prompt);
	certificate_token_unref(fixture->token);
	certificate_tokens_free(fixture->tokens);
	active = NULL;
	g_object_unref(fixture->cancellable);
	g_mutex_clear(&fixture->lock);
	g_cond_clear(&fixture->cond);
	certificate_pin_set_login_timeout(60);
}

static void start(Fixture* fixture)
{
	certificate_pin_login_full(fixture->token, NULL, NULL, "Test application", "test PIN policy",
	                           login, refresh, abandon, fixture, login_data_free,
	                           fixture->cancellable, done, fixture);
	if (fixture->expected_closes != 0)
		wait_for(&fixture->ui.shows, 1);
}

static void finish(Fixture* fixture, CertificatePinOutcome outcome, guint attempts)
{
	wait_for(&fixture->frees, 1);
	g_assert_cmpint(fixture->outcome, ==, outcome);
	g_assert_cmpuint(fixture->attempts, ==, attempts);
	g_assert_cmpuint(fixture->ui.closes, ==, fixture->expected_closes);
}

static void next_session(Fixture* fixture, const char* session_id)
{
	fixture->done_calls = fixture->frees = 0;
	fixture->expected_closes++;
	certificate_pin_login_full(fixture->token, session_id, NULL, "Test application",
	                           "test PIN policy", login, refresh, abandon, fixture,
	                           login_data_free, fixture->cancellable, done, fixture);
	wait_for(&fixture->ui.shows, fixture->expected_closes);
}

static void test_correct_pin(Fixture* fixture, gconstpointer user_data)
{
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_cmpuint(fixture->ui.retries, ==, 0);
	g_assert_cmpuint(fixture->ui.shows, ==, 1);
}

static void test_provider_snapshot(Fixture* fixture, gconstpointer user_data)
{
	FakePinProvider replacement;

	start(fixture);
	fake_pin_provider_init(&replacement);
	certificate_pin_set_provider(&replacement.provider);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_cmpuint(replacement.shows, ==, 0);
	g_assert_cmpuint(replacement.closes, ==, 0);
}

static void test_wrong_then_right(Fixture* fixture, gconstpointer user_data)
{
	fixture->refusals = 1;
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "pin-prompted session=(none) detail=on-screen flags=none");
	start(fixture);
	g_test_assert_expected_messages();
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "pin-incorrect session=(none) detail=retry-offered flags=count_low");
	fake_pin_provider_submit(&fixture->ui, BAD_PIN);
	wait_for(&fixture->ui.retries, 1);
	g_test_assert_expected_messages();
	g_assert_cmpuint(fixture->refreshes, ==, 2);
	g_assert_true(fixture->ui.count_low);
	g_assert_false(fixture->ui.busy);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 2);
	g_assert_cmpuint(fixture->ui.shows, ==, 1);
}

static void test_attempt_cap(Fixture* fixture, gconstpointer user_data)
{
	fixture->refusals = 10;
	start(fixture);
	for (guint i = 0; i < 3; i++)
	{
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
		                      "pin-incorrect session=(none) detail=retry-offered flags=count_low");
		if (i == 2)
			g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			                      "pin-incorrect session=(none) detail=attempt-cap flags=count_low");
		fake_pin_provider_submit(&fixture->ui, BAD_PIN);
		if (i < 2)
			wait_for(&fixture->ui.retries, i + 1);
		else
			wait_for(&fixture->frees, 1);
		g_test_assert_expected_messages();
	}
	finish(fixture, CERTIFICATE_PIN_INCORRECT, 3);
	g_assert_cmpuint(fixture->refreshes, ==, 4);
	g_assert_cmpuint(fixture->ui.retries, ==, 2);
}

static void test_cancel(Fixture* fixture, gconstpointer user_data)
{
	start(fixture);
	g_cancellable_cancel(fixture->cancellable);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 0);
}

static void test_final_try(Fixture* fixture, gconstpointer user_data)
{
	gboolean accepted = GPOINTER_TO_INT(user_data);

	fixture->flags = CKF_USER_PIN_FINAL_TRY;
	start(fixture);
	g_assert_true(fixture->ui.final_try);
	g_assert_cmpuint(fixture->ui.warnings, ==, 0);
	g_assert_cmpuint(fixture->attempts, ==, 0);
	if (accepted)
		fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	else
		fake_pin_provider_cancel(&fixture->ui);
	finish(fixture, accepted ? CERTIFICATE_PIN_OK : CERTIFICATE_PIN_CANCELLED, accepted ? 1 : 0);
	g_assert_cmpuint(fixture->ui.warnings, ==, 0);
}

static void test_count_low_at_open(Fixture* fixture, gconstpointer user_data)
{
	fixture->flags = CKF_USER_PIN_COUNT_LOW;
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "pin-prompted session=(none) detail=on-screen flags=count_low");
	start(fixture);
	g_test_assert_expected_messages();
	g_assert_true(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_cmpuint(fixture->ui.warnings, ==, 0);
}

static void test_refreshed_final_try(Fixture* fixture, gconstpointer user_data)
{
	fixture->refusals = 1;
	fixture->refusal_flags |= CKF_USER_PIN_FINAL_TRY;
	start(fixture);
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                      "pin-incorrect session=(none) detail=retry-offered flags=count_low,final_try");
	fake_pin_provider_submit(&fixture->ui, BAD_PIN);
	wait_for(&fixture->ui.retries, 1);
	g_test_assert_expected_messages();
	g_assert_true(fixture->ui.final_try);
	g_assert_cmpuint(fixture->ui.warnings, ==, 0);
	g_assert_cmpuint(fixture->attempts, ==, 1);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 2);
	g_assert_cmpuint(fixture->ui.warnings, ==, 0);
}

static void test_refreshed_locked(Fixture* fixture, gconstpointer user_data)
{
	fixture->refusals = 1;
	fixture->refusal_flags |= CKF_USER_PIN_LOCKED;
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, BAD_PIN);
	finish(fixture, CERTIFICATE_PIN_LOCKED, 1);
	g_assert_cmpuint(fixture->ui.retries, ==, 0);
}

static void test_flags_across_sessions(Fixture* fixture, gconstpointer user_data)
{
	gboolean final_try = GPOINTER_TO_INT(user_data);
	g_autoptr(GPtrArray) rediscovered = NULL;

	fixture->refusals = 1;
	if (final_try)
		fixture->refusal_flags |= CKF_USER_PIN_FINAL_TRY;
	start(fixture);
	g_assert_false(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	fake_pin_provider_submit(&fixture->ui, BAD_PIN);
	wait_for(&fixture->ui.retries, 1);
	g_assert_true(fixture->ui.count_low);
	g_assert_cmpint(fixture->ui.final_try, ==, final_try);
	fake_pin_provider_cancel(&fixture->ui);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 1);

	/* A new prompt must still warn while the module reports the failed attempt. */
	next_session(fixture, "/test/session2");
	g_assert_true(fixture->ui.count_low);
	g_assert_cmpint(fixture->ui.final_try, ==, final_try);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 2);
	/* C_Login reset the module flags, and the success refresh updated our copy. */
	g_assert_false(fixture->token->pin_count_low);
	g_assert_false(fixture->token->pin_final_try);
	g_assert_cmpuint(fixture->refreshes, ==, 4);
	g_assert_cmpuint(fixture->sessions, ==, 2);
	rediscovered = certificate_tokens_list(fixture->tokens, NULL);
	g_assert_cmpuint(rediscovered->len, ==, 1);
	CertificateToken* fresh = g_ptr_array_index(rediscovered, 0);
	g_assert_true(certificate_token_same_presence(fresh, fixture->token));
	g_assert_false(fresh->pin_count_low);
	g_assert_false(fresh->pin_final_try);

	/* A new prompt/session deliberately reuses the original token record. */
	next_session(fixture, "/test/session3");
	g_assert_false(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 3);
	g_assert_cmpuint(fixture->sessions, ==, 3);
	g_assert_cmpuint(fixture->refreshes, ==, 6);
}

static void test_success_suppresses_module_flags(Fixture* fixture, gconstpointer user_data)
{
	guint mode = GPOINTER_TO_UINT(user_data);
	g_autoptr(GPtrArray) rediscovered = NULL;
	g_autoptr(GError) error = NULL;

	fixture->login_user = (mode & 1) ? CKU_CONTEXT_SPECIFIC : CKU_USER;
	if (mode & 2)
	{
		fixture->serial_less = TRUE;
		g_free(fixture->token->serial);
		fixture->token->serial = g_strdup("");
		/* Serial-less records cannot rebind grants; supply a module session for this callback. */
		g_assert_cmpuint(module.C_OpenSession(fixture->token->slot, CKF_SERIAL_SESSION,
		                                     NULL, NULL, &fixture->session), ==, CKR_OK);
	}
	fixture->flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
	fixture->keep_flags_on_success = TRUE;
	fixture->keep_session = TRUE;
	start(fixture);
	g_assert_true(fixture->ui.count_low);
	g_assert_true(fixture->ui.final_try);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_false(fixture->token->pin_count_low);
	g_assert_false(fixture->token->pin_final_try);
	g_assert_cmpuint(fixture->flags, ==, CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY);

	/* The next prompt reuses the open PKCS#11 session. */
	next_session(fixture, "/test/session1");
	g_assert_false(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	fixture->keep_session = FALSE;
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 2);
	g_assert_cmpuint(fixture->sessions, ==, 1);

	/* A new token store and record must retain the process's suppression. */
	certificate_tokens_free(fixture->tokens);
	fixture->tokens = certificate_tokens_new(NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(fixture->tokens);
	rediscovered = certificate_tokens_list(fixture->tokens, &error);
	g_assert_no_error(error);
	g_assert_cmpuint(rediscovered->len, ==, 1);
	CertificateToken* fresh = g_ptr_array_index(rediscovered, 0);
	g_assert_true(certificate_token_same_presence(fresh, fixture->token));
	g_assert_false(fresh->pin_count_low);
	g_assert_false(fresh->pin_final_try);
	certificate_token_unref(fixture->token);
	fixture->token = certificate_token_ref(fresh);

	if (fixture->serial_less)
		g_assert_cmpuint(module.C_OpenSession(fixture->token->slot, CKF_SERIAL_SESSION,
		                                     NULL, NULL, &fixture->session), ==, CKR_OK);
	next_session(fixture, "/test/session2");
	g_assert_false(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 3);
	g_assert_cmpuint(fixture->sessions, ==, 2);
	g_assert_cmpuint(fixture->flags, ==, CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY);
}

/* Modules other than OpenSC 0.27 PIV keep reporting their own flags after success. */
static void test_unaffected_module_keeps_flags(Fixture* fixture, gconstpointer user_data)
{
	guint mode = GPOINTER_TO_UINT(user_data);
	g_autoptr(GPtrArray) list = NULL;
	g_autoptr(GError) error = NULL;

	if (mode == 0)
		fixture->library_manufacturer = "SoftHSM";
	else if (mode == 1)
		fixture->library_minor = 28;
	else
		fixture->token_manufacturer = "OpenSC Project";
	certificate_tokens_free(fixture->tokens);
	fixture->tokens = certificate_tokens_new(NULL, &error);
	g_assert_no_error(error);
	list = certificate_tokens_list(fixture->tokens, &error);
	g_assert_no_error(error);
	g_assert_cmpuint(list->len, ==, 1);
	certificate_token_unref(fixture->token);
	fixture->token = certificate_token_ref(g_ptr_array_index(list, 0));
	g_assert_false(fixture->token->stale_retry_flags);

	fixture->flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
	fixture->keep_flags_on_success = TRUE;
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_true(fixture->token->pin_count_low);
	g_assert_true(fixture->token->pin_final_try);
}

/* A refusal through an unaffected module still ends suppression for the card. */
static void test_unaffected_refusal_ends_suppression(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GPtrArray) list = NULL;
	g_autoptr(GError) error = NULL;

	fixture->flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
	fixture->keep_flags_on_success = TRUE;
	fixture->keep_session = TRUE;
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_false(fixture->token->pin_final_try);

	certificate_token_record_login_result(fixture->token, TRUE);
	fixture->token->stale_retry_flags = FALSE;
	certificate_token_record_login_result(fixture->token, FALSE);

	certificate_tokens_free(fixture->tokens);
	fixture->tokens = certificate_tokens_new(NULL, &error);
	g_assert_no_error(error);
	list = certificate_tokens_list(fixture->tokens, &error);
	g_assert_no_error(error);
	g_assert_cmpuint(list->len, ==, 1);
	g_assert_true(((CertificateToken*) g_ptr_array_index(list, 0))->stale_retry_flags);
	g_assert_true(((CertificateToken*) g_ptr_array_index(list, 0))->pin_final_try);
	fixture->keep_session = FALSE;
}

static void test_refusal_restores_module_flags(Fixture* fixture, gconstpointer user_data)
{
	gboolean final_try = GPOINTER_TO_INT(user_data);

	fixture->flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
	fixture->keep_flags_on_success = TRUE;
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_false(fixture->token->pin_count_low);
	g_assert_false(fixture->token->pin_final_try);

	next_session(fixture, "/test/session2");
	g_assert_false(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	fixture->refusals = fixture->attempts + 1;
	fixture->refusal_flags = final_try ? CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY : 0;
	fake_pin_provider_submit(&fixture->ui, BAD_PIN);
	wait_for(&fixture->ui.retries, 1);
	g_assert_cmpint(fixture->ui.count_low, ==, final_try);
	g_assert_cmpint(fixture->ui.final_try, ==, final_try);
	fake_pin_provider_cancel(&fixture->ui);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 2);

	next_session(fixture, "/test/session3");
	g_assert_cmpint(fixture->ui.count_low, ==, final_try);
	g_assert_cmpint(fixture->ui.final_try, ==, final_try);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 3);
	g_assert_false(fixture->token->pin_count_low);
	g_assert_false(fixture->token->pin_final_try);

	next_session(fixture, "/test/session4");
	g_assert_false(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	fake_pin_provider_cancel(&fixture->ui);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 3);
}

static void test_locked_after_success(Fixture* fixture, gconstpointer user_data)
{
	gboolean refused = GPOINTER_TO_INT(user_data);

	fixture->flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
	fixture->keep_flags_on_success = TRUE;
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_false(fixture->token->pin_count_low);
	g_assert_false(fixture->token->pin_final_try);

	if (refused)
	{
		next_session(fixture, "/test/session2");
		g_assert_false(fixture->ui.final_try);
		fixture->refusals = fixture->attempts + 1;
		fixture->refusal_flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY |
		                         CKF_USER_PIN_LOCKED;
		fake_pin_provider_submit(&fixture->ui, BAD_PIN);
		finish(fixture, CERTIFICATE_PIN_LOCKED, 2);
		g_assert_true(fixture->token->pin_count_low);
		g_assert_true(fixture->token->pin_final_try);
	}
	else
	{
		fixture->flags |= CKF_USER_PIN_LOCKED;
		fixture->done_calls = fixture->frees = 0;
		fixture->expected_closes++;
		certificate_pin_login_full(fixture->token, "/test/session2", NULL, "Test application",
		                           "test PIN policy", login, refresh, abandon, fixture,
		                           login_data_free, fixture->cancellable, done, fixture);
		finish(fixture, CERTIFICATE_PIN_LOCKED, 1);
		g_assert_false(fixture->token->pin_count_low);
		g_assert_false(fixture->token->pin_final_try);
		g_assert_cmpuint(fixture->ui.shows, ==, 1);
	}
	g_assert_true(fixture->token->pin_locked);
	g_assert_cmpuint(fixture->ui.retries, ==, 0);
}

static void test_success_other_token(Fixture* fixture, gconstpointer user_data)
{
	g_autoptr(GPtrArray) rediscovered = NULL;

	fixture->flags = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
	fixture->keep_flags_on_success = TRUE;
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
	g_assert_false(fixture->token->pin_final_try);

	g_strlcat(fixture->label, " other", sizeof(fixture->label));
	rediscovered = certificate_tokens_list(fixture->tokens, NULL);
	g_assert_cmpuint(rediscovered->len, ==, 1);
	CertificateToken* fresh = g_ptr_array_index(rediscovered, 0);
	g_assert_false(certificate_token_same_presence(fresh, fixture->token));
	certificate_token_unref(fixture->token);
	fixture->token = certificate_token_ref(fresh);
	next_session(fixture, "/test/session2");
	g_assert_true(fixture->ui.count_low);
	g_assert_true(fixture->ui.final_try);
	fake_pin_provider_cancel(&fixture->ui);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 1);
}

static void test_stale_flags_at_open(Fixture* fixture, gconstpointer user_data)
{
	/* Also exercise same-presence matching for serial-less discovery records. */
	if (GPOINTER_TO_INT(user_data))
	{
		fixture->serial_less = TRUE;
		g_free(fixture->token->serial);
		fixture->token->serial = g_strdup("");
	}
	fixture->token->pin_count_low = TRUE;
	fixture->token->pin_final_try = TRUE;
	fixture->token->pin_locked = TRUE;
	start(fixture);
	g_assert_false(fixture->ui.count_low);
	g_assert_false(fixture->ui.final_try);
	g_assert_false(fixture->token->pin_locked);
	g_assert_cmpuint(fixture->refreshes, ==, 1);
	fake_pin_provider_cancel(&fixture->ui);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 0);
}

static void test_refresh_missed(Fixture* fixture, gconstpointer user_data)
{
	gboolean stale_flags = GPOINTER_TO_INT(user_data);

	g_free(fixture->token->serial);
	fixture->token->serial = g_strdup("changed");
	fixture->token->pin_count_low = stale_flags;
	fixture->token->pin_final_try = stale_flags;
	fixture->token->pin_locked = stale_flags;
	fixture->flags = stale_flags ? 0 :
	    CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED;
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, stale_flags ?
	    "pin-flags-refresh-missed session=(none) detail=no-matching-token flags=count_low,final_try,locked" :
	    "pin-flags-refresh-missed session=(none) detail=no-matching-token flags=none");
	certificate_tokens_refresh_flags(fixture->tokens, fixture->token);
	g_test_assert_expected_messages();
	g_assert_cmpint(fixture->token->pin_count_low, ==, stale_flags);
	g_assert_cmpint(fixture->token->pin_final_try, ==, stale_flags);
	g_assert_cmpint(fixture->token->pin_locked, ==, stale_flags);

	g_free(fixture->token->serial);
	fixture->token->serial = g_strdup("123456");
	fixture->flags = 0;
	start(fixture);
	fake_pin_provider_cancel(&fixture->ui);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 0);
}

static void test_locked_at_open(Fixture* fixture, gconstpointer user_data)
{
	fixture->flags = CKF_USER_PIN_LOCKED;
	certificate_pin_login_full(fixture->token, NULL, NULL, "Test application", "test PIN policy",
	                           login, refresh, abandon, fixture, login_data_free,
	                           fixture->cancellable, done, fixture);
	finish(fixture, CERTIFICATE_PIN_LOCKED, 0);
	g_assert_cmpuint(fixture->ui.shows, ==, 0);
	g_assert_cmpuint(fixture->refreshes, ==, 1);
}

static void test_protected_path(Fixture* fixture, gconstpointer user_data)
{
	fixture->token->protected_authentication_path = TRUE;
	fixture->refusals = GPOINTER_TO_UINT(user_data);
	start(fixture);
	g_assert_true(fixture->ui.protected_path);
	finish(fixture, fixture->refusals ? CERTIFICATE_PIN_INCORRECT : CERTIFICATE_PIN_OK, 1);
	g_assert_cmpuint(fixture->ui.retries, ==, 0);
}

static void test_protected_final_try(Fixture* fixture, gconstpointer user_data)
{
	gboolean accepted = GPOINTER_TO_INT(user_data);
	PinPrompt* prompt;

	fixture->token->protected_authentication_path = TRUE;
	fixture->flags = CKF_USER_PIN_FINAL_TRY;
	start(fixture);
	prompt = certificate_pin_prompt_ref(fixture->ui.prompt);
	g_assert_true(fixture->ui.final_try);
	g_assert_cmpuint(fixture->ui.warnings, ==, 1);
	/* Submitting without Continue must neither start the reader nor repeat the warning. */
	fake_pin_provider_submit(&fixture->ui, NULL);
	fake_pin_provider_submit(&fixture->ui, NULL);
	g_assert_cmpuint(fixture->ui.warnings, ==, 1);
	g_assert_cmpuint(fixture->attempts, ==, 0);
	fake_pin_provider_confirm(&fixture->ui, accepted);
	/* Repeated replies/submits during login and after completion cannot restart the reader. */
	certificate_pin_prompt_warning_reply(prompt, TRUE);
	certificate_pin_prompt_submit(prompt);
	wait_for(&fixture->done_calls, 1);
	certificate_pin_prompt_warning_reply(prompt, TRUE);
	certificate_pin_prompt_submit(prompt);
	certificate_pin_prompt_unref(prompt);
	finish(fixture, accepted ? CERTIFICATE_PIN_OK : CERTIFICATE_PIN_CANCELLED, accepted ? 1 : 0);
}

static void release_login(Fixture* fixture)
{
	g_mutex_lock(&fixture->lock);
	fixture->release = TRUE;
	g_cond_signal(&fixture->cond);
	g_mutex_unlock(&fixture->lock);
}

static void test_cancel_during_refresh(Fixture* fixture, gconstpointer user_data)
{
	fixture->block_refresh = TRUE;
	certificate_pin_login_full(fixture->token, NULL, NULL, "Test application", "test PIN policy",
	                           login, refresh, abandon, fixture, login_data_free,
	                           fixture->cancellable, done, fixture);
	wait_for(&fixture->refreshing, 1);
	g_cancellable_cancel(fixture->cancellable);
	while (g_main_context_iteration(NULL, FALSE))
		;
	g_assert_cmpuint(fixture->ui.shows, ==, 0);
	g_assert_cmpuint(fixture->done_calls, ==, 0);
	g_assert_cmpuint(fixture->frees, ==, 0);
	release_login(fixture);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 0);
	g_assert_cmpuint(fixture->ui.shows, ==, 0);
	g_assert_cmpuint(fixture->ui.hides, ==, 0);
	g_assert_cmpuint(fixture->abandons, ==, 0);
}

static void test_in_flight(Fixture* fixture, gconstpointer user_data)
{
	gboolean timeout = GPOINTER_TO_INT(user_data);

	fixture->block = TRUE;
	if (timeout)
		certificate_pin_set_login_timeout(1);
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	if (!timeout)
		fake_pin_provider_cancel(&fixture->ui);
	wait_for(&fixture->ui.hides, 1);
	g_assert_cmpuint(fixture->done_calls, ==, 0);
	g_assert_cmpuint(fixture->frees, ==, 0);
	g_assert_cmpuint(fixture->ui.closes, ==, 0);
	release_login(fixture);
	finish(fixture, timeout ? CERTIFICATE_PIN_TIMED_OUT : CERTIFICATE_PIN_CANCELLED, 1);
	g_assert_cmpuint(fixture->abandons, ==, 1);
}

static void test_empty_answer(Fixture* fixture, gconstpointer user_data)
{
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, "");
	g_assert_cmpuint(fixture->ui.retries, ==, 1);
	g_assert_cmpuint(fixture->attempts, ==, 0);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
}

static void test_memory_unavailable(Fixture* fixture, gconstpointer user_data)
{
	start(fixture);
	g_assert_false(certificate_pin_prompt_hold(fixture->ui.prompt, NULL, 0));
	g_assert_cmpuint(fixture->ui.retries, ==, 1);
	g_assert_cmpstr(fixture->ui.status, ==, "Could not allocate memory for the PIN.");
	g_assert_cmpuint(fixture->attempts, ==, 0);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
}

static void test_oversized_answer(Fixture* fixture, gconstpointer user_data)
{
	char pin[513];

	memset(pin, '1', sizeof(pin) - 1);
	pin[sizeof(pin) - 1] = '\0';
	start(fixture);
	fake_pin_provider_submit(&fixture->ui, pin);
	g_assert_cmpuint(fixture->ui.retries, ==, 1);
	g_assert_cmpuint(fixture->attempts, ==, 0);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
}

static void test_submit_without_input(Fixture* fixture, gconstpointer user_data)
{
	start(fixture);
	certificate_pin_prompt_submit(fixture->ui.prompt);
	g_assert_cmpuint(fixture->ui.retries, ==, 1);
	g_assert_cmpuint(fixture->attempts, ==, 0);
	fake_pin_provider_submit(&fixture->ui, GOOD_PIN);
	finish(fixture, CERTIFICATE_PIN_OK, 1);
}

static void test_stale_secret(Fixture* fixture, gconstpointer user_data)
{
	PinPrompt* prompt;
	XccSecret* secret = xcc_secret_new();
	uint8_t* data;

	g_assert_nonnull(secret);
	data = xcc_secret_data(secret, NULL);
	memcpy(data, GOOD_PIN, strlen(GOOD_PIN));
	start(fixture);
	prompt = certificate_pin_prompt_ref(fixture->ui.prompt);
	fake_pin_provider_cancel(&fixture->ui);
	g_assert_false(certificate_pin_prompt_hold(prompt, secret, strlen(GOOD_PIN)));
	certificate_pin_prompt_unref(prompt);
	finish(fixture, CERTIFICATE_PIN_CANCELLED, 0);
}

static void test_no_display(Fixture* fixture, gconstpointer user_data)
{
	fixture->ui.provider.needs_display = TRUE;
	certificate_pin_set_provider(&fixture->ui.provider);
	/* No interaction exists on this early return. */
	fixture->expected_closes = 0;
	start(fixture);
	finish(fixture, CERTIFICATE_PIN_NO_DISPLAY, 0);
	g_assert_cmpuint(fixture->ui.shows, ==, 0);
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);

#define ADD(path, data, function) \
	g_test_add("/pin-policy/" path, Fixture, GINT_TO_POINTER(data), \
	           fixture_set_up, function, fixture_tear_down)

	ADD("correct-pin", 0, test_correct_pin);
	ADD("provider-snapshot", 0, test_provider_snapshot);
	ADD("wrong-then-right", 0, test_wrong_then_right);
	ADD("attempt-cap", 0, test_attempt_cap);
	ADD("cancel", 0, test_cancel);
	ADD("final-try-cancelled", FALSE, test_final_try);
	ADD("final-try-one-submit", TRUE, test_final_try);
	ADD("count-low-at-open", 0, test_count_low_at_open);
	ADD("refreshed-final-try", 0, test_refreshed_final_try);
	ADD("refreshed-locked", 0, test_refreshed_locked);
	ADD("final-try-clears-across-sessions", TRUE, test_flags_across_sessions);
	ADD("count-low-clears-across-sessions", FALSE, test_flags_across_sessions);
	ADD("success-suppresses-module-flags", 0, test_success_suppresses_module_flags);
	ADD("context-success-suppresses-module-flags", 1, test_success_suppresses_module_flags);
	ADD("serial-less-success-suppresses-module-flags", 2, test_success_suppresses_module_flags);
	ADD("serial-less-context-success-suppresses-module-flags", 3, test_success_suppresses_module_flags);
	ADD("other-library-keeps-flags", 0, test_unaffected_module_keeps_flags);
	ADD("newer-opensc-keeps-flags", 1, test_unaffected_module_keeps_flags);
	ADD("other-opensc-card-keeps-flags", 2, test_unaffected_module_keeps_flags);
	ADD("unaffected-refusal-ends-suppression", 0, test_unaffected_refusal_ends_suppression);
	ADD("refusal-restores-final-try", TRUE, test_refusal_restores_module_flags);
	ADD("refusal-reports-clear-flags", FALSE, test_refusal_restores_module_flags);
	ADD("locked-after-success", FALSE, test_locked_after_success);
	ADD("refusal-locked-after-success", TRUE, test_locked_after_success);
	ADD("success-other-token", 0, test_success_other_token);
	ADD("stale-flags-at-open", FALSE, test_stale_flags_at_open);
	ADD("serial-less-stale-flags-at-open", TRUE, test_stale_flags_at_open);
	ADD("refresh-missed-clear-flags", FALSE, test_refresh_missed);
	ADD("refresh-missed-set-flags", TRUE, test_refresh_missed);
	ADD("locked-at-open", 0, test_locked_at_open);
	ADD("cancel-during-refresh", 0, test_cancel_during_refresh);
	ADD("protected-path", 0, test_protected_path);
	ADD("protected-path-refused", 1, test_protected_path);
	ADD("protected-final-try-refused", FALSE, test_protected_final_try);
	ADD("protected-final-try-accepted", TRUE, test_protected_final_try);
	ADD("timeout-abandons-success", TRUE, test_in_flight);
	ADD("cancel-abandons-success", FALSE, test_in_flight);
	ADD("empty-answer", 0, test_empty_answer);
	ADD("memory-unavailable", 0, test_memory_unavailable);
	ADD("oversized-answer", 0, test_oversized_answer);
	ADD("submit-without-input", 0, test_submit_without_input);
	ADD("stale-secret", 0, test_stale_secret);
	ADD("no-display", 0, test_no_display);

#undef ADD

	return g_test_run();
}
