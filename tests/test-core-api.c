/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <string.h>
#include "core/core.h"
#include "core/context-private.h"
#include "core/ui.h"
#include "core/dispatch-glib.h"
#include "broker/operations.h"
#include "fixture-util.h"

typedef struct
{
	gboolean open, find_pending, initialized, context_authenticated, stale;
} TokenSession;

/* Script the token boundary, retaining the real transactions, broker and PIN policy. */
typedef struct
{
	XccContext* context;
	XccSession* session;
	CertificateCandidate* candidate;
	GThread* desktop;
	guint chooser_shows, pin_shows, context_pin_shows, closes, hides, completions, updates;
	XccUiId chooser_id, pin_id;
	uint64_t revision, choice;
	gboolean choose, submit, shutdown, always_auth, empty, confirm, pause_context;
	uint64_t warning_id;
	guint warnings, ordered_completions;
	guint user_logins, context_logins, signatures, logouts;
	guint already_logged_in, settle_login_after;
	guint sessions_opened, sessions_closed, open_sessions, key_generation, session_queries;
	gboolean token_logged_in, hide_private_key, public_session;
	TokenSession handles[32];
	CK_RV login_result;
	CK_RV sign_result;
	guint sign_failure_stage, removals;
	gboolean fail_context_login;
	gint clock_offset;
	GMutex lock;
	GCond cond;
	gboolean hold_enumeration, enumerating, hold_login, logging_in, hold_open, opening;
	gboolean hold_sign, signing;
	gboolean hold_session_info, querying_session;
	GCancellable* observed_open;
	gint opened_callbacks, budget_refusals;
	guint expirations;
	gboolean real_watch;
	GString* deliveries;
} Fixture;
static Fixture* active;

void __wrap_certificate_tokens_watch(CertificateTokens*, CertificateTokenEvent, gpointer);
void __wrap_certificate_tokens_stop_watch(CertificateTokens*);
void __real_certificate_tokens_watch(CertificateTokens*, CertificateTokenEvent, gpointer);
void __real_certificate_tokens_stop_watch(CertificateTokens*);
void __wrap_certificate_tokens_enumerate_async(CertificateTokens*, GCancellable*,
											   GAsyncReadyCallback, gpointer);
GPtrArray* __wrap_certificate_tokens_enumerate_finish(CertificateTokens*, GAsyncResult*, gboolean*,
													  GError**);
gboolean __wrap_certificate_tokens_open_session(CertificateTokens*, const CertificateToken*,
												CK_FUNCTION_LIST**, CK_SESSION_HANDLE*, GError**);
void __wrap_certificate_tokens_refresh_flags(CertificateTokens*, CertificateToken*);
gint64 __real_g_get_monotonic_time(void);
gint64 __wrap_g_get_monotonic_time(void);
gboolean __real_g_task_propagate_boolean(GTask*, GError**);
gboolean __wrap_g_task_propagate_boolean(GTask*, GError**);
gpointer __real_g_task_propagate_pointer(GTask*, GError**);
gpointer __wrap_g_task_propagate_pointer(GTask*, GError**);

/* Observe on_opened before it reads device state, including while the token is stalled. */
static void observe_opened(GTask* task)
{
	g_mutex_lock(&active->lock);
	if (active->observed_open != NULL &&
	    g_task_get_cancellable(task) == active->observed_open)
		g_atomic_int_inc(&active->opened_callbacks);
	g_mutex_unlock(&active->lock);
}
gboolean __wrap_g_task_propagate_boolean(GTask* task, GError** error)
{
	gboolean ok = __real_g_task_propagate_boolean(task, error);
	observe_opened(task);
	return ok;
}
gpointer __wrap_g_task_propagate_pointer(GTask* task, GError** error)
{
	gpointer result = __real_g_task_propagate_pointer(task, error);
	observe_opened(task);
	return result;
}

gint64 __wrap_g_get_monotonic_time(void)
{
	return __real_g_get_monotonic_time() +
		   (active != NULL ? (gint64)g_atomic_int_get(&active->clock_offset) * G_USEC_PER_SEC : 0);
}
void __wrap_certificate_tokens_watch(CertificateTokens* t, CertificateTokenEvent event,
									 gpointer data)
{
	if (active->real_watch)
		__real_certificate_tokens_watch(t, event, data);
}
void __wrap_certificate_tokens_stop_watch(CertificateTokens* t)
{
	if (active->real_watch)
		__real_certificate_tokens_stop_watch(t);
}
void __wrap_certificate_tokens_refresh_flags(CertificateTokens* t, CertificateToken* token)
{
}
static void enumerated(GTask* task, gpointer source, gpointer data, GCancellable* cancellable)
{
	Fixture* f = data;
	g_assert_true(g_thread_self() != f->desktop);
	g_mutex_lock(&f->lock);
	f->enumerating = TRUE;
	g_cond_broadcast(&f->cond);
	while (f->hold_enumeration)
		g_cond_wait(&f->cond, &f->lock);
	g_mutex_unlock(&f->lock);
	GPtrArray* values = g_ptr_array_new_with_free_func((GDestroyNotify)certificate_candidate_unref);
	if (!f->empty)
		g_ptr_array_add(values, certificate_candidate_ref(f->candidate));
	g_task_return_pointer(task, values, (GDestroyNotify)g_ptr_array_unref);
}
void __wrap_certificate_tokens_enumerate_async(CertificateTokens* t, GCancellable* cancel,
											   GAsyncReadyCallback callback, gpointer data)
{
	g_autoptr(GTask) task = g_task_new(NULL, cancel, callback, data);
	g_task_set_task_data(task, active, NULL);
	g_task_run_in_thread(task, enumerated);
}
GPtrArray* __wrap_certificate_tokens_enumerate_finish(CertificateTokens* t, GAsyncResult* result,
													  gboolean* present, GError** error)
{
	*present = TRUE;
	return g_task_propagate_pointer(G_TASK(result), error);
}
static CK_RV find_init(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
	g_mutex_lock(&active->lock);
	active->handles[h].find_pending = !active->hide_private_key || active->token_logged_in;
	g_mutex_unlock(&active->lock);
	return CKR_OK;
}
static CK_RV find(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR objects, CK_ULONG max,
				  CK_ULONG_PTR count)
{
	g_mutex_lock(&active->lock);
	*count = active->handles[h].find_pending ? 1 : 0;
	if (*count != 0)
		objects[0] = 7 + active->key_generation;
	active->handles[h].find_pending = FALSE;
	g_mutex_unlock(&active->lock);
	return CKR_OK;
}
static CK_RV finish_find(CK_SESSION_HANDLE h)
{
	return CKR_OK;
}
static CK_RV attribute(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE key, CK_ATTRIBUTE_PTR attrs,
					   CK_ULONG count)
{
	g_assert_cmpuint(count, ==, 1);
	g_assert_cmpuint(attrs[0].type, ==, CKA_ALWAYS_AUTHENTICATE);
	*(CK_BBOOL*)attrs[0].pValue = active->always_auth ? CK_TRUE : CK_FALSE;
	attrs[0].ulValueLen = sizeof(CK_BBOOL);
	return CKR_OK;
}
static CK_RV login(CK_SESSION_HANDLE h, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG length)
{
	Fixture* f = active;
	g_assert_true(g_thread_self() != f->desktop);
	if (f->candidate->token->protected_authentication_path)
	{
		g_assert_null(pin);
		g_assert_cmpuint(length, ==, 0);
	}
	else
		g_assert_cmpmem(pin, length, "123456", 6);
	g_mutex_lock(&f->lock);
	f->logging_in = TRUE;
	g_cond_broadcast(&f->cond);
	while (f->hold_login)
		g_cond_wait(&f->cond, &f->lock);
	if (user == CKU_USER)
	{
		f->user_logins++;
		if (f->settle_login_after != 0 && f->user_logins >= f->settle_login_after)
			f->public_session = FALSE;
		if (f->token_logged_in)
		{
			f->already_logged_in++;
			g_mutex_unlock(&f->lock);
			return CKR_USER_ALREADY_LOGGED_IN;
		}
	}
	else
	{
		g_assert_cmpuint(user, ==, CKU_CONTEXT_SPECIFIC);
		g_assert_true(f->handles[h].initialized);
		f->context_logins++;
		f->handles[h].context_authenticated = f->login_result == CKR_OK;
	}
	CK_RV rv = user == CKU_USER && f->fail_context_login ? CKR_OK : f->login_result;
	if (user == CKU_USER && rv == CKR_OK)
		f->token_logged_in = TRUE;
	g_mutex_unlock(&f->lock);
	return rv;
}
/* Removal invalidates every handle; reinsertion precedes the next discovery poll. */
static CK_RV remove_during_sign(guint stage)
{
	Fixture* f = active;
	if (f->sign_result == CKR_OK || f->sign_failure_stage != stage)
		return CKR_OK;

	CK_RV rv = f->sign_result;
	f->sign_result = CKR_OK;
	f->token_logged_in = FALSE;
	f->key_generation++;
	for (guint i = 0; i < G_N_ELEMENTS(f->handles); i++)
	{
		if (f->handles[i].open)
			f->handles[i].stale = TRUE;
	}
	return rv;
}
static CK_RV sign_init(CK_SESSION_HANDLE h, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	g_mutex_lock(&active->lock);
	CK_RV rv = remove_during_sign(0);
	if (rv != CKR_OK)
	{
		g_mutex_unlock(&active->lock);
		return rv;
	}
	if (!active->token_logged_in)
	{
		g_mutex_unlock(&active->lock);
		return CKR_USER_NOT_LOGGED_IN;
	}
	g_assert_cmpuint(key, ==, 7 + active->key_generation);
	g_assert_false(active->handles[h].initialized);
	active->handles[h].initialized = TRUE;
	active->handles[h].context_authenticated = FALSE;
	g_mutex_unlock(&active->lock);
	return CKR_OK;
}
static CK_RV sign(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG length, CK_BYTE_PTR out,
				  CK_ULONG_PTR size)
{
	Fixture* f = active;
	g_mutex_lock(&f->lock);
	f->signing = TRUE;
	g_cond_broadcast(&f->cond);
	while (f->hold_sign)
		g_cond_wait(&f->cond, &f->lock);
	CK_RV rv = remove_during_sign(out == NULL ? 1 : 2);
	if (rv != CKR_OK)
	{
		g_mutex_unlock(&f->lock);
		return rv;
	}
	g_assert_true(f->token_logged_in);
	g_assert_true(f->handles[h].initialized);
	if (f->always_auth)
		g_assert_true(f->handles[h].context_authenticated);
	*size = 1;
	if (out != NULL)
	{
		out[0] = 42;
		f->signatures++;
		f->handles[h].initialized = FALSE;
	}
	g_mutex_unlock(&f->lock);
	return CKR_OK;
}
static CK_RV logout(CK_SESSION_HANDLE h)
{
	g_mutex_lock(&active->lock);
	active->logouts++;
	active->token_logged_in = FALSE;
	active->key_generation++;
	g_mutex_unlock(&active->lock);
	return CKR_OK;
}
static CK_RV close_device(CK_SESSION_HANDLE h)
{
	g_mutex_lock(&active->lock);
	g_assert_true(active->handles[h].open);
	gboolean stale = active->handles[h].stale;
	active->handles[h] = (TokenSession){0};
	active->sessions_closed++;
	if (--active->open_sessions == 0)
	{
		active->token_logged_in = FALSE;
		active->key_generation++;
	}
	g_mutex_unlock(&active->lock);
	return stale ? CKR_SESSION_HANDLE_INVALID : CKR_OK;
}
static CK_RV session_info(CK_SESSION_HANDLE h, CK_SESSION_INFO_PTR info)
{
	g_mutex_lock(&active->lock);
	active->session_queries++;
	active->querying_session = TRUE;
	g_cond_broadcast(&active->cond);
	gint64 deadline = __real_g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (active->hold_session_info)
		g_assert_true(g_cond_wait_until(&active->cond, &active->lock, deadline));
	g_assert_true(active->handles[h].open);
	if (active->handles[h].stale)
	{
		g_mutex_unlock(&active->lock);
		return CKR_SESSION_HANDLE_INVALID;
	}
	*info = (CK_SESSION_INFO){ .slotID = 1, .flags = CKF_SERIAL_SESSION,
	                          .state = active->token_logged_in && !active->public_session
	                                       ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION };
	g_mutex_unlock(&active->lock);
	return CKR_OK;
}
static CK_FUNCTION_LIST module = {.C_FindObjectsInit = find_init,
								  .C_FindObjects = find,
								  .C_FindObjectsFinal = finish_find,
								  .C_GetAttributeValue = attribute,
								  .C_Login = login,
								  .C_SignInit = sign_init,
								  .C_Sign = sign,
								  .C_Logout = logout,
								  .C_GetSessionInfo = session_info,
								  .C_CloseSession = close_device};
gboolean __wrap_certificate_tokens_open_session(CertificateTokens* t, const CertificateToken* token,
												CK_FUNCTION_LIST** output,
												CK_SESSION_HANDLE* handle, GError** error)
{
	Fixture* f = active;
	g_mutex_lock(&f->lock);
	f->opening = TRUE;
	g_cond_broadcast(&f->cond);
	while (f->hold_open)
		g_cond_wait(&f->cond, &f->lock);
	*handle = ++f->sessions_opened;
	g_assert_cmpuint(*handle, <, G_N_ELEMENTS(f->handles));
	f->handles[*handle].open = TRUE;
	f->open_sessions++;
	g_mutex_unlock(&f->lock);
	*output = &module;
	return TRUE;
}
static void assert_desktop(Fixture* f)
{
	g_assert_true(g_thread_self() == f->desktop);
}
static void choose(void* data, XccUiId id, const XccChooserView* view)
{
	Fixture* f = data;
	assert_desktop(f);
	f->chooser_shows++;
	f->chooser_id = id;
	f->revision = view->revision;
	g_assert_cmpuint(view->n_candidates, ==, f->empty ? 0 : 1);
	if (!f->empty)
	{
		/* Exercise the dispatched snapshot, including its owned appended string. */
		const XccChooserCandidateView* row = xcc_chooser_view_candidate(view, 0);
		g_assert_cmpint(row->not_before, ==, f->candidate->not_before);
		g_assert_cmpint(row->not_after, ==, f->candidate->not_after);
		g_assert_cmpstr(row->key_type, ==, f->candidate->key_type);
		g_assert_true(row->key_type != f->candidate->key_type);
		g_assert_cmpuint(row->key_size, ==, f->candidate->key_size);
	}
	f->choice = view->n_candidates != 0 ? view->candidates[0].id : 0;
	g_string_append_c(f->deliveries, 'C');
	if (f->choose)
		xcc_choose(f->context, id, view->revision, f->choice);
}
static void chooser_update(void* data, XccUiId id, const XccChooserView* view)
{
	assert_desktop(data);
}
static void submit_pin(Fixture* f, XccUiId id)
{
	XccSecret* secret = xcc_secret_new();
	g_assert_nonnull(secret);
	size_t capacity;
	uint8_t* storage = xcc_secret_data(secret, &capacity);
	g_assert_cmpuint(capacity, >, 6);
	memcpy(storage, "123456", 6);
	g_assert_true(xcc_secret_set_length(secret, 6));
	xcc_pin_submit(f->context, id, secret);
}
static void pin_show(void* data, XccUiId id, const XccPinView* view)
{
	Fixture* f = data;
	assert_desktop(f);
	f->pin_shows++;
	f->pin_id = id;
	g_assert_cmpuint(view->status_code, ==, XCC_PIN_STATUS_NONE);
	g_assert_false(view->generic_purpose);
	xcc_pin_ready(f->context, id);
	g_string_append_c(f->deliveries, 'P');
	if (view->context_specific)
	{
		g_assert_true(f->always_auth);
		f->context_pin_shows++;
	}
	if (f->submit && (!view->context_specific || !f->pause_context))
		submit_pin(f, id);
}
static void pin_update(void* data, XccUiId id, const XccPinView* view)
{
	Fixture* f = data;
	assert_desktop(f);
	f->updates++;
}
static void warning(void* data, XccUiId id, const XccWarning* view)
{
	Fixture* f = data;
	assert_desktop(f);
	f->warnings++;
	f->warning_id = view->warning_id;
	if (f->confirm)
		xcc_warning_reply(f->context, id, view->warning_id, TRUE);
}
static void hide(void* data, XccUiId id)
{
	Fixture* f = data;
	assert_desktop(f);
	f->hides++;
}
static void close_ui(void* data, XccUiId id)
{
	Fixture* f = data;
	assert_desktop(f);
	f->closes++;
	g_string_append_c(f->deliveries, 'X');
}
typedef struct
{
	Fixture* f;
	guint calls;
	XccErrorCode error;
	guint order;
} Done;
static void done(XccRequest* request, const XccResult* result, void* data)
{
	Done* d = data;
	assert_desktop(d->f);
	if (d->order != 0)
	{
		d->f->ordered_completions++;
		g_assert_cmpuint(d->order, ==, d->f->ordered_completions);
	}
	d->calls++;
	d->f->completions++;
	d->error = result->error;
	g_assert_cmpuint(d->calls, ==, 1);
	g_string_append_c(d->f->deliveries, 'D');
	if (result->error == XCC_OK && result->kind == XCC_RESULT_ACQUIRE)
	{
		XccBytes der = xcc_candidate_certificate(result->candidate);
		g_assert_cmpuint(der.size, >, 0);
	}
	else if (result->error == XCC_OK && result->kind == XCC_RESULT_SIGN)
	{
		g_assert_cmpuint(result->signature.size, ==, 1);
		g_assert_cmpuint(result->signature.data[0], ==, 42);
	}
}
#define WAIT(condition)                                                                            \
	G_STMT_START                                                                                   \
	{                                                                                              \
		gint64 wait_end = __real_g_get_monotonic_time() + 10 * G_USEC_PER_SEC;                     \
		while (!(condition) && __real_g_get_monotonic_time() < wait_end)                           \
		{                                                                                          \
			g_main_context_iteration(NULL, FALSE);                                                 \
			g_usleep(1000);                                                                        \
		}                                                                                          \
		g_assert_true(condition);                                                                  \
	}                                                                                              \
	G_STMT_END
static void shutdown_done(XccContext* context, void* data)
{
	Fixture* f = data;
	assert_desktop(f);
	f->shutdown = TRUE;
}
static void setup(Fixture* f, gconstpointer data)
{
	active = f;
	f->real_watch = GPOINTER_TO_INT(data) != 0;
	f->desktop = g_thread_self();
	g_mutex_init(&f->lock);
	g_cond_init(&f->cond);
	f->deliveries = g_string_new(NULL);
	f->choose = TRUE;
	f->candidate = certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	f->candidate->token->login_required = TRUE;
	f->candidate->cka_id = g_byte_array_new();
	g_byte_array_append(f->candidate->cka_id, (const guint8*)"key", 3);
	const char* modules[] = {NULL};
	XccConfig config = {
		.struct_size = sizeof(config), .abi_version = XCC_ABI_VERSION, .module_paths = modules};
	XccUiV1 ui = {sizeof(ui), XCC_ABI_VERSION, 0,		f,	  choose,  chooser_update,
				  pin_show,	  pin_update,	   warning, hide, close_ui};
	XccDispatch dispatch = xcc_dispatch_glib(NULL);
	XccError error;
	f->context = xcc_context_new(&config, &ui, &dispatch, &error);
	g_assert_nonnull(f->context);
	g_assert_cmpint(error.code, ==, XCC_OK);
	xcc_context_set_owner_generation(f->context, 7);
	XccSessionSpec spec = {.struct_size = sizeof(spec),
						   .abi_version = XCC_ABI_VERSION,
						   .owner_generation = 7,
						   .app_id = "org.example.Core",
						   .log_id = "core-api-test"};
	f->session = xcc_session_new(f->context, &spec, &error);
	g_assert_nonnull(f->session);
}
static void teardown(Fixture* f, gconstpointer data)
{
	certificate_broker_set_open_gate(NULL, NULL);
	g_mutex_lock(&f->lock);
	f->hold_enumeration = f->hold_login = f->hold_open = f->hold_sign =
	    f->hold_session_info = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	if (!f->shutdown)
	{
		xcc_context_shutdown_async(f->context, shutdown_done, f);
		WAIT(f->shutdown);
	}
	g_object_unref(f->session);
	xcc_context_unref(f->context);
	certificate_candidate_unref(f->candidate);
	g_mutex_clear(&f->lock);
	g_cond_clear(&f->cond);
	g_string_free(f->deliveries, TRUE);
	active = NULL;
}
static XccAcquireSpec acquire_spec(void)
{
	return (XccAcquireSpec){.struct_size = sizeof(XccAcquireSpec),
							.abi_version = XCC_ABI_VERSION,
							.principal = {sizeof(XccPrincipal), XCC_ABI_VERSION, 7,
										  "org.example.Core",
										  CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED, TRUE},
							.purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH};
}
static XccRequest* acquire(Fixture* f, Done* d)
{
	XccAcquireSpec spec = acquire_spec();
	return xcc_acquire_async(f->session, &spec, done, d);
}
static XccRequest* sign_on_session(XccSession* session, Done* d)
{
	static const uint8_t digest[32] = {0};
	XccSignSpec spec = {.struct_size = sizeof(spec),
						.abi_version = XCC_ABI_VERSION,
						.principal = {sizeof(XccPrincipal), XCC_ABI_VERSION, 7, "org.example.Core",
									  CERTIFICATE_IDENTITY_VERIFIED_SANDBOXED, TRUE},
						.mechanism = "RSA_PKCS1_V1_5",
						.hash_present = TRUE,
						.hash = "SHA256",
						.data = {sizeof(XccBytes), XCC_ABI_VERSION, digest, sizeof(digest)}};
	return xcc_sign_async(session, &spec, done, d);
}
static XccRequest* sign_request(Fixture* f, Done* d)
{
	return sign_on_session(f->session, d);
}
static void grant(Fixture* f)
{
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_OK);
	xcc_request_unref(r);
}
static void test_acquire(Fixture* f, gconstpointer data)
{
	grant(f);
	g_assert_cmpstr(f->deliveries->str, ==, "CXD");
	xcc_choose(f->context, f->chooser_id, f->revision, f->choice);
	xcc_ui_cancel(f->context, f->chooser_id);
	/* A later FIFO completion also proves the stale replies were processed without a second
	 * completion. */
	Done d = {.f = f};
	XccRequest* r = xcc_get_capabilities_async(f->context, done, &d);
	WAIT(d.calls == 1);
	g_assert_cmpuint(f->completions, ==, 2);
	xcc_request_unref(r);
}
typedef struct
{
	Fixture* f;
	XccRequest* request;
	gint entered;
	gboolean released;
} ConsentBarrier;
static void hold_before_consent(void* data)
{
	ConsentBarrier* b = data;
	g_assert_false(b->request->enumerating);
	g_assert_false(b->request->chooser_completed);
	g_mutex_lock(&b->f->lock);
	g_atomic_int_set(&b->entered, TRUE);
	gint64 deadline = __real_g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (!b->released)
		g_assert_true(g_cond_wait_until(&b->f->cond, &b->f->lock, deadline));
	g_mutex_unlock(&b->f->lock);
}
static void test_removal_before_consent(Fixture* f, gconstpointer data)
{
	f->choose = FALSE;
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(f->chooser_shows == 1);
	ConsentBarrier barrier = {.f = f, .request = r};
	xcc_context_post(f->context, hold_before_consent, &barrier);
	WAIT(g_atomic_int_get(&barrier.entered));
	/* The real discovery queue has a ready priority-200 removal, followed by a
	 * priority-0 reply. No worker/refresh or scheduler timing can mask the race. */
	certificate_tokens_emit_event(f->context->tokens, f->candidate->token, FALSE);
	xcc_choose(f->context, f->chooser_id, f->revision, f->choice);
	g_mutex_lock(&f->lock);
	barrier.released = TRUE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_TOKEN_REMOVED);
	g_assert_cmpuint(xcc_error_wire_response(d.error), ==, 2);
	g_assert_cmpstr(xcc_error_wire_name(d.error), ==, "token_removed");
	g_assert_false(r->result.candidate_present);
	g_assert_null(r->candidate);
	g_assert_false(f->session->granted);
	g_assert_null(f->session->candidate);
	xcc_request_unref(r);
}
static void test_cancel_before(Fixture* f, gconstpointer data)
{
	f->hold_enumeration = TRUE;
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	xcc_request_cancel(r, XCC_CANCEL_USER);
	g_mutex_lock(&f->lock);
	f->hold_enumeration = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_CANCELLED);
	g_assert_cmpuint(f->chooser_shows, ==, 0);
	xcc_request_unref(r);
}
static void test_cancel_chooser(Fixture* f, gconstpointer data)
{
	f->choose = FALSE;
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(f->chooser_shows == 1);
	xcc_request_cancel(r, XCC_CANCEL_USER);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_CANCELLED);
	g_assert_cmpuint(f->closes, ==, 1);
	xcc_choose(f->context, f->chooser_id, f->revision, f->choice);
	xcc_request_unref(r);
}
static void test_mismatch(Fixture* f, gconstpointer data)
{
	XccAcquireSpec spec = acquire_spec();
	spec.principal.owner_generation = 6;
	Done d = {.f = f};
	XccRequest* r = xcc_acquire_async(f->session, &spec, done, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_NO_SUCH_SESSION);
	g_assert_cmpuint(f->chooser_shows, ==, 0);
	XccSessionSpec session_spec = {.struct_size = sizeof(session_spec),
								   .abi_version = XCC_ABI_VERSION,
								   .owner_generation = 6,
								   .app_id = "org.example.Core"};
	XccError error;
	XccSession* rejected = xcc_session_new(f->context, &session_spec, &error);
	g_assert_null(rejected);
	g_assert_cmpint(error.code, ==, XCC_ERROR_NO_SUCH_SESSION);
	xcc_request_unref(r);
	spec.principal.owner_generation = 7;
	spec.principal.app_id = "org.example.Other";
	d.calls = 0;
	r = xcc_acquire_async(f->session, &spec, done, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_NO_SUCH_SESSION);
	xcc_request_unref(r);
}
static void test_identity(Fixture* f, gconstpointer data)
{
	XccAcquireSpec spec = acquire_spec();
	spec.principal.identity_level = CERTIFICATE_IDENTITY_UNKNOWN;
	Done d = {.f = f};
	XccRequest* r = xcc_acquire_async(f->session, &spec, done, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_OK);
	xcc_request_unref(r);
	d.calls = 0;
	r = acquire(f, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_NO_SUCH_SESSION);
	xcc_request_unref(r);
}
static void test_cancel_pin(Fixture* f, gconstpointer data)
{
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(f->pin_shows == 1);
	xcc_request_cancel(r, XCC_CANCEL_USER);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_CANCELLED);
	submit_pin(f, f->pin_id);
	Done barrier = {.f = f};
	XccRequest* query = xcc_get_capabilities_async(f->context, done, &barrier);
	WAIT(barrier.calls == 1);
	g_assert_cmpuint(f->user_logins, ==, 0);
	xcc_request_unref(query);
	xcc_request_unref(r);
}
static gboolean logging_in(Fixture* f)
{
	g_mutex_lock(&f->lock);
	gboolean value = f->logging_in;
	g_mutex_unlock(&f->lock);
	return value;
}
static void test_cancel_submitted(Fixture* f, gconstpointer data)
{
	grant(f);
	f->hold_login = TRUE;
	f->submit = TRUE;
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(logging_in(f));
	xcc_request_cancel(r, XCC_CANCEL_USER);
	WAIT(f->hides == 1);
	g_mutex_lock(&f->lock);
	f->hold_login = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_CANCELLED);
	xcc_request_unref(r);
}
typedef struct
{
	Fixture* f;
	gboolean ready;
	guint count;
	gboolean settled;
} WaitersBarrier;
static void waiters_ready(void* data)
{
	((WaitersBarrier*)data)->ready = TRUE;
}
static gboolean observe_waiters(void* data)
{
	WaitersBarrier* b = data;
	if (b->settled)
	{
		if (b->f->session->login_in_progress)
			return G_SOURCE_CONTINUE;
	}
	else if (b->f->session->login_waiters == NULL ||
	         b->f->session->login_waiters->len != b->count)
		return G_SOURCE_CONTINUE;
	XccDispatch d = xcc_dispatch_glib(NULL);
	d.post(d.user, waiters_ready, b);
	return G_SOURCE_REMOVE;
}
static void start_waiters_barrier(void* data)
{
	xcc_idle_add(NULL, observe_waiters, data, NULL);
}
static void test_shared_waiters(Fixture* f, gconstpointer data)
{
	grant(f);
	Done a = {.f = f}, b = {.f = f};
	XccRequest* first = sign_request(f, &a);
	XccRequest* second = sign_request(f, &b);
	WAIT(f->pin_shows == 1);
	WaitersBarrier barrier = {.f = f, .count = 2};
	xcc_context_post(f->context, start_waiters_barrier, &barrier);
	WAIT(barrier.ready);
	xcc_request_cancel(first, XCC_CANCEL_USER);
	WAIT(a.calls == 1);
	g_assert_cmpuint(f->hides, ==, 0);
	submit_pin(f, f->pin_id);
	WAIT(b.calls == 1);
	g_assert_cmpint(a.error, ==, XCC_ERROR_CANCELLED);
	g_assert_cmpint(b.error, ==, XCC_OK);
	g_assert_cmpuint(f->pin_shows, ==, 1);
	g_assert_cmpuint(f->user_logins, ==, 1);
	g_assert_cmpuint(f->signatures, ==, 1);
	xcc_request_unref(first);
	xcc_request_unref(second);
}

static XccSession* new_session(Fixture* f)
{
	XccSessionSpec spec = {.struct_size = sizeof(spec),
	                       .abi_version = XCC_ABI_VERSION,
	                       .owner_generation = 7,
	                       .app_id = "org.example.Core",
	                       .log_id = "core-api-second-grant"};
	XccError error;
	XccSession* session = xcc_session_new(f->context, &spec, &error);
	g_assert_nonnull(session);
	g_assert_cmpint(error.code, ==, XCC_OK);
	return session;
}

static XccSession* second_grant(Fixture* f)
{
	XccSession* session = new_session(f);
	XccAcquireSpec consent = acquire_spec();
	Done d = {.f = f};
	XccRequest* r = xcc_acquire_async(session, &consent, done, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_OK);
	xcc_request_unref(r);
	return session;
}

static void sign_successfully(Fixture* f, XccSession* session)
{
	Done d = {.f = f};
	XccRequest* r = sign_on_session(session, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_OK);
	xcc_request_unref(r);
}

static guint sessions_closed(Fixture* f)
{
	g_mutex_lock(&f->lock);
	guint count = f->sessions_closed;
	g_mutex_unlock(&f->lock);
	return count;
}

static void test_two_grants(Fixture* f, gconstpointer data)
{
	f->hide_private_key = TRUE;
	grant(f);
	g_autoptr(XccSession) other = second_grant(f);
	f->submit = TRUE;
	sign_successfully(f, f->session);
	sign_successfully(f, other);
	xcc_session_close(f->session);
	WAIT(sessions_closed(f) == 1);
	sign_successfully(f, other);
	g_assert_cmpuint(f->pin_shows, ==, 1);
	g_assert_cmpuint(f->user_logins, ==, 1);
	g_assert_cmpuint(f->logouts, ==, 0);
	g_assert_cmpuint(f->signatures, ==, 3);
	xcc_session_close(other);
	WAIT(sessions_closed(f) == 2);
	g_assert_false(f->token_logged_in);
}

static void test_token_logout(Fixture* f, gconstpointer data)
{
	f->hide_private_key = TRUE;
	grant(f);
	f->submit = TRUE;
	sign_successfully(f, f->session);
	g_assert_cmpuint(logout(1), ==, CKR_OK);
	sign_successfully(f, f->session);
	sign_successfully(f, f->session);
	g_assert_cmpuint(f->pin_shows, ==, 2);
	g_assert_cmpuint(f->user_logins, ==, 2);
	g_assert_cmpuint(f->signatures, ==, 3);
}

typedef struct
{
	const char* name;
	guint stage;
	CK_RV rv;
} SignRemoval;
static const SignRemoval sign_removals[] = {
	{ "init", 0, CKR_TOKEN_NOT_PRESENT },
	{ "size", 1, CKR_DEVICE_REMOVED },
	{ "value", 2, CKR_SESSION_HANDLE_INVALID },
};
static void removed_during_sign(XccSession* session, const char* reason, gpointer data)
{
	Fixture* f = data;
	assert_desktop(f);
	g_assert_cmpstr(reason, ==, "token_removed");
	f->removals++;
}
static void test_removal_during_sign(Fixture* f, gconstpointer data)
{
	const SignRemoval* test = data;
	grant(f);
	g_autoptr(XccSession) other = second_grant(f);
	xcc_session_set_invalidated_callback(f->session, removed_during_sign, f);
	xcc_session_set_invalidated_callback(other, removed_during_sign, f);
	f->hide_private_key = f->submit = TRUE;
	sign_successfully(f, f->session);
	sign_successfully(f, other);

	g_mutex_lock(&f->lock);
	f->sign_result = test->rv;
	f->sign_failure_stage = test->stage;
	g_mutex_unlock(&f->lock);
	Done failed = {.f = f};
	XccRequest* request = sign_request(f, &failed);
	WAIT(failed.calls == 1);
	g_assert_cmpint(failed.error, ==, XCC_ERROR_TOKEN_REMOVED);
	g_assert_cmpstr(xcc_error_wire_name(failed.error), ==, "token_removed");
	g_assert_cmpuint(f->removals, ==, 1);
	g_assert_true(xcc_session_is_closed(f->session));
	WAIT(sessions_closed(f) == 1);
	xcc_request_unref(request);

	Done retry = {.f = f};
	request = sign_request(f, &retry);
	WAIT(retry.calls == 1);
	g_assert_cmpint(retry.error, ==, XCC_ERROR_NO_SUCH_SESSION);
	g_assert_cmpuint(f->sessions_opened, ==, 2);
	xcc_request_unref(request);

	/* A fresh grant logs in on the reinserted token while another stale grant remains. */
	g_autoptr(XccSession) fresh = second_grant(f);
	sign_successfully(f, fresh);
	Done stale = {.f = f};
	request = sign_on_session(other, &stale);
	WAIT(stale.calls == 1);
	g_assert_cmpint(stale.error, ==, XCC_ERROR_TOKEN_REMOVED);
	g_assert_cmpuint(f->removals, ==, 2);
	g_assert_true(xcc_session_is_closed(other));
	WAIT(sessions_closed(f) == 2);
	xcc_request_unref(request);

	sign_successfully(f, fresh);
	g_assert_cmpuint(f->pin_shows, ==, 2);
	g_assert_cmpuint(f->user_logins, ==, 2);
	g_assert_cmpuint(f->logouts, ==, 0);
	g_assert_cmpuint(f->signatures, ==, 4);
	g_assert_cmpuint(f->sessions_opened, ==, 3);
}

typedef struct
{
	const char* name;
	gboolean logged_in;
	guint settle_after, prompts;
	XccErrorCode error;
} LoginState;
static const LoginState login_states[] = {
	{ "already-logged-in", TRUE, 1, 1, XCC_OK },
	{ "reauthentication-recovers", TRUE, 2, 2, XCC_OK },
	{ "public-after-already-logged-in", TRUE, 0, 2, XCC_ERROR_DEVICE },
	{ "public-after-login-success", FALSE, 0, 2, XCC_ERROR_DEVICE },
};
static void test_login_state(Fixture* f, gconstpointer data)
{
	const LoginState* test = data;
	f->token_logged_in = test->logged_in;
	f->hide_private_key = f->public_session = TRUE;
	f->settle_login_after = test->settle_after;
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	for (guint i = 0; i < test->prompts; i++)
	{
		WAIT(f->pin_shows == i + 1 || d.calls != 0);
		g_assert_cmpuint(d.calls, ==, 0);
		submit_pin(f, f->pin_id);
	}
	/* A third prompt fails immediately on the unbounded retry path. */
	WAIT(d.calls == 1 || f->pin_shows > test->prompts);
	g_assert_cmpuint(f->pin_shows, ==, test->prompts);
	g_assert_cmpuint(d.calls, ==, 1);
	g_assert_cmpint(d.error, ==, test->error);
	g_assert_cmpuint(f->user_logins, ==, test->prompts);
	g_assert_cmpuint(f->already_logged_in, ==, test->prompts - (test->logged_in ? 0 : 1));
	g_assert_cmpuint(f->signatures, ==, test->error == XCC_OK ? 1 : 0);
	if (test->error != XCC_OK)
	{
		g_assert_cmpuint(xcc_error_wire_response(d.error), ==, 2);
		g_assert_cmpstr(xcc_error_wire_name(d.error), ==, "device_error");
	}
	xcc_request_unref(r);

	g_mutex_lock(&f->lock);
	f->public_session = FALSE;
	g_mutex_unlock(&f->lock);
	sign_successfully(f, f->session);
	g_assert_cmpuint(f->pin_shows, ==, test->prompts);
	g_assert_cmpuint(f->user_logins, ==, test->prompts);
	g_assert_cmpuint(f->signatures, ==, test->error == XCC_OK ? 2 : 1);
	g_assert_cmpuint(f->logouts, ==, 0);
}

static void test_context_cancel_preserves_login(Fixture* f, gconstpointer data)
{
	grant(f);
	g_autoptr(XccSession) other = second_grant(f);
	f->submit = TRUE;
	sign_successfully(f, f->session);
	f->always_auth = TRUE;
	f->pause_context = TRUE;
	Done d = {.f = f};
	XccRequest* r = sign_on_session(other, &d);
	WAIT(f->context_pin_shows == 1);
	xcc_ui_cancel(f->context, f->pin_id);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_CANCELLED);
	f->always_auth = FALSE;
	f->pause_context = FALSE;
	sign_successfully(f, f->session);
	g_assert_cmpuint(f->pin_shows, ==, 2);
	g_assert_cmpuint(f->user_logins, ==, 1);
	g_assert_cmpuint(f->logouts, ==, 0);
	xcc_request_unref(r);
}

typedef struct
{
	Fixture* f;
	gint entered;
	gboolean released;
} OpenBarrier;

static void hold_opened(gpointer data)
{
	OpenBarrier* b = data;
	g_mutex_lock(&b->f->lock);
	g_atomic_int_set(&b->entered, TRUE);
	gint64 deadline = __real_g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (!b->released)
		g_assert_true(g_cond_wait_until(&b->f->cond, &b->f->lock, deadline));
	g_mutex_unlock(&b->f->lock);
}

static gboolean signing(Fixture* f)
{
	g_mutex_lock(&f->lock);
	gboolean value = f->signing;
	g_mutex_unlock(&f->lock);
	return value;
}

static gboolean querying_session(Fixture* f)
{
	g_mutex_lock(&f->lock);
	gboolean value = f->querying_session;
	g_mutex_unlock(&f->lock);
	return value;
}

static void coordinator_ready(void* data)
{
	g_atomic_int_set((gint*)data, TRUE);
}

static void test_open_after_successful_login(Fixture* f, gconstpointer data)
{
	gboolean stalled = GPOINTER_TO_INT(data) != 0;
	grant(f);
	f->hide_private_key = TRUE;
	Done a = {.f = f}, b = {.f = f}, c = {.f = f};
	XccRequest* first = sign_request(f, &a);
	WAIT(f->pin_shows == 1);
	OpenBarrier opened = {.f = f};
	certificate_broker_set_open_gate(hold_opened, &opened);
	XccRequest* second = sign_request(f, &b);
	WAIT(g_atomic_int_get(&opened.entered));
	submit_pin(f, f->pin_id);
	WAIT(a.calls == 1);
	g_assert_cmpint(a.error, ==, XCC_OK);
	g_assert_cmpuint(b.calls, ==, 0);
	XccRequest* third = NULL;
	if (stalled)
	{
		g_mutex_lock(&f->lock);
		f->hold_session_info = TRUE;
		f->querying_session = FALSE;
		g_mutex_unlock(&f->lock);
		third = sign_request(f, &c);
		WAIT(querying_session(f));
	}
	/* Deliver the login-needed snapshot after the shared login has completed. */
	g_mutex_lock(&f->lock);
	f->observed_open = second->cancellable;
	opened.released = TRUE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	if (stalled)
	{
		WAIT(g_atomic_int_get(&f->opened_callbacks) != 0);
		gint ready = FALSE;
		xcc_context_post(f->context, coordinator_ready, &ready);
		WAIT(g_atomic_int_get(&ready));
		g_assert_cmpuint(b.calls, ==, 0);
		g_assert_cmpuint(c.calls, ==, 0);
		g_assert_cmpuint(f->pin_shows, ==, 1);
		g_mutex_lock(&f->lock);
		f->hold_session_info = FALSE;
		g_cond_broadcast(&f->cond);
		g_mutex_unlock(&f->lock);
	}
	WAIT(b.calls == 1 || f->pin_shows > 1);
	g_assert_cmpuint(f->pin_shows, ==, 1);
	g_assert_cmpuint(b.calls, ==, 1);
	g_assert_cmpint(b.error, ==, XCC_OK);
	if (stalled)
	{
		WAIT(c.calls == 1);
		g_assert_cmpint(c.error, ==, XCC_OK);
	}
	g_assert_cmpuint(a.calls, ==, 1);
	g_assert_cmpuint(f->user_logins, ==, 1);
	g_assert_cmpuint(f->signatures, ==, stalled ? 3 : 2);
	g_assert_cmpuint(f->sessions_opened, ==, 1);
	g_assert_cmpuint(f->sessions_closed, ==, 0);
	g_assert_cmpuint(f->logouts, ==, 0);
	g_mutex_lock(&f->lock);
	f->observed_open = NULL;
	g_mutex_unlock(&f->lock);
	xcc_request_unref(first);
	xcc_request_unref(second);
	if (third != NULL)
		xcc_request_unref(third);
}

static void test_concurrent_signs(Fixture* f, gconstpointer data)
{
	grant(f);
	f->submit = TRUE;
	sign_successfully(f, f->session);
	guint queries = f->session_queries;
	OpenBarrier opened = {.f = f};
	certificate_broker_set_open_gate(hold_opened, &opened);
	Done a = {.f = f}, b = {.f = f};
	XccRequest* first = sign_request(f, &a);
	WAIT(g_atomic_int_get(&opened.entered));

	/* Deliver the first open while the second holds device_lock in C_GetSessionInfo. */
	g_mutex_lock(&f->lock);
	f->hold_session_info = TRUE;
	f->querying_session = FALSE;
	g_mutex_unlock(&f->lock);
	XccRequest* second = sign_request(f, &b);
	WAIT(querying_session(f));
	g_mutex_lock(&f->lock);
	f->observed_open = first->cancellable;
	opened.released = TRUE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(g_atomic_int_get(&f->opened_callbacks) != 0);
	gint ready = FALSE;
	xcc_context_post(f->context, coordinator_ready, &ready);
	WAIT(g_atomic_int_get(&ready));
	g_assert_cmpuint(a.calls, ==, 0);
	g_assert_cmpuint(b.calls, ==, 0);

	g_mutex_lock(&f->lock);
	f->observed_open = NULL;
	f->hold_session_info = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(a.calls == 1 && b.calls == 1);
	g_assert_cmpint(a.error, ==, XCC_OK);
	g_assert_cmpint(b.error, ==, XCC_OK);
	g_assert_cmpuint(f->signatures, ==, 3);
	g_assert_cmpuint(f->user_logins, ==, 1);
	g_assert_cmpuint(f->sessions_opened, ==, 1);
	/* Each sign needs one open query and one pre-sign query. */
	g_assert_cmpuint(f->session_queries, ==, queries + 4);
	xcc_request_unref(first);
	xcc_request_unref(second);
}

static void expired(XccSession* session, const char* reason, gpointer data)
{
	Fixture* f = data;
	assert_desktop(f);
	g_assert_true(session == f->session);
	g_assert_cmpstr(reason, ==, "expired");
	f->expirations++;
}

static void expire_grant(void* data)
{
	Fixture* f = data;
	g_atomic_int_set(&f->clock_offset, 301 + CERTIFICATE_EXPIRY_GRACE_SECONDS);
	GSource* expiry = g_main_context_find_source_by_id(f->context->coordinator,
	                                                f->session->expiry_source);
	g_assert_nonnull(expiry);
	g_source_set_ready_time(expiry, 0);
}

static void budget_refused(GBytes* result, const GError* error, gpointer data)
{
	Fixture* f = data;
	g_assert_null(result);
	g_assert_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED);
	g_atomic_int_inc(&f->budget_refusals);
}

static void check_decrypt_budget(void* data)
{
	Fixture* f = data;
	certificate_broker_perform(f->context->tokens, f->session, TRUE, "stalled-budget",
	                           "RSA_PKCS1_V1_5", NULL, NULL, NULL, NULL, NULL,
	                           budget_refused, f);
}

static void test_stalled_token(Fixture* f, gconstpointer data)
{
	gboolean context_login = GPOINTER_TO_INT(data) != 0;
	grant(f);
	g_autoptr(XccSession) other = new_session(f);
	f->submit = TRUE;
	sign_successfully(f, f->session);
	xcc_session_set_invalidated_callback(f->session, expired, f);

	/* Delay one open completion until another operation holds device_lock inside the token. */
	OpenBarrier opened = {.f = f};
	certificate_broker_set_open_gate(hold_opened, &opened);
	Done queued = {.f = f}, stalled = {.f = f};
	XccRequest* pending = sign_request(f, &queued);
	WAIT(g_atomic_int_get(&opened.entered));
	g_mutex_lock(&f->lock);
	f->signing = f->logging_in = FALSE;
	f->hold_sign = !context_login;
	f->always_auth = f->pause_context = context_login;
	g_mutex_unlock(&f->lock);
	XccRequest* running = sign_request(f, &stalled);
	if (context_login)
	{
		WAIT(f->context_pin_shows == 1);
		g_mutex_lock(&f->lock);
		f->hold_login = TRUE;
		g_mutex_unlock(&f->lock);
		submit_pin(f, f->pin_id);
		WAIT(logging_in(f));
	}
	else
		WAIT(signing(f));
	g_mutex_lock(&f->lock);
	f->observed_open = pending->cancellable;
	opened.released = TRUE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(g_atomic_int_get(&f->opened_callbacks) != 0);

	xcc_request_cancel(pending, XCC_CANCEL_USER);
	WAIT(g_cancellable_is_cancelled(pending->cancellable));
	xcc_context_post(f->context, check_decrypt_budget, f);
	WAIT(g_atomic_int_get(&f->budget_refusals) == 1);
	f->choose = FALSE;
	Done cancelled = {.f = f};
	XccAcquireSpec spec = acquire_spec();
	XccRequest* chooser = xcc_acquire_async(other, &spec, done, &cancelled);
	WAIT(f->chooser_shows == 2);
	xcc_request_cancel(chooser, XCC_CANCEL_USER);
	WAIT(cancelled.calls == 1);
	g_assert_cmpint(cancelled.error, ==, XCC_ERROR_CANCELLED);
	xcc_session_close(other);
	xcc_context_post(f->context, expire_grant, f);
	WAIT(f->expirations == 1);
	g_assert_true(xcc_session_is_closed(f->session));
	g_assert_cmpuint(stalled.calls, ==, 0);
	g_assert_cmpuint(queued.calls, ==, 0);

	g_mutex_lock(&f->lock);
	guint queries = f->session_queries;
	f->hold_sign = f->hold_login = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(stalled.calls == 1 && queued.calls == 1);
	g_assert_cmpint(queued.error, ==, XCC_ERROR_CANCELLED);
	g_assert_cmpint(stalled.error, ==, XCC_ERROR_DEVICE);
	g_assert_cmpuint(f->signatures, ==, context_login ? 1 : 2);
	g_assert_cmpuint(f->sessions_opened, ==, 1);
	g_assert_cmpuint(f->session_queries, ==, queries);
	xcc_request_unref(chooser);
	xcc_request_unref(pending);
	xcc_request_unref(running);
}

static void test_acquire_during_sign(Fixture* f, gconstpointer data)
{
	grant(f);
	g_autoptr(CertificateCandidate) original = certificate_candidate_ref(f->candidate);
	gint64 expiry = f->session->expires_at;
	guint expiry_source = f->session->expiry_source;
	f->submit = f->hold_sign = TRUE;
	Done signed_result = {.f = f}, repeated = {.f = f};
	XccRequest* running = sign_request(f, &signed_result);
	WAIT(signing(f));

	CertificateCandidate* replacement = certificate_test_candidate("no-eku-rsa.pem", TRUE, FALSE);
	replacement->token->login_required = TRUE;
	replacement->cka_id = g_byte_array_new();
	g_byte_array_append(replacement->cka_id, (const guint8*)"other-key", 9);
	g_mutex_lock(&f->lock);
	certificate_candidate_unref(f->candidate);
	f->candidate = replacement;
	g_mutex_unlock(&f->lock);
	XccAcquireSpec spec = acquire_spec();
	spec.lifetime_present = TRUE;
	spec.lifetime_seconds = 3600;
	XccRequest* duplicate = xcc_acquire_async(f->session, &spec, done, &repeated);
	WAIT(repeated.calls == 1 || f->chooser_shows > 1);
	g_assert_cmpuint(repeated.calls, ==, 1);
	g_assert_cmpint(repeated.error, ==, XCC_ERROR_INVALID_REQUEST);
	g_assert_cmpuint(f->chooser_shows, ==, 1);
	g_assert_false(duplicate->result.candidate_present);
	g_assert_null(duplicate->candidate);
	g_assert_true(f->session->candidate == original);
	g_assert_cmpint(f->session->expires_at, ==, expiry);
	g_assert_cmpuint(f->session->expiry_source, ==, expiry_source);
	g_assert_cmpuint(signed_result.calls, ==, 0);

	g_mutex_lock(&f->lock);
	f->hold_sign = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(signed_result.calls == 1);
	g_assert_cmpint(signed_result.error, ==, XCC_OK);
	g_assert_cmpuint(f->signatures, ==, 1);
	g_assert_cmpuint(f->sessions_opened, ==, 1);
	xcc_request_unref(duplicate);
	xcc_request_unref(running);
}

static gboolean enumerating(Fixture* f)
{
	g_mutex_lock(&f->lock);
	gboolean value = f->enumerating;
	g_mutex_unlock(&f->lock);
	return value;
}

static void test_overlapping_acquire(Fixture* f, gconstpointer data)
{
	gboolean discovery = GPOINTER_TO_INT(data) != 0;
	f->choose = FALSE;
	f->hold_enumeration = discovery;
	Done first_result = {.f = f}, second_result = {.f = f};
	XccRequest* first = acquire(f, &first_result);
	if (discovery)
		WAIT(enumerating(f));
	else
		WAIT(f->chooser_shows == 1);
	XccRequest* second = acquire(f, &second_result);
	WAIT(second_result.calls == 1 || f->chooser_shows > 1);
	g_assert_cmpuint(second_result.calls, ==, 1);
	g_assert_cmpint(second_result.error, ==, XCC_ERROR_INVALID_REQUEST);
	g_assert_cmpuint(f->chooser_shows, ==, discovery ? 0 : 1);
	g_assert_cmpuint(first_result.calls, ==, 0);
	xcc_request_cancel(first, XCC_CANCEL_USER);
	g_mutex_lock(&f->lock);
	f->hold_enumeration = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(first_result.calls == 1);
	g_assert_cmpint(first_result.error, ==, XCC_ERROR_CANCELLED);
	f->choose = TRUE;
	grant(f);
	xcc_request_unref(first);
	xcc_request_unref(second);
}

static void test_acquire_after_expiry(Fixture* f, gconstpointer data)
{
	grant(f);
	gint64 expiry = f->session->expires_at;
	g_atomic_int_set(&f->clock_offset, 301);
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_INVALID_REQUEST);
	g_assert_cmpuint(f->chooser_shows, ==, 1);
	g_assert_cmpint(f->session->expires_at, ==, expiry);
	xcc_request_unref(r);
}

typedef struct
{
	Fixture* f;
	XccRequest* request;
	XccErrorCode error;
	gboolean ready;
} CompletionBarrier;

static void completion_queued(void* data)
{
	CompletionBarrier* b = data;
	g_assert_true(b->request->answered);
	g_assert_cmpint(b->request->result.error, ==, b->error);
	g_mutex_lock(&b->f->lock);
	b->ready = TRUE;
	g_cond_broadcast(&b->f->cond);
	g_mutex_unlock(&b->f->lock);
}

/* Wait for the coordinator without delivering queued desktop callbacks. */
static void wait_for_completion(Fixture* f, XccRequest* request, XccErrorCode error)
{
	CompletionBarrier b = {.f = f, .request = request, .error = error};
	xcc_context_post(f->context, completion_queued, &b);
	g_mutex_lock(&f->lock);
	gint64 deadline = __real_g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
	while (!b.ready)
		g_assert_true(g_cond_wait_until(&f->cond, &f->lock, deadline));
	g_mutex_unlock(&f->lock);
}

typedef struct
{
	Done acquired, following;
	XccRequest* next;
	guint expiry_source;
} AcquireFollowup;

static void retry_cancelled_acquire(XccRequest* request, const XccResult* result, void* data)
{
	AcquireFollowup* followup = data;
	Fixture* f = followup->acquired.f;
	done(request, result, &followup->acquired);
	g_assert_cmpint(result->error, ==, XCC_ERROR_CANCELLED);
	g_assert_cmpuint(xcc_error_wire_response(result->error), ==, 1);
	g_assert_false(result->candidate_present);
	g_assert_null(result->candidate);
	g_assert_false(result->signature_present);
	g_assert_false(result->mechanisms_present);
	g_assert_false(xcc_session_is_closed(f->session));
	g_assert_false(f->session->granted);
	g_assert_null(f->session->candidate);
	g_assert_false(f->session->may_sign);
	g_assert_false(f->session->may_decrypt);
	g_assert_cmpuint(f->session->lifetime, ==, 0);
	g_assert_cmpint(f->session->expires_at, ==, 0);
	g_assert_cmpuint(f->session->expiry_source, ==, 0);
	g_assert_null(g_main_context_find_source_by_id(f->context->coordinator,
	                                             followup->expiry_source));
	followup->next = acquire(f, &followup->following);
}

static void test_cancel_committed_acquire(Fixture* f, gconstpointer data)
{
	gboolean logged_in = GPOINTER_TO_INT(data) != 0;
	g_autoptr(XccSession) other = NULL;
	if (logged_in)
	{
		f->submit = TRUE;
		other = second_grant(f);
		sign_successfully(f, other);
	}
	f->choose = FALSE;
	AcquireFollowup followup = {.acquired = {.f = f}, .following = {.f = f}};
	XccAcquireSpec spec = acquire_spec();
	XccRequest* request = xcc_acquire_async(f->session, &spec, retry_cancelled_acquire, &followup);
	WAIT(f->chooser_shows == (logged_in ? 2 : 1));
	xcc_choose(f->context, f->chooser_id, f->revision, f->choice);
	wait_for_completion(f, request, XCC_OK);
	g_assert_true(f->session->granted);
	g_assert_cmpuint(f->session->expiry_source, !=, 0);
	followup.expiry_source = f->session->expiry_source;
	g_assert_cmpuint(followup.acquired.calls, ==, 0);
	g_assert_cmpuint(f->closes, ==, logged_in ? 2 : 0);
	f->choose = f->submit = TRUE;
	xcc_request_cancel(request, XCC_CANCEL_USER);
	WAIT(followup.following.calls == 1);
	g_assert_cmpuint(followup.acquired.calls, ==, 1);
	g_assert_cmpint(followup.following.error, ==, XCC_OK);
	g_assert_cmpuint(f->chooser_shows, ==, logged_in ? 3 : 2);
	g_assert_cmpuint(f->sessions_opened, ==, logged_in ? 1 : 0);
	g_assert_cmpuint(f->sessions_closed, ==, 0);
	g_assert_cmpuint(f->user_logins, ==, logged_in ? 1 : 0);
	g_assert_cmpuint(f->logouts, ==, 0);
	/* A repeated Close for the old request must leave the retry's grant intact. */
	xcc_request_cancel(request, XCC_CANCEL_USER);
	sign_successfully(f, f->session);
	if (other != NULL)
	{
		sign_successfully(f, other);
		g_assert_cmpuint(f->user_logins, ==, 1);
		xcc_session_close(other);
	}
	xcc_request_unref(followup.next);
	xcc_request_unref(request);
}

static void sign_after_acquire(XccRequest* request, const XccResult* result, void* data)
{
	AcquireFollowup* followup = data;
	done(request, result, &followup->acquired);
	g_assert_cmpint(result->error, ==, XCC_OK);
	followup->next = sign_request(followup->acquired.f, &followup->following);
}

static void test_sign_before_acquire_delivery(Fixture* f, gconstpointer data)
{
	f->choose = FALSE;
	f->submit = TRUE;
	AcquireFollowup followup = {.acquired = {.f = f}, .following = {.f = f}};
	XccAcquireSpec spec = acquire_spec();
	XccRequest* request = xcc_acquire_async(f->session, &spec, sign_after_acquire, &followup);
	WAIT(f->chooser_shows == 1);
	xcc_choose(f->context, f->chooser_id, f->revision, f->choice);
	wait_for_completion(f, request, XCC_OK);
	Done premature = {.f = f};
	XccRequest* sign = sign_request(f, &premature);
	wait_for_completion(f, sign, XCC_ERROR_INVALID_REQUEST);
	g_assert_cmpuint(f->sessions_opened, ==, 0);
	g_assert_cmpuint(f->user_logins, ==, 0);
	WAIT(followup.following.calls == 1 && premature.calls == 1);
	g_assert_cmpint(premature.error, ==, XCC_ERROR_INVALID_REQUEST);
	g_assert_cmpint(followup.following.error, ==, XCC_OK);
	g_assert_cmpuint(f->signatures, ==, 1);
	xcc_request_unref(followup.next);
	xcc_request_unref(sign);
	xcc_request_unref(request);
}

static void test_cancel_delivered_acquire(Fixture* f, gconstpointer data)
{
	Done acquired = {.f = f};
	XccRequest* request = acquire(f, &acquired);
	WAIT(acquired.calls == 1);
	g_assert_cmpint(acquired.error, ==, XCC_OK);
	gint64 expiry = f->session->expires_at;
	guint expiry_source = f->session->expiry_source;
	f->submit = f->hold_sign = TRUE;
	Done signed_result = {.f = f};
	XccRequest* sign = sign_request(f, &signed_result);
	WAIT(signing(f));
	xcc_request_cancel(request, XCC_CANCEL_USER);
	Done barrier = {.f = f};
	XccRequest* query = xcc_get_capabilities_async(f->context, done, &barrier);
	WAIT(barrier.calls == 1);
	g_assert_true(f->session->granted);
	g_assert_true(f->session->candidate == f->candidate);
	g_assert_cmpint(f->session->expires_at, ==, expiry);
	g_assert_cmpuint(f->session->expiry_source, ==, expiry_source);
	g_assert_cmpuint(f->logouts, ==, 0);
	g_mutex_lock(&f->lock);
	f->hold_sign = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(signed_result.calls == 1);
	g_assert_cmpint(signed_result.error, ==, XCC_OK);
	g_assert_cmpuint(acquired.calls, ==, 1);
	xcc_request_unref(query);
	xcc_request_unref(sign);
	xcc_request_unref(request);
}

static void test_cancel_rejected_acquire(Fixture* f, gconstpointer data)
{
	grant(f);
	gint64 expiry = f->session->expires_at;
	guint expiry_source = f->session->expiry_source;
	Done rejected = {.f = f};
	XccRequest* request = acquire(f, &rejected);
	wait_for_completion(f, request, XCC_ERROR_INVALID_REQUEST);
	xcc_request_cancel(request, XCC_CANCEL_USER);
	WAIT(rejected.calls == 1);
	g_assert_cmpint(rejected.error, ==, XCC_ERROR_CANCELLED);
	g_assert_true(f->session->granted);
	g_assert_true(f->session->candidate == f->candidate);
	g_assert_cmpint(f->session->expires_at, ==, expiry);
	g_assert_cmpuint(f->session->expiry_source, ==, expiry_source);
	f->submit = TRUE;
	sign_successfully(f, f->session);
	g_assert_cmpuint(f->chooser_shows, ==, 1);
	xcc_request_unref(request);
}

static void test_close_committed_acquire(Fixture* f, gconstpointer data)
{
	gboolean shutdown = GPOINTER_TO_INT(data) != 0;
	f->choose = FALSE;
	Done acquired = {.f = f};
	XccRequest* request = acquire(f, &acquired);
	WAIT(f->chooser_shows == 1);
	xcc_choose(f->context, f->chooser_id, f->revision, f->choice);
	wait_for_completion(f, request, XCC_OK);
	if (shutdown)
		xcc_context_shutdown_async(f->context, shutdown_done, f);
	else
		xcc_session_close(f->session);
	wait_for_completion(f, request, XCC_OK);
	WAIT(acquired.calls == 1);
	g_assert_cmpint(acquired.error, ==, shutdown ? XCC_ERROR_BACKEND_GONE
	                                           : XCC_ERROR_NO_SUCH_SESSION);
	g_assert_true(xcc_session_is_closed(f->session));
	g_assert_false(f->session->granted);
	g_assert_null(f->session->candidate);
	g_assert_cmpuint(f->session->expiry_source, ==, 0);
	g_assert_cmpuint(f->sessions_opened, ==, 0);
	if (shutdown)
		WAIT(f->shutdown);
	xcc_request_unref(request);
}

static void test_join_cancelled_login(Fixture* f, gconstpointer data)
{
	gboolean ui_cancel = GPOINTER_TO_INT(data) == 1;
	gboolean after_close = GPOINTER_TO_INT(data) == 2;
	grant(f);
	Done a = {.f = f}, b = {.f = f};
	XccRequest* first = sign_request(f, &a);
	WAIT(f->pin_shows == 1);
	OpenBarrier opened = {.f = f};
	certificate_broker_set_open_gate(hold_opened, &opened);
	XccRequest* second = sign_request(f, &b);
	WAIT(g_atomic_int_get(&opened.entered));
	f->hold_login = TRUE;
	submit_pin(f, f->pin_id);
	WAIT(logging_in(f));
	if (ui_cancel)
		xcc_ui_cancel(f->context, f->pin_id);
	else
		xcc_request_cancel(first, XCC_CANCEL_USER);
	WAIT(f->hides == 1);
	if (!ui_cancel)
		WAIT(a.calls == 1);
	if (after_close)
	{
		g_mutex_lock(&f->lock);
		f->hold_login = FALSE;
		g_cond_broadcast(&f->cond);
		g_mutex_unlock(&f->lock);
		WaitersBarrier settled = {.f = f, .settled = TRUE};
		xcc_context_post(f->context, start_waiters_barrier, &settled);
		WAIT(settled.ready);
		g_assert_cmpuint(sessions_closed(f), ==, 1);
	}
	g_mutex_lock(&f->lock);
	opened.released = TRUE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	if (!after_close)
	{
		WaitersBarrier barrier = {.f = f, .count = ui_cancel ? 2 : 1};
		xcc_context_post(f->context, start_waiters_barrier, &barrier);
		WAIT(barrier.ready);
		g_assert_cmpuint(b.calls, ==, 0);
		g_assert_cmpuint(f->pin_shows, ==, 1);
		g_mutex_lock(&f->lock);
		f->hold_login = FALSE;
		g_cond_broadcast(&f->cond);
		g_mutex_unlock(&f->lock);
	}
	WAIT(f->pin_shows == 2 || b.calls == 1);
	g_assert_cmpuint(b.calls, ==, 0);
	submit_pin(f, f->pin_id);
	WAIT(b.calls == 1);
	g_assert_cmpint(a.error, ==, XCC_ERROR_CANCELLED);
	g_assert_cmpint(b.error, ==, XCC_OK);
	g_assert_cmpuint(f->user_logins, ==, 2);
	g_assert_cmpuint(f->signatures, ==, 1);
	g_assert_cmpuint(f->logouts, ==, 0);
	xcc_request_unref(first);
	xcc_request_unref(second);
}

/* Existing lifecycle guard: SDK close cancels the prompt before a late PIN reply. */
static void test_login_after_close(Fixture* f, gconstpointer data)
{
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(f->pin_shows == 1);
	xcc_session_close(f->session);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_NO_SUCH_SESSION);
	submit_pin(f, f->pin_id);
	Done barrier = {.f = f};
	XccRequest* query = xcc_get_capabilities_async(f->context, done, &barrier);
	WAIT(barrier.calls == 1);
	g_assert_cmpuint(f->user_logins, ==, 0);
	g_assert_cmpuint(f->signatures, ==, 0);
	xcc_request_unref(query);
	xcc_request_unref(r);
}

static void test_login_with_closed_grant(Fixture* f, gconstpointer data)
{
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(f->pin_shows == 1);
	/* Isolate closure from prompt cancellation and asynchronous device teardown. */
	g_mutex_lock(&f->session->device_lock);
	g_atomic_int_set(&f->session->closed, TRUE);
	submit_pin(f, f->pin_id);
	g_mutex_unlock(&f->session->device_lock);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_DEVICE);
	g_assert_cmpuint(f->user_logins, ==, 0);
	g_assert_cmpuint(f->signatures, ==, 0);
	/* Restore the fixture state so normal close performs teardown. */
	g_atomic_int_set(&f->session->closed, FALSE);
	xcc_session_close(f->session);
	xcc_request_unref(r);
}
static void test_always_auth(Fixture* f, gconstpointer data)
{
	grant(f);
	f->always_auth = TRUE;
	f->submit = TRUE;
	for (guint i = 0; i < 2; i++)
	{
		Done d = {.f = f};
		XccRequest* r = sign_request(f, &d);
		WAIT(d.calls == 1);
		g_assert_cmpint(d.error, ==, XCC_OK);
		xcc_request_unref(r);
	}
	g_assert_cmpuint(f->user_logins, ==, 1);
	g_assert_cmpuint(f->context_logins, ==, 2);
	g_assert_cmpuint(f->signatures, ==, 2);
	g_assert_cmpuint(f->pin_shows, ==, 3);
}
static void test_expiry(Fixture* f, gconstpointer data)
{
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(f->pin_shows == 1);
	g_atomic_int_set(&f->clock_offset, 301);
	submit_pin(f, f->pin_id);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_DEVICE);
	g_assert_cmpuint(f->user_logins, ==, 0);
	g_assert_cmpuint(f->signatures, ==, 0);
	xcc_request_unref(r);
}
static void test_ui_failure(Fixture* f, gconstpointer data)
{
	f->choose = FALSE;
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(f->chooser_shows == 1);
	xcc_ui_failed(f->context, f->chooser_id, XCC_ERROR_NO_DISPLAY);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_NO_DISPLAY);
	xcc_request_unref(r);
}
static void setup_scripted(Fixture* f, gconstpointer data)
{
	setup(f, NULL);
}
typedef struct
{
	const char* name;
	CK_RV rv;
	XccErrorCode error;
	const char* reason;
	guint32 response;
	gboolean context_specific;
} LoginFailure;
static const LoginFailure login_failures[] = {
	{ "cancel", CKR_CANCEL, XCC_ERROR_CANCELLED, "cancelled", 1, FALSE },
	{ "function-canceled", CKR_FUNCTION_CANCELED, XCC_ERROR_CANCELLED, "cancelled", 1, FALSE },
	{ "locked", CKR_PIN_LOCKED, XCC_ERROR_PIN_LOCKED, "pin_locked", 2, FALSE },
	{ "removed", CKR_TOKEN_NOT_PRESENT, XCC_ERROR_TOKEN_REMOVED, "token_removed", 2, FALSE },
	{ "device", CKR_DEVICE_ERROR, XCC_ERROR_DEVICE, "device_error", 2, FALSE },
	{ "context-cancel", CKR_CANCEL, XCC_ERROR_CANCELLED, "cancelled", 1, TRUE },
	{ "context-function-canceled", CKR_FUNCTION_CANCELED, XCC_ERROR_CANCELLED, "cancelled", 1, TRUE },
};
static void test_pin_provider_failure(Fixture* f, gconstpointer data)
{
	XccErrorCode supplied = GPOINTER_TO_INT(data);
	XccErrorCode expected = supplied == XCC_ERROR_NO_DISPLAY ? XCC_ERROR_NO_DISPLAY
	                                                       : XCC_ERROR_DEVICE;
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(f->pin_shows == 1);
	xcc_ui_failed(f->context, f->pin_id, supplied);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, expected);
	g_assert_cmpuint(xcc_error_wire_response(d.error), ==, 2);
	g_assert_cmpstr(xcc_error_wire_name(d.error), ==,
	                expected == XCC_ERROR_NO_DISPLAY ? "no_display" : "device_error");
	g_assert_cmpuint(f->user_logins, ==, 0);
	g_assert_cmpuint(f->signatures, ==, 0);
	xcc_request_unref(r);
}
static void test_reader_login_failure(Fixture* f, gconstpointer data)
{
	const LoginFailure* test = data;
	f->candidate->token->protected_authentication_path = TRUE;
	f->login_result = test->rv;
	f->always_auth = f->fail_context_login = test->context_specific;
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, test->error);
	g_assert_cmpuint(xcc_error_wire_response(d.error), ==, test->response);
	g_assert_cmpstr(xcc_error_wire_name(d.error), ==, test->reason);
	g_assert_cmpuint(f->pin_shows, ==, test->context_specific ? 2 : 1);
	g_assert_cmpuint(f->user_logins, ==, 1);
	g_assert_cmpuint(f->context_logins, ==, test->context_specific ? 1 : 0);
	g_assert_cmpuint(f->signatures, ==, 0);
	xcc_request_unref(r);
}
static void test_owner_replacement(Fixture* f, gconstpointer data)
{
	f->choose = FALSE;
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(f->chooser_shows == 1);
	xcc_context_set_owner_generation(f->context, 8);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_OWNER_GONE);
	g_assert_true(xcc_session_is_closed(f->session));
	xcc_request_unref(r);
}
static void test_dispatch_order(Fixture* f, gconstpointer data)
{
	XccAcquireSpec invalid = {0};
	Done results[3] = {{.f = f, .order = 1}, {.f = f, .order = 2}, {.f = f, .order = 3}};
	XccRequest* requests[3];
	for (guint i = 0; i < 3; i++)
	{
		requests[i] = xcc_acquire_async(f->session, &invalid, done, &results[i]);
		g_assert_cmpuint(results[i].calls, ==, 0);
	}
	WAIT(f->ordered_completions == 3);
	for (guint i = 0; i < 3; i++)
	{
		g_assert_cmpuint(results[i].calls, ==, 1);
		g_assert_cmpint(results[i].error, ==, XCC_ERROR_INVALID_REQUEST);
		xcc_request_unref(requests[i]);
	}
}
static void test_protected_final_try(Fixture* f, gconstpointer data)
{
	f->candidate->token->protected_authentication_path = TRUE;
	f->candidate->token->pin_final_try = TRUE;
	grant(f);
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(f->warnings == 1);
	xcc_warning_reply(f->context, f->pin_id, f->warning_id + 1, TRUE);
	Done barrier = {.f = f};
	XccRequest* query = xcc_get_capabilities_async(f->context, done, &barrier);
	WAIT(barrier.calls == 1);
	g_assert_cmpuint(f->user_logins, ==, 0);
	xcc_warning_reply(f->context, f->pin_id, f->warning_id, TRUE);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_OK);
	g_assert_cmpuint(f->user_logins, ==, 1);
	xcc_request_unref(r);
	xcc_request_unref(query);
}
static void test_empty_chooser(Fixture* f, gconstpointer data)
{
	f->empty = TRUE;
	f->choose = FALSE;
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(f->chooser_shows == 1);
	g_assert_cmpuint(f->choice, ==, 0);
	xcc_ui_cancel(f->context, f->chooser_id);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_CANCELLED);
	xcc_request_unref(r);
}
static void test_forbidden(Fixture* f, gconstpointer data)
{
	XccAcquireSpec spec = acquire_spec();
	spec.interaction_present = TRUE;
	spec.interaction_forbidden = TRUE;
	Done d = {.f = f};
	XccRequest* r = xcc_acquire_async(f->session, &spec, done, &d);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_INTERACTION_REQUIRED);
	g_assert_cmpuint(f->chooser_shows, ==, 0);
	xcc_request_unref(r);
}
static void test_close_session(Fixture* f, gconstpointer data)
{
	f->choose = FALSE;
	Done d = {.f = f};
	XccRequest* r = acquire(f, &d);
	WAIT(f->chooser_shows == 1);
	xcc_session_close(f->session);
	WAIT(d.calls == 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_NO_SUCH_SESSION);
	xcc_request_unref(r);
}
static void test_shutdown_with_login(Fixture* f, gconstpointer data)
{
	grant(f);
	f->hold_login = TRUE;
	f->submit = TRUE;
	Done d = {.f = f};
	XccRequest* r = sign_request(f, &d);
	WAIT(logging_in(f));
	xcc_context_shutdown_async(f->context, shutdown_done, f);
	WAIT(f->hides == 1);
	g_assert_false(f->shutdown);
	g_mutex_lock(&f->lock);
	f->hold_login = FALSE;
	g_cond_broadcast(&f->cond);
	g_mutex_unlock(&f->lock);
	WAIT(f->shutdown);
	g_assert_cmpuint(d.calls, ==, 1);
	g_assert_cmpint(d.error, ==, XCC_ERROR_BACKEND_GONE);
	g_assert_cmpuint(f->sessions_closed, >=, 1);
	g_assert_false(f->token_logged_in);
	xcc_request_unref(r);
	submit_pin(f, f->pin_id); /* Late input is consumed after the coordinator has stopped. */
	Done late = {.f = f};
	XccRequest* query = xcc_get_capabilities_async(f->context, done, &late);
	WAIT(late.calls == 1);
	g_assert_cmpint(late.error, ==, XCC_ERROR_BACKEND_GONE);
	xcc_request_unref(query);
}
int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
#define TEST(name, function) g_test_add("/core-api/" name, Fixture, NULL, setup, function, teardown)
	TEST("acquire-dispatch-stale-replies", test_acquire);
	g_test_add("/core-api/removal-before-consent-without-refresh", Fixture, GINT_TO_POINTER(1),
			   setup, test_removal_before_consent, teardown);
	TEST("cancel-before-chooser", test_cancel_before);
	TEST("cancel-after-chooser", test_cancel_chooser);
	TEST("principal-mismatch", test_mismatch);
	TEST("non-increasing-identity", test_identity);
	TEST("cancel-during-pin", test_cancel_pin);
	TEST("cancel-submitted-pin", test_cancel_submitted);
	TEST("shared-login-waiters", test_shared_waiters);
	TEST("two-grants-one-token", test_two_grants);
	TEST("token-logout-reprompts", test_token_logout);
	for (guint i = 0; i < G_N_ELEMENTS(sign_removals); i++)
	{
		g_autofree char* name = g_strdup_printf("/core-api/removal-during-sign/%s",
		                                     sign_removals[i].name);
		g_test_add(name, Fixture, &sign_removals[i], setup_scripted,
		           test_removal_during_sign, teardown);
	}
	for (guint i = 0; i < G_N_ELEMENTS(login_states); i++)
	{
		g_autofree char* name = g_strdup_printf("/core-api/login-state/%s",
		                                     login_states[i].name);
		g_test_add(name, Fixture, &login_states[i], setup_scripted, test_login_state, teardown);
	}
	TEST("context-cancel-preserves-token-login", test_context_cancel_preserves_login);
	TEST("open-snapshot-after-successful-login", test_open_after_successful_login);
	g_test_add("/core-api/stale-login-snapshot-stalled-refresh", Fixture, GINT_TO_POINTER(1),
	           setup_scripted, test_open_after_successful_login, teardown);
	TEST("concurrent-signs-slow-session-info", test_concurrent_signs);
	TEST("stalled-sign-cancel-expiry", test_stalled_token);
	g_test_add("/core-api/stalled-context-login-cancel-expiry", Fixture, GINT_TO_POINTER(1),
	           setup_scripted, test_stalled_token, teardown);
	TEST("acquire-during-sign", test_acquire_during_sign);
	TEST("overlapping-acquire-chooser", test_overlapping_acquire);
	g_test_add("/core-api/overlapping-acquire-discovery", Fixture, GINT_TO_POINTER(1),
	           setup_scripted, test_overlapping_acquire, teardown);
	TEST("acquire-after-expiry", test_acquire_after_expiry);
	TEST("cancel-after-acquire-commit", test_cancel_committed_acquire);
	g_test_add("/core-api/cancel-after-acquire-commit-with-token-login", Fixture, GINT_TO_POINTER(1),
	           setup_scripted, test_cancel_committed_acquire, teardown);
	TEST("sign-before-acquire-delivery", test_sign_before_acquire_delivery);
	TEST("cancel-delivered-acquire", test_cancel_delivered_acquire);
	TEST("cancel-rejected-acquire", test_cancel_rejected_acquire);
	TEST("close-after-acquire-commit", test_close_committed_acquire);
	g_test_add("/core-api/shutdown-after-acquire-commit", Fixture, GINT_TO_POINTER(1),
	           setup_scripted, test_close_committed_acquire, teardown);
	TEST("join-after-cancelled-login", test_join_cancelled_login);
	g_test_add("/core-api/join-after-dismissed-login", Fixture, GINT_TO_POINTER(1),
	           setup_scripted, test_join_cancelled_login, teardown);
	g_test_add("/core-api/open-snapshot-after-cancelled-login", Fixture, GINT_TO_POINTER(2),
	           setup_scripted, test_join_cancelled_login, teardown);
	TEST("login-after-session-close", test_login_after_close);
	TEST("login-with-closed-grant", test_login_with_closed_grant);
	TEST("always-authenticate-order", test_always_auth);
	TEST("expiry-during-request", test_expiry);
	TEST("ui-failure", test_ui_failure);
	g_test_add("/core-api/pin-provider/no-display", Fixture, GINT_TO_POINTER(XCC_ERROR_NO_DISPLAY),
	           setup_scripted, test_pin_provider_failure, teardown);
	g_test_add("/core-api/pin-provider/device", Fixture, GINT_TO_POINTER(XCC_ERROR_DEVICE),
	           setup_scripted, test_pin_provider_failure, teardown);
	g_test_add("/core-api/pin-provider/unspecified", Fixture, GINT_TO_POINTER(XCC_OK),
	           setup_scripted, test_pin_provider_failure, teardown);
	for (guint i = 0; i < G_N_ELEMENTS(login_failures); i++)
	{
		g_autofree char* name = g_strdup_printf("/core-api/reader-login-failure/%s",
		                                     login_failures[i].name);
		g_test_add(name, Fixture, &login_failures[i], setup_scripted,
		           test_reader_login_failure, teardown);
	}
	TEST("owner-replacement", test_owner_replacement);
	TEST("completion-dispatch-order", test_dispatch_order);
	TEST("protected-final-try-stale-warning", test_protected_final_try);
	TEST("empty-chooser", test_empty_chooser);
	TEST("interaction-forbidden", test_forbidden);
	TEST("session-close", test_close_session);
	TEST("shutdown-with-submitted-login", test_shutdown_with_login);
#undef TEST
	return g_test_run();
}
