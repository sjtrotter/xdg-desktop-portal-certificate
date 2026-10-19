/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <string.h>
#include "core/core.h"
#include "core/context-private.h"
#include "core/ui.h"
#include "core/dispatch-glib.h"
#include "fixture-util.h"

/* Script the token boundary, retaining the real transactions, broker and PIN policy. */
typedef struct
{
	XccContext* context;
	XccSession* session;
	CertificateCandidate* candidate;
	GThread* desktop;
	guint chooser_shows, pin_shows, closes, hides, completions, updates;
	XccUiId chooser_id, pin_id;
	uint64_t revision, choice;
	gboolean choose, submit, shutdown, always_auth, initialized, context_authenticated, empty,
		confirm;
	uint64_t warning_id;
	guint warnings, ordered_completions;
	guint user_logins, context_logins, signatures, logouts;
	gint clock_offset;
	GMutex lock;
	GCond cond;
	gboolean hold_enumeration, enumerating, hold_login, logging_in, hold_open, opening;
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
static gboolean find_pending;
static CK_RV find_init(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
	find_pending = TRUE;
	return CKR_OK;
}
static CK_RV find(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR objects, CK_ULONG max,
				  CK_ULONG_PTR count)
{
	*count = find_pending ? 1 : 0;
	if (find_pending)
		objects[0] = 7;
	find_pending = FALSE;
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
	g_mutex_unlock(&f->lock);
	if (user == CKU_USER)
		f->user_logins++;
	else
	{
		g_assert_cmpuint(user, ==, CKU_CONTEXT_SPECIFIC);
		g_assert_true(f->initialized);
		f->context_logins++;
		f->context_authenticated = TRUE;
	}
	return CKR_OK;
}
static CK_RV sign_init(CK_SESSION_HANDLE h, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	g_assert_false(active->initialized);
	active->initialized = TRUE;
	active->context_authenticated = FALSE;
	return CKR_OK;
}
static CK_RV sign(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG length, CK_BYTE_PTR out,
				  CK_ULONG_PTR size)
{
	Fixture* f = active;
	g_assert_true(f->initialized);
	if (f->always_auth)
		g_assert_true(f->context_authenticated);
	*size = 1;
	if (out != NULL)
	{
		out[0] = 42;
		f->signatures++;
		f->initialized = FALSE;
	}
	return CKR_OK;
}
static CK_RV logout(CK_SESSION_HANDLE h)
{
	active->logouts++;
	return CKR_OK;
}
static CK_RV close_device(CK_SESSION_HANDLE h)
{
	active->initialized = FALSE;
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
	g_mutex_unlock(&f->lock);
	*output = &module;
	*handle = 1;
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
	xcc_pin_ready(f->context, id);
	g_string_append_c(f->deliveries, 'P');
	if (view->context_specific)
		g_assert_true(f->always_auth);
	if (f->submit)
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
		gint64 deadline = __real_g_get_monotonic_time() + 10 * G_USEC_PER_SEC;                     \
		while (!(condition) && __real_g_get_monotonic_time() < deadline)                           \
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
	g_mutex_lock(&f->lock);
	f->hold_enumeration = f->hold_login = f->hold_open = FALSE;
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
static XccRequest* sign_request(Fixture* f, Done* d)
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
	return xcc_sign_async(f->session, &spec, done, d);
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
} WaitersBarrier;
static void waiters_ready(void* data)
{
	((WaitersBarrier*)data)->ready = TRUE;
}
static gboolean observe_waiters(void* data)
{
	WaitersBarrier* b = data;
	if (b->f->session->login_waiters == NULL || b->f->session->login_waiters->len != 2)
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
	WaitersBarrier barrier = {.f = f};
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
	g_assert_cmpuint(f->logouts, >=, 1);
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
	TEST("always-authenticate-order", test_always_auth);
	TEST("expiry-during-request", test_expiry);
	TEST("ui-failure", test_ui_failure);
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
