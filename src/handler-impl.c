/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "handler-impl.h"

#include <errno.h>
#include <sys/random.h>
#include <string.h>

#include "core/adapter.h"
#include "core/session-private.h"
#include "step-provider.h"
#include "tokens/filter.h"
#include "xdp-handler-dbus.h"

#define CHOOSER_TIMEOUT_MS (300u * 1000u)

typedef enum
{
	STEP_CHOOSER
} StepKind;

typedef struct
{
	CertificateHandler* handler;
	CertificateImplSession* session;
	XccRequest* core;
	GDBusMethodInvocation* pending;
	char* handle;
	char* core_id;
	char* owner;
	guint64 generation, instance, session_instance;
	guint64 token, revision, step_revision;
	XccUiId ui_id;
	StepKind kind;
	GVariant* view;
	guint issue_source, timeout_source;
	gboolean ended, step_out;
} Operation;

struct CertificateHandler
{
	CertificateImpl* impl;
	XccContext* context;
	GDBusConnection* connection;
	guint registration;
	CertificateStepProvider* provider;
	GHashTable* operations; /* Borrowed until core completion, indexed by handle. */
	GHashTable* core_ids;
	GMutex token_lock;
	GHashTable* tokens; /* Borrowed operation, indexed by its live token. */
	guint64 next_instance;
	guint chooser_timeout_ms;
};

static GVariant* results_with_instance(GVariant* results, guint64 instance)
{
	g_autoptr(GVariant) owned = g_variant_ref_sink(results);
	GVariantDict dict;
	g_variant_dict_init(&dict, owned);
	g_variant_dict_insert(&dict, "instance", "t", instance);
	return g_variant_dict_end(&dict);
}

static GVariant* reason_results(const char* reason)
{
	GVariantBuilder builder;
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	if (reason != NULL)
		g_variant_builder_add(&builder, "{sv}", "reason", g_variant_new_string(reason));
	return g_variant_builder_end(&builder);
}

static void answer(GDBusMethodInvocation* invocation, guint response, GVariant* results,
				   guint64 instance)
{
	g_dbus_method_invocation_return_value(
		invocation, g_variant_new("(u@a{sv})", response, results_with_instance(results, instance)));
}

static void emit(CertificateHandler* handler, const char* owner, const char* signal,
				 GVariant* parameters)
{
	g_dbus_connection_emit_signal(handler->connection, owner, CERTIFICATE_IMPL_OBJECT_PATH,
								  CERTIFICATE_HANDLER_INTERFACE, signal, parameters, NULL);
}

static void drop_token(Operation* operation)
{
	CertificateHandler* handler = operation->handler;
	g_mutex_lock(&handler->token_lock);
	if (operation->token != 0)
		g_hash_table_remove(handler->tokens, &operation->token);
	operation->token = 0;
	g_mutex_unlock(&handler->token_lock);
}

static void clear_sources(Operation* operation)
{
	if (operation->issue_source != 0)
		g_source_remove(operation->issue_source);
	if (operation->timeout_source != 0)
		g_source_remove(operation->timeout_source);
	operation->issue_source = operation->timeout_source = 0;
}

static void finish(Operation* operation, guint response, GVariant* results, gboolean notify)
{
	g_autoptr(GVariant) owned = g_variant_ref_sink(results);
	if (operation->ended)
		return;
	operation->ended = TRUE;
	drop_token(operation);
	clear_sources(operation);
	g_hash_table_remove(operation->handler->operations, operation->handle);
	g_hash_table_remove(operation->handler->core_ids, operation->core_id);
	if (operation->pending != NULL)
	{
		answer(operation->pending, response, owned, operation->instance);
		g_clear_object(&operation->pending);
	}
	else if (notify && operation->step_out)
		emit(operation->handler, operation->owner, "OperationEnded",
			 g_variant_new("(otu@a{sv})", operation->handle, operation->instance, response,
						   results_with_instance(owned, operation->instance)));
}

static void cancel_operation(Operation* operation, guint response, const char* reason,
							 XccCancelReason cancel, gboolean notify)
{
	finish(operation, response, reason_results(reason), notify);
	xcc_request_cancel(operation->core, cancel);
}

static gboolean on_timeout(gpointer data)
{
	Operation* operation = data;
	operation->timeout_source = 0;
	cancel_operation(operation, 2, "timeout", XCC_CANCEL_USER, TRUE);
	return G_SOURCE_REMOVE;
}

static gboolean mint_token(Operation* operation)
{
	CertificateHandler* handler = operation->handler;
	guint64 token;
	g_mutex_lock(&handler->token_lock);
	do
	{
		ssize_t count;
		do
			count = getrandom(&token, sizeof(token), 0);
		while (count < 0 && errno == EINTR);
		if (count != sizeof(token))
		{
			g_mutex_unlock(&handler->token_lock);
			return FALSE;
		}
	} while (token == 0 || g_hash_table_contains(handler->tokens, &token));
	operation->token = token;
	operation->kind = STEP_CHOOSER;
	operation->step_revision = operation->revision;
	g_hash_table_insert(handler->tokens, &operation->token, operation);
	g_mutex_unlock(&handler->token_lock);
	return TRUE;
}

static gboolean issue_step(gpointer data)
{
	Operation* operation = data;
	CertificateHandler* handler = operation->handler;
	GVariantBuilder builder;
	operation->issue_source = 0;
	if (operation->ended || operation->pending == NULL || operation->view == NULL)
		return G_SOURCE_REMOVE;
	if (!mint_token(operation))
	{
		cancel_operation(operation, 2, "error", XCC_CANCEL_DEVICE, TRUE);
		return G_SOURCE_REMOVE;
	}
	if (operation->timeout_source != 0)
		g_source_remove(operation->timeout_source);
	operation->timeout_source = g_timeout_add(handler->chooser_timeout_ms, on_timeout, operation);
	guint64 deadline =
		(g_get_monotonic_time() + (gint64)handler->chooser_timeout_ms * 1000 + G_USEC_PER_SEC - 1) /
		G_USEC_PER_SEC;
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "step", g_variant_new_string("chooser"));
	g_variant_builder_add(&builder, "{sv}", "token", g_variant_new_uint64(operation->token));
	g_variant_builder_add(&builder, "{sv}", "deadline", g_variant_new_uint64(deadline));
	g_variant_builder_add(&builder, "{sv}", "view", operation->view);
	operation->step_out = TRUE;
	answer(operation->pending, 0, g_variant_builder_end(&builder), operation->instance);
	g_clear_object(&operation->pending);
	return G_SOURCE_REMOVE;
}

static void schedule_step(Operation* operation)
{
	if (operation->issue_source == 0)
		operation->issue_source = g_idle_add(issue_step, operation);
}

static GVariant* chooser_view(const XccChooserView* view)
{
	GVariantBuilder builder, rows;
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
#define TEXT(field)                                                                                \
	g_variant_builder_add(&builder, "{sv}", #field,                                                \
						  g_variant_new_string(view->field != NULL ? view->field : ""))
#define UINT(field)                                                                                \
	g_variant_builder_add(&builder, "{sv}", #field, g_variant_new_uint32(view->field))
#define BOOL(field)                                                                                \
	g_variant_builder_add(&builder, "{sv}", #field, g_variant_new_boolean(view->field))
	g_variant_builder_add(&builder, "{sv}", "revision", g_variant_new_uint64(view->revision));
	TEXT(caller_name);
	TEXT(app_id);
	UINT(identity_level);
	TEXT(identity_detail);
	UINT(purpose);
	TEXT(purpose_text);
	TEXT(purpose_detail);
	BOOL(may_sign);
	BOOL(may_decrypt);
	TEXT(operation_scope);
	UINT(lifetime_seconds);
	TEXT(duration);
	TEXT(later_prompt);
	TEXT(reason_label);
	TEXT(untrusted_reason);
	BOOL(tokens_present);
	TEXT(parent_window);
	TEXT(activation_token);
	BOOL(generic_purpose);
	UINT(display_flags);
	BOOL(tokens_reading);
	TEXT(session_id);
	TEXT(operation_id);
#undef TEXT
#undef UINT
#undef BOOL
	g_variant_builder_init(&rows, G_VARIANT_TYPE("aa{sv}"));
	for (gsize i = 0; i < view->n_candidates; i++)
	{
		const XccChooserCandidateView* row = xcc_chooser_view_candidate(view, i);
		GVariantBuilder candidate;
		g_variant_builder_init(&candidate, G_VARIANT_TYPE_VARDICT);
#define TEXT(field)                                                                                \
	g_variant_builder_add(&candidate, "{sv}", #field,                                              \
						  g_variant_new_string(row->field != NULL ? row->field : ""))
#define UINT(field)                                                                                \
	g_variant_builder_add(&candidate, "{sv}", #field, g_variant_new_uint32(row->field))
		g_variant_builder_add(&candidate, "{sv}", "id", g_variant_new_uint64(row->id));
		TEXT(subject);
		TEXT(issuer);
		TEXT(token);
		TEXT(reader);
		TEXT(expiry);
		TEXT(detail);
		TEXT(fingerprint);
		g_variant_builder_add(&candidate, "{sv}", "invalid", g_variant_new_boolean(row->invalid));
		g_variant_builder_add(&candidate, "{sv}", "not_before",
							  g_variant_new_int64(row->not_before));
		g_variant_builder_add(&candidate, "{sv}", "not_after", g_variant_new_int64(row->not_after));
		UINT(validity);
		TEXT(key_type);
		UINT(key_size);
		UINT(display_flags);
#undef TEXT
#undef UINT
		g_variant_builder_add_value(&rows, g_variant_builder_end(&candidate));
	}
	g_variant_builder_add(&builder, "{sv}", "candidates", g_variant_builder_end(&rows));
	return g_variant_builder_end(&builder);
}

void certificate_handler_chooser(CertificateHandler* handler, XccUiId id,
								 const XccChooserView* view)
{
	Operation* operation = g_hash_table_lookup(handler->core_ids, view->operation_id);
	if (operation == NULL || operation->ended ||
		g_strcmp0(operation->session->id, view->session_id) != 0)
		return;
	operation->ui_id = id;
	operation->revision = view->revision;
	g_clear_pointer(&operation->view, g_variant_unref);
	operation->view = g_variant_ref_sink(chooser_view(view));
	if (operation->pending != NULL)
		schedule_step(operation);
	else if (operation->token != 0)
		emit(handler, operation->owner, "OperationUpdated",
			 g_variant_new("(ott@a{sv})", operation->handle, operation->instance, operation->token,
						   operation->view));
}

void certificate_handler_ui_closed(CertificateHandler* handler, XccUiId id)
{
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, handler->operations);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		Operation* operation = value;
		if (operation->ui_id == id)
		{
			drop_token(operation);
			if (operation->issue_source != 0)
				g_source_remove(operation->issue_source);
			operation->issue_source = 0;
		}
	}
	/* Core completion supplies the terminal response after hide/close. */
}

static void core_done(XccRequest* request, const XccResult* result, void* data)
{
	Operation* operation = data;
	if (!operation->ended && result->error == XCC_OK)
		operation->session->handler_granted = TRUE;
	GVariant* results = result->error == XCC_OK
							? certificate_impl_acquire_results(
								  (CertificateCandidate*)xcc_candidate_internal(result->candidate),
								  result->may_sign)
							: reason_results(xcc_error_wire_name(result->error));
	finish(operation, xcc_error_wire_response(result->error), results, TRUE);
	xcc_request_unref(operation->core);
	g_clear_object(&operation->session);
	g_clear_pointer(&operation->view, g_variant_unref);
	g_free(operation->handle);
	g_free(operation->core_id);
	g_free(operation->owner);
	g_free(operation);
}

static gboolean take(GVariant* options, const char* key, const GVariantType* type, GVariant** value)
{
	*value = g_variant_lookup_value(options, key, NULL);
	return *value == NULL || g_variant_is_of_type(*value, type);
}

static void acquire(CertificateHandler* handler, GDBusMethodInvocation* invocation,
					const char* handle, const char* session_handle, GVariant* options)
{
	Operation* live = g_hash_table_lookup(handler->operations, handle);
	if (live != NULL)
	{
		answer(invocation, 2, reason_results("invalid_request"), live->instance);
		return;
	}
	guint64 instance = ++handler->next_instance;
	CertificateImplSession* session = certificate_impl_find_session(handler->impl, session_handle);
	if (session == NULL || !session->handler || xcc_session_is_closed(session->core))
	{
		answer(invocation, 2, reason_results("no_such_session"), instance);
		return;
	}
	Operation* operation = g_new0(Operation, 1);
	operation->handler = handler;
	operation->handle = g_strdup(handle);
	operation->instance = instance;
	operation->session = g_object_ref(session);
	operation->session_instance = session->instance;
	operation->owner = g_strdup(g_dbus_method_invocation_get_sender(invocation));
	operation->generation = certificate_impl_generation(handler->impl);
	operation->core_id = g_strdup_printf("%s#%" G_GUINT64_FORMAT, handle, instance);
	operation->pending = g_object_ref(invocation);
	g_hash_table_insert(handler->operations, operation->handle, operation);
	g_hash_table_insert(handler->core_ids, operation->core_id, operation);

	g_autoptr(GVariant) purpose = NULL;
	g_autoptr(GVariant) level = NULL;
	g_autoptr(GVariant) interaction = NULL;
	g_autoptr(GVariant) reason = NULL;
	g_autoptr(GVariant) activation = NULL;
	g_autoptr(GVariant) lifetime = NULL;
	g_autoptr(GVariant) policy = NULL;
	g_autoptr(GVariant) sign = NULL;
	CertificatePurpose parsed_purpose = CERTIFICATE_PURPOSE_CLIENT_AUTH;
	const char* failure = "invalid_request";
	gboolean valid =
		take(options, "purpose", G_VARIANT_TYPE_STRING, &purpose) && purpose != NULL &&
		certificate_purpose_parse(g_variant_get_string(purpose, NULL), &parsed_purpose);
	if (!valid)
		failure = "invalid_purpose";
	valid = valid && take(options, "app_identity_level", G_VARIANT_TYPE_STRING, &level) &&
			take(options, "interaction_mode", G_VARIANT_TYPE_STRING, &interaction) &&
			take(options, "reason", G_VARIANT_TYPE_STRING, &reason) &&
			take(options, "activation_token", G_VARIANT_TYPE_STRING, &activation) &&
			take(options, "lifetime", G_VARIANT_TYPE_UINT32, &lifetime) &&
			take(options, "operation_policy", G_VARIANT_TYPE_VARDICT, &policy);
	const char* identity = level != NULL && g_variant_is_of_type(level, G_VARIANT_TYPE_STRING)
							   ? g_variant_get_string(level, NULL)
							   : NULL;
	valid = valid && (identity == NULL || g_str_equal(identity, "sandboxed") ||
					  g_str_equal(identity, "host") || g_str_equal(identity, "unidentified"));
	const char* mode =
		interaction != NULL && g_variant_is_of_type(interaction, G_VARIANT_TYPE_STRING)
			? g_variant_get_string(interaction, NULL)
			: NULL;
	valid = valid && (mode == NULL || g_str_equal(mode, "required") ||
					  g_str_equal(mode, "allowed") || g_str_equal(mode, "forbidden"));
	if (valid && lifetime != NULL && g_variant_get_uint32(lifetime) == 0)
		valid = FALSE;
	if (valid && policy != NULL)
	{
		GVariantIter iter;
		const char* key;
		g_variant_iter_init(&iter, policy);
		while (g_variant_iter_next(&iter, "{&sv}", &key, NULL))
			if (!g_str_equal(key, "sign"))
				valid = FALSE;
		valid = valid && take(policy, "sign", G_VARIANT_TYPE_BOOLEAN, &sign);
	}
	XccAcquireSpec spec = {.struct_size = sizeof(spec),
						   .abi_version = XCC_ABI_VERSION,
						   .principal = {sizeof(XccPrincipal), XCC_ABI_VERSION,
										 operation->generation, session->app_id,
										 certificate_identity_level_parse(identity), TRUE},
						   .purpose = parsed_purpose,
						   .operation_id = operation->core_id};
	CertificateFilter filter = {0};
	g_autoptr(GError) error = NULL;
	if (valid && !certificate_filter_parse(
					 options, parsed_purpose,
					 (sign == NULL || g_variant_get_boolean(sign)) ? CERTIFICATE_OPERATION_SIGN : 0,
					 &filter, &error))
	{
		valid = FALSE;
		failure = "invalid_filter";
	}
	if (valid)
	{
		spec.reason = reason != NULL ? g_variant_get_string(reason, NULL) : NULL;
		spec.activation_token = activation != NULL ? g_variant_get_string(activation, NULL) : NULL;
		spec.lifetime_present = TRUE;
		spec.lifetime_seconds = lifetime != NULL ? MIN(g_variant_get_uint32(lifetime), 3600u) : 300;
		spec.sign_present = TRUE;
		spec.sign = sign == NULL || g_variant_get_boolean(sign);
		spec.interaction_present = TRUE;
		spec.interaction_forbidden = g_strcmp0(mode, "forbidden") == 0;
		spec.issuers_present = filter.issuers != NULL;
		spec.key_usage_present = filter.key_usage != NULL;
		spec.key_usage = (const char* const*)filter.key_usage;
		spec.eku_oids_present = filter.eku_oids != NULL;
		spec.eku_oids = (const char* const*)filter.eku_oids;
		spec.key_algorithms_present = filter.key_algorithms != NULL;
		spec.key_algorithms = (const char* const*)filter.key_algorithms;
		spec.token_label_present = filter.token_label != NULL;
		spec.token_label = filter.token_label;
		spec.piv_slot_present = filter.piv_slot != NULL;
		spec.piv_slot = filter.piv_slot;
	}
	g_autofree XccBytes* issuers = NULL;
	if (valid && spec.issuers_present)
	{
		spec.n_issuers = filter.issuers->len;
		issuers = g_new0(XccBytes, spec.n_issuers);
		for (guint i = 0; i < spec.n_issuers; i++)
		{
			issuers[i].struct_size = sizeof(XccBytes);
			issuers[i].abi_version = XCC_ABI_VERSION;
			issuers[i].data =
				g_bytes_get_data(g_ptr_array_index(filter.issuers, i), &issuers[i].size);
		}
		spec.issuers = issuers;
	}
	operation->core = xcc_acquire_async(session->core, valid ? &spec : NULL, core_done, operation);
	certificate_filter_clear(&filter);
	if (!valid)
		finish(operation, 2, reason_results(failure), TRUE);
}

static void choose(CertificateHandler* handler, GDBusMethodInvocation* invocation,
				   const char* handle, guint64 token, guint64 candidate)
{
	const char* owner = g_dbus_method_invocation_get_sender(invocation);
	g_mutex_lock(&handler->token_lock);
	Operation* operation = g_hash_table_lookup(handler->tokens, &token);
	gboolean valid = operation != NULL && !operation->ended && operation->kind == STEP_CHOOSER &&
					 g_str_equal(operation->handle, handle) &&
					 g_str_equal(operation->owner, owner) &&
					 operation->generation == certificate_impl_generation(handler->impl) &&
					 operation->session_instance == operation->session->instance &&
					 certificate_impl_find_session(handler->impl, operation->session->id) ==
						 operation->session &&
					 !xcc_session_is_closed(operation->session->core);
	if (valid)
	{
		g_hash_table_remove(handler->tokens, &token);
		operation->token = 0;
	}
	g_mutex_unlock(&handler->token_lock);
	if (!valid)
	{
		Operation* live = g_hash_table_lookup(handler->operations, handle);
		answer(invocation, 2, reason_results("stale_step"), live != NULL ? live->instance : 0);
		return;
	}
	if (operation->timeout_source != 0)
		g_source_remove(operation->timeout_source);
	operation->timeout_source = 0;
	operation->pending = g_object_ref(invocation);
	if (xcc_choose(handler->context, operation->ui_id, operation->step_revision, candidate) ==
		XCC_UI_REPLY_STALE)
		schedule_step(operation);
}

static void create_session(CertificateHandler* handler, GDBusMethodInvocation* invocation,
						   const char* handle, const char* path, const char* app_id,
						   GVariant* identity, GVariant* options)
{
	guint64 instance = ++handler->next_instance;
	CertificateImplSession* existing = certificate_impl_find_session(handler->impl, path);
	if (g_variant_n_children(identity) != 0 ||
		(existing != NULL && !xcc_session_is_closed(existing->core)))
	{
		answer(invocation, 2, reason_results("invalid_request"), instance);
		return;
	}
	if (existing != NULL)
		certificate_impl_session_forget(existing);
	CertificateImplSession* session = certificate_impl_session_new_for_context(
		handler->context, certificate_impl_generation(handler->impl), path, app_id);
	g_autoptr(GError) error = NULL;
	if (session == NULL)
	{
		answer(invocation, 2, reason_results("no_such_session"), instance);
		return;
	}
	session->handler = TRUE;
	session->instance = instance;
	session->owner = g_strdup(g_dbus_method_invocation_get_sender(invocation));
	g_atomic_int_set(&session->core->handler_ui, TRUE);
	if (!certificate_impl_session_export(session, handler->connection, &error))
	{
		certificate_impl_session_close(session);
		g_object_unref(session);
		answer(invocation, 2, reason_results("invalid_request"), instance);
		return;
	}
	certificate_impl_add_session(handler->impl, session);
	answer(invocation, 0, reason_results(NULL), instance);
}

static void capabilities_done(XccRequest* request, const XccResult* result, void* data)
{
	g_autoptr(GDBusMethodInvocation) invocation = data;
	GVariantBuilder builder;
	static const char* const purposes[] = {"client_auth", "signing", "email", "ssh", NULL};
	static const char* const operations[] = {"sign", NULL};
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "purposes", g_variant_new_strv(purposes, -1));
	g_variant_builder_add(&builder, "{sv}", "operations", g_variant_new_strv(operations, -1));
	g_variant_builder_add(&builder, "{sv}", "mechanisms",
						  g_variant_new_strv(result->mechanisms, -1));
	g_variant_builder_add(&builder, "{sv}", "protected_authentication_path",
						  g_variant_new_boolean(result->protected_path));
	g_dbus_method_invocation_return_value(
		invocation, g_variant_new("(@a{sv})", g_variant_builder_end(&builder)));
}

static void method_call(GDBusConnection* connection, const char* sender, const char* path,
						const char* interface, const char* method, GVariant* parameters,
						GDBusMethodInvocation* invocation, gpointer data)
{
	CertificateHandler* handler = data;
	if (!certificate_impl_sender_is_frontend(handler->impl, sender))
	{
		g_dbus_method_invocation_return_error_literal(
			invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
			"Only xdg-desktop-portal may call this interface");
		return;
	}
	if (g_str_equal(method, "CreateSession"))
	{
		const char *handle, *session, *app;
		g_autoptr(GVariant) identity = NULL;
		g_autoptr(GVariant) options = NULL;
		g_variant_get(parameters, "(&o&o&s@a{sv}@a{sv})", &handle, &session, &app, &identity,
					  &options);
		create_session(handler, invocation, handle, session, app, identity, options);
	}
	else if (g_str_equal(method, "Acquire"))
	{
		const char *handle, *session;
		g_autoptr(GVariant) options = NULL;
		g_variant_get(parameters, "(&o&o@a{sv})", &handle, &session, &options);
		acquire(handler, invocation, handle, session, options);
	}
	else if (g_str_equal(method, "Choose"))
	{
		const char* handle;
		guint64 token, candidate;
		g_variant_get(parameters, "(&ott)", &handle, &token, &candidate);
		choose(handler, invocation, handle, token, candidate);
	}
	else if (g_str_equal(method, "Cancel"))
	{
		const char* handle;
		g_variant_get(parameters, "(&o)", &handle);
		Operation* operation = g_hash_table_lookup(handler->operations, handle);
		if (operation != NULL)
			cancel_operation(operation, 1, NULL, XCC_CANCEL_USER, TRUE);
		g_dbus_method_invocation_return_value(invocation, NULL);
	}
	else if (g_str_equal(method, "GetCapabilities"))
	{
		XccRequest* request = xcc_get_capabilities_async(handler->context, capabilities_done,
														 g_object_ref(invocation));
		xcc_request_unref(request);
	}
	else
	{
		g_autoptr(GVariant) handle = g_variant_get_child_value(parameters, 0);
		Operation* operation =
			g_hash_table_lookup(handler->operations, g_variant_get_string(handle, NULL));
		answer(invocation, 2, reason_results("unsupported"),
			   operation != NULL ? operation->instance : 0);
	}
}

CertificateHandler* certificate_handler_new(CertificateImpl* impl, GDBusConnection* connection,
											GError** error)
{
	static const GDBusInterfaceVTable vtable = {.method_call = method_call};
	CertificateHandler* handler = g_new0(CertificateHandler, 1);
	handler->impl = impl;
	handler->context = certificate_impl_context(impl);
	handler->connection = g_object_ref(connection);
	handler->chooser_timeout_ms = CHOOSER_TIMEOUT_MS;
	handler->operations = g_hash_table_new(g_str_hash, g_str_equal);
	handler->core_ids = g_hash_table_new(g_str_hash, g_str_equal);
	handler->tokens = g_hash_table_new(g_int64_hash, g_int64_equal);
	g_mutex_init(&handler->token_lock);
	handler->registration = g_dbus_connection_register_object(
		connection, CERTIFICATE_IMPL_OBJECT_PATH,
		xdp_handler_experimental_certificate1_interface_info(), &vtable, handler, NULL, error);
	if (handler->registration == 0)
	{
		certificate_handler_free(handler);
		return NULL;
	}
	certificate_impl_set_handler(impl, handler);
	handler->provider = certificate_step_provider_new(handler->context, handler);
	return handler;
}

static void cancel_matching(CertificateHandler* handler, CertificateImplSession* session,
							const char* reason, gboolean notify)
{
	if (handler == NULL)
		return;
	g_autoptr(GPtrArray) operations = g_ptr_array_new();
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, handler->operations);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		Operation* operation = value;
		if (session == NULL || operation->session == session)
			g_ptr_array_add(operations, operation);
	}
	for (guint i = 0; i < operations->len; i++)
		cancel_operation(g_ptr_array_index(operations, i), 2, reason,
						 notify ? XCC_CANCEL_SESSION_CLOSED : XCC_CANCEL_OWNER_GONE, notify);
}

void certificate_handler_owner_changed(CertificateHandler* handler)
{
	cancel_matching(handler, NULL, "owner_gone", FALSE);
}

void certificate_handler_session_closed(CertificateHandler* handler,
										CertificateImplSession* session, const char* reason)
{
	cancel_matching(handler, session, reason, TRUE);
}

void certificate_handler_session_invalidated(CertificateHandler* handler,
											 CertificateImplSession* session, const char* reason)
{
	certificate_handler_session_closed(handler, session, reason);
	if (session->handler_granted &&
		certificate_impl_find_session(handler->impl, session->id) == session)
		emit(handler, session->owner, "SessionInvalidated",
			 g_variant_new("(os)", session->id, reason));
}

void certificate_handler_set_chooser_timeout_for_tests(CertificateHandler* handler,
													   guint milliseconds)
{
	g_return_if_fail(milliseconds > 0);
	handler->chooser_timeout_ms = milliseconds;
}

void certificate_handler_free(CertificateHandler* handler)
{
	if (handler == NULL)
		return;
	certificate_impl_shutdown(handler->impl);
	certificate_impl_set_handler(handler->impl, NULL);
	if (handler->registration != 0)
		g_dbus_connection_unregister_object(handler->connection, handler->registration);
	certificate_step_provider_free(handler->provider);
	g_hash_table_unref(handler->operations);
	g_hash_table_unref(handler->core_ids);
	g_hash_table_unref(handler->tokens);
	g_mutex_clear(&handler->token_lock);
	g_object_unref(handler->connection);
	g_free(handler);
}
