/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "context-private.h"
#include "pin-internal.h"
#include <string.h>

typedef struct
{
	XccUiId id;
	gboolean pin, shown, ready;
	/* ready_requested includes a queued acknowledgement. */
	gboolean ready_requested, pending, inactive, busy, protected_path, warning_pending;
	uint64_t revision;
	GArray* candidates;
	XccUiId chooser_id;
	PinPrompt* prompt;
	uint64_t warning_id;
} Interaction;
typedef enum
{
	CHOOSER_SHOW,
	CHOOSER_UPDATE,
	PIN_SHOW,
	PIN_UPDATE,
	WARNING,
	HIDE,
	CLOSE
} UiCall;
typedef struct
{
	XccContext* c;
	XccUiId id;
	UiCall call;
	XccChooserView chooser;
	XccPinView pin;
	XccWarning warning;
	GPtrArray* text;
	XccChooserCandidateView* rows;
} Message;
static const char* copy(Message* m, const char* text)
{
	char* result = g_strdup(text);
	g_ptr_array_add(m->text, result);
	return result;
}
static void ui_deliver(void* data)
{
	Message* m = data;
	XccUiV1* ui = &m->c->ui;
	switch (m->call)
	{
	case CHOOSER_SHOW:
		ui->chooser_show(ui->user, m->id, &m->chooser);
		break;
	case CHOOSER_UPDATE:
		ui->chooser_update(ui->user, m->id, &m->chooser);
		break;
	case PIN_SHOW:
		ui->pin_show(ui->user, m->id, &m->pin);
		break;
	case PIN_UPDATE:
		ui->pin_update(ui->user, m->id, &m->pin);
		break;
	case WARNING:
		ui->warning(ui->user, m->id, &m->warning);
		break;
	case HIDE:
		ui->hide(ui->user, m->id);
		break;
	case CLOSE:
		ui->close(ui->user, m->id);
		break;
	}
	g_ptr_array_unref(m->text);
	g_free(m->rows);
	g_atomic_int_add(&m->c->ui_pending, -1);
	xcc_context_unref(m->c);
	g_free(m);
}
static Message* message(XccContext* c, Interaction* i, UiCall call)
{
	Message* m = g_new0(Message, 1);
	m->c = xcc_context_ref(c);
	m->id = i->id;
	m->call = call;
	m->text = g_ptr_array_new_with_free_func(g_free);
	return m;
}
static void post(Message* m)
{
	g_atomic_int_inc(&m->c->ui_pending);
	m->c->dispatch.post(m->c->dispatch.user, ui_deliver, m);
}
static Interaction* interaction(XccContext* c, XccUiId chooser_id, PinPrompt* prompt,
								gboolean create)
{
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, c->interactions);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		Interaction* i = value;
		if ((prompt != NULL && i->pin && i->prompt == prompt) ||
			(prompt == NULL && !i->pin && i->chooser_id == chooser_id))
			return i;
	}
	if (!create)
		return NULL;
	Interaction* i = g_new0(Interaction, 1);
	i->id = ++c->next_ui_id;
	i->pin = prompt != NULL;
	i->chooser_id = chooser_id;
	i->prompt = prompt != NULL ? certificate_pin_prompt_ref(prompt) : NULL;
	g_hash_table_insert(c->interactions, &i->id, i);
	return i;
}
static void chooser_message(XccContext* c, XccUiId id, const XccChooserView* view, UiCall call)
{
	g_mutex_lock(&c->interactions_lock);
	Interaction* i = interaction(c, id, NULL, TRUE);
	i->revision = view->revision;
	if (i->candidates == NULL)
		i->candidates = g_array_new(FALSE, FALSE, sizeof(uint64_t));
	g_array_set_size(i->candidates, 0);
	for (gsize j = 0; j < view->n_candidates; j++)
	{
		uint64_t candidate = xcc_chooser_view_candidate(view, j)->id;
		g_array_append_val(i->candidates, candidate);
	}
	i->shown = TRUE;
	Message* m = message(c, i, call);
	m->chooser = *view;
	m->chooser.struct_size = sizeof(m->chooser);
#define COPY(field) m->chooser.field = copy(m, view->field)
	COPY(caller_name);
	COPY(app_id);
	COPY(identity_detail);
	COPY(purpose_text);
	COPY(purpose_detail);
	COPY(operation_scope);
	COPY(duration);
	COPY(later_prompt);
	COPY(reason_label);
	COPY(untrusted_reason);
	COPY(parent_window);
	COPY(activation_token);
	COPY(session_id);
	COPY(operation_id);
#undef COPY
	m->rows = g_new0(XccChooserCandidateView, view->n_candidates);
	for (gsize j = 0; j < view->n_candidates; j++)
	{
		const XccChooserCandidateView* row = xcc_chooser_view_candidate(view, j);
		m->rows[j] = *row;
		m->rows[j].struct_size = sizeof(m->rows[j]);
#define COPY(field) m->rows[j].field = copy(m, row->field)
		COPY(subject);
		COPY(issuer);
		COPY(token);
		COPY(reader);
		COPY(expiry);
		COPY(detail);
		COPY(fingerprint);
		COPY(key_type);
#undef COPY
	}
	m->chooser.candidates = m->rows;
	g_mutex_unlock(&c->interactions_lock);
	post(m);
}
static void chooser_show(void* c, XccUiId id, const XccChooserView* v)
{
	chooser_message(c, id, v, CHOOSER_SHOW);
}
static void chooser_update(void* c, XccUiId id, const XccChooserView* v)
{
	chooser_message(c, id, v, CHOOSER_UPDATE);
}
static void close_interaction(XccContext* c, Interaction* i)
{
	if (i == NULL)
		return;
	if (i->shown)
		post(message(c, i, CLOSE));
	g_hash_table_remove(c->interactions, &i->id);
	if (i->prompt != NULL)
		certificate_pin_prompt_unref(i->prompt);
	g_clear_pointer(&i->candidates, g_array_unref);
	g_free(i);
}
static void chooser_close(void* c, XccUiId id)
{
	XccContext* context = c;
	g_mutex_lock(&context->interactions_lock);
	close_interaction(c, interaction(c, id, NULL, FALSE));
	g_mutex_unlock(&context->interactions_lock);
}
static void pin_message(XccContext* c, PinPrompt* prompt, const XccPinView* view, UiCall call)
{
	g_mutex_lock(&c->interactions_lock);
	Interaction* i = interaction(c, 0, prompt, TRUE);
	i->busy = view->busy;
	i->protected_path = view->protected_path;
	if (!view->busy)
		i->pending = FALSE;
	i->shown = TRUE;
	Message* m = message(c, i, call);
	m->pin = *view;
	m->pin.struct_size = sizeof(m->pin);
#define COPY(field, cap, fallback)                                                                 \
	do                                                                                             \
	{                                                                                              \
		char* text = certificate_display_text(view->field, cap, fallback);                         \
		m->pin.field = copy(m, text);                                                              \
		g_free(text);                                                                              \
	} while (0)
	g_autofree char* token_label = certificate_display_text(view->token_label,
	    CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, NULL);
	if (token_label == NULL)
		m->pin.display_flags |= XCC_DISPLAY_TOKEN_FALLBACK;
	COPY(token_label, CERTIFICATE_DISPLAY_MAX_TOKEN_LABEL, "Unnamed token");
	COPY(reader, CERTIFICATE_DISPLAY_MAX_READER, NULL);
	COPY(caller_display, CERTIFICATE_DISPLAY_MAX_APP_NAME, NULL);
	COPY(purpose_display, CERTIFICATE_DISPLAY_MAX_PURPOSE, NULL);
#undef COPY
	m->pin.parent_window = copy(m, view->parent_window);
	m->pin.status = copy(m, view->status);
	m->pin.session_id = copy(m, view->session_id);
	m->pin.operation_id = copy(m, view->operation_id);
	g_mutex_unlock(&c->interactions_lock);
	post(m);
}
static void pin_show(void* c, PinPrompt* p, const XccPinView* v)
{
	pin_message(c, p, v, PIN_SHOW);
}
static void pin_update(void* c, PinPrompt* p, const XccPinView* v)
{
	pin_message(c, p, v, PIN_UPDATE);
}
static void warning(void* c, PinPrompt* p, const char* text)
{
	XccContext* context = c;
	g_mutex_lock(&context->interactions_lock);
	Interaction* i = interaction(c, 0, p, TRUE);
	i->warning_pending = TRUE;
	Message* m = message(c, i, WARNING);
	m->warning = (XccWarning){.struct_size = sizeof(XccWarning),
							 .abi_version = XCC_ABI_VERSION,
							 .code = XCC_WARNING_FINAL_TRY,
							 .warning_id = ++i->warning_id,
							 .message = copy(m, text)};
	g_mutex_unlock(&context->interactions_lock);
	post(m);
}
static void hide(void* data, PinPrompt* p)
{
	XccContext* c = data;
	g_mutex_lock(&c->interactions_lock);
	Interaction* i = interaction(c, 0, p, FALSE);
	if (i != NULL)
	{
		i->inactive = TRUE;
		if (i->shown)
			post(message(c, i, HIDE));
	}
	g_mutex_unlock(&c->interactions_lock);
}
static void pin_close(void* data, PinPrompt* p)
{
	XccContext* c = data;
	g_mutex_lock(&c->interactions_lock);
	close_interaction(c, interaction(c, 0, p, FALSE));
	g_mutex_unlock(&c->interactions_lock);
}

void xcc_ui_install(XccContext* c)
{
	CertificateChooserProvider chooser = {"dispatch",
										  (c->ui.capabilities & XCC_UI_CHOOSER_NEEDS_DISPLAY) != 0,
										  c,
										  chooser_show,
										  chooser_update,
										  chooser_close};
	CertificatePinProvider pin = {"dispatch", (c->ui.capabilities & XCC_UI_PIN_NEEDS_DISPLAY) != 0,
								  c,		  pin_show,
								  pin_update, warning,
								  hide,		  pin_close};
	certificate_ui_set_has_display(c->config.has_display);
	certificate_chooser_set_provider(&chooser);
	certificate_pin_set_provider(&pin);
}
void xcc_ui_uninstall(XccContext* c)
{
	xcc_ui_legacy_restore(c);
	certificate_chooser_set_provider(c->previous_chooser.chooser_show != NULL ? &c->previous_chooser
																			  : NULL);
	certificate_pin_set_provider(c->previous_pin.pin_show != NULL ? &c->previous_pin : NULL);
}
typedef struct
{
	XccContext* c;
	XccUiId id;
	uint64_t revision, candidate, warning;
	gboolean accepted;
	XccSecret* secret;
	XccErrorCode error;
	int kind;
} Reply;
static gboolean pin_live(Interaction* i)
{
	return i->pin && !i->prompt->finished && !i->prompt->cancel_deferred &&
		!g_cancellable_is_cancelled(i->prompt->cancellable);
}
static XccUiReply apply_reply(Reply* r)
{
	Interaction* i = g_hash_table_lookup(r->c->interactions, &r->id);
	if (i == NULL)
		return XCC_UI_REPLY_STALE;
	if (r->kind == 0 && !i->pin)
		return certificate_chooser_reply(i->chooser_id, r->revision, r->candidate);
	if (r->kind == 1 && pin_live(i) && !i->prompt->busy &&
		!i->prompt->login_in_flight && !i->prompt->warning_pending && i->ready)
	{
		PinPrompt* p = i->prompt;
		if (p->protected_path)
		{
			xcc_secret_free(g_steal_pointer(&r->secret));
			certificate_pin_prompt_submit(p);
			return XCC_UI_REPLY_ACCEPTED;
		}
		if (r->secret != NULL)
		{
			size_t length = xcc_secret_length(r->secret);
			if (certificate_pin_prompt_hold(p, g_steal_pointer(&r->secret), length))
			{
				certificate_pin_prompt_submit(p);
				return XCC_UI_REPLY_ACCEPTED;
			}
		}
	}
	else if (r->kind == 2 && pin_live(i) && r->warning == i->warning_id &&
			 !i->prompt->busy && !i->prompt->login_in_flight && i->prompt->warning_pending)
	{
		certificate_pin_prompt_warning_reply(i->prompt, r->accepted);
		return XCC_UI_REPLY_ACCEPTED;
	}
	else if (r->kind == 5 && pin_live(i) && !i->ready)
	{
		i->ready = TRUE;
		if (i->prompt->protected_path)
			certificate_pin_prompt_submit(i->prompt);
		return XCC_UI_REPLY_ACCEPTED;
	}
	else if (r->kind == 3 || r->kind == 4)
	{
		if (i->pin)
			certificate_pin_prompt_answer(i->prompt, r->kind == 3
														 ? CERTIFICATE_PIN_CANCELLED
														 : r->error == XCC_ERROR_NO_DISPLAY
														 ? CERTIFICATE_PIN_NO_DISPLAY
														 : CERTIFICATE_PIN_DEVICE_ERROR);
		else if (r->kind == 4)
			certificate_chooser_fail(i->chooser_id,
									 r->error != XCC_OK ? r->error : XCC_ERROR_DEVICE);
		else
			certificate_chooser_cancel(i->chooser_id);
		return XCC_UI_REPLY_ACCEPTED;
	}
	return XCC_UI_REPLY_STALE;
}
static void free_reply(Reply* r)
{
	xcc_secret_free(r->secret);
	xcc_context_unref(r->c);
	g_free(r);
}
static void reply(void* data)
{
	Reply* r = data;
	XccUiReply result = apply_reply(r);
	if (result == XCC_UI_REPLY_STALE && r->kind <= 2)
	{
		g_mutex_lock(&r->c->interactions_lock);
		Interaction* i = g_hash_table_lookup(r->c->interactions, &r->id);
		if (i != NULL)
			i->pending = FALSE;
		g_mutex_unlock(&r->c->interactions_lock);
	}
	free_reply(r);
}
static XccUiReply send_reply_checked(Reply* r)
{
	XccContext* c = r->c;
	if (g_main_context_is_owner(c->coordinator))
	{
		XccUiReply result = apply_reply(r);
		free_reply(r);
		return result;
	}
	gboolean valid = FALSE;
	g_mutex_lock(&c->interactions_lock);
	Interaction* i = g_hash_table_lookup(c->interactions, &r->id);
	if (i != NULL && !i->inactive &&
	    (i->prompt == NULL || !g_cancellable_is_cancelled(i->prompt->cancellable)))
	{
		if (r->kind == 0 && !i->pin && !i->pending && r->revision == i->revision)
		{
			for (guint j = 0; j < i->candidates->len; j++)
				if (g_array_index(i->candidates, uint64_t, j) == r->candidate)
					valid = TRUE;
		}
		else if (r->kind == 5 && i->pin && !i->ready_requested)
		{
			valid = TRUE;
			i->ready_requested = TRUE;
			if (i->protected_path)
				i->pending = TRUE;
		}
		else if (r->kind == 1 && i->pin && i->ready_requested && !i->pending &&
		         !i->busy && !i->warning_pending && (i->protected_path || r->secret != NULL))
			valid = TRUE;
		else if (r->kind == 2 && i->pin && !i->busy && i->warning_pending &&
		         r->warning == i->warning_id)
		{
			valid = TRUE;
			i->warning_pending = FALSE;
		}
		if (valid && r->kind != 5)
			i->pending = TRUE;
	}
	g_mutex_unlock(&c->interactions_lock);
	if (valid && xcc_context_post(c, reply, r))
		return XCC_UI_REPLY_ACCEPTED_PENDING;
	free_reply(r);
	return XCC_UI_REPLY_STALE;
}
static void send_reply(Reply* r)
{
	if (!xcc_context_post(r->c, reply, r))
	{
		xcc_secret_free(r->secret);
		xcc_context_unref(r->c);
		g_free(r);
	}
}
static Reply* make_reply(XccContext* c, XccUiId id, int kind)
{
	Reply* r = g_new0(Reply, 1);
	r->c = xcc_context_ref(c);
	r->id = id;
	r->kind = kind;
	return r;
}
XccUiReply xcc_choose(XccContext* c, XccUiId id, uint64_t revision, uint64_t candidate)
{
	if (g_atomic_int_get(&c->stopping))
		return XCC_UI_REPLY_STALE;
	Reply* r = make_reply(c, id, 0);
	r->revision = revision;
	r->candidate = candidate;
	return send_reply_checked(r);
}
XccUiReply xcc_pin_ready(XccContext* c, XccUiId id)
{
	if (g_atomic_int_get(&c->stopping))
		return XCC_UI_REPLY_STALE;
	return send_reply_checked(make_reply(c, id, 5));
}
XccUiReply xcc_pin_submit(XccContext* c, XccUiId id, XccSecret* secret)
{
	if (g_atomic_int_get(&c->stopping))
	{
		xcc_secret_free(secret);
		return XCC_UI_REPLY_STALE;
	}
	Reply* r = make_reply(c, id, 1);
	r->secret = secret;
	return send_reply_checked(r);
}
XccUiReply xcc_warning_reply(XccContext* c, XccUiId id, uint64_t warning, bool accepted)
{
	if (g_atomic_int_get(&c->stopping))
		return XCC_UI_REPLY_STALE;
	Reply* r = make_reply(c, id, 2);
	r->warning = warning;
	r->accepted = accepted;
	return send_reply_checked(r);
}
void xcc_ui_cancel(XccContext* c, XccUiId id)
{
	if (g_atomic_int_get(&c->stopping))
		return;
	send_reply(make_reply(c, id, 3));
}
void xcc_ui_failed(XccContext* c, XccUiId id, XccErrorCode error)
{
	if (g_atomic_int_get(&c->stopping))
		return;
	Reply* r = make_reply(c, id, 4);
	r->error = error;
	send_reply(r);
}
