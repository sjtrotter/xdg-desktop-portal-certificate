/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "context-private.h"
#include "pin-internal.h"
#include <string.h>

typedef struct
{
	XccUiId id;
	gboolean pin, shown, ready;
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
	Interaction* i = interaction(c, id, NULL, TRUE);
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
	g_free(i);
}
static void chooser_close(void* c, XccUiId id)
{
	close_interaction(c, interaction(c, id, NULL, FALSE));
}
static void pin_message(XccContext* c, PinPrompt* prompt, const XccPinView* view, UiCall call)
{
	Interaction* i = interaction(c, 0, prompt, TRUE);
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
	Interaction* i = interaction(c, 0, p, TRUE);
	Message* m = message(c, i, WARNING);
	m->warning = (XccWarning){.struct_size = sizeof(XccWarning),
							 .abi_version = XCC_ABI_VERSION,
							 .code = XCC_WARNING_FINAL_TRY,
							 .warning_id = ++i->warning_id,
							 .message = copy(m, text)};
	post(m);
}
static void hide(void* c, PinPrompt* p)
{
	Interaction* i = interaction(c, 0, p, FALSE);
	if (i != NULL && i->shown)
		post(message(c, i, HIDE));
}
static void pin_close(void* c, PinPrompt* p)
{
	close_interaction(c, interaction(c, 0, p, FALSE));
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
static void reply(void* data)
{
	Reply* r = data;
	Interaction* i = g_hash_table_lookup(r->c->interactions, &r->id);
	if (i != NULL)
	{
		if (r->kind == 0 && !i->pin)
			certificate_chooser_choose(i->chooser_id, r->revision, r->candidate);
		else if (r->kind == 1 && i->pin && !i->prompt->finished && !i->prompt->cancel_deferred &&
				 !i->prompt->busy && !i->prompt->login_in_flight && i->ready)
		{
			PinPrompt* p = i->prompt;
			if (p->protected_path)
			{
				xcc_secret_free(g_steal_pointer(&r->secret));
				certificate_pin_prompt_submit(p);
			}
			else if (r->secret != NULL)
			{
				size_t length = xcc_secret_length(r->secret);
				if (certificate_pin_prompt_hold(p, g_steal_pointer(&r->secret), length))
					certificate_pin_prompt_submit(p);
			}
		}
		else if (r->kind == 2 && i->pin && r->warning == i->warning_id &&
				 i->prompt->warning_pending)
			certificate_pin_prompt_warning_reply(i->prompt, r->accepted);
		else if (r->kind == 5 && i->pin && !i->ready && !i->prompt->finished &&
				 !g_cancellable_is_cancelled(i->prompt->cancellable))
		{
			i->ready = TRUE;
			if (i->prompt->protected_path)
				certificate_pin_prompt_submit(i->prompt);
		}
		else if (r->kind == 3 || r->kind == 4)
		{
			if (i->pin)
				certificate_pin_prompt_answer(i->prompt, r->kind == 3
															 ? CERTIFICATE_PIN_CANCELLED
															 : CERTIFICATE_PIN_DEVICE_ERROR);
			else if (r->kind == 4)
				certificate_chooser_fail(i->chooser_id,
										 r->error != XCC_OK ? r->error : XCC_ERROR_DEVICE);
			else
				certificate_chooser_cancel(i->chooser_id);
		}
	}
	xcc_secret_free(r->secret);
	xcc_context_unref(r->c);
	g_free(r);
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
void xcc_choose(XccContext* c, XccUiId id, uint64_t revision, uint64_t candidate)
{
	if (g_atomic_int_get(&c->stopping))
		return;
	Reply* r = make_reply(c, id, 0);
	r->revision = revision;
	r->candidate = candidate;
	send_reply(r);
}
void xcc_pin_ready(XccContext* c, XccUiId id)
{
	if (!g_atomic_int_get(&c->stopping))
		send_reply(make_reply(c, id, 5));
}
void xcc_pin_submit(XccContext* c, XccUiId id, XccSecret* secret)
{
	if (g_atomic_int_get(&c->stopping))
	{
		xcc_secret_free(secret);
		return;
	}
	Reply* r = make_reply(c, id, 1);
	r->secret = secret;
	send_reply(r);
}
void xcc_warning_reply(XccContext* c, XccUiId id, uint64_t warning, bool accepted)
{
	if (g_atomic_int_get(&c->stopping))
		return;
	Reply* r = make_reply(c, id, 2);
	r->warning = warning;
	r->accepted = accepted;
	send_reply(r);
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
