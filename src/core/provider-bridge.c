/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "context-private.h"
#include "pin-internal.h"
static CertificateChooserProvider old_chooser;
static CertificatePinProvider old_pin;
static XccContext* legacy_context;
static GHashTable* pins;
static PinPrompt* lookup(XccUiId id)
{
	return pins != NULL ? g_hash_table_lookup(pins, &id) : NULL;
}
static void chooser_show(void* c, XccUiId id, const XccChooserView* v)
{
	if (old_chooser.chooser_show != NULL)
		old_chooser.chooser_show(old_chooser.user_data, id, v);
	else
		xcc_ui_failed(c, id, XCC_ERROR_NO_DISPLAY);
}
static void chooser_update(void* c, XccUiId id, const XccChooserView* v)
{
	if (old_chooser.chooser_update != NULL)
		old_chooser.chooser_update(old_chooser.user_data, id, v);
}
static void pin_show(void* data, XccUiId id, const XccPinView* view)
{
	XccContext* c = data;
	g_atomic_int_inc(&c->ui_handles);
	PinPrompt* p = g_new0(PinPrompt, 1);
	p->refs = 1;
	p->coordinator = g_main_context_ref_thread_default();
	p->ui_context = xcc_context_ref(c);
	p->ui_id = id;
	p->provider = old_pin;
	p->token = g_new0(CertificateToken, 1);
	g_atomic_ref_count_init(&p->token->ref_count);
	p->token->label = g_strdup(view->token_label);
	p->token->reader_name = g_strdup(view->reader);
	p->token->pin_final_try = view->final_try;
	p->token->pin_count_low = view->count_low;
	p->token->pin_locked = view->locked;
	p->parent_window = g_strdup(view->parent_window);
	p->caller_display = g_strdup(view->caller_display);
	p->purpose_display = g_strdup(view->purpose_display);
	p->protected_path = view->protected_path;
	p->busy = view->busy;
	p->context_specific = view->context_specific;
	if (pins == NULL)
		pins = g_hash_table_new(g_int64_hash, g_int64_equal);
	g_hash_table_insert(pins, &p->ui_id, p);
	if (old_pin.pin_show != NULL)
		old_pin.pin_show(old_pin.user_data, p, view);
	else
		xcc_ui_failed(c, id, XCC_ERROR_DEVICE);
}
static void pin_update(void* c, XccUiId id, const XccPinView* v)
{
	PinPrompt* p = lookup(id);
	if (p == NULL)
		return;
	p->busy = v->busy;
	p->token->pin_final_try = v->final_try;
	p->token->pin_count_low = v->count_low;
	p->token->pin_locked = v->locked;
	if (old_pin.pin_update != NULL)
		old_pin.pin_update(old_pin.user_data, p, v);
}
static void warning(void* c, XccUiId id, const XccWarning* v)
{
	PinPrompt* p = lookup(id);
	if (p == NULL)
		return;
	p->warning_id = v->warning_id;
	if (old_pin.warning != NULL)
		old_pin.warning(old_pin.user_data, p, v->message);
}
static void hide(void* c, XccUiId id)
{
	PinPrompt* p = lookup(id);
	if (p && old_pin.hide != NULL)
		old_pin.hide(old_pin.user_data, p);
}
static void close_ui(void* c, XccUiId id)
{
	PinPrompt* p = lookup(id);
	if (p == NULL)
	{
		if (old_chooser.close != NULL)
			old_chooser.close(old_chooser.user_data, id);
		return;
	}
	p->finished = TRUE;
	if (old_pin.close != NULL)
		old_pin.close(old_pin.user_data, p);
	g_hash_table_remove(pins, &id);
	certificate_pin_prompt_unref(p);
	if (g_hash_table_size(pins) == 0)
		g_clear_pointer(&pins, g_hash_table_unref);
}
void xcc_ui_legacy_init(XccContext* c)
{
	old_chooser = *certificate_chooser_get_provider();
	old_pin = *certificate_pin_get_provider();
	legacy_context = c;
	c->ui = (XccUiV1){sizeof(XccUiV1),
					  XCC_ABI_VERSION,
					  (old_chooser.needs_display ? XCC_UI_CHOOSER_NEEDS_DISPLAY : 0) |
						  (old_pin.needs_display ? XCC_UI_PIN_NEEDS_DISPLAY : 0),
					  c,
					  chooser_show,
					  chooser_update,
					  pin_show,
					  pin_update,
					  warning,
					  hide,
					  close_ui};
}
void xcc_ui_legacy_restore(XccContext* c)
{
	if (legacy_context != c)
		return;

	legacy_context = NULL;
}
gboolean xcc_legacy_choose(XccUiId id, guint64 revision, guint64 candidate)
{
	XccContext* c = legacy_context;
	if (c == NULL || g_main_context_is_owner(c->coordinator))
		return FALSE;
	if (candidate != 0)
		xcc_choose(c, id, revision, candidate);
	else
		xcc_ui_cancel(c, id);
	return TRUE;
}
