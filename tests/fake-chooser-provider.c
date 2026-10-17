/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */

#include "fake-chooser-provider.h"

static const char* copy_text(FakeChooserProvider* fake, const char* text)
{
	char* copy = g_strdup(text);

	g_ptr_array_add(fake->text, copy);
	return copy;
}

static void snapshot(FakeChooserProvider* fake, const XccChooserView* view)
{
	g_clear_pointer(&fake->candidates, g_free);
	g_ptr_array_set_size(fake->text, 0);
	fake->view = *view;
#define COPY(field) fake->view.field = copy_text(fake, view->field)
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
	fake->candidates = g_new0(XccChooserCandidateView, view->n_candidates);
	for (gsize i = 0; i < view->n_candidates; i++)
	{
		fake->candidates[i] = view->candidates[i];
#define COPY(field) fake->candidates[i].field = copy_text(fake, view->candidates[i].field)
		COPY(subject);
		COPY(issuer);
		COPY(token);
		COPY(reader);
		COPY(expiry);
		COPY(detail);
		COPY(fingerprint);
#undef COPY
	}
	fake->view.candidates = fake->candidates;
}

static void fake_show(gpointer user_data, XccUiId id, const XccChooserView* view)
{
	FakeChooserProvider* fake = user_data;

	g_assert_cmpuint(fake->id, ==, 0);
	fake->id = id;
	fake->shows++;
	snapshot(fake, view);
	if (fake->cancel_on_show)
		xcc_ui_cancel(id);
}

static void fake_update(gpointer user_data, XccUiId id, const XccChooserView* view)
{
	FakeChooserProvider* fake = user_data;

	g_assert_cmpuint(fake->id, ==, id);
	g_assert_cmpuint(view->revision, >, fake->view.revision);
	fake->updates++;
	snapshot(fake, view);
}

static void fake_close(gpointer user_data, XccUiId id)
{
	FakeChooserProvider* fake = user_data;

	g_assert_cmpuint(fake->id, ==, id);
	fake->id = 0;
	fake->closes++;
}

void fake_chooser_provider_init(FakeChooserProvider* fake)
{
	*fake = (FakeChooserProvider) {
		.provider = {
			.name = "fake",
			.user_data = fake,
			.chooser_show = fake_show,
			.chooser_update = fake_update,
			.close = fake_close,
		},
		.text = g_ptr_array_new_with_free_func(g_free),
	};
}

void fake_chooser_provider_clear(FakeChooserProvider* fake)
{
	g_assert_cmpuint(fake->id, ==, 0);
	g_clear_pointer(&fake->candidates, g_free);
	g_clear_pointer(&fake->text, g_ptr_array_unref);
}

void fake_chooser_provider_choose(FakeChooserProvider* fake, gsize index)
{
	g_assert_cmpuint(fake->id, !=, 0);
	g_assert_cmpuint(index, <, fake->view.n_candidates);
	xcc_choose(fake->id, fake->view.revision, fake->view.candidates[index].id);
}

void fake_chooser_provider_cancel(FakeChooserProvider* fake)
{
	g_assert_cmpuint(fake->id, !=, 0);
	xcc_ui_cancel(fake->id);
}
