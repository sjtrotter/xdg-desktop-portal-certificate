/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */

#include "fake-pin-provider.h"
#include "ui/pin-internal.h"

static void fake_show(gpointer user_data, PinPrompt* prompt)
{
	FakePinProvider* fake = user_data;

	g_assert_null(fake->prompt);
	fake->prompt = prompt;
	fake->shows++;
	fake->protected_path = prompt->protected_path;
	if (fake->protected_path)
		certificate_pin_prompt_submit(prompt);
}

static void fake_update(gpointer user_data, PinPrompt* prompt, const char* status)
{
	FakePinProvider* fake = user_data;

	g_assert_true(fake->prompt == prompt);
	fake->busy = prompt->busy;
	fake->count_low = prompt->token->pin_count_low;
	fake->final_try = prompt->token->pin_final_try;
	if (status != NULL)
	{
		fake->retries++;
		fake->status = status;
	}
	else
		fake->busy_updates++;
}

static void fake_warning(gpointer user_data, PinPrompt* prompt, const char* message)
{
	FakePinProvider* fake = user_data;

	g_assert_true(fake->prompt == prompt);
	g_assert_nonnull(message);
	fake->warnings++;
}

static void fake_hide(gpointer user_data, PinPrompt* prompt)
{
	FakePinProvider* fake = user_data;

	g_assert_true(fake->prompt == prompt);
	fake->hides++;
}

static void fake_close(gpointer user_data, PinPrompt* prompt)
{
	FakePinProvider* fake = user_data;

	/* Queued interactions may close before show. */
	if (fake->prompt == prompt)
		fake->prompt = NULL;
	fake->closes++;
}

void fake_pin_provider_init(FakePinProvider* fake)
{
	*fake = (FakePinProvider) {
		.provider = {
			.name = "fake",
			.user_data = fake,
			.pin_show = fake_show,
			.pin_update = fake_update,
			.warning = fake_warning,
			.hide = fake_hide,
			.close = fake_close,
		},
	};
}

void fake_pin_provider_submit(FakePinProvider* fake, const char* pin)
{
	g_assert_nonnull(fake->prompt);
	if (fake->protected_path)
		g_assert_null(pin);
	else if (!certificate_pin_prompt_hold(fake->prompt, pin))
		return;

	certificate_pin_prompt_submit(fake->prompt);
}

void fake_pin_provider_confirm(FakePinProvider* fake, gboolean accepted)
{
	g_assert_nonnull(fake->prompt);
	certificate_pin_prompt_warning_reply(fake->prompt, accepted);
}

void fake_pin_provider_cancel(FakePinProvider* fake)
{
	g_assert_nonnull(fake->prompt);
	certificate_pin_prompt_answer(fake->prompt, CERTIFICATE_PIN_CANCELLED);
}
