/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* UI-local compatibility handles for the existing GTK/gcr providers. Policy and
 * workers live in the shared core; these helpers only forward typed UI replies. */
#include "legacy-bridge.h"
#include "../core/pin-internal.h"

static CertificateChooserProvider chooser_provider;
static CertificatePinProvider pin_provider;
static gboolean has_display;
static guint login_timeout = 60;

void certificate_chooser_set_provider(const CertificateChooserProvider* provider)
{
	chooser_provider = provider != NULL ? *provider : (CertificateChooserProvider){0};
}
const CertificateChooserProvider* certificate_chooser_get_provider(void)
{
	return &chooser_provider;
}
void certificate_pin_set_provider(const CertificatePinProvider* provider)
{
	pin_provider = provider != NULL ? *provider : (CertificatePinProvider){0};
}
const CertificatePinProvider* certificate_pin_get_provider(void)
{
	return &pin_provider;
}
void certificate_ui_set_has_display(gboolean value)
{
	has_display = value;
}
gboolean certificate_ui_has_display(void)
{
	return has_display;
}
void certificate_pin_set_login_timeout(guint seconds)
{
	login_timeout = seconds;
}
guint certificate_pin_login_timeout(void)
{
	return login_timeout;
}

PinPrompt* certificate_pin_prompt_ref(PinPrompt* prompt)
{
	g_atomic_int_inc(&prompt->refs);
	return prompt;
}
void certificate_pin_prompt_unref(PinPrompt* prompt)
{
	if (prompt == NULL || !g_atomic_int_dec_and_test(&prompt->refs))
		return;
	if (prompt->impl_data != NULL && prompt->impl_data_free != NULL)
		prompt->impl_data_free(prompt->impl_data);
	xcc_secret_free(prompt->secret);
	certificate_token_unref(prompt->token);
	g_free(prompt->session_id);
	g_free(prompt->parent_window);
	g_free(prompt->caller_display);
	g_free(prompt->purpose_display);
	g_clear_object(&prompt->cancellable);
	g_main_context_unref(prompt->coordinator);
	xcc_context_release_ui(prompt->ui_context);
	g_free(prompt);
}
void certificate_pin_prompt_answer(PinPrompt* prompt, CertificatePinOutcome outcome)
{
	if (prompt->finished)
		return;
	if (outcome == CERTIFICATE_PIN_CANCELLED)
		xcc_ui_cancel(prompt->ui_context, prompt->ui_id);
	else
		xcc_ui_failed(prompt->ui_context, prompt->ui_id,
		              outcome == CERTIFICATE_PIN_NO_DISPLAY ? XCC_ERROR_NO_DISPLAY
		                                                    : XCC_ERROR_DEVICE);
}
gboolean certificate_pin_prompt_hold(PinPrompt* prompt, XccSecret* secret, size_t length)
{
	if (prompt->finished || prompt->busy)
	{
		xcc_secret_free(secret);
		return FALSE;
	}
	g_clear_pointer(&prompt->secret, xcc_secret_free);
	if (secret == NULL || !xcc_secret_set_length(secret, length))
	{
		const char* status = secret == NULL ? "Could not allocate memory for the PIN."
							 : length == 0	? "Enter the PIN for this token."
											: "PIN exceeds the supported length.";
		XccPinView view = {.struct_size = sizeof(view),
						   .abi_version = XCC_ABI_VERSION,
						   .token_label = prompt->token->label,
						   .reader = prompt->token->reader_name,
						   .caller_display = prompt->caller_display,
						   .purpose_display = prompt->purpose_display,
						   .parent_window = prompt->parent_window,
						   .context_specific = prompt->context_specific,
						   .protected_path = prompt->protected_path,
						   .busy = prompt->busy,
						   .count_low = prompt->token->pin_count_low,
						   .final_try = prompt->token->pin_final_try,
						   .locked = prompt->token->pin_locked,
						   .status = status};
		xcc_secret_free(secret);
		prompt->provider.pin_update(prompt->provider.user_data, prompt, &view);
		return FALSE;
	}
	prompt->secret = secret;
	return TRUE;
}
void certificate_pin_prompt_ready(PinPrompt* prompt)
{
	if (!prompt->finished)
		xcc_pin_ready(prompt->ui_context, prompt->ui_id);
}
void certificate_pin_prompt_submit(PinPrompt* prompt)
{
	if (!prompt->finished && !prompt->busy)
		xcc_pin_submit(prompt->ui_context, prompt->ui_id, g_steal_pointer(&prompt->secret));
}
void certificate_pin_prompt_warning_reply(PinPrompt* prompt, gboolean accepted)
{
	if (!prompt->finished)
		xcc_warning_reply(prompt->ui_context, prompt->ui_id, prompt->warning_id, accepted);
}
