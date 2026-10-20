/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "core/context-private.h"
#include "core/pin-internal.h"

/* Capture replies from each bridge's compatibility entry point. */
static XccContext* reply_context;
static XccUiId reply_id;
static XccErrorCode reply_error;
static guint replies;

void __wrap_xcc_ui_failed(XccContext*, XccUiId, XccErrorCode);
void __wrap_xcc_ui_cancel(XccContext*, XccUiId);

void __wrap_xcc_ui_failed(XccContext* context, XccUiId id, XccErrorCode error)
{
	reply_context = context;
	reply_id = id;
	reply_error = error;
	replies++;
}

void __wrap_xcc_ui_cancel(XccContext* context, XccUiId id)
{
	__wrap_xcc_ui_failed(context, id, XCC_ERROR_CANCELLED);
}

typedef struct
{
	const char* name;
	CertificatePinOutcome outcome;
	XccErrorCode error;
} Failure;

static void test_answer(gconstpointer data)
{
	const Failure* failure = data;
	XccContext context = {0};
	PinPrompt prompt = {.ui_context = &context, .ui_id = 42};

	reply_context = NULL;
	reply_id = 0;
	reply_error = XCC_OK;
	replies = 0;
	certificate_pin_prompt_answer(&prompt, failure->outcome);
	g_assert_cmpuint(replies, ==, 1);
	g_assert_true(reply_context == &context);
	g_assert_cmpuint(reply_id, ==, prompt.ui_id);
	g_assert_cmpint(reply_error, ==, failure->error);

	prompt.finished = TRUE;
	certificate_pin_prompt_answer(&prompt, failure->outcome);
	g_assert_cmpuint(replies, ==, 1);
}

int main(int argc, char** argv)
{
	static const Failure failures[] = {
		{"no-display", CERTIFICATE_PIN_NO_DISPLAY, XCC_ERROR_NO_DISPLAY},
		{"cancelled", CERTIFICATE_PIN_CANCELLED, XCC_ERROR_CANCELLED},
		{"device-error", CERTIFICATE_PIN_DEVICE_ERROR, XCC_ERROR_DEVICE},
		{"timed-out", CERTIFICATE_PIN_TIMED_OUT, XCC_ERROR_DEVICE},
	};

	g_test_init(&argc, &argv, NULL);
	for (guint i = 0; i < G_N_ELEMENTS(failures); i++)
	{
		g_autofree char* path = g_strdup_printf("/pin-bridge/%s", failures[i].name);
		g_test_add_data_func(path, &failures[i], test_answer);
	}
	return g_test_run();
}
