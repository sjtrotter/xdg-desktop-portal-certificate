/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pin-internal.h"

/* PKCS#11 exposes retry-state flags without a portable remaining-attempt count. */
const char* certificate_pin_prompt_retry_hint(const XccPinView* view)
{
	if (view->locked)
		return "This token is locked. It cannot be unlocked here.";
	if (view->final_try)
		return "This is the last attempt before the token locks.";
	if (view->count_low)
		return "There have been recent failed attempts on this token.";

	return NULL;
}

const char* certificate_pin_prompt_final_try_warning(void)
{
	return "Token will lock if this last attempt fails. Continue to enter the PIN on the reader, "
		   "or Cancel.";
}

const char* certificate_pin_prompt_heading(const PinPrompt* prompt)
{
	return prompt->protected_path ? "Enter your PIN on the reader"
								  : "Enter your PIN to unlock this token";
}

const char* certificate_pin_prompt_protected_note(void)
{
	return "This reader collects the PIN itself. Follow the instructions on the reader; "
		   "nothing typed on screen is sent to the token.";
}
