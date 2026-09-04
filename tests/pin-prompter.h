/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_TESTS_PIN_PROMPTER_H
#define CERTIFICATE_TESTS_PIN_PROMPTER_H

#include <gio/gio.h>
#include <glib.h>

/** @file
 *  A SYSTEM PROMPTER THAT NOBODY HAS TO TYPE INTO.
 *
 *  src/ui/pin-system.c hands the PIN field to whatever owns
 *  org.gnome.keyring.SystemPrompter. On a real session that is gnome-shell,
 *  which cannot be driven from a test and must never be driven from one: the
 *  operator's own shell is not a fixture. gcr ships the server half of the
 *  protocol as GcrSystemPrompter, so this stands one up on a PRIVATE bus, owns
 *  the same well-known name there, and answers with a scripted PIN.
 *
 *  That is what makes the retry, warning and final-try logic testable at all:
 *  the answers are a queue, so "wrong PIN, then the right one" is three lines
 *  rather than a person.
 *
 *  THE SCRIPT IS PROCESS-WIDE, because GcrSystemPrompter instantiates the
 *  prompt type itself and there is nowhere to hang per-instance state.
 *
 *  Used by tests/test-pin-system.c in-process, and by
 *  tests/certificate-test-prompter (a main() around the same code) so that
 *  tools/ui-smoke.sh can run the whole stack against the system-prompter path
 *  on its private bus.
 */

/** Own @bus_name on @connection and serve prompts on it. @bus_name is
 *  normally "org.gnome.keyring.SystemPrompter" -- the name src/ui/pin-system.c
 *  looks for, which on a private bus is free. Returns an opaque handle to pass
 *  to certificate_test_prompter_stop(). */
typedef struct _CertificateTestPrompter CertificateTestPrompter;

CertificateTestPrompter* certificate_test_prompter_start(GDBusConnection* connection,
                                                         const char* bus_name);
void certificate_test_prompter_stop(CertificateTestPrompter* prompter);

/** Empty the script and the record of what was seen. */
void certificate_test_prompter_reset(void);

/** Queue an answer to the next password round. @password NULL means the user
 *  pressed Cancel. */
void certificate_test_prompter_expect_password(const char* password);

/** Queue an answer to the next confirmation round. */
void certificate_test_prompter_expect_confirm(gboolean ok);

/** With an empty script, answer every password round with @password and every
 *  confirmation with Continue. That is what the ui-smoke helper wants and what
 *  a test asserting on counts must NOT have. NULL turns it off. */
void certificate_test_prompter_set_default_password(const char* password);

/** How long the prompter takes to answer, in milliseconds. Non-zero by
 *  default: an answer that arrives before the caller has returned from
 *  gcr_prompt_password_async() would not exercise anything. */
void certificate_test_prompter_set_delay(guint msec);

/** What the last round was shown. Freshly allocated; NULL when unset. */
char* certificate_test_prompter_last_title(void);
char* certificate_test_prompter_last_message(void);
char* certificate_test_prompter_last_description(void);
char* certificate_test_prompter_last_warning(void);
char* certificate_test_prompter_last_choice_label(void);
char* certificate_test_prompter_last_continue_label(void);
char* certificate_test_prompter_last_caller_window(void);
gboolean certificate_test_prompter_last_password_new(void);

/** Round counters, which is how "one prompt, three attempts" is told apart
 *  from "three prompts". */
guint certificate_test_prompter_password_rounds(void);
guint certificate_test_prompter_confirm_rounds(void);
guint certificate_test_prompter_prompts_created(void);
guint certificate_test_prompter_closes(void);

#endif /* CERTIFICATE_TESTS_PIN_PROMPTER_H */
