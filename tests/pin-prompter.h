/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_TESTS_PIN_PROMPTER_H
#define CERTIFICATE_TESTS_PIN_PROMPTER_H

#include <gio/gio.h>
#include <glib.h>

/* Use a private-bus scripted prompter; never drive the user's system prompter. */

typedef struct _CertificateTestPrompter CertificateTestPrompter;

CertificateTestPrompter* certificate_test_prompter_start(GDBusConnection* connection,
                                                         const char* bus_name);
void certificate_test_prompter_stop(CertificateTestPrompter* prompter);

void certificate_test_prompter_reset(void);

void certificate_test_prompter_expect_password(const char* password);

void certificate_test_prompter_expect_confirm(gboolean ok);

/* NULL disables automatic answers; count assertions require an explicit script. */
void certificate_test_prompter_set_default_password(const char* password);

/* Simulate shell dismissal even after PIN submission, when no round is pending. */
void certificate_test_prompter_dismiss(void);

/* Drop only the bus name to simulate a crash; stop() is still required for cleanup. */
void certificate_test_prompter_vanish(CertificateTestPrompter* prompter);

/* Delay replies to exercise asynchronous completion. */
void certificate_test_prompter_set_delay(guint msec);

/* Caller owns the returned string; NULL means unset. */
char* certificate_test_prompter_last_title(void);
char* certificate_test_prompter_last_message(void);
char* certificate_test_prompter_last_description(void);
char* certificate_test_prompter_last_warning(void);
char* certificate_test_prompter_last_choice_label(void);
char* certificate_test_prompter_last_continue_label(void);
char* certificate_test_prompter_last_caller_window(void);
gboolean certificate_test_prompter_last_password_new(void);

guint certificate_test_prompter_password_rounds(void);
guint certificate_test_prompter_confirm_rounds(void);
guint certificate_test_prompter_prompts_created(void);
guint certificate_test_prompter_closes(void);

/* Hold gcr protocol replies to reproduce duplicate completion; no PIN is collected. */
typedef struct _CertificateTestStallingPrompter CertificateTestStallingPrompter;

/* FALSE withholds PromptReady and leaves open pending. */
CertificateTestStallingPrompter*
certificate_test_stalling_prompter_start(GDBusConnection* connection, const char* bus_name,
                                         gboolean send_ready);
void certificate_test_stalling_prompter_stop(CertificateTestStallingPrompter* prompter);

gboolean certificate_test_stalling_prompter_is_performing(CertificateTestStallingPrompter* self);

void certificate_test_stalling_prompter_fail_perform(CertificateTestStallingPrompter* self);

void certificate_test_stalling_prompter_vanish(CertificateTestStallingPrompter* self);

#endif
