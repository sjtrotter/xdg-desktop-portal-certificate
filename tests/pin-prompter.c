/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 *
 * The server half of the system-prompt protocol, scripted. See pin-prompter.h.
 */

#define GCR_API_SUBJECT_TO_CHANGE 1

#include "pin-prompter.h"

#include <gcr/gcr.h>

/* ---------------------------------------------------------------- the script */

typedef enum
{
	ROUND_PASSWORD,
	ROUND_CONFIRM
} RoundKind;

typedef struct
{
	RoundKind kind;
	char* password; /* ROUND_PASSWORD; NULL means "cancelled" */
	gboolean ok;    /* ROUND_CONFIRM */
} ScriptedRound;

static GQueue script = G_QUEUE_INIT;
static char* default_password = NULL;
static guint answer_delay_msec = 40;

static char* seen_title = NULL;
static char* seen_message = NULL;
static char* seen_description = NULL;
static char* seen_warning = NULL;
static char* seen_choice_label = NULL;
static char* seen_continue_label = NULL;
static char* seen_caller_window = NULL;
static gboolean seen_password_new = FALSE;

static guint password_rounds = 0;
static guint confirm_rounds = 0;
static guint prompts_created = 0;
static guint prompt_closes = 0;

static void scripted_round_free(gpointer data)
{
	ScriptedRound* round = data;

	g_free(round->password);
	g_free(round);
}

void certificate_test_prompter_reset(void)
{
	ScriptedRound* round = NULL;

	while ((round = g_queue_pop_head(&script)) != NULL)
		scripted_round_free(round);

	g_clear_pointer(&seen_title, g_free);
	g_clear_pointer(&seen_message, g_free);
	g_clear_pointer(&seen_description, g_free);
	g_clear_pointer(&seen_warning, g_free);
	g_clear_pointer(&seen_choice_label, g_free);
	g_clear_pointer(&seen_continue_label, g_free);
	g_clear_pointer(&seen_caller_window, g_free);
	seen_password_new = FALSE;

	password_rounds = 0;
	confirm_rounds = 0;
	prompts_created = 0;
	prompt_closes = 0;
}

void certificate_test_prompter_expect_password(const char* password)
{
	ScriptedRound* round = g_new0(ScriptedRound, 1);

	round->kind = ROUND_PASSWORD;
	round->password = g_strdup(password);
	g_queue_push_tail(&script, round);
}

void certificate_test_prompter_expect_confirm(gboolean ok)
{
	ScriptedRound* round = g_new0(ScriptedRound, 1);

	round->kind = ROUND_CONFIRM;
	round->ok = ok;
	g_queue_push_tail(&script, round);
}

void certificate_test_prompter_set_default_password(const char* password)
{
	g_free(default_password);
	default_password = g_strdup(password);
}

void certificate_test_prompter_set_delay(guint msec)
{
	answer_delay_msec = msec;
}

char* certificate_test_prompter_last_title(void)
{
	return g_strdup(seen_title);
}
char* certificate_test_prompter_last_message(void)
{
	return g_strdup(seen_message);
}
char* certificate_test_prompter_last_description(void)
{
	return g_strdup(seen_description);
}
char* certificate_test_prompter_last_warning(void)
{
	return g_strdup(seen_warning);
}
char* certificate_test_prompter_last_choice_label(void)
{
	return g_strdup(seen_choice_label);
}
char* certificate_test_prompter_last_continue_label(void)
{
	return g_strdup(seen_continue_label);
}
char* certificate_test_prompter_last_caller_window(void)
{
	return g_strdup(seen_caller_window);
}
gboolean certificate_test_prompter_last_password_new(void)
{
	return seen_password_new;
}
guint certificate_test_prompter_password_rounds(void)
{
	return password_rounds;
}
guint certificate_test_prompter_confirm_rounds(void)
{
	return confirm_rounds;
}
guint certificate_test_prompter_prompts_created(void)
{
	return prompts_created;
}
guint certificate_test_prompter_closes(void)
{
	return prompt_closes;
}

/* ----------------------------------------------------------------- the prompt */

#define TEST_TYPE_PROMPT (test_prompt_get_type())
G_DECLARE_FINAL_TYPE(TestPrompt, test_prompt, TEST, PROMPT, GObject)

struct _TestPrompt
{
	GObject parent;

	char* title;
	char* message;
	char* description;
	char* warning;
	char* choice_label;
	char* continue_label;
	char* cancel_label;
	char* caller_window;
	gboolean choice_chosen;
	gboolean password_new;

	/* The answer to the round in flight. gcr_prompt_password_finish() returns a
	 * borrowed string owned by the prompt, so it lives here and is replaced --
	 * not appended to -- on the next round. */
	char* answer;

	GTask* pending;
	gboolean pending_is_password;
	guint pending_source;
	gboolean closed;
};

static void test_prompt_iface_init(GcrPromptInterface* iface);

G_DEFINE_TYPE_WITH_CODE(TestPrompt, test_prompt, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(GCR_TYPE_PROMPT, test_prompt_iface_init))

enum
{
	PROP_0,
	PROP_TITLE,
	PROP_MESSAGE,
	PROP_DESCRIPTION,
	PROP_WARNING,
	PROP_PASSWORD_NEW,
	PROP_PASSWORD_STRENGTH,
	PROP_CHOICE_LABEL,
	PROP_CHOICE_CHOSEN,
	PROP_CALLER_WINDOW,
	PROP_CONTINUE_LABEL,
	PROP_CANCEL_LABEL
};

static void test_prompt_init(TestPrompt* self)
{
	prompts_created++;
}

static void test_prompt_finalize(GObject* object)
{
	TestPrompt* self = TEST_PROMPT(object);

	if (self->pending_source != 0)
		g_source_remove(self->pending_source);
	g_clear_object(&self->pending);

	g_free(self->title);
	g_free(self->message);
	g_free(self->description);
	g_free(self->warning);
	g_free(self->choice_label);
	g_free(self->continue_label);
	g_free(self->cancel_label);
	g_free(self->caller_window);
	g_free(self->answer);

	G_OBJECT_CLASS(test_prompt_parent_class)->finalize(object);
}

static void test_prompt_set_property(GObject* object, guint id, const GValue* value,
                                     GParamSpec* spec)
{
	TestPrompt* self = TEST_PROMPT(object);

	switch (id)
	{
		case PROP_TITLE:
			g_free(self->title);
			self->title = g_value_dup_string(value);
			break;
		case PROP_MESSAGE:
			g_free(self->message);
			self->message = g_value_dup_string(value);
			break;
		case PROP_DESCRIPTION:
			g_free(self->description);
			self->description = g_value_dup_string(value);
			break;
		case PROP_WARNING:
			g_free(self->warning);
			self->warning = g_value_dup_string(value);
			break;
		case PROP_CHOICE_LABEL:
			g_free(self->choice_label);
			self->choice_label = g_value_dup_string(value);
			break;
		case PROP_CONTINUE_LABEL:
			g_free(self->continue_label);
			self->continue_label = g_value_dup_string(value);
			break;
		case PROP_CANCEL_LABEL:
			g_free(self->cancel_label);
			self->cancel_label = g_value_dup_string(value);
			break;
		case PROP_CALLER_WINDOW:
			g_free(self->caller_window);
			self->caller_window = g_value_dup_string(value);
			break;
		case PROP_CHOICE_CHOSEN:
			self->choice_chosen = g_value_get_boolean(value);
			break;
		case PROP_PASSWORD_NEW:
			self->password_new = g_value_get_boolean(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, spec);
			break;
	}
}

static void test_prompt_get_property(GObject* object, guint id, GValue* value, GParamSpec* spec)
{
	TestPrompt* self = TEST_PROMPT(object);

	switch (id)
	{
		case PROP_TITLE:
			g_value_set_string(value, self->title);
			break;
		case PROP_MESSAGE:
			g_value_set_string(value, self->message);
			break;
		case PROP_DESCRIPTION:
			g_value_set_string(value, self->description);
			break;
		case PROP_WARNING:
			g_value_set_string(value, self->warning);
			break;
		case PROP_CHOICE_LABEL:
			g_value_set_string(value, self->choice_label);
			break;
		case PROP_CONTINUE_LABEL:
			g_value_set_string(value, self->continue_label);
			break;
		case PROP_CANCEL_LABEL:
			g_value_set_string(value, self->cancel_label);
			break;
		case PROP_CALLER_WINDOW:
			g_value_set_string(value, self->caller_window);
			break;
		case PROP_CHOICE_CHOSEN:
			g_value_set_boolean(value, self->choice_chosen);
			break;
		case PROP_PASSWORD_NEW:
			g_value_set_boolean(value, self->password_new);
			break;
		case PROP_PASSWORD_STRENGTH:
			g_value_set_int(value, 0);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, spec);
			break;
	}
}

static void test_prompt_class_init(TestPromptClass* klass)
{
	GObjectClass* object_class = G_OBJECT_CLASS(klass);

	object_class->finalize = test_prompt_finalize;
	object_class->set_property = test_prompt_set_property;
	object_class->get_property = test_prompt_get_property;

	/* Every property GcrPrompt defines, overridden. An implementation that
	 * misses one warns at run time and the prompter stops working, so they are
	 * listed rather than looped over. */
	g_object_class_override_property(object_class, PROP_TITLE, "title");
	g_object_class_override_property(object_class, PROP_MESSAGE, "message");
	g_object_class_override_property(object_class, PROP_DESCRIPTION, "description");
	g_object_class_override_property(object_class, PROP_WARNING, "warning");
	g_object_class_override_property(object_class, PROP_PASSWORD_NEW, "password-new");
	g_object_class_override_property(object_class, PROP_PASSWORD_STRENGTH, "password-strength");
	g_object_class_override_property(object_class, PROP_CHOICE_LABEL, "choice-label");
	g_object_class_override_property(object_class, PROP_CHOICE_CHOSEN, "choice-chosen");
	g_object_class_override_property(object_class, PROP_CALLER_WINDOW, "caller-window");
	g_object_class_override_property(object_class, PROP_CONTINUE_LABEL, "continue-label");
	g_object_class_override_property(object_class, PROP_CANCEL_LABEL, "cancel-label");
}

/* What the prompt was showing when this round was asked for. Recorded on the
 * way in, because the client sets the properties and then asks. */
static void record(TestPrompt* self)
{
	g_free(seen_title);
	seen_title = g_strdup(self->title);
	g_free(seen_message);
	seen_message = g_strdup(self->message);
	g_free(seen_description);
	seen_description = g_strdup(self->description);
	g_free(seen_warning);
	seen_warning = g_strdup(self->warning);
	g_free(seen_choice_label);
	seen_choice_label = g_strdup(self->choice_label);
	g_free(seen_continue_label);
	seen_continue_label = g_strdup(self->continue_label);
	g_free(seen_caller_window);
	seen_caller_window = g_strdup(self->caller_window);
	seen_password_new = self->password_new;
}

static ScriptedRound* next_round(RoundKind kind)
{
	ScriptedRound* round = g_queue_pop_head(&script);

	if (round != NULL)
	{
		if (round->kind != kind)
			g_error("test prompter: a %s round was asked for and the script had a %s one",
			        kind == ROUND_PASSWORD ? "password" : "confirm",
			        round->kind == ROUND_PASSWORD ? "password" : "confirm");

		return round;
	}

	if (default_password == NULL)
		return NULL;

	round = g_new0(ScriptedRound, 1);
	round->kind = kind;
	round->password = g_strdup(default_password);
	round->ok = TRUE;
	return round;
}

static gboolean answer_now(gpointer user_data)
{
	TestPrompt* self = user_data;
	g_autoptr(GTask) task = g_steal_pointer(&self->pending);

	self->pending_source = 0;

	if (task != NULL)
		g_task_return_boolean(task, TRUE);

	return G_SOURCE_REMOVE;
}

static void arm_answer(TestPrompt* self, GTask* task, gboolean is_password)
{
	self->pending = g_object_ref(task);
	self->pending_is_password = is_password;

	if (answer_delay_msec == 0)
		self->pending_source = g_idle_add(answer_now, self);
	else
		self->pending_source = g_timeout_add(answer_delay_msec, answer_now, self);
}

static void test_prompt_password_async(GcrPrompt* prompt, GCancellable* cancellable,
                                       GAsyncReadyCallback callback, gpointer user_data)
{
	TestPrompt* self = TEST_PROMPT(prompt);
	g_autoptr(GTask) task = g_task_new(prompt, cancellable, callback, user_data);
	ScriptedRound* round = NULL;

	record(self);
	password_rounds++;

	round = next_round(ROUND_PASSWORD);

	g_clear_pointer(&self->answer, g_free);
	if (round != NULL)
	{
		self->answer = g_strdup(round->password);
		scripted_round_free(round);
	}

	if (self->closed)
	{
		g_clear_pointer(&self->answer, g_free);
		g_task_return_boolean(task, TRUE);
		return;
	}

	arm_answer(self, task, TRUE);
}

static const gchar* test_prompt_password_finish(GcrPrompt* prompt, GAsyncResult* result,
                                                GError** error)
{
	TestPrompt* self = TEST_PROMPT(prompt);

	if (!g_task_propagate_boolean(G_TASK(result), error))
		return NULL;

	/* gcr's convention: NULL with no error is "the user pressed Cancel". */
	return self->answer;
}

static void test_prompt_confirm_async(GcrPrompt* prompt, GCancellable* cancellable,
                                      GAsyncReadyCallback callback, gpointer user_data)
{
	TestPrompt* self = TEST_PROMPT(prompt);
	g_autoptr(GTask) task = g_task_new(prompt, cancellable, callback, user_data);
	ScriptedRound* round = NULL;

	record(self);
	confirm_rounds++;

	round = next_round(ROUND_CONFIRM);
	g_task_set_task_data(task, GINT_TO_POINTER(round != NULL && round->ok), NULL);
	if (round != NULL)
		scripted_round_free(round);

	if (self->closed)
	{
		g_task_set_task_data(task, GINT_TO_POINTER(FALSE), NULL);
		g_task_return_boolean(task, TRUE);
		return;
	}

	arm_answer(self, task, FALSE);
}

static GcrPromptReply test_prompt_confirm_finish(GcrPrompt* prompt, GAsyncResult* result,
                                                 GError** error)
{
	if (!g_task_propagate_boolean(G_TASK(result), error))
		return GCR_PROMPT_REPLY_CANCEL;

	return GPOINTER_TO_INT(g_task_get_task_data(G_TASK(result))) ? GCR_PROMPT_REPLY_CONTINUE
	                                                             : GCR_PROMPT_REPLY_CANCEL;
}

/* The client closed the prompt. A round in flight comes back as if the user
 * had dismissed it, which is what a real prompter does. */
static void test_prompt_close(GcrPrompt* prompt)
{
	TestPrompt* self = TEST_PROMPT(prompt);

	prompt_closes++;
	self->closed = TRUE;

	if (self->pending_source != 0)
	{
		g_source_remove(self->pending_source);
		self->pending_source = 0;
	}

	g_clear_pointer(&self->answer, g_free);

	if (self->pending != NULL)
	{
		g_autoptr(GTask) task = g_steal_pointer(&self->pending);

		if (!self->pending_is_password)
			g_task_set_task_data(task, GINT_TO_POINTER(FALSE), NULL);

		g_task_return_boolean(task, TRUE);
	}
}

static void test_prompt_iface_init(GcrPromptInterface* iface)
{
	iface->prompt_password_async = test_prompt_password_async;
	iface->prompt_password_finish = test_prompt_password_finish;
	iface->prompt_confirm_async = test_prompt_confirm_async;
	iface->prompt_confirm_finish = test_prompt_confirm_finish;
	iface->prompt_close = test_prompt_close;
}

/* --------------------------------------------------------------- the prompter */

struct _CertificateTestPrompter
{
	GcrSystemPrompter* prompter;
	GDBusConnection* connection;
	guint owner_id;
};

CertificateTestPrompter* certificate_test_prompter_start(GDBusConnection* connection,
                                                         const char* bus_name)
{
	CertificateTestPrompter* self = g_new0(CertificateTestPrompter, 1);

	self->connection = g_object_ref(connection);
	/* MULTIPLE, so that a second prompt does not have to wait for the first to
	 * be closed. The backend serialises its own prompts anyway; making the
	 * fixture the thing that enforces it would hide a regression. */
	self->prompter = gcr_system_prompter_new(GCR_SYSTEM_PROMPTER_MULTIPLE, TEST_TYPE_PROMPT);
	gcr_system_prompter_register(self->prompter, connection);

	self->owner_id = g_bus_own_name_on_connection(connection, bus_name,
	                                              G_BUS_NAME_OWNER_FLAGS_NONE, NULL, NULL, NULL,
	                                              NULL);

	return self;
}

void certificate_test_prompter_stop(CertificateTestPrompter* self)
{
	if (self == NULL)
		return;

	if (self->owner_id != 0)
		g_bus_unown_name(self->owner_id);

	gcr_system_prompter_unregister(self->prompter, TRUE);
	g_clear_object(&self->prompter);
	g_clear_object(&self->connection);
	g_free(self);
}
