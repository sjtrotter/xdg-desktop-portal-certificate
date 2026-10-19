/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Compiled as both C11 and C++17 using only the staged SDK and its .pc file. */
#define _POSIX_C_SOURCE 200809L
#include <xdp-certificate/core.h>
#include <xdp-certificate/ui.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct Task
{
	XccFunction function;
	void* closure;
	struct Task* next;
};
struct Queue
{
	pthread_mutex_t mutex;
	pthread_cond_t ready;
	struct Task* head;
	struct Task* tail;
	pthread_t desktop;
	unsigned completions;
	bool stopped;
};
#define REQUIRE(condition)                                                                         \
	do                                                                                             \
	{                                                                                              \
		if (!(condition))                                                                          \
		{                                                                                          \
			fprintf(stderr, "line %d: %s\n", __LINE__, #condition);                                \
			abort();                                                                               \
		}                                                                                          \
	} while (0)

static void post(void* user, XccFunction function, void* closure)
{
	struct Queue* queue = (struct Queue*)user;
	struct Task* task = (struct Task*)malloc(sizeof(*task));
	REQUIRE(task != NULL);
	task->function = function;
	task->closure = closure;
	task->next = NULL;
	REQUIRE(pthread_mutex_lock(&queue->mutex) == 0);
	if (queue->tail != NULL)
		queue->tail->next = task;
	else
		queue->head = task;
	queue->tail = task;
	REQUIRE(pthread_cond_signal(&queue->ready) == 0);
	REQUIRE(pthread_mutex_unlock(&queue->mutex) == 0);
}
static void pump(struct Queue* queue)
{
	struct timespec deadline;
	REQUIRE(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
	deadline.tv_sec += 20;
	REQUIRE(pthread_mutex_lock(&queue->mutex) == 0);
	while (queue->head == NULL)
		REQUIRE(pthread_cond_timedwait(&queue->ready, &queue->mutex, &deadline) == 0);
	struct Task* task = queue->head;
	queue->head = task->next;
	if (queue->head == NULL)
		queue->tail = NULL;
	REQUIRE(pthread_mutex_unlock(&queue->mutex) == 0);
	task->function(task->closure);
	free(task);
}
static void chooser(void* user, XccUiId id, const XccChooserView* view)
{
	(void)user;
	(void)id;
	(void)view;
	abort();
}
static void pin(void* user, XccUiId id, const XccPinView* view)
{
	(void)user;
	(void)id;
	(void)view;
	abort();
}
static void warning(void* user, XccUiId id, const XccWarning* view)
{
	(void)user;
	(void)id;
	(void)view;
	abort();
}
static void close_ui(void* user, XccUiId id)
{
	(void)user;
	(void)id;
	abort();
}
static void capabilities(XccRequest* request, const XccResult* result, void* user)
{
	struct Queue* queue = (struct Queue*)user;
	(void)request;
	REQUIRE(pthread_equal(pthread_self(), queue->desktop));
	REQUIRE(result->struct_size >= sizeof(*result));
	REQUIRE(result->abi_version == XCC_ABI_VERSION);
	REQUIRE(result->signature.struct_size >= sizeof(XccBytes));
	REQUIRE(result->signature.abi_version == XCC_ABI_VERSION);
	REQUIRE(result->kind == XCC_RESULT_CAPABILITIES);
	REQUIRE(result->error == XCC_OK);
	REQUIRE(result->mechanisms_present && result->mechanisms != NULL);
	REQUIRE(!result->has_display);
	REQUIRE(++queue->completions == 1);
}
static void stopped(XccContext* context, void* user)
{
	struct Queue* queue = (struct Queue*)user;
	(void)context;
	REQUIRE(pthread_equal(pthread_self(), queue->desktop));
	REQUIRE(!queue->stopped);
	queue->stopped = true;
}
int main(void)
{
	struct Queue queue;
	memset(&queue, 0, sizeof(queue));
	REQUIRE(pthread_mutex_init(&queue.mutex, NULL) == 0);
	REQUIRE(pthread_cond_init(&queue.ready, NULL) == 0);
	queue.desktop = pthread_self();
	XccDispatch dispatch;
	memset(&dispatch, 0, sizeof(dispatch));
	dispatch.struct_size = sizeof(dispatch);
	dispatch.abi_version = XCC_ABI_VERSION;
	dispatch.user = &queue;
	dispatch.post = post;
	XccUiV1 ui;
	memset(&ui, 0, sizeof(ui));
	ui.struct_size = sizeof(ui);
	ui.abi_version = XCC_ABI_VERSION;
	ui.chooser_show = chooser;
	ui.chooser_update = chooser;
	ui.pin_show = pin;
	ui.pin_update = pin;
	ui.warning = warning;
	ui.hide = close_ui;
	ui.close = close_ui;
	/* Empty, explicit module list needs no SoftHSM or host token configuration. */
	const char* modules[] = {NULL};
	XccConfig config;
	memset(&config, 0, sizeof(config));
	config.struct_size = sizeof(config);
	config.abi_version = XCC_ABI_VERSION;
	config.module_paths = modules;
	XccError error;
	memset(&error, 0, sizeof(error));
	error.struct_size = sizeof(error);
	error.abi_version = XCC_ABI_VERSION;
	XccContext* context = xcc_context_new(&config, &ui, &dispatch, &error);
	REQUIRE(context != NULL && error.code == XCC_OK);
	XccSessionSpec spec;
	memset(&spec, 0, sizeof(spec));
	spec.struct_size = sizeof(spec);
	spec.abi_version = XCC_ABI_VERSION;
	spec.app_id = "org.example.SdkConsumer";
	XccSession* session = xcc_session_new(context, &spec, &error);
	REQUIRE(session != NULL && error.code == XCC_OK);
	xcc_session_unref(xcc_session_ref(session));
	xcc_session_close(session);
	xcc_session_unref(session);
	XccRequest* request = xcc_get_capabilities_async(context, capabilities, &queue);
	REQUIRE(request != NULL);
	REQUIRE(queue.completions == 0);
	while (queue.completions == 0)
		pump(&queue);
	xcc_request_unref(request);
	xcc_context_shutdown_async(context, stopped, &queue);
	while (!queue.stopped)
		pump(&queue);
	REQUIRE(queue.completions == 1 && queue.head == NULL);
	xcc_context_unref(context);
	REQUIRE(pthread_cond_destroy(&queue.ready) == 0);
	REQUIRE(pthread_mutex_destroy(&queue.mutex) == 0);
	return EXIT_SUCCESS;
}
