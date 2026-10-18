/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "dispatch-glib.h"
#include "sources.h"
typedef struct
{
	XccFunction function;
	void* closure;
} Posted;
static gboolean deliver(gpointer data)
{
	Posted* p = data;
	p->function(p->closure);
	return G_SOURCE_REMOVE;
}
static void post(void* user, XccFunction function, void* closure)
{
	Posted* p = g_new(Posted, 1);
	*p = (Posted){function, closure};
	xcc_idle_add(user, deliver, p, g_free);
}
XccDispatch xcc_dispatch_glib(GMainContext* context)
{
	return (XccDispatch){sizeof(XccDispatch), XCC_ABI_VERSION,
						 context != NULL ? context : g_main_context_default(), post};
}
guint xcc_idle_add(GMainContext* context, GSourceFunc function, void* data, GDestroyNotify destroy)
{
	GSource* source = g_idle_source_new();
	g_source_set_priority(source, G_PRIORITY_DEFAULT);
	g_source_set_callback(source, function, data, destroy);
	guint id =
		g_source_attach(source, context != NULL ? context : g_main_context_get_thread_default());
	g_source_unref(source);
	return id;
}
guint xcc_timeout_add(guint seconds, GSourceFunc function, void* data)
{
	/* Keep the existing timer seam for legacy session tests. */
	if (g_main_context_get_thread_default() == NULL)
		return g_timeout_add_seconds(seconds, function, data);
	GSource* source = g_timeout_source_new_seconds(seconds);
	g_source_set_callback(source, function, data, NULL);
	guint id = g_source_attach(source, g_main_context_get_thread_default());
	g_source_unref(source);
	return id;
}
void xcc_source_remove(guint id)
{
	GMainContext* context = g_main_context_get_thread_default();
	GSource* source = g_main_context_find_source_by_id(context, id);
	if (source != NULL)
		g_source_destroy(source);
}
