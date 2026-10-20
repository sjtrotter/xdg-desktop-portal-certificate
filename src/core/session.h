/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#ifndef XCC_SESSION_H
#define XCC_SESSION_H

#include <glib-object.h>

#include "../certificate.h"
#include "../tokens/discovery.h"

G_BEGIN_DECLS

#define XCC_TYPE_SESSION (xcc_session_get_type())
G_DECLARE_FINAL_TYPE(XccSession, xcc_session, XCC, SESSION, GObject)

/** Device teardown follows the operation deadline by this grace period. */
#define CERTIFICATE_EXPIRY_GRACE_SECONDS 30
#define CERTIFICATE_MAX_DECRYPTS_PER_GRANT 32

/** Called at most once, before invalidation closes the session; reason is borrowed. */
typedef void (*XccSessionInvalidated)(XccSession* session, const char* reason, gpointer user_data);

XCC_API XccSession* xcc_session_new_legacy(const char* log_id, XccSessionInvalidated invalidated,
										   gpointer user_data);

/** Callback runs on the main context; clear it before destroying user_data. */
XCC_API void xcc_session_set_invalidated_callback(XccSession* session,
												  XccSessionInvalidated invalidated,
												  gpointer user_data);

/** Main-context grant with the validated, frontend-approved lifetime in seconds. */
void xcc_session_grant(XccSession* session, CertificateCandidate* candidate,
                        CertificatePurpose purpose, gboolean may_sign, gboolean may_decrypt,
                        guint32 lifetime);

gboolean xcc_session_is_expired(XccSession* session);
XCC_API gboolean xcc_session_is_closed(XccSession* session);
gboolean xcc_session_uses_token(XccSession* session, const CertificateToken* token);

/** Main-context invalidation: expired, token_removed, policy, backend_gone, error. */
XCC_API void xcc_session_invalidate(XccSession* session, const char* reason);
/** Main-context, idempotent close without invalidation notification. */
void xcc_session_close(XccSession* session);

/** Blocking; main-context callers use the async form. */
void xcc_session_release_device(XccSession* session);
void xcc_session_release_device_async(XccSession* session);
/** Always dispatch a worker release, then call done on the coordinator. */
void xcc_session_release_device_async_full(XccSession* session, GDestroyNotify done,
                                           gpointer user_data);

/** Shutdown only: drain pending worker releases for at most timeout_ms. */
void xcc_session_drain_releases(guint timeout_ms);
guint xcc_session_releases_pending(void);

G_END_DECLS

#endif
